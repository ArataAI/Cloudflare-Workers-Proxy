/**
 * Cloudflare Workers VLESS-XHTTP 代理服务
 * 
 * 安全增强版 - 修复内容:
 * 1. 移除硬编码凭据 - 强制使用环境变量
 * 2. 添加速率限制 - 防止暴力破解
 * 3. 添加输入验证 - 防止 SSRF 攻击
 * 4. 添加安全响应头
 * 5. 优化连接管理
 * 
 * 必需环境变量:
 * - UUID: 用户 UUID
 * 
 * 可选环境变量:
 * - PROXYIP: 代理 IP
 * 
 * 注意：绑定自定义域名后，需要在域名下左侧的网络菜单开启GRPC功能
 */

import { connect } from 'cloudflare:sockets';

// ==================== 配置常量 ====================

const CONFIG = {
    RATE_LIMIT: {
        WINDOW_MS: 60000,
        MAX_REQUESTS: 100,
    },
    
    CONNECTION: {
        BUFFER_SIZE: 512 * 1024,
        TIMEOUT_MS: 3000,
        IDLE_TIMEOUT_MS: 30000,
        MAX_RETRIES: 2,
        MAX_CONCURRENT: 64,
    },
    
    PRIVATE_IP_RANGES: [
        /^10\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
        /^192\.168\./, /^127\./, /^0\./, /^169\.254\./,
        /^::1$/, /^fc00:/i, /^fe80:/i, /^localhost$/i,
    ],
    
    CDN_DOMAINS: [
        'mfa.gov.ua', 'saas.sin.fan', 'store.ubi.com',
        'cf.130519.xyz', 'cf.008500.xyz', 'cf.090227.xyz',
        'cf.877774.xyz', 'cdns.doon.eu.org',
        'sub.danfeng.eu.org', 'cf.zhetengsha.eu.org'
    ],
};

// ==================== 全局状态 ====================

let ACTIVE_CONNECTIONS = 0;
const activeConnections = new WeakMap();
const activeStreams = new WeakMap();

// ==================== 速率限制器 ====================

class RateLimiter {
    constructor() {
        this.requests = new Map();
    }

    isAllowed(clientIP) {
        const now = Date.now();
        const windowStart = now - CONFIG.RATE_LIMIT.WINDOW_MS;
        const requests = this.requests.get(clientIP) || [];
        const validRequests = requests.filter(time => time > windowStart);
        
        if (validRequests.length >= CONFIG.RATE_LIMIT.MAX_REQUESTS) {
            return false;
        }
        
        validRequests.push(now);
        this.requests.set(clientIP, validRequests);
        return true;
    }
}

const rateLimiter = new RateLimiter();

// ==================== 安全工具函数 ====================

function getClientIP(request) {
    return request.headers.get('CF-Connecting-IP') || 
           request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 
           'unknown';
}

function getSecurityHeaders(contentType = 'text/html;charset=utf-8') {
    return {
        'Content-Type': contentType,
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
    };
}

function isValidUUID(uuid) {
    if (!uuid || typeof uuid !== 'string') return false;
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(uuid);
}

function validateHostname(hostname) {
    if (!hostname || typeof hostname !== 'string') {
        return { valid: false, reason: 'Invalid hostname' };
    }
    hostname = hostname.trim().toLowerCase();
    for (const pattern of CONFIG.PRIVATE_IP_RANGES) {
        if (pattern.test(hostname)) {
            return { valid: false, reason: 'Private address not allowed' };
        }
    }
    if (hostname.length > 253) {
        return { valid: false, reason: 'Hostname too long' };
    }
    return { valid: true };
}

function isValidPort(port) {
    return Number.isInteger(port) && port > 0 && port <= 65535;
}

// ==================== 配置管理 ====================

function loadConfig(env) {
    const errors = [];
    const getEnv = (...keys) => keys.map(k => env[k]).find(Boolean) || null;
    
    const uuid = getEnv('UUID', 'uuid');
    
    if (!uuid) {
        errors.push('UUID environment variable is required');
    } else if (!isValidUUID(uuid)) {
        errors.push('Invalid UUID format');
    }
    
    const proxyIPStr = getEnv('PROXYIP', 'proxyip', 'proxyIP') || '';
    const proxyIPs = proxyIPStr.split(',').map(s => s.trim()).filter(Boolean);
    
    return {
        config: {
            uuid: uuid || '',
            proxyIP: proxyIPs[0] || '',
        },
        errors,
    };
}

// ==================== 工具函数 ====================

const ADDRESS_TYPE_IPV4 = 1, ADDRESS_TYPE_URL = 2, ADDRESS_TYPE_IPV6 = 3;

function get_buffer(size) { 
    return new Uint8Array(size || CONFIG.CONNECTION.BUFFER_SIZE);
}

function parse_uuid(uuid) {
    uuid = uuid.replaceAll('-', '');
    const r = [];
    for (let i = 0; i < 16; i++) r.push(parseInt(uuid.substr(i * 2, 2), 16));
    return r;
}

function validate_uuid(id, uuid) {
    for (let i = 0; i < 16; i++) if (id[i] !== uuid[i]) return false;
    return true;
}

function concat_typed_arrays(first, ...args) {
    let len = first.length;
    for (let a of args) len += a.length;
    const r = new first.constructor(len);
    r.set(first, 0);
    len = first.length;
    for (let a of args) { r.set(a, len); len += a.length; }
    return r;
}

// ==================== 协议解析 ====================

async function read_header(readable, uuid_str) {
    const reader = readable.getReader({ mode: 'byob' });
    try {
        let r = await reader.readAtLeast(1 + 16 + 1, get_buffer(1024));
        let rlen = 0;
        let cache = r.value;
        rlen += r.value.length;
        const version = cache[0];
        const id = cache.slice(1, 17);
        const uuid = parse_uuid(uuid_str);
        if (!validate_uuid(id, uuid)) {
            reader.releaseLock();
            return null;
        }
        const pb_len = cache[17];
        const addr_plus1 = 1 + 16 + 1 + pb_len + 1 + 2 + 1;
        if (addr_plus1 + 1 > rlen) {
            if (r.done) {
                reader.releaseLock();
                return null;
            }
            r = await reader.readAtLeast(addr_plus1 + 1 - rlen, get_buffer(1024));
            rlen += r.value.length;
            cache = concat_typed_arrays(cache, r.value);
        }
        const cmd = cache[1 + 16 + 1 + pb_len];
        if (cmd !== 1) {
            reader.releaseLock();
            return null;
        }
        const port = (cache[addr_plus1 - 3] << 8) + cache[addr_plus1 - 2];
        const atype = cache[addr_plus1 - 1];
        let header_len = -1;
        if (atype === ADDRESS_TYPE_IPV4) header_len = addr_plus1 + 4;
        else if (atype === ADDRESS_TYPE_IPV6) header_len = addr_plus1 + 16;
        else if (atype === ADDRESS_TYPE_URL) header_len = addr_plus1 + 1 + cache[addr_plus1];
        if (header_len < 0) {
            reader.releaseLock();
            return null;
        }
        if (header_len > rlen) {
            r = await reader.readAtLeast(header_len - rlen, get_buffer(1024));
            rlen += r.value.length;
            cache = concat_typed_arrays(cache, r.value);
        }
        let hostname = '';
        const idx = addr_plus1;
        if (atype === ADDRESS_TYPE_IPV4) hostname = cache.slice(idx, idx + 4).join('.');
        else if (atype === ADDRESS_TYPE_URL) hostname = new TextDecoder().decode(cache.slice(idx + 1, idx + 1 + cache[idx]));
        else if (atype === ADDRESS_TYPE_IPV6) hostname = cache.slice(idx, idx + 16).reduce((s, b2, i2, a) => i2 % 2 ? s.concat(((a[i2 - 1] << 8) + b2).toString(16)) : s, []).join(':');
        if (!hostname) {
            reader.releaseLock();
            return null;
        }
        
        // 安全检查
        const validation = validateHostname(hostname);
        if (!validation.valid) {
            reader.releaseLock();
            return null;
        }
        
        const data = cache.slice(header_len);
        return { hostname, port, data, resp: new Uint8Array([version, 0]), reader, done: r.done };
    } catch (e) {
        try { reader.releaseLock(); } catch (_) { }
        throw e;
    }
}

// ==================== 流处理 ====================

class Counter {
    #total;
    constructor() { this.#total = 0; }
    get() { return this.#total; }
    add(size) { this.#total += size; }
}

async function upload_to_remote(counter, writer, httpx) {
    const writeStreamRef = new WeakRef(writer);
    activeStreams.set(writer, { type: 'upload', timestamp: Date.now() });
    
    async function inner(d) { 
        if (!d || d.length === 0) return; 
        counter.add(d.length); 
        await writer.write(d); 
    }
    
    try {
        await inner(httpx.data);
        while (!httpx.done) {
            const r = await httpx.reader.read(get_buffer(16 * 1024));
            if (r.done) break;
            await inner(r.value);
            httpx.done = r.done;
        }
    } catch (e) {
        console.error('Upload error:', e.message);
        throw e;
    } finally {
        try { 
            httpx.reader.releaseLock(); 
        } catch (_) {}
        
        try {
            const stream = writeStreamRef.deref();
            if (stream) {
                activeStreams.delete(stream);
            }
        } catch (_) {}
    }
}

function create_uploader(httpx, writable) {
    const counter = new Counter();
    const writer = writable.getWriter();
    const done = (async () => {
        try {
            await upload_to_remote(counter, writer, httpx);
        } catch (e) {
            try { writer.abort(); } catch (_) { }
            throw e;
        } finally {
            try { await writer.close(); } catch (_) { }
        }
    })();
    return { counter, done, abort: () => { try { writer.abort(); } catch (_) { } } };
}

function create_downloader(resp, remote_readable) {
    const counter = new Counter();
    let stream;
    const done = new Promise((resolve, reject) => {
        stream = new TransformStream({
            start(c) { counter.add(resp.length); c.enqueue(resp); },
            transform(chunk, c) { counter.add(chunk.length); c.enqueue(chunk); },
            cancel(reason) { reject(reason); }
        }, null, new ByteLengthQueuingStrategy({ highWaterMark: CONFIG.CONNECTION.BUFFER_SIZE }));

        const reader = remote_readable.getReader();
        const writer = stream.writable.getWriter();
        activeStreams.set(reader, { type: 'download_reader', timestamp: Date.now() });
        activeStreams.set(writer, { type: 'download_writer', timestamp: Date.now() });

        ;(async () => {
            try {
                while (true) {
                    const r = await reader.read();
                    if (r.done) break;
                    await writer.write(r.value);
                }
                await writer.close();
                resolve();
            } catch (e) {
                reject(e);
            } finally {
                try { reader.releaseLock(); } catch (_) {}
                try { writer.releaseLock(); } catch (_) {}
                
                try {
                    activeStreams.delete(reader);
                    activeStreams.delete(writer);
                } catch (_) {}
            }
        })();
    });
    return {
        readable: stream.readable,
        counter,
        done,
        abort: () => {
            try { stream.readable.cancel(); } catch (_) { }
            try { stream.writable.abort(); } catch (_) { }
        }
    };
}

// ==================== 代理连接 ====================

function parseProxyConfig(proxyStr) {
    if (!proxyStr) return null;
    proxyStr = proxyStr.trim();
    
    if (proxyStr.startsWith('socks://') || proxyStr.startsWith('socks5://')) {
        const urlStr = proxyStr.replace(/^socks:\/\//, 'socks5://');
        try {
            const url = new URL(urlStr);
            const validation = validateHostname(url.hostname);
            if (!validation.valid) return null;
            return {
                type: 'socks5',
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : '',
                host: url.hostname,
                port: parseInt(url.port) || 1080
            };
        } catch (e) {
            return null;
        }
    }
    
    if (proxyStr.startsWith('http://') || proxyStr.startsWith('https://')) {
        try {
            const url = new URL(proxyStr);
            const validation = validateHostname(url.hostname);
            if (!validation.valid) return null;
            return {
                type: url.protocol === 'https:' ? 'https' : 'http',
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : '',
                host: url.hostname,
                port: parseInt(url.port) || (url.protocol === 'https:' ? 443 : 80)
            };
        } catch (e) {
            return null;
        }
    }
    
    const hostMatch = proxyStr.match(/^([^:]+)(?::(\d+))?$/);
    if (hostMatch) {
        const validation = validateHostname(hostMatch[1]);
        if (!validation.valid) return null;
        return {
            type: 'direct',
            host: hostMatch[1],
            port: parseInt(hostMatch[2] || '443')
        };
    }
    return null;
}

async function socks5Connect(remote, targetHost, targetPort, username, password) {
    let writer, reader;
    try {
        writer = remote.writable.getWriter();
        const hasAuth = username && password;
        const authMethods = hasAuth ? 
            new Uint8Array([0x05, 0x02, 0x00, 0x02]) :
            new Uint8Array([0x05, 0x01, 0x00]); 
        
        await writer.write(authMethods);
        writer.releaseLock();
        
        reader = remote.readable.getReader();
        const authResponse = await reader.read();
        if (authResponse.done || authResponse.value.byteLength < 2) {
            throw new Error('S5 method selection failed');
        }
        
        const selectedMethod = new Uint8Array(authResponse.value)[1];
        reader.releaseLock();
        
        if (selectedMethod === 0x02) {
            if (!username || !password) {
                throw new Error('S5 requires authentication');
            }
            const writer2 = remote.writable.getWriter();
            const userBytes = new TextEncoder().encode(username);
            const passBytes = new TextEncoder().encode(password);
            const authPacket = new Uint8Array(3 + userBytes.length + passBytes.length);
            authPacket[0] = 0x01; 
            authPacket[1] = userBytes.length;
            authPacket.set(userBytes, 2);
            authPacket[2 + userBytes.length] = passBytes.length;
            authPacket.set(passBytes, 3 + userBytes.length);
            await writer2.write(authPacket);
            writer2.releaseLock();
            
            const reader2 = remote.readable.getReader();
            const authResponse2 = await reader2.read();
            if (authResponse2.done || new Uint8Array(authResponse2.value)[1] !== 0x00) {
                throw new Error('S5 authentication failed');
            }
            reader2.releaseLock();
        } else if (selectedMethod !== 0x00) {
            throw new Error(`S5 unsupported auth method: ${selectedMethod}`);
        }
        
        const writer3 = remote.writable.getWriter();
        const hostBytes = new TextEncoder().encode(targetHost);
        const connectPacket = new Uint8Array(7 + hostBytes.length);
        connectPacket[0] = 0x05;
        connectPacket[1] = 0x01;
        connectPacket[2] = 0x00; 
        connectPacket[3] = 0x03; 
        connectPacket[4] = hostBytes.length;
        connectPacket.set(hostBytes, 5);
        new DataView(connectPacket.buffer).setUint16(5 + hostBytes.length, targetPort, false);
        await writer3.write(connectPacket);
        writer3.releaseLock();
        
        const reader3 = remote.readable.getReader();
        const connectResponse = await reader3.read();
        if (connectResponse.done || new Uint8Array(connectResponse.value)[1] !== 0x00) {
            throw new Error('S5 connection failed');
        }
        reader3.releaseLock();
        return true;
    } catch (e) {
        try { if (writer) writer.releaseLock(); } catch (_) {}
        try { if (reader) reader.releaseLock(); } catch (_) {}
        throw new Error(`s5 error: ${e.message}`);
    }
}

async function httpConnect(remote, targetHost, targetPort, username, password) {
    let writer, reader;
    try {
        writer = remote.writable.getWriter();
        let connectRequest = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n`;
        connectRequest += `Host: ${targetHost}:${targetPort}\r\n`;
        if (username && password) {
            const auth = btoa(`${username}:${password}`);
            connectRequest += `Proxy-Authorization: Basic ${auth}\r\n`;
        }
        connectRequest += '\r\n';
        await writer.write(new TextEncoder().encode(connectRequest));
        writer.releaseLock();
        reader = remote.readable.getReader();
        let responseData = new Uint8Array(0);
        let headerComplete = false;
        const readTimeout = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('HTTP read timeout')), CONFIG.CONNECTION.TIMEOUT_MS)
        );
        
        while (!headerComplete) {
            const chunk = await Promise.race([
                reader.read(),
                readTimeout
            ]);
            
            if (chunk.done) {
                throw new Error('HTTP connection closed unexpectedly');
            }
            
            const newData = new Uint8Array(responseData.length + chunk.value.byteLength);
            newData.set(responseData);
            newData.set(new Uint8Array(chunk.value), responseData.length);
            responseData = newData;
            
            const responseText = new TextDecoder().decode(responseData);
            if (responseText.includes('\r\n\r\n')) {
                headerComplete = true;
            }
        }
        reader.releaseLock();
        
        const responseText = new TextDecoder().decode(responseData);
        if (!responseText.startsWith('HTTP/1.1 200') && !responseText.startsWith('HTTP/1.0 200')) {
            throw new Error(`HTTP connection failed: ${responseText.split('\r\n')[0]}`);
        }
        return true;
    } catch (e) {
        try { if (writer) writer.releaseLock(); } catch (_) {}
        try { if (reader) reader.releaseLock(); } catch (_) {}
        throw new Error(`HTTP connection failed: ${e.message}`);
    }
}

async function connect_to_remote(httpx, proxyIP, fallbackProxyIP) {
    const proxyConfig = parseProxyConfig(proxyIP);
    
    if (proxyConfig && (proxyConfig.type === 'socks5' || proxyConfig.type === 'http' || proxyConfig.type === 'https')) {
        let remote = null;
        try {
            remote = connect({ hostname: proxyConfig.host, port: proxyConfig.port });
            activeConnections.set(remote, { 
                type: proxyConfig.type, 
                host: proxyConfig.host, 
                port: proxyConfig.port,
                timestamp: Date.now() 
            });
        
            await Promise.race([
                remote.opened,
                new Promise((_, reject) => 
                    setTimeout(() => reject(new Error(`connect ${proxyConfig.host}:${proxyConfig.port} timeout`)), CONFIG.CONNECTION.TIMEOUT_MS)
                )
            ]);
            
            if (proxyConfig.type === 'socks5') {
                await socks5Connect(remote, httpx.hostname, httpx.port, proxyConfig.username, proxyConfig.password);
            } else {
                await httpConnect(remote, httpx.hostname, httpx.port, proxyConfig.username, proxyConfig.password);
            }
            
            const uploader = create_uploader(httpx, remote.writable);
            const downloader = create_downloader(httpx.resp, remote.readable);
            return {
                downloader,
                uploader,
                close: () => { 
                    try { 
                        activeConnections.delete(remote);
                        remote.close(); 
                    } catch (_) {} 
                }
            };
        } catch (e) {
            if (remote) {
                try { 
                    activeConnections.delete(remote);
                    remote.close(); 
                } catch (_) {}
            }
            console.error(`${proxyConfig.type.toUpperCase()} connect failed:`, e.message);
            return null;
        }
    }
    
    const connectionTargets = [
        { type: "direct", host: httpx.hostname, port: httpx.port },
        { type: "proxy", host: proxyConfig ? proxyConfig.host : proxyIP, port: proxyConfig ? proxyConfig.port : httpx.port },
        { type: "fallback", host: fallbackProxyIP, port: httpx.port }
    ].filter(target => target.host);

    const connectionPromises = connectionTargets.map(({ type, host, port }) =>
        (async () => {
            let remote = null;
            for (let attempt = 0; attempt < CONFIG.CONNECTION.MAX_RETRIES + 1; attempt++) {
                try {
                    // 安全检查
                    const validation = validateHostname(host);
                    if (!validation.valid) {
                        throw new Error(validation.reason);
                    }
                    
                    remote = connect({ hostname: host, port: port });
                    activeConnections.set(remote, { 
                        type, 
                        host, 
                        port,
                        timestamp: Date.now(),
                        attempt
                    });
                
                    await Promise.race([
                        remote.opened,
                        new Promise((_, reject) => 
                            setTimeout(() => reject(new Error(` ${host} timeout`)), CONFIG.CONNECTION.TIMEOUT_MS)
                        )
                    ]);
                    return { remote, host, type };
                } catch (error) {
                    if (remote) {
                        try { 
                            activeConnections.delete(remote);
                            remote.close(); 
                        } catch (_) {}
                    }
                    
                    if (attempt < CONFIG.CONNECTION.MAX_RETRIES) {
                        await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)));
                        continue;
                    }
                    throw error;
                }
            }
        })()
    );

    let successfulConnection = null;
    const results = await Promise.allSettled(connectionPromises);
    
    for (const result of results) {
        if (result.status === 'fulfilled' && result.value) {
            successfulConnection = result.value;
            break;
        }
    }

    if (successfulConnection) {
        const { remote } = successfulConnection;
        const uploader = create_uploader(httpx, remote.writable);
        const downloader = create_downloader(httpx.resp, remote.readable);
        return {
            downloader,
            uploader,
            close: () => { 
                try { 
                    activeConnections.delete(remote);
                    remote.close(); 
                } catch (_) {} 
            }
        };
    } else {
        return null;
    }
}

// ==================== 请求处理 ====================

async function handle_client(body, cfg) {
    if (ACTIVE_CONNECTIONS >= CONFIG.CONNECTION.MAX_CONCURRENT) {
        return new Response('Too many connections', { status: 429 });
    }
    
    ACTIVE_CONNECTIONS++;
    let cleaned = false;
    
    const cleanup = () => {
        if (!cleaned) {
            ACTIVE_CONNECTIONS = Math.max(0, ACTIVE_CONNECTIONS - 1);
            cleaned = true;
        }
    };

    try {
        const httpx = await read_header(body, cfg.UUID);
        if (!httpx) {
            cleanup();
            return null;
        }
        
        const remoteConnection = await connect_to_remote(httpx, cfg.PROXYIP, '');
        if (!remoteConnection) {
            cleanup();
            return null;
        }

        const connectionClosed = Promise.race([
            remoteConnection.downloader.done.catch(() => { }),
            remoteConnection.uploader.done.catch(() => { }),
            new Promise(resolve => setTimeout(resolve, CONFIG.CONNECTION.IDLE_TIMEOUT_MS))
        ]).finally(() => {
            try { remoteConnection.close(); } catch (_) { }
            try { remoteConnection.downloader.abort(); } catch (_) { }
            try { remoteConnection.uploader.abort(); } catch (_) { }
            cleanup();
        });

        return { 
            readable: remoteConnection.downloader.readable, 
            closed: connectionClosed 
        };
    } catch (e) {
        console.error('Client handling error:', e.message);
        cleanup();
        return null;
    }
}

async function handle_post(request, cfg) {
    try {
        return await handle_client(request.body, cfg);
    } catch (e) {
        console.error('POST handling error:', e.message);
        return null;
    }
}

// ==================== 订阅生成 ====================

function generate_link(uuid, hostname, port, path, sni, currentHost, proxyIP = null) {
    const protc = 'xhttp', header = 'vless';
    const params = new URLSearchParams({
        encryption: 'none', security: 'tls', sni: sni || currentHost, fp: 'chrome', allowInsecure: '1', alpn: 'h2,http/1.1',
        type: protc, host: currentHost, path: path.startsWith('/') ? path : `/${path}`, mode: 'stream-one'
    });
    
    if (proxyIP) {
        params.append('proxyip', proxyIP);
    }
    
    return `${header}://${uuid}@${hostname}:${port}?${params.toString()}#${header}-${protc}`;
}

function generate_subscription(uuid, cfipList, port = 443, path, sni, currentHost, proxyIP = null) {
    return btoa(cfipList.map(h => generate_link(uuid, h, port, path, sni, currentHost, proxyIP)).join('\n'));
}

// ==================== 主导出 ====================

export default {
    async fetch(request, env) {
        const clientIP = getClientIP(request);
        
        if (!rateLimiter.isAllowed(clientIP)) {
            return new Response('Too Many Requests', { 
                status: 429, 
                headers: { 'Retry-After': '60' } 
            });
        }

        const { config, errors } = loadConfig(env);
        
        if (errors.length > 0) {
            return new Response(
                `Configuration Error:\n${errors.join('\n')}\n\nPlease set required environment variables.`,
                { status: 500, headers: getSecurityHeaders('text/plain;charset=utf-8') }
            );
        }

        const url = new URL(request.url);
        let customProxyIP = config.proxyIP;
        let pathProxyIP = null;
        let pathname = url.pathname;
        
        if (pathname.startsWith('/proxyip=')) {
            try { 
                pathProxyIP = decodeURIComponent(pathname.substring(9)).trim();
            } catch (e) { }
        }
        customProxyIP = pathProxyIP || url.searchParams.get('proxyip') || request.headers.get('proxyip') || config.proxyIP;
        
        const cfg = { UUID: config.uuid, PROXYIP: customProxyIP };
        
        if (request.method === 'POST') {
            const r = await handle_post(request, cfg);
            if (r) return new Response(r.readable, {
                headers: {
                    'X-Accel-Buffering': 'no',
                    'Cache-Control': 'no-store',
                    'Connection': 'keep-alive',
                    'User-Agent': 'Go-http-client/2.0',
                    'Content-Type': 'application/grpc'
                }
            });
            return new Response('Internal Server Error', { status: 500 });
        }
        
        if (request.method === 'GET') {
            const path = url.pathname;
            
            if (path === '/') {
                const html = `<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VLESS XHTTP</title><style>body{font-family:Arial,sans-serif;background:linear-gradient(135deg, #85dfb5 0%, #136e92 100%);min-height:100vh;display:flex;align-items:center;justify-content:center}.container{max-width:600px;background:#fff;padding:40px;border-radius:10px;box-shadow:0 10px 40px rgba(0,0,0,.3);text-align:center}h1{color:#667eea;margin-bottom:20px}.info{font-size:18px;color:#666;margin:20px 0}.link{display:inline-block;background:#667eea;color:#fff;padding:12px 30px;border-radius:5px;text-decoration:none;margin-top:20px}.link:hover{background:#5568d3}.footer{margin-top:30px;padding-top:20px;border-top:1px solid #eee;font-size:14px;color:#999}.footer a{color:#667eea;text-decoration:none;margin:0 10px}.footer a:hover{text-decoration:underline}</style></head><body><div class="container"><h2>VLESS-XHTTP 代理服务</h2><div class="info">请访问: <strong>https://${url.hostname}/你的UUID</strong><br><br><p>查看节点订阅链接</p><div class="footer"><a href="https://github.com/eooce/CF-Workers-and-Snip-VLESS" target="_blank">GitHub 项目</a>|<a href="https://t.me/eooceu" target="_blank">Telegram 群组</a>|<a href="https://check-proxyip.ssss.nyc.mn" target="_blank">ProxyIP 检测服务</a></div></div></body></html>`;
                return new Response(html, { headers: getSecurityHeaders() });
            }
            
            if (path.includes(cfg.UUID) && path.toLowerCase() !== `/sub/${config.uuid}`) {
                const html = `<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VLESS XHTTP</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial,sans-serif;background:linear-gradient(135deg, #85dfb5 0%, #136e92 100%);min-height:100vh;padding:20px}.container{max-width:900px;margin:0 auto;background:#fff;border-radius:15px;padding:30px;box-shadow:0 20px 60px rgba(0,0,0,.3)}h1{color:#667eea;margin-bottom:10px;font-size:2rem;text-align:center}.section{margin-bottom:25px}.section-title{color:#667eea;font-size:16px;font-weight:600;margin-bottom:12px;padding-bottom:6px;border-bottom:2px solid #667eea}.link-box{background:#f7f9fc;border:1px solid #e1e8ed;border-radius:8px;padding:12px;margin-bottom:10px}.link-label{font-size:16px;color:#666;margin-bottom:6px;font-weight:700}.link-content{display:flex;gap:8px}.link-text{flex:1;background:#fff;padding:8px 12px;border-radius:5px;border:1px solid #ddd;font-size:.8rem;word-break:break-all;font-family:monospace}.copy-btn{background:#667eea;color:#fff;border:none;padding:8px 16px;border-radius:5px;cursor:pointer;font-size:13px;white-space:nowrap}.copy-btn:hover{background:#5568d3}.copy-btn.copied{background:#48c774}.footer{margin-top:30px;padding-top:20px;border-top:1px solid #e1e8ed;text-align:center;font-size:14px;color:#999}.footer a{color:#667eea;text-decoration:none;margin:0 10px}.footer a:hover{text-decoration:underline}</style></head><body><div class="container"><h1>VLESS-XHTTP 订阅中心</h1><br><div class="section"><div class="section-title">🔗 通用订阅</div><div class="link-box"><div class="link-label">v2rayN / Loon / Shadowrocket / Karing</div><div class="link-content"><div class="link-text" id="v2ray-link">https://${url.hostname}/sub/${config.uuid}</div><button class="copy-btn" onclick="copyToClipboard('v2ray-link',this)">复制</button></div></div></div><div class="footer"><a href="https://github.com/eooce/CF-Workers-and-Snip-VLESS" target="_blank">GitHub 项目</a>|<a href="https://t.me/eooceu" target="_blank">Telegram 群组</a>|<a href="https://check-proxyip.ssss.nyc.mn" target="_blank">ProxyIP 检测服务</a></div></div><script>function copyToClipboard(e,t){const n=document.getElementById(e).textContent;navigator.clipboard&&navigator.clipboard.writeText?navigator.clipboard.writeText(n).then(()=>{showCopySuccess(t)}).catch(()=>{fallbackCopy(n,t)}):fallbackCopy(n,t)}function fallbackCopy(e,t){const n=document.createElement("textarea");n.value=e,n.style.position="fixed",n.style.left="-999999px",document.body.appendChild(n),n.select();try{document.execCommand("copy"),showCopySuccess(t)}catch(e){alert("复制失败，请手动复制")}document.body.removeChild(n)}function showCopySuccess(e){const t=e.textContent;e.textContent="已复制",e.classList.add("copied"),setTimeout(()=>{e.textContent=t,e.classList.remove("copied")},2e3)}</script></body></html>`;
                return new Response(html, { headers: getSecurityHeaders() });
            }
            
            if (path.toLowerCase() === `/sub/${config.uuid}`) {
                const port = 443,
                    nodePath = '/',
                    sni = url.searchParams.get('sni') || url.hostname,
                    currentHost = url.hostname;
                const subscription = generate_subscription(cfg.UUID, CONFIG.CDN_DOMAINS, port, nodePath, sni, currentHost, cfg.PROXYIP);
                return new Response(subscription, {
                    headers: {
                        'Content-Type': 'text/plain; charset=utf-8',
                        'Cache-Control': 'no-cache, no-store, must-revalidate',
                        'Pragma': 'no-cache',
                        'Expires': '0'
                    }
                });
            }
        }
        
        return new Response('Method Not Allowed', { status: 405 });
    }
};
