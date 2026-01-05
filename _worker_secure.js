/**
 * Cloudflare Workers VLESS + Trojan + Shadowsocks 代理服务
 * 
 * 安全增强版 - 支持三种协议:
 * - VLESS: 主流协议，轻量高效
 * - Trojan: 模仿 HTTPS 流量
 * - Shadowsocks: 兼容性广泛
 * 
 * 安全特性:
 * 1. 移除硬编码凭据 - 强制使用环境变量
 * 2. 添加速率限制 - 防止暴力破解
 * 3. 添加输入验证 - 防止 SSRF 攻击
 * 4. 改进认证机制 - 使用 Cookie + Token
 * 5. 添加安全响应头
 * 
 * 必需环境变量:
 * - UUID: 用户 UUID
 * - PASSWORD: 访问密码
 * 
 * 可选环境变量:
 * - PROXYIP: 代理 IP
 * - SUB_PATH: 订阅路径
 * - DISABLE_TROJAN: 禁用 Trojan
 * - DISABLE_SS: 禁用 Shadowsocks
 * - SS_PATH: Shadowsocks 路径
 */

import { connect } from 'cloudflare:sockets';

// ==================== 配置常量 ====================

const CONFIG = {
    DEFAULT_SUB_PATH: 'link',
    
    RATE_LIMIT: {
        WINDOW_MS: 60000,
        MAX_REQUESTS: 100,
        MAX_AUTH_ATTEMPTS: 5,
        AUTH_LOCKOUT_MS: 300000,
    },
    
    CONNECTION: {
        TIMEOUT_MS: 10000,
        MAX_CONCURRENT: 64,
        MAX_HEADER_SIZE: 8192,
    },
    
    SPEED_TEST_DOMAINS: [
        'speedtest.net', 'fast.com', 'speedtest.cn',
        'speed.cloudflare.com', 'ovo.speedtestcustom.com'
    ],
    
    PRIVATE_IP_RANGES: [
        /^10\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
        /^192\.168\./, /^127\./, /^0\./, /^169\.254\./,
        /^::1$/, /^fc00:/i, /^fe80:/i, /^localhost$/i,
    ],
    
    // CDN 优选域名
    CDN_DOMAINS: [
        'mfa.gov.ua#SG', 'saas.sin.fan#HK', 'store.ubi.com#JP',
        'cf.130519.xyz#KR', 'cf.008500.xyz#HK', 'cf.090227.xyz#SG',
        'cf.877774.xyz#HK', 'cdns.doon.eu.org#JP',
        'sub.danfeng.eu.org#TW', 'cf.zhetengsha.eu.org#HK'
    ],
};

// ==================== 速率限制器 ====================

class RateLimiter {
    constructor() {
        this.requests = new Map();
        this.authAttempts = new Map();
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

    recordAuthFailure(clientIP) {
        const now = Date.now();
        const record = this.authAttempts.get(clientIP) || { count: 0, lockedUntil: 0 };
        
        if (record.lockedUntil > now) return true;
        
        record.count++;
        if (record.count >= CONFIG.RATE_LIMIT.MAX_AUTH_ATTEMPTS) {
            record.lockedUntil = now + CONFIG.RATE_LIMIT.AUTH_LOCKOUT_MS;
            record.count = 0;
        }
        
        this.authAttempts.set(clientIP, record);
        return record.lockedUntil > now;
    }

    isAuthLocked(clientIP) {
        const record = this.authAttempts.get(clientIP);
        return record && record.lockedUntil > Date.now();
    }

    resetAuth(clientIP) {
        this.authAttempts.delete(clientIP);
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
        'Referrer-Policy': 'strict-origin-when-cross-origin',
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

// ==================== 通用工具函数 ====================

function closeSocketQuietly(socket) {
    try {
        if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING)) {
            socket.close();
        }
    } catch (error) {}
}

function formatIdentifier(arr, offset = 0) {
    const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.substring(0,8)}-${hex.substring(8,12)}-${hex.substring(12,16)}-${hex.substring(16,20)}-${hex.substring(20)}`;
}

function base64ToArray(b64Str) {
    if (!b64Str) return { error: null };
    try {
        const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return { earlyData: bytes.buffer, error: null };
    } catch (error) {
        return { error };
    }
}

function parsePryAddress(serverStr) {
    if (!serverStr) return null;
    serverStr = serverStr.trim();

    if (serverStr.startsWith('socks://') || serverStr.startsWith('socks5://')) {
        const urlStr = serverStr.replace(/^socks:\/\//, 'socks5://');
        try {
            const url = new URL(urlStr);
            const host = url.hostname;
            const port = parseInt(url.port) || 1080;
            
            const validation = validateHostname(host);
            if (!validation.valid || !isValidPort(port)) return null;
            
            return {
                type: 'socks5', host, port,
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) { return null; }
    }

    if (serverStr.startsWith('http://') || serverStr.startsWith('https://')) {
        try {
            const url = new URL(serverStr);
            const host = url.hostname;
            const port = parseInt(url.port) || (serverStr.startsWith('https://') ? 443 : 80);
            
            const validation = validateHostname(host);
            if (!validation.valid || !isValidPort(port)) return null;
            
            return {
                type: 'http', host, port,
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) { return null; }
    }

    if (serverStr.startsWith('[')) {
        const closeBracket = serverStr.indexOf(']');
        if (closeBracket > 0) {
            const host = serverStr.substring(1, closeBracket);
            const rest = serverStr.substring(closeBracket + 1);
            
            const validation = validateHostname(host);
            if (!validation.valid) return null;
            
            if (rest.startsWith(':')) {
                const port = parseInt(rest.substring(1), 10);
                if (isValidPort(port)) return { type: 'direct', host, port };
            }
            return { type: 'direct', host, port: 443 };
        }
    }

    const lastColonIndex = serverStr.lastIndexOf(':');
    if (lastColonIndex > 0) {
        const host = serverStr.substring(0, lastColonIndex);
        const port = parseInt(serverStr.substring(lastColonIndex + 1), 10);
        
        const validation = validateHostname(host);
        if (!validation.valid) return null;
        if (isValidPort(port)) return { type: 'direct', host, port };
    }

    const validation = validateHostname(serverStr);
    if (!validation.valid) return null;
    return { type: 'direct', host: serverStr, port: 443 };
}

function isSpeedTestSite(hostname) {
    if (!hostname) return false;
    hostname = hostname.toLowerCase();
    for (const domain of CONFIG.SPEED_TEST_DOMAINS) {
        if (hostname === domain || hostname.endsWith('.' + domain)) return true;
    }
    return false;
}

// ==================== SHA-224 ====================

async function sha224(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    let H = [0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4];
    const msgLen = data.length;
    const bitLen = msgLen * 8;
    const paddedLen = Math.ceil((msgLen + 9) / 64) * 64;
    const padded = new Uint8Array(paddedLen);
    padded.set(data);
    padded[msgLen] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(paddedLen - 4, bitLen, false);
    
    function rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
    }
    
    for (let chunk = 0; chunk < paddedLen; chunk += 64) {
        const W = new Uint32Array(64);
        for (let i = 0; i < 16; i++) W[i] = view.getUint32(chunk + i * 4, false);
        for (let i = 16; i < 64; i++) {
            const s0 = rightRotate(W[i-15],7)^rightRotate(W[i-15],18)^(W[i-15]>>>3);
            const s1 = rightRotate(W[i-2],17)^rightRotate(W[i-2],19)^(W[i-2]>>>10);
            W[i] = (W[i-16]+s0+W[i-7]+s1)>>>0;
        }
        let [a,b,c,d,e,f,g,h] = H;
        for (let i = 0; i < 64; i++) {
            const S1 = rightRotate(e,6)^rightRotate(e,11)^rightRotate(e,25);
            const ch = (e&f)^(~e&g);
            const temp1 = (h+S1+ch+K[i]+W[i])>>>0;
            const S0 = rightRotate(a,2)^rightRotate(a,13)^rightRotate(a,22);
            const maj = (a&b)^(a&c)^(b&c);
            const temp2 = (S0+maj)>>>0;
            h=g;g=f;f=e;e=(d+temp1)>>>0;d=c;c=b;b=a;a=(temp1+temp2)>>>0;
        }
        H[0]=(H[0]+a)>>>0;H[1]=(H[1]+b)>>>0;H[2]=(H[2]+c)>>>0;H[3]=(H[3]+d)>>>0;
        H[4]=(H[4]+e)>>>0;H[5]=(H[5]+f)>>>0;H[6]=(H[6]+g)>>>0;H[7]=(H[7]+h)>>>0;
    }
    const result = [];
    for (let i = 0; i < 7; i++) {
        result.push(
            ((H[i]>>>24)&0xff).toString(16).padStart(2,'0'),
            ((H[i]>>>16)&0xff).toString(16).padStart(2,'0'),
            ((H[i]>>>8)&0xff).toString(16).padStart(2,'0'),
            (H[i]&0xff).toString(16).padStart(2,'0')
        );
    }
    return result.join('');
}

// ==================== 配置管理 ====================

function loadConfig(env) {
    const errors = [];
    const getEnv = (...keys) => keys.map(k => env[k]).find(Boolean) || null;
    
    const uuid = getEnv('UUID', 'uuid', 'AUTH');
    const password = getEnv('PASSWORD', 'PASSWD', 'password');
    
    if (!uuid) errors.push('UUID environment variable is required');
    else if (!isValidUUID(uuid)) errors.push('Invalid UUID format');
    
    if (!password) errors.push('PASSWORD environment variable is required');
    else if (password.length < 6) errors.push('Password must be at least 6 characters');
    
    const proxyIPStr = getEnv('PROXYIP', 'proxyip', 'proxyIP') || '';
    const proxyIPs = proxyIPStr.split(',').map(s => s.trim()).filter(Boolean);
    
    return {
        config: {
            uuid: uuid || '',
            password: password || '',
            proxyIP: proxyIPs[0] || '',
            subPath: getEnv('SUB_PATH', 'subpath') || CONFIG.DEFAULT_SUB_PATH,
            disableTrojan: getEnv('DISABLE_TROJAN', 'CLOSE_TROJAN') === 'true',
            disableSS: getEnv('DISABLE_SS') === 'true',
            ssPath: getEnv('SS_PATH', 'SSPATH') || uuid || '',
        },
        errors,
    };
}

// ==================== 认证 ====================

async function generateAuthToken(password, secret) {
    const timestamp = Date.now();
    const hash = await sha224(`${password}:${timestamp}:${secret}`);
    return btoa(JSON.stringify({ t: timestamp, h: hash.substring(0, 32) }));
}

async function verifyAuthToken(token, password, secret, maxAgeMs = 24*60*60*1000) {
    try {
        const { t: timestamp, h: hash } = JSON.parse(atob(token));
        if (Date.now() - timestamp > maxAgeMs) return false;
        const expectedHash = await sha224(`${password}:${timestamp}:${secret}`);
        return hash === expectedHash.substring(0, 32);
    } catch { return false; }
}

function getAuthCookie(request) {
    const cookieHeader = request.headers.get('Cookie') || '';
    const match = cookieHeader.match(/auth_token=([^;]+)/);
    return match ? match[1] : null;
}

// ==================== 主导出 ====================

export default {
    async fetch(request, env, ctx) {
        const clientIP = getClientIP(request);
        
        // 速率限制检查
        if (!rateLimiter.isAllowed(clientIP)) {
            return new Response('Too Many Requests', { 
                status: 429, 
                headers: { 'Retry-After': '60' } 
            });
        }

        // 加载配置
        const { config, errors } = loadConfig(env);
        
        if (errors.length > 0) {
            return new Response(
                `Configuration Error:\n${errors.join('\n')}\n\nPlease set required environment variables.`,
                { status: 500, headers: getSecurityHeaders('text/plain;charset=utf-8') }
            );
        }

        const { uuid: yourUUID, password, proxyIP, subPath, disableTrojan, disableSS, ssPath } = config;

        try {
            const url = new URL(request.url);
            const pathname = url.pathname;
            
            // 处理 proxyIP 路径
            let customProxyIP = proxyIP;
            if (pathname.startsWith('/proxyip=')) {
                try {
                    const pathProxyIP = decodeURIComponent(pathname.substring(9)).trim();
                    if (pathProxyIP && !request.headers.get('Upgrade')) {
                        return new Response(`set proxyIP to: ${pathProxyIP}\n\n`, {
                            headers: getSecurityHeaders('text/plain;charset=utf-8'),
                        });
                    }
                    customProxyIP = pathProxyIP || customProxyIP;
                } catch (e) {}
            }
            
            customProxyIP = url.searchParams.get('proxyip') || request.headers.get('proxyip') || customProxyIP;

            // WebSocket 处理
            if (request.headers.get('Upgrade') === 'websocket') {
                // SS 路径检查
                if (!disableSS && pathname.toLowerCase().startsWith(`/${ssPath.toLowerCase()}`)) {
                    return await handleSSRequest(request, customProxyIP);
                }
                // VLESS/Trojan
                return await handleVlsRequest(request, yourUUID, customProxyIP, disableTrojan);
            }
            
            // GET 请求处理
            if (request.method === 'GET') {
                if (pathname === '/') {
                    return getHomePage(request, password, yourUUID, subPath, clientIP);
                }
                
                if (pathname.toLowerCase().includes(`/${subPath.toLowerCase()}`)) {
                    return getSubscription(url, yourUUID, disableTrojan, disableSS, ssPath);
                }
            }
            
            // POST 请求处理（登录）
            if (request.method === 'POST' && pathname === '/login') {
                return handleLogin(request, password, yourUUID, clientIP);
            }

            return new Response('Not Found', { status: 404, headers: getSecurityHeaders('text/plain') });
        } catch (err) {
            console.error('Worker error:', err);
            return new Response('Internal Server Error', { 
                status: 500, 
                headers: getSecurityHeaders('text/plain') 
            });
        }
    },
};

// ==================== WebSocket 处理 ====================

async function handleVlsRequest(request, yourUUID, customProxyIP, disableTrojan) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();
    
    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false;
    let isTrojan = false;
    
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStr(serverSock, earlyData);

    readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDnsQuery) return await forwardataudp(chunk, serverSock, null);
            
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            
            // 尝试 Trojan 协议
            if (!disableTrojan) {
                const trojanResult = await parsetroHeader(chunk, yourUUID);
                if (!trojanResult.hasError) {
                    isTrojan = true;
                    const { port, hostname, rawClientData } = trojanResult;
                    
                    // 安全检查
                    if (isSpeedTestSite(hostname)) {
                        throw new Error('Speedtest site is blocked');
                    }
                    const validation = validateHostname(hostname);
                    if (!validation.valid) {
                        throw new Error(validation.reason);
                    }
                    
                    await forwardataTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper, customProxyIP);
                    return;
                }
            }
            
            // VLESS 协议
            const { hasError, message, port, hostname, rawIndex, version, isUDP } = parseVLsPacketHeader(chunk, yourUUID);
            if (hasError) throw new Error(message);

            // 安全检查
            if (isSpeedTestSite(hostname)) {
                throw new Error('Speedtest site is blocked');
            }
            const validation = validateHostname(hostname);
            if (!validation.valid) {
                throw new Error(validation.reason);
            }

            if (isUDP) {
                if (port === 53) isDnsQuery = true;
                else throw new Error('UDP is not supported');
            }
            
            const respHeader = new Uint8Array([version[0], 0]);
            const rawData = chunk.slice(rawIndex);
            
            if (isDnsQuery) return forwardataudp(rawData, serverSock, respHeader);
            await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, customProxyIP);
        },
    })).catch(() => {});

    return new Response(null, { status: 101, webSocket: clientSock });
}

// ==================== Shadowsocks WebSocket 处理 ====================

async function handleSSRequest(request, customProxyIP) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();
    
    let remoteConnWrapper = { socket: null };
    let isDnsQuery = false;
    
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStr(serverSock, earlyData);

    readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDnsQuery) return await forwardataudp(chunk, serverSock, null);
            
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            
            const { hasError, message, addressType, port, hostname, rawIndex } = parseSSPacketHeader(chunk);
            if (hasError) throw new Error(message);

            // 安全检查
            if (isSpeedTestSite(hostname)) {
                throw new Error('Speedtest site is blocked');
            }
            const validation = validateHostname(hostname);
            if (!validation.valid) {
                throw new Error(validation.reason);
            }

            if (addressType === 2) {
                if (port === 53) isDnsQuery = true;
                else throw new Error('UDP is not supported');
            }
            
            const rawData = chunk.slice(rawIndex);
            if (isDnsQuery) return forwardataudp(rawData, serverSock, null);
            await forwardataTCP(hostname, port, rawData, serverSock, null, remoteConnWrapper, customProxyIP);
        },
    })).catch(() => {});

    return new Response(null, { status: 101, webSocket: clientSock });
}

// ==================== 协议解析 ====================

function parseSSPacketHeader(chunk) {
    if (chunk.byteLength < 7) return { hasError: true, message: 'Invalid data' };
    try {
        const view = new Uint8Array(chunk);
        const addressType = view[0];
        let addrIdx = 1, addrLen = 0, addrValIdx = addrIdx, hostname = '';
        
        switch (addressType) {
            case 1: // IPv4
                addrLen = 4;
                hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.');
                addrValIdx += addrLen;
                break;
            case 3: // Domain
                addrLen = view[addrIdx];
                addrValIdx += 1;
                hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen));
                addrValIdx += addrLen;
                break;
            case 4: // IPv6
                addrLen = 16;
                const ipv6 = [];
                const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen));
                for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
                hostname = ipv6.join(':');
                addrValIdx += addrLen;
                break;
            default:
                return { hasError: true, message: `Invalid address type: ${addressType}` };
        }
        
        if (!hostname) return { hasError: true, message: 'Invalid address' };
        const port = new DataView(chunk.slice(addrValIdx, addrValIdx + 2)).getUint16(0);
        return { hasError: false, addressType, port, hostname, rawIndex: addrValIdx + 2 };
    } catch (e) {
        return { hasError: true, message: 'Failed to parse SS packet header' };
    }
}

async function parsetroHeader(buffer, passwordPlainText) {
    const sha224Password = await sha224(passwordPlainText);
    
    if (buffer.byteLength < 56) return { hasError: true, message: "invalid data" };
    
    if (new Uint8Array(buffer.slice(56,57))[0] !== 0x0d || new Uint8Array(buffer.slice(57,58))[0] !== 0x0a) {
        return { hasError: true, message: "invalid header format" };
    }
    
    const password = new TextDecoder().decode(buffer.slice(0, 56));
    if (password !== sha224Password) return { hasError: true, message: "invalid password" };

    const socks5DataBuffer = buffer.slice(58);
    if (socks5DataBuffer.byteLength < 6) return { hasError: true, message: "invalid S5 request data" };

    const view = new DataView(socks5DataBuffer);
    if (view.getUint8(0) !== 1) return { hasError: true, message: "unsupported command" };

    const atype = view.getUint8(1);
    let addressLength = 0, addressIndex = 2, address = "";
    
    switch (atype) {
        case 1:
            addressLength = 4;
            address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex+addressLength)).join(".");
            break;
        case 3:
            addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex+1))[0];
            addressIndex += 1;
            address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex+addressLength));
            break;
        case 4:
            addressLength = 16;
            const dv = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex+addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) ipv6.push(dv.getUint16(i*2).toString(16));
            address = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: `invalid addressType: ${atype}` };
    }

    if (!address) return { hasError: true, message: "empty address" };

    const portIndex = addressIndex + addressLength;
    const portRemote = new DataView(socks5DataBuffer.slice(portIndex, portIndex+2)).getUint16(0);

    return {
        hasError: false,
        addressType: atype,
        port: portRemote,
        hostname: address,
        rawClientData: socks5DataBuffer.slice(portIndex + 4)
    };
}

function parseVLsPacketHeader(chunk, token) {
    if (chunk.byteLength < 24) return { hasError: true, message: 'Invalid data' };
    
    const version = new Uint8Array(chunk.slice(0, 1));
    if (formatIdentifier(new Uint8Array(chunk.slice(1, 17))) !== token) {
        return { hasError: true, message: 'Invalid uuid' };
    }
    
    const optLen = new Uint8Array(chunk.slice(17, 18))[0];
    const cmd = new Uint8Array(chunk.slice(18+optLen, 19+optLen))[0];
    let isUDP = false;
    
    if (cmd === 1) {} 
    else if (cmd === 2) isUDP = true;
    else return { hasError: true, message: 'Invalid command' };
    
    const portIdx = 19 + optLen;
    const port = new DataView(chunk.slice(portIdx, portIdx+2)).getUint16(0);
    let addrIdx = portIdx + 2, addrLen = 0, addrValIdx = addrIdx + 1, hostname = '';
    const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0];
    
    switch (addressType) {
        case 1:
            addrLen = 4;
            hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx+addrLen)).join('.');
            break;
        case 2:
            addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx+1))[0];
            addrValIdx += 1;
            hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx+addrLen));
            break;
        case 3:
            addrLen = 16;
            const ipv6 = [];
            const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx+addrLen));
            for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i*2).toString(16));
            hostname = ipv6.join(':');
            break;
        default:
            return { hasError: true, message: `Invalid address type: ${addressType}` };
    }
    
    if (!hostname) return { hasError: true, message: 'Invalid address' };
    return { hasError: false, addressType, port, hostname, isUDP, rawIndex: addrValIdx+addrLen, version };
}

// ==================== 代理连接 ====================

async function connect2Socks5(proxyConfig, targetHost, targetPort, initialData) {
    const { host, port, username, password } = proxyConfig;
    const socket = connect({ hostname: host, port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    
    try {
        const authMethods = username && password ? 
            new Uint8Array([0x05, 0x02, 0x00, 0x02]) :
            new Uint8Array([0x05, 0x01, 0x00]);
        
        await writer.write(authMethods);
        const methodResponse = await reader.read();
        if (methodResponse.done || methodResponse.value.byteLength < 2) {
            throw new Error('S5 method selection failed');
        }
        
        const selectedMethod = new Uint8Array(methodResponse.value)[1];
        if (selectedMethod === 0x02) {
            if (!username || !password) throw new Error('S5 requires authentication');
            const userBytes = new TextEncoder().encode(username);
            const passBytes = new TextEncoder().encode(password);
            const authPacket = new Uint8Array(3 + userBytes.length + passBytes.length);
            authPacket[0] = 0x01;
            authPacket[1] = userBytes.length;
            authPacket.set(userBytes, 2);
            authPacket[2+userBytes.length] = passBytes.length;
            authPacket.set(passBytes, 3+userBytes.length);
            await writer.write(authPacket);
            const authResponse = await reader.read();
            if (authResponse.done || new Uint8Array(authResponse.value)[1] !== 0x00) {
                throw new Error('S5 authentication failed');
            }
        } else if (selectedMethod !== 0x00) {
            throw new Error(`S5 unsupported auth method: ${selectedMethod}`);
        }
        
        const hostBytes = new TextEncoder().encode(targetHost);
        const connectPacket = new Uint8Array(7 + hostBytes.length);
        connectPacket[0] = 0x05;
        connectPacket[1] = 0x01;
        connectPacket[2] = 0x00;
        connectPacket[3] = 0x03;
        connectPacket[4] = hostBytes.length;
        connectPacket.set(hostBytes, 5);
        new DataView(connectPacket.buffer).setUint16(5+hostBytes.length, targetPort, false);
        await writer.write(connectPacket);
        
        const connectResponse = await reader.read();
        if (connectResponse.done || new Uint8Array(connectResponse.value)[1] !== 0x00) {
            throw new Error('S5 connection failed');
        }
        
        await writer.write(initialData);
        writer.releaseLock();
        reader.releaseLock();
        return socket;
    } catch (error) {
        writer.releaseLock();
        reader.releaseLock();
        throw error;
    }
}

async function connect2Http(proxyConfig, targetHost, targetPort, initialData) {
    const { host, port, username, password } = proxyConfig;
    const socket = connect({ hostname: host, port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    
    try {
        let connectRequest = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n`;
        connectRequest += `Host: ${targetHost}:${targetPort}\r\n`;
        if (username && password) {
            connectRequest += `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n`;
        }
        connectRequest += `User-Agent: Mozilla/5.0\r\n`;
        connectRequest += `Connection: keep-alive\r\n\r\n`;
        
        await writer.write(new TextEncoder().encode(connectRequest));
        
        // 优化：预分配缓冲区
        const maxHeaderSize = CONFIG.CONNECTION.MAX_HEADER_SIZE;
        const buffer = new Uint8Array(maxHeaderSize);
        let offset = 0;
        let headerEndIndex = -1;
        
        while (headerEndIndex === -1 && offset < maxHeaderSize) {
            const { done, value } = await reader.read();
            if (done) throw new Error('Connection closed');
            
            const chunk = new Uint8Array(value);
            if (offset + chunk.length > maxHeaderSize) {
                throw new Error('Header too large');
            }
            buffer.set(chunk, offset);
            offset += chunk.length;
            
            // 查找 \r\n\r\n
            for (let i = Math.max(0, offset - chunk.length - 3); i < offset - 3; i++) {
                if (buffer[i]===0x0d && buffer[i+1]===0x0a && buffer[i+2]===0x0d && buffer[i+3]===0x0a) {
                    headerEndIndex = i + 4;
                    break;
                }
            }
        }
        
        if (headerEndIndex === -1) throw new Error('Invalid HTTP response');
        
        const headerText = new TextDecoder().decode(buffer.slice(0, headerEndIndex));
        const statusMatch = headerText.match(/HTTP\/\d\.\d\s+(\d+)/);
        if (!statusMatch) throw new Error('Invalid response');
        
        const statusCode = parseInt(statusMatch[1]);
        if (statusCode < 200 || statusCode >= 300) {
            throw new Error(`Connection failed: ${statusCode}`);
        }
        
        await writer.write(initialData);
        writer.releaseLock();
        reader.releaseLock();
        return socket;
    } catch (error) {
        try { writer.releaseLock(); } catch {}
        try { reader.releaseLock(); } catch {}
        try { socket.close(); } catch {}
        throw error;
    }
}

async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, customProxyIP) {
    async function connectDirect(address, port, data) {
        const remoteSock = connect({ hostname: address, port });
        const writer = remoteSock.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();
        return remoteSock;
    }
    
    let proxyConfig = parsePryAddress(customProxyIP);
    let shouldUseProxy = proxyConfig && ['socks5', 'http', 'https'].includes(proxyConfig.type);
    
    if (!proxyConfig) {
        proxyConfig = { type: 'direct', host: customProxyIP || host, port: portNum };
    }
    
    async function connecttoPry() {
        let newSocket;
        if (proxyConfig.type === 'socks5') {
            newSocket = await connect2Socks5(proxyConfig, host, portNum, rawData);
        } else if (proxyConfig.type === 'http' || proxyConfig.type === 'https') {
            newSocket = await connect2Http(proxyConfig, host, portNum, rawData);
        } else {
            newSocket = await connectDirect(proxyConfig.host, proxyConfig.port, rawData);
        }
        
        remoteConnWrapper.socket = newSocket;
        newSocket.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
        connectStreams(newSocket, ws, respHeader, null);
    }
    
    if (shouldUseProxy) {
        await connecttoPry();
    } else {
        try {
            const initialSocket = await connectDirect(host, portNum, rawData);
            remoteConnWrapper.socket = initialSocket;
            connectStreams(initialSocket, ws, respHeader, connecttoPry);
        } catch {
            await connecttoPry();
        }
    }
}

function makeReadableStr(socket, earlyDataHeader) {
    let cancelled = false;
    return new ReadableStream({
        start(controller) {
            socket.addEventListener('message', (event) => {
                if (!cancelled) controller.enqueue(event.data);
            });
            socket.addEventListener('close', () => {
                if (!cancelled) {
                    closeSocketQuietly(socket);
                    controller.close();
                }
            });
            socket.addEventListener('error', (err) => controller.error(err));
            const { earlyData, error } = base64ToArray(earlyDataHeader);
            if (error) controller.error(error);
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() {
            cancelled = true;
            closeSocketQuietly(socket);
        }
    });
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
    let header = headerData, hasData = false;
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            async write(chunk) {
                hasData = true;
                if (webSocket.readyState !== WebSocket.OPEN) {
                    throw new Error('WebSocket closed');
                }
                if (header) {
                    const response = new Uint8Array(header.length + chunk.byteLength);
                    response.set(header, 0);
                    response.set(chunk, header.length);
                    webSocket.send(response.buffer);
                    header = null;
                } else {
                    webSocket.send(chunk);
                }
            },
            abort() {},
        })
    ).catch(() => closeSocketQuietly(webSocket));
    
    if (!hasData && retryFunc) await retryFunc();
}

async function forwardataudp(udpChunk, webSocket, respHeader) {
    try {
        const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
        let vlessHeader = respHeader;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk);
        writer.releaseLock();
        
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WebSocket.OPEN) {
                    if (vlessHeader) {
                        const response = new Uint8Array(vlessHeader.length + chunk.byteLength);
                        response.set(vlessHeader, 0);
                        response.set(chunk, vlessHeader.length);
                        webSocket.send(response.buffer);
                        vlessHeader = null;
                    } else {
                        webSocket.send(chunk);
                    }
                }
            },
        }));
    } catch {}
}

// ==================== 页面生成 ====================

async function getHomePage(request, password, yourUUID, subPath, clientIP) {
    const url = new URL(request.url);
    const baseUrl = `https://${url.hostname}`;
    
    // 检查认证锁定
    if (rateLimiter.isAuthLocked(clientIP)) {
        return new Response('Too many failed attempts. Please try again later.', {
            status: 429,
            headers: getSecurityHeaders('text/plain')
        });
    }
    
    // 检查 Cookie 认证
    const authToken = getAuthCookie(request);
    if (authToken && await verifyAuthToken(authToken, password, yourUUID)) {
        return getMainPageContent(url.hostname, baseUrl, yourUUID, subPath);
    }
    
    // 检查 URL 参数认证（兼容旧方式）
    const providedPassword = url.searchParams.get('password');
    if (providedPassword) {
        if (providedPassword === password) {
            rateLimiter.resetAuth(clientIP);
            const token = await generateAuthToken(password, yourUUID);
            const response = getMainPageContent(url.hostname, baseUrl, yourUUID, subPath);
            const headers = new Headers(response.headers);
            headers.set('Set-Cookie', `auth_token=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`);
            return new Response(response.body, { status: response.status, headers });
        } else {
            rateLimiter.recordAuthFailure(clientIP);
            return getLoginPage(baseUrl, true);
        }
    }
    
    return getLoginPage(baseUrl, false);
}

async function handleLogin(request, password, yourUUID, clientIP) {
    if (rateLimiter.isAuthLocked(clientIP)) {
        return new Response(JSON.stringify({ error: 'Too many failed attempts' }), {
            status: 429,
            headers: getSecurityHeaders('application/json')
        });
    }
    
    try {
        const formData = await request.formData();
        const providedPassword = formData.get('password');
        
        if (providedPassword === password) {
            rateLimiter.resetAuth(clientIP);
            const token = await generateAuthToken(password, yourUUID);
            return new Response(JSON.stringify({ success: true }), {
                status: 200,
                headers: {
                    ...getSecurityHeaders('application/json'),
                    'Set-Cookie': `auth_token=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`
                }
            });
        } else {
            rateLimiter.recordAuthFailure(clientIP);
            return new Response(JSON.stringify({ error: 'Invalid password' }), {
                status: 401,
                headers: getSecurityHeaders('application/json')
            });
        }
    } catch {
        return new Response(JSON.stringify({ error: 'Invalid request' }), {
            status: 400,
            headers: getSecurityHeaders('application/json')
        });
    }
}

function getLoginPage(baseUrl, showError = false) {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Service - Login</title>
    <style>
        :root { --primary: #6366f1; --primary-dark: #4f46e5; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 1rem; }
        .card { background: #fff; border-radius: 1rem; padding: 2.5rem; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25); width: 100%; max-width: 400px; }
        .logo { width: 64px; height: 64px; margin: 0 auto 1.5rem; display: block; }
        h1 { font-size: 1.5rem; text-align: center; color: #1f2937; margin-bottom: 0.5rem; }
        .subtitle { text-align: center; color: #6b7280; margin-bottom: 2rem; font-size: 0.95rem; }
        .input-group { margin-bottom: 1.5rem; }
        label { display: block; font-size: 0.875rem; font-weight: 500; color: #374151; margin-bottom: 0.5rem; }
        input { width: 100%; padding: 0.75rem 1rem; border: 1px solid #d1d5db; border-radius: 0.5rem; font-size: 1rem; transition: border-color 0.2s, box-shadow 0.2s; }
        input:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(99,102,241,0.1); }
        .btn { width: 100%; padding: 0.75rem 1.5rem; background: var(--primary); color: #fff; border: none; border-radius: 0.5rem; font-size: 1rem; font-weight: 600; cursor: pointer; transition: background 0.2s, transform 0.1s; }
        .btn:hover { background: var(--primary-dark); }
        .btn:active { transform: scale(0.98); }
        .error { background: #fef2f2; border: 1px solid #fecaca; color: #dc2626; padding: 0.75rem 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem; font-size: 0.875rem; text-align: center; }
        .footer { text-align: center; margin-top: 1.5rem; font-size: 0.8rem; color: #9ca3af; }
        @media (max-width: 480px) { .card { padding: 1.5rem; } h1 { font-size: 1.25rem; } }
    </style>
</head>
<body>
    <div class="card">
        <img src="https://img.icons8.com/fluency/96/cloud-sync--v1.png" alt="Logo" class="logo">
        <h1>Proxy Service</h1>
        <p class="subtitle">Enter your password to continue</p>
        ${showError ? '<div class="error">Invalid password. Please try again.</div>' : ''}
        <form method="POST" action="/login" id="loginForm">
            <div class="input-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter password" required autofocus>
            </div>
            <button type="submit" class="btn">Sign In</button>
        </form>
        <p class="footer">Secured by Cloudflare Workers</p>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            try {
                const resp = await fetch('/login', { method: 'POST', body: formData });
                if (resp.ok) window.location.reload();
                else window.location.href = '/?error=1';
            } catch { window.location.href = '/?password=' + formData.get('password'); }
        });
    </script>
</body>
</html>`;
    return new Response(html, { status: 200, headers: getSecurityHeaders() });
}

function getMainPageContent(hostname, baseUrl, yourUUID, subPath) {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Service - Dashboard</title>
    <style>
        :root { --primary: #6366f1; --primary-dark: #4f46e5; --success: #10b981; --bg: #f3f4f6; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 1rem; }
        .container { max-width: 720px; margin: 0 auto; }
        .card { background: #fff; border-radius: 1rem; padding: 1.5rem; box-shadow: 0 10px 40px rgba(0,0,0,0.15); margin-bottom: 1rem; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 1rem; }
        h1 { font-size: 1.5rem; color: #1f2937; display: flex; align-items: center; gap: 0.5rem; }
        .status { width: 10px; height: 10px; background: var(--success); border-radius: 50%; animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .logout { background: #ef4444; color: #fff; border: none; padding: 0.5rem 1rem; border-radius: 0.5rem; cursor: pointer; font-weight: 500; font-size: 0.875rem; }
        .logout:hover { background: #dc2626; }
        .section-title { font-size: 0.75rem; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.75rem; }
        .info-row { display: flex; justify-content: space-between; align-items: flex-start; padding: 0.75rem 0; border-bottom: 1px solid #e5e7eb; gap: 1rem; flex-wrap: wrap; }
        .info-row:last-child { border-bottom: none; }
        .info-label { font-weight: 500; color: #374151; min-width: 100px; }
        .info-value { font-family: 'SF Mono', Monaco, monospace; font-size: 0.875rem; color: #4b5563; background: #f9fafb; padding: 0.25rem 0.5rem; border-radius: 0.25rem; word-break: break-all; flex: 1; }
        .sub-card { background: #f9fafb; border-radius: 0.75rem; padding: 1rem; margin-top: 0.5rem; }
        .sub-item { display: flex; justify-content: space-between; align-items: center; padding: 0.5rem 0; gap: 0.75rem; flex-wrap: wrap; }
        .sub-label { font-weight: 500; color: #374151; font-size: 0.875rem; }
        .sub-url { font-family: monospace; font-size: 0.75rem; color: #6b7280; flex: 1; word-break: break-all; }
        .copy-btn { background: var(--primary); color: #fff; border: none; padding: 0.375rem 0.75rem; border-radius: 0.375rem; cursor: pointer; font-size: 0.75rem; font-weight: 500; white-space: nowrap; transition: background 0.2s; }
        .copy-btn:hover { background: var(--primary-dark); }
        .toast { position: fixed; top: 1rem; right: 1rem; background: #10b981; color: #fff; padding: 0.75rem 1rem; border-radius: 0.5rem; font-size: 0.875rem; opacity: 0; transform: translateY(-1rem); transition: all 0.3s; z-index: 100; }
        .toast.show { opacity: 1; transform: translateY(0); }
        .footer { text-align: center; font-size: 0.75rem; color: rgba(255,255,255,0.7); margin-top: 1rem; }
        @media (max-width: 640px) { .header { flex-direction: column; align-items: flex-start; } h1 { font-size: 1.25rem; } .sub-item { flex-direction: column; align-items: flex-start; } .sub-url { width: 100%; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <h1><span class="status"></span> Proxy Service</h1>
                <button onclick="logout()" class="logout">Sign Out</button>
            </div>
            <p class="section-title">Service Information</p>
            <div class="info-row"><span class="info-label">Host</span><span class="info-value">${hostname}</span></div>
            <div class="info-row"><span class="info-label">UUID</span><span class="info-value">${yourUUID}</span></div>
            <div class="info-row"><span class="info-label">Protocols</span><span class="info-value">VLESS + Trojan + Shadowsocks</span></div>
        </div>
        <div class="card">
            <p class="section-title">Subscription Links</p>
            <div class="sub-card">
                <div class="sub-item"><span class="sub-label">Universal</span><span class="sub-url" id="v2sub">${baseUrl}/${subPath}</span><button class="copy-btn" onclick="copy('v2sub')">Copy</button></div>
                <div class="sub-item"><span class="sub-label">Clash</span><span class="sub-url" id="clashsub">https://sublink.eooce.com/clash?config=${baseUrl}/${subPath}</span><button class="copy-btn" onclick="copy('clashsub')">Copy</button></div>
                <div class="sub-item"><span class="sub-label">Sing-box</span><span class="sub-url" id="singsub">https://sublink.eooce.com/singbox?config=${baseUrl}/${subPath}</span><button class="copy-btn" onclick="copy('singsub')">Copy</button></div>
            </div>
        </div>
        <p class="footer">Powered by Cloudflare Workers</p>
    </div>
    <div class="toast" id="toast"></div>
    <script>
        function copy(id) {
            const text = document.getElementById(id).textContent;
            navigator.clipboard.writeText(text).then(() => showToast('Copied to clipboard'));
        }
        function showToast(msg) {
            const toast = document.getElementById('toast');
            toast.textContent = msg;
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 2000);
        }
        function logout() {
            document.cookie = 'auth_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
            window.location.href = '/';
        }
    </script>
</body>
</html>`;
    return new Response(html, { status: 200, headers: getSecurityHeaders() });
}

function getSubscription(url, yourUUID, disableTrojan, disableSS = false, ssPath = '') {
    const currentDomain = url.hostname;
    const vlsHeader = 'vless';
    const troHeader = 'trojan';
    const ssHeader = 'ss';
    const ssMethod = 'none';
    const validSSPath = ssPath || yourUUID;
    
    const vlsLinks = CONFIG.CDN_DOMAINS.map(cdnItem => {
        let host, port = 443, nodeName = '';
        if (cdnItem.includes('#')) {
            const parts = cdnItem.split('#');
            cdnItem = parts[0];
            nodeName = parts[1];
        }
        if (cdnItem.startsWith('[') && cdnItem.includes(']:')) {
            const ipv6End = cdnItem.indexOf(']:');
            host = cdnItem.substring(0, ipv6End + 1);
            port = parseInt(cdnItem.substring(ipv6End + 2)) || 443;
        } else if (cdnItem.includes(':')) {
            const parts = cdnItem.split(':');
            host = parts[0];
            port = parseInt(parts[1]) || 443;
        } else {
            host = cdnItem;
        }
        const vlsNodeName = nodeName ? `${nodeName}-${vlsHeader}` : `Workers-${vlsHeader}`;
        return `${vlsHeader}://${yourUUID}@${host}:${port}?encryption=none&security=tls&sni=${currentDomain}&fp=firefox&allowInsecure=1&type=ws&host=${currentDomain}&path=%2F%3Fed%3D2560#${vlsNodeName}`;
    });
    
    let allLinks = [...vlsLinks];
    
    if (!disableTrojan) {
        const troLinks = CONFIG.CDN_DOMAINS.map(cdnItem => {
            let host, port = 443, nodeName = '';
            if (cdnItem.includes('#')) {
                const parts = cdnItem.split('#');
                cdnItem = parts[0];
                nodeName = parts[1];
            }
            if (cdnItem.startsWith('[') && cdnItem.includes(']:')) {
                const ipv6End = cdnItem.indexOf(']:');
                host = cdnItem.substring(0, ipv6End + 1);
                port = parseInt(cdnItem.substring(ipv6End + 2)) || 443;
            } else if (cdnItem.includes(':')) {
                const parts = cdnItem.split(':');
                host = parts[0];
                port = parseInt(parts[1]) || 443;
            } else {
                host = cdnItem;
            }
            const troNodeName = nodeName ? `${nodeName}-${troHeader}` : `Workers-${troHeader}`;
            return `${troHeader}://${yourUUID}@${host}:${port}?security=tls&sni=${currentDomain}&fp=firefox&allowInsecure=1&type=ws&host=${currentDomain}&path=%2F%3Fed%3D2560#${troNodeName}`;
        });
        allLinks = [...allLinks, ...troLinks];
    }
    
    // Shadowsocks 链接
    if (!disableSS) {
        const ssLinks = CONFIG.CDN_DOMAINS.map(cdnItem => {
            let host, port = 443, nodeName = '';
            if (cdnItem.includes('#')) {
                const parts = cdnItem.split('#');
                cdnItem = parts[0];
                nodeName = parts[1];
            }
            if (cdnItem.startsWith('[') && cdnItem.includes(']:')) {
                const ipv6End = cdnItem.indexOf(']:');
                host = cdnItem.substring(0, ipv6End + 1);
                port = parseInt(cdnItem.substring(ipv6End + 2)) || 443;
            } else if (cdnItem.includes(':')) {
                const parts = cdnItem.split(':');
                host = parts[0];
                port = parseInt(parts[1]) || 443;
            } else {
                host = cdnItem;
            }
            const ssNodeName = nodeName ? `${nodeName}-${ssHeader}` : `Workers-${ssHeader}`;
            const ssConfig = `${ssMethod}:${yourUUID}`;
            const encodedConfig = btoa(ssConfig);
            return `${ssHeader}://${encodedConfig}@${host}:${port}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D${currentDomain};path%3D/${validSSPath}/?ed%3D2560;tls;sni%3D${currentDomain}#${ssNodeName}`;
        });
        allLinks = [...allLinks, ...ssLinks];
    }
    
    const linksText = allLinks.join('\n');
    const base64Content = btoa(unescape(encodeURIComponent(linksText)));
    
    return new Response(base64Content, {
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        },
    });
}
