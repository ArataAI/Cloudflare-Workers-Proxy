/**
 * Cloudflare Snippets VLESS 代理服务
 * 
 * 安全增强版 - 修复内容:
 * 1. 移除硬编码凭据 - 强制使用环境变量
 * 2. 添加速率限制 - 防止暴力破解
 * 3. 添加输入验证 - 防止 SSRF 攻击
 * 4. 添加安全响应头
 * 5. 优化内存使用
 * 
 * 必需环境变量:
 * - UUID: 用户 UUID
 * 
 * 可选环境变量:
 * - PROXYIP: 代理 IP
 */

import { connect } from 'cloudflare:sockets';

// ==================== 配置常量 ====================

const CONFIG = {
    RATE_LIMIT: {
        WINDOW_MS: 60000,
        MAX_REQUESTS: 100,
    },
    
    CONNECTION: {
        TIMEOUT_MS: 10000,
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
    
    CDN_DOMAINS: [
        'mfa.gov.ua#SG', 'saas.sin.fan#JP', 'store.ubi.com#SG',
        'cf.130519.xyz#KR', 'cf.008500.xyz#HK', 'cf.090227.xyz#SG',
        'cf.877774.xyz#HK', 'cdns.doon.eu.org#JP',
        'sub.danfeng.eu.org#TW', 'cf.zhetengsha.eu.org#HK'
    ],
};

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

        const { uuid: yourUUID, proxyIP } = config;
        const vlsHeader = 'vless';

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
                return await handleVlsRequest(request, yourUUID, customProxyIP, proxyIP);
            }
            
            // GET 请求处理
            if (request.method === 'GET') {
                if (pathname === '/') {
                    return getHomePageHTML(url.hostname, yourUUID);
                }
                
                if (pathname === `/${yourUUID}`) {
                    return getSubPageHTML(url.hostname, yourUUID);
                }
                
                if (pathname.toLowerCase() === `/sub/${yourUUID.toLowerCase()}`) {
                    return getSubscription(url, yourUUID, vlsHeader);
                }
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

async function handleVlsRequest(request, yourUUID, customProxyIP, defaultProxyIP) {
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
            await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, customProxyIP || defaultProxyIP);
        },
    })).catch(() => {});

    return new Response(null, { status: 101, webSocket: clientSock });
}

// ==================== 协议解析 ====================

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
        
        const maxHeaderSize = CONFIG.CONNECTION.MAX_HEADER_SIZE;
        const buffer = new Uint8Array(maxHeaderSize);
        let offset = 0;
        let headerEndIndex = -1;
        
        while (headerEndIndex === -1 && offset < maxHeaderSize) {
            const { done, value } = await reader.read();
            if (done) throw new Error('Connection closed');
            
            const chunk = new Uint8Array(value);
            if (offset + chunk.length > maxHeaderSize) throw new Error('Header too large');
            buffer.set(chunk, offset);
            offset += chunk.length;
            
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
        if (statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: ${statusCode}`);
        
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
                if (webSocket.readyState !== WebSocket.OPEN) throw new Error('WebSocket closed');
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

function getHomePageHTML(currentDomain, yourUUID) {
    const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Snippets代理服务</title><style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;padding:20px;background:linear-gradient(135deg,#7dd3ca 0%,#a17ec4 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;}.container{max-width:600px;background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);border-radius:20px;padding:40px;box-shadow:0 20px 40px rgba(0,0,0,0.1);text-align:center;}.title{font-size:2rem;margin-bottom:20px;color:#2d3748;}.info{font-size:1.1rem;color:#666;margin:30px 0;line-height:1.8;background:#f8f9fa;padding:20px;border-radius:10px;}.highlight{font-weight:bold;color:#667eea;}.footer{margin-top:30px;color:#718096;font-size:0.9rem;}.footer a{color:#667eea;text-decoration:none;margin:0 10px;}</style></head><body><div class="container"><h1 class="title">Hello Snippets!</h1><div class="info">访问 <span class="highlight">https://${currentDomain}/你的UUID</span><br>进入订阅中心</div><div class="footer"><a href="https://github.com/eooce/CF-workers-and-snip-VLESS" target="_blank">GitHub</a>|<a href="https://t.me/eooceu" target="_blank">Telegram</a></div></div></body></html>`;
    return new Response(html, { status: 200, headers: getSecurityHeaders() });
}

function getSubPageHTML(currentDomain, yourUUID) {
    const v2raySubLink = `https://${currentDomain}/sub/${yourUUID}`;
    const clashLink = `https://sub.ssss.xx.kg/clash?config=${v2raySubLink}`;
    const singboxLink = `https://sub.ssss.xx.kg/singbox?config=${v2raySubLink}`;
    
    const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Snippets 订阅中心</title><style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;padding:20px;background:linear-gradient(135deg,#7dd3ca 0%,#a17ec4 100%);}.container{max-width:800px;margin:0 auto;}.header{text-align:center;margin-bottom:30px;}.header h1{color:#007fff;}.section{background:rgba(255,255,255,0.95);border-radius:12px;padding:20px;margin-bottom:20px;}.section h2{color:#b33ce7;margin-bottom:15px;font-size:1.1rem;}.link-box{background:#f0fffa;border:1px solid #ddd;border-radius:8px;padding:15px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:10px;}.lintext{flex:1;word-break:break-all;font-family:monospace;color:#2980b9;font-size:0.9rem;}.copy-btn{background:#27aea2;color:white;border:none;padding:10px 20px;border-radius:6px;cursor:pointer;font-weight:600;}.copy-btn:hover{background:#219652;}.footer{text-align:center;color:#7f8c8d;margin-top:30px;}.footer a{color:#667eea;text-decoration:none;margin:0 15px;}</style></head><body><div class="container"><div class="header"><h1>Snippets 订阅中心</h1></div><div class="section"><h2>通用订阅 (v2rayN/Nekobox/小火箭)</h2><div class="link-box"><div class="lintext" id="v2sub">${v2raySubLink}</div><button class="copy-btn" onclick="copy('v2sub')">复制</button></div></div><div class="section"><h2>Clash 订阅</h2><div class="link-box"><div class="lintext" id="clashsub">${clashLink}</div><button class="copy-btn" onclick="copy('clashsub')">复制</button></div></div><div class="section"><h2>Sing-box 订阅</h2><div class="link-box"><div class="lintext" id="singsub">${singboxLink}</div><button class="copy-btn" onclick="copy('singsub')">复制</button></div></div><div class="footer"><a href="https://github.com/eooce/CF-workers-and-snip-VLESS" target="_blank">GitHub</a>|<a href="https://t.me/eooceu" target="_blank">Telegram</a></div></div><script>function copy(id){const text=document.getElementById(id).textContent;navigator.clipboard.writeText(text).then(()=>alert('已复制到剪贴板'));}</script></body></html>`;
    return new Response(html, { status: 200, headers: getSecurityHeaders() });
}

function getSubscription(url, yourUUID, vlsHeader) {
    const currentDomain = url.hostname;
    
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
        const vlsNodeName = nodeName ? `${nodeName}-${vlsHeader}` : `Snip-${vlsHeader}`;
        return `${vlsHeader}://${yourUUID}@${host}:${port}?encryption=none&security=tls&sni=${currentDomain}&fp=firefox&allowInsecure=1&type=ws&host=${currentDomain}&path=%2F%3Fed%3D2560#${vlsNodeName}`;
    });
    
    const linksText = vlsLinks.join('\n');
    const base64Content = btoa(unescape(encodeURIComponent(linksText)));
    
    return new Response(base64Content, {
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        },
    });
}
