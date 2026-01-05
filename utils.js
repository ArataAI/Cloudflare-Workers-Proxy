/**
 * Cloudflare Workers 代理服务 - 公共工具模块
 * 
 * 此模块包含所有共享的工具函数和安全功能
 * 注意：由于 Workers 环境限制，此代码需要内联到主文件中
 */

// ==================== 配置常量 ====================

const CONFIG = {
    // 默认值（仅供备用，强烈建议使用环境变量）
    DEFAULT_PROXY_IP: '',  // 不设置默认值，强制使用环境变量
    DEFAULT_SUB_PATH: 'link',
    
    // 安全配置
    RATE_LIMIT: {
        WINDOW_MS: 60000,           // 1 分钟窗口
        MAX_REQUESTS: 100,          // 每分钟最大请求数
        MAX_AUTH_ATTEMPTS: 5,       // 最大认证尝试次数
        AUTH_LOCKOUT_MS: 300000,    // 认证锁定时间 5 分钟
    },
    
    // 连接配置
    CONNECTION: {
        TIMEOUT_MS: 10000,          // 连接超时
        MAX_CONCURRENT: 64,         // 最大并发连接
        MAX_HEADER_SIZE: 8192,      // 最大 HTTP 头大小
    },
    
    // 测速网站黑名单
    SPEED_TEST_DOMAINS: [
        'speedtest.net',
        'fast.com',
        'speedtest.cn',
        'speed.cloudflare.com',
        'ovo.speedtestcustom.com'
    ],
    
    // 私有网络地址段（防 SSRF）
    PRIVATE_IP_RANGES: [
        /^10\./,
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
        /^192\.168\./,
        /^127\./,
        /^0\./,
        /^169\.254\./,
        /^::1$/,
        /^fc00:/i,
        /^fe80:/i,
        /^localhost$/i,
    ],
};

// ==================== 速率限制器 ====================

class RateLimiter {
    constructor() {
        this.requests = new Map();
        this.authAttempts = new Map();
    }

    /**
     * 检查是否允许请求
     * @param {string} clientIP - 客户端 IP
     * @returns {boolean}
     */
    isAllowed(clientIP) {
        const now = Date.now();
        const windowStart = now - CONFIG.RATE_LIMIT.WINDOW_MS;
        
        // 清理过期记录
        const requests = this.requests.get(clientIP) || [];
        const validRequests = requests.filter(time => time > windowStart);
        
        if (validRequests.length >= CONFIG.RATE_LIMIT.MAX_REQUESTS) {
            return false;
        }
        
        validRequests.push(now);
        this.requests.set(clientIP, validRequests);
        return true;
    }

    /**
     * 记录认证失败
     * @param {string} clientIP - 客户端 IP
     * @returns {boolean} - 是否被锁定
     */
    recordAuthFailure(clientIP) {
        const now = Date.now();
        const record = this.authAttempts.get(clientIP) || { count: 0, lockedUntil: 0 };
        
        // 检查是否在锁定期
        if (record.lockedUntil > now) {
            return true; // 仍在锁定中
        }
        
        record.count++;
        
        if (record.count >= CONFIG.RATE_LIMIT.MAX_AUTH_ATTEMPTS) {
            record.lockedUntil = now + CONFIG.RATE_LIMIT.AUTH_LOCKOUT_MS;
            record.count = 0;
        }
        
        this.authAttempts.set(clientIP, record);
        return record.lockedUntil > now;
    }

    /**
     * 检查是否被认证锁定
     * @param {string} clientIP - 客户端 IP
     * @returns {boolean}
     */
    isAuthLocked(clientIP) {
        const record = this.authAttempts.get(clientIP);
        if (!record) return false;
        return record.lockedUntil > Date.now();
    }

    /**
     * 重置认证记录（登录成功后调用）
     * @param {string} clientIP - 客户端 IP
     */
    resetAuth(clientIP) {
        this.authAttempts.delete(clientIP);
    }
}

// 全局速率限制器实例
const rateLimiter = new RateLimiter();

// ==================== 安全工具函数 ====================

/**
 * 获取客户端 IP
 * @param {Request} request
 * @returns {string}
 */
function getClientIP(request) {
    return request.headers.get('CF-Connecting-IP') || 
           request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 
           'unknown';
}

/**
 * 获取安全响应头
 * @param {string} contentType
 * @returns {Object}
 */
function getSecurityHeaders(contentType = 'text/html;charset=utf-8') {
    return {
        'Content-Type': contentType,
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' https://img.icons8.com data:; font-src 'self' https://cdnjs.cloudflare.com;",
    };
}

/**
 * 验证 UUID 格式
 * @param {string} uuid
 * @returns {boolean}
 */
function isValidUUID(uuid) {
    if (!uuid || typeof uuid !== 'string') return false;
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

/**
 * 验证主机名是否安全（防 SSRF）
 * @param {string} hostname
 * @returns {{valid: boolean, reason?: string}}
 */
function validateHostname(hostname) {
    if (!hostname || typeof hostname !== 'string') {
        return { valid: false, reason: 'Invalid hostname' };
    }

    hostname = hostname.trim().toLowerCase();

    // 检查是否为私有地址
    for (const pattern of CONFIG.PRIVATE_IP_RANGES) {
        if (pattern.test(hostname)) {
            return { valid: false, reason: 'Private address not allowed' };
        }
    }

    // 检查基本格式
    if (hostname.length > 253) {
        return { valid: false, reason: 'Hostname too long' };
    }

    // 检查是否包含非法字符
    if (!/^[a-z0-9.\-:[\]]+$/.test(hostname)) {
        return { valid: false, reason: 'Invalid characters in hostname' };
    }

    return { valid: true };
}

/**
 * 验证端口号
 * @param {number} port
 * @returns {boolean}
 */
function isValidPort(port) {
    return Number.isInteger(port) && port > 0 && port <= 65535;
}

// ==================== 通用工具函数 ====================

/**
 * 安全关闭 WebSocket
 * @param {WebSocket} socket
 */
function closeSocketQuietly(socket) {
    try {
        if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING)) {
            socket.close();
        }
    } catch (error) {
        // 忽略关闭错误
    }
}

/**
 * Base64 解码为 ArrayBuffer
 * @param {string} b64Str
 * @returns {{earlyData?: ArrayBuffer, error?: Error}}
 */
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

/**
 * 格式化 UUID
 * @param {Uint8Array} arr
 * @param {number} offset
 * @returns {string}
 */
function formatIdentifier(arr, offset = 0) {
    const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.substring(0,8)}-${hex.substring(8,12)}-${hex.substring(12,16)}-${hex.substring(16,20)}-${hex.substring(20)}`;
}

/**
 * 检查是否为测速网站
 * @param {string} hostname
 * @returns {boolean}
 */
function isSpeedTestSite(hostname) {
    if (!hostname) return false;
    hostname = hostname.toLowerCase();
    
    for (const domain of CONFIG.SPEED_TEST_DOMAINS) {
        if (hostname === domain || hostname.endsWith('.' + domain)) {
            return true;
        }
    }
    return false;
}

/**
 * 解析代理地址
 * @param {string} serverStr
 * @returns {Object|null}
 */
function parsePryAddress(serverStr) {
    if (!serverStr) return null;
    serverStr = serverStr.trim();
    
    // 解析 SOCKS5
    if (serverStr.startsWith('socks://') || serverStr.startsWith('socks5://')) {
        const urlStr = serverStr.replace(/^socks:\/\//, 'socks5://');
        try {
            const url = new URL(urlStr);
            const host = url.hostname;
            const port = parseInt(url.port) || 1080;
            
            // 验证地址安全性
            const validation = validateHostname(host);
            if (!validation.valid) return null;
            if (!isValidPort(port)) return null;
            
            return {
                type: 'socks5',
                host,
                port,
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }

    // 解析 HTTP/HTTPS
    if (serverStr.startsWith('http://') || serverStr.startsWith('https://')) {
        try {
            const url = new URL(serverStr);
            const host = url.hostname;
            const port = parseInt(url.port) || (serverStr.startsWith('https://') ? 443 : 80);
            
            const validation = validateHostname(host);
            if (!validation.valid) return null;
            if (!isValidPort(port)) return null;
            
            return {
                type: 'http',
                host,
                port,
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }

    // 处理 IPv6 格式 [host]:port
    if (serverStr.startsWith('[')) {
        const closeBracket = serverStr.indexOf(']');
        if (closeBracket > 0) {
            const host = serverStr.substring(1, closeBracket);
            const rest = serverStr.substring(closeBracket + 1);
            
            const validation = validateHostname(host);
            if (!validation.valid) return null;
            
            if (rest.startsWith(':')) {
                const port = parseInt(rest.substring(1), 10);
                if (isValidPort(port)) {
                    return { type: 'direct', host, port };
                }
            }
            return { type: 'direct', host, port: 443 };
        }
    }

    // 处理普通 host:port 格式
    const lastColonIndex = serverStr.lastIndexOf(':');
    if (lastColonIndex > 0) {
        const host = serverStr.substring(0, lastColonIndex);
        const portStr = serverStr.substring(lastColonIndex + 1);
        const port = parseInt(portStr, 10);
        
        const validation = validateHostname(host);
        if (!validation.valid) return null;
        
        if (isValidPort(port)) {
            return { type: 'direct', host, port };
        }
    }

    // 仅主机名
    const validation = validateHostname(serverStr);
    if (!validation.valid) return null;
    
    return { type: 'direct', host: serverStr, port: 443 };
}

// ==================== 加密函数 ====================

/**
 * SHA-224 哈希（用于 Trojan 协议）
 * @param {string} text
 * @returns {Promise<string>}
 */
async function sha224(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    
    const K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    
    let H = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
    
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
        
        for (let i = 0; i < 16; i++) {
            W[i] = view.getUint32(chunk + i * 4, false);
        }
        
        for (let i = 16; i < 64; i++) {
            const s0 = rightRotate(W[i - 15], 7) ^ rightRotate(W[i - 15], 18) ^ (W[i - 15] >>> 3);
            const s1 = rightRotate(W[i - 2], 17) ^ rightRotate(W[i - 2], 19) ^ (W[i - 2] >>> 10);
            W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
        }
        
        let [a, b, c, d, e, f, g, h] = H;
        
        for (let i = 0; i < 64; i++) {
            const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
            const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) >>> 0;
            
            h = g;
            g = f;
            f = e;
            e = (d + temp1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) >>> 0;
        }
        
        H[0] = (H[0] + a) >>> 0;
        H[1] = (H[1] + b) >>> 0;
        H[2] = (H[2] + c) >>> 0;
        H[3] = (H[3] + d) >>> 0;
        H[4] = (H[4] + e) >>> 0;
        H[5] = (H[5] + f) >>> 0;
        H[6] = (H[6] + g) >>> 0;
        H[7] = (H[7] + h) >>> 0;
    }
    
    const result = [];
    for (let i = 0; i < 7; i++) {
        result.push(
            ((H[i] >>> 24) & 0xff).toString(16).padStart(2, '0'),
            ((H[i] >>> 16) & 0xff).toString(16).padStart(2, '0'),
            ((H[i] >>> 8) & 0xff).toString(16).padStart(2, '0'),
            (H[i] & 0xff).toString(16).padStart(2, '0')
        );
    }
    return result.join('');
}

// ==================== 配置管理 ====================

/**
 * 从环境变量读取配置
 * @param {Object} env - 环境变量对象
 * @returns {{config: Object, errors: string[]}}
 */
function loadConfig(env) {
    const errors = [];
    
    // 辅助函数：尝试多个环境变量名
    const getEnv = (...keys) => {
        for (const key of keys) {
            if (env[key]) return env[key];
        }
        return null;
    };
    
    // 读取必需配置
    const uuid = getEnv('UUID', 'uuid', 'AUTH');
    const password = getEnv('PASSWORD', 'PASSWD', 'password');
    
    // 验证 UUID
    if (!uuid) {
        errors.push('UUID environment variable is required');
    } else if (!isValidUUID(uuid)) {
        errors.push('Invalid UUID format');
    }
    
    // 验证密码
    if (!password) {
        errors.push('PASSWORD environment variable is required');
    } else if (password.length < 6) {
        errors.push('Password must be at least 6 characters');
    }
    
    // 读取可选配置
    const proxyIPStr = getEnv('PROXYIP', 'proxyip', 'proxyIP') || '';
    const proxyIPs = proxyIPStr.split(',').map(s => s.trim()).filter(Boolean);
    const proxyIP = proxyIPs[0] || '';
    
    const subPath = getEnv('SUB_PATH', 'subpath') || CONFIG.DEFAULT_SUB_PATH;
    const disableTrojan = getEnv('DISABLE_TROJAN', 'CLOSE_TROJAN') === 'true';
    
    return {
        config: {
            uuid: uuid || '',
            password: password || '',
            proxyIP,
            proxyIPs,
            subPath,
            disableTrojan,
        },
        errors,
    };
}

// ==================== Cookie 认证 ====================

/**
 * 生成认证 Token
 * @param {string} password
 * @param {string} secret - 用于签名的 UUID
 * @returns {Promise<string>}
 */
async function generateAuthToken(password, secret) {
    const timestamp = Date.now();
    const data = `${password}:${timestamp}:${secret}`;
    const hash = await sha224(data);
    return btoa(JSON.stringify({ t: timestamp, h: hash.substring(0, 32) }));
}

/**
 * 验证认证 Token
 * @param {string} token
 * @param {string} password
 * @param {string} secret
 * @param {number} maxAgeMs - Token 有效期
 * @returns {Promise<boolean>}
 */
async function verifyAuthToken(token, password, secret, maxAgeMs = 24 * 60 * 60 * 1000) {
    try {
        const decoded = JSON.parse(atob(token));
        const { t: timestamp, h: hash } = decoded;
        
        // 检查是否过期
        if (Date.now() - timestamp > maxAgeMs) {
            return false;
        }
        
        // 验证签名
        const data = `${password}:${timestamp}:${secret}`;
        const expectedHash = await sha224(data);
        return hash === expectedHash.substring(0, 32);
    } catch {
        return false;
    }
}

/**
 * 从请求中获取认证 Cookie
 * @param {Request} request
 * @returns {string|null}
 */
function getAuthCookie(request) {
    const cookieHeader = request.headers.get('Cookie') || '';
    const match = cookieHeader.match(/auth_token=([^;]+)/);
    return match ? match[1] : null;
}

// ==================== 导出 ====================

// 注意：在实际使用时，需要将这些函数内联到主文件中
// 或使用 Cloudflare Workers 的 ES modules 格式

export {
    CONFIG,
    RateLimiter,
    rateLimiter,
    getClientIP,
    getSecurityHeaders,
    isValidUUID,
    validateHostname,
    isValidPort,
    closeSocketQuietly,
    base64ToArray,
    formatIdentifier,
    isSpeedTestSite,
    parsePryAddress,
    sha224,
    loadConfig,
    generateAuthToken,
    verifyAuthToken,
    getAuthCookie,
};
