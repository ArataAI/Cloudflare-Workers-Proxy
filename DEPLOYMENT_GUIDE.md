# Cloudflare Workers 代理服务部署指南

本指南介绍如何部署安全增强版的 Cloudflare Workers 代理服务。

---

## 目录

- [前置要求](#前置要求)
- [版本选择](#版本选择)
- [Workers 部署](#workers-部署)
- [Snippets 部署](#snippets-部署)
- [环境变量配置](#环境变量配置)
- [自定义域名配置](#自定义域名配置)
- [客户端配置](#客户端配置)
- [常见问题](#常见问题)

---

## 前置要求

- Cloudflare 账户（免费版即可）
- （可选）已托管在 Cloudflare 的域名

---

## 版本选择

根据需要的协议选择对应的脚本：

| 脚本 | 协议 | 适用场景 |
|------|------|----------|
| `_worker_secure.js` | VLESS + Trojan + SS | 三协议合一，推荐使用 |
| `shadowsocks_secure.js` | Shadowsocks | 独立 SS 版本 |
| `trojan_secure.js` | Trojan | 独立 Trojan 版本 |
| `snippets_secure.js` | VLESS | Snippets 部署方式 |
| `xhttp_secure.js` | VLESS-XHTTP | gRPC 方式，需开启 gRPC |

---

## Workers 部署

### 步骤 1：创建 Worker

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 点击左侧菜单 **Workers & Pages**
3. 点击 **Create application** → **Create Worker**
4. 输入 Worker 名称（建议使用默认名称，避免敏感词如 proxy、vless 等）
5. 点击 **Deploy**

### 步骤 2：上传代码

1. 部署成功后，点击 **Edit code**
2. 删除编辑器中的默认代码
3. 将 `_worker_secure.js`（或其他选择的脚本）的全部内容粘贴到编辑器
4. 点击右上角 **Deploy**

### 步骤 3：配置环境变量

1. 返回 Worker 概览页面
2. 点击 **Settings** → **Variables**
3. 在 **Environment Variables** 部分添加必需变量
4. 点击 **Save and Deploy**

---

## Snippets 部署

如果使用 `snippets_secure.js`：

### 步骤 1：创建 Snippet

1. 登录 Cloudflare Dashboard
2. 选择你的域名
3. 点击 **Rules** → **Snippets**
4. 点击 **Create snippet**
5. 粘贴 `snippets_secure.js` 代码
6. 保存

### 步骤 2：配置触发规则

设置 URL 匹配规则，例如：
```
(http.host eq "proxy.yourdomain.com")
```

---

## 环境变量配置

### 必需变量

#### _worker_secure.js

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `UUID` | 用户标识（UUID 格式） | `5dc15e15-f285-4a9d-959b-0e4fbdd77b63` |
| `PASSWORD` | 访问密码（至少 6 位） | `MySecurePass123` |

#### shadowsocks_secure.js

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `PASSWORD` 或 `UUID` | SS 密码 | `your-password` |

#### trojan_secure.js / snippets_secure.js / xhttp_secure.js

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `UUID` | 用户标识 | `5dc15e15-f285-4a9d-959b-0e4fbdd77b63` |

### 可选变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `PROXYIP` | ProxyIP 地址 | 无 |
| `SUB_PATH` | 订阅路径 | `link` |
| `DISABLE_TROJAN` | 禁用 Trojan | `false` |
| `DISABLE_SS` | 禁用 Shadowsocks | `false` |
| `SS_PATH` | Shadowsocks 连接路径 | 使用 UUID |

### 如何生成 UUID

方法一：在线生成
- 访问 https://www.uuidgenerator.net/

方法二：命令行生成
```bash
# macOS / Linux
uuidgen

# 或使用 Python
python3 -c "import uuid; print(uuid.uuid4())"
```

---

## 自定义域名配置

### 为什么需要自定义域名？

- workers.dev 域名可能被限制
- 自定义域名更稳定可靠
- 可以使用自己的 SSL 证书

### 配置步骤

1. 在 Worker 页面点击 **Settings** → **Triggers**
2. 在 **Custom Domains** 下点击 **Add Custom Domain**
3. 输入你的子域名，如 `proxy.yourdomain.com`
4. 点击 **Add Custom Domain**
5. 等待 DNS 记录生效（通常几分钟）

### XHTTP 版本特殊配置

如果使用 `xhttp_secure.js`：

1. 进入域名的 **Network** 设置
2. 启用 **gRPC** 功能
3. 否则连接将无法正常工作

---

## 客户端配置

### 获取订阅链接

部署成功后，访问以下地址获取订阅：

| 脚本 | 订阅中心 | 订阅链接 |
|------|----------|----------|
| `_worker_secure.js` | `https://你的域名/?password=密码` | `https://你的域名/link` |
| `shadowsocks_secure.js` | `https://你的域名/UUID` | `https://你的域名/sub/UUID` |
| `trojan_secure.js` | `https://你的域名/UUID` | `https://你的域名/sub/UUID` |
| `snippets_secure.js` | `https://你的域名/UUID` | `https://你的域名/sub/UUID` |
| `xhttp_secure.js` | `https://你的域名/UUID` | `https://你的域名/sub/UUID` |

### 支持的客户端

| 平台 | 推荐客户端 |
|------|-----------|
| Windows | v2rayN, Clash Verge |
| macOS | ClashX Pro, V2rayU |
| iOS | Shadowrocket, Loon, Quantumult X |
| Android | v2rayNG, Clash for Android |
| Linux | Clash, v2ray |

### 订阅转换

如需转换为其他格式：

- **Clash**: `https://sublink.eooce.com/clash?config=订阅链接`
- **Sing-box**: `https://sublink.eooce.com/singbox?config=订阅链接`

---

## 常见问题

### Q: 显示 "Configuration Error"

**原因**: 未设置必需的环境变量

**解决**: 
1. 检查是否设置了 `UUID` 和 `PASSWORD`（如适用）
2. 确保 UUID 格式正确
3. 密码至少 6 位

### Q: 显示 "Too Many Requests"

**原因**: 触发了速率限制（100 请求/分钟）

**解决**: 等待 1 分钟后重试

### Q: 无法连接

**检查清单**:
1. ✅ 环境变量是否正确设置
2. ✅ 客户端 UUID 是否与服务端一致
3. ✅ 是否使用了正确的域名和端口
4. ✅ TLS 是否启用
5. ✅ WebSocket 路径是否正确（默认 `/?ed=2560`）

### Q: Speedtest 被阻止

**原因**: 安全版本默认阻止测速网站防止滥用

**解决**: 这是正常的安全特性，不需要修改

### Q: 如何自定义 ProxyIP？

**方法一**: 设置环境变量 `PROXYIP`

**方法二**: 在路径中指定
```
https://你的域名/proxyip=1.2.3.4:443
```

**方法三**: 在节点 path 中指定
```
/?ed=2560&proxyip=1.2.3.4
```

---

## 相关链接

- [GitHub 项目](https://github.com/eooce/CF-Workers-VLESS)
- [Telegram 交流群](https://t.me/eooceu)
- [ProxyIP 检测服务](https://check-proxyip.ssss.nyc.mn/)

---

## 安全建议

1. **定期更换 UUID 和密码**
2. **不要分享订阅链接**
3. **监控异常流量**
4. **保持代码更新**
