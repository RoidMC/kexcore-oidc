# 自签 TLS 证书

用于 storm-server 的 HTTPS 模式，替代 cloudflared 隧道。

## 文件说明

| 文件 | 说明 |
|------|------|
| `gen.go` | 证书生成脚本（P-256 ECDSA，10 年有效期） |
| `server.crt` | 自签证书（**可提交到仓库**） |
| `server.key` | 私钥（**不要提交到仓库**，已在 .gitignore 中） |

## 重新生成证书

```bash
cd example/storm-server/cert/web
go run gen.go
```

默认包含的 SAN：
- `localhost`
- `127.0.0.1`
- `::1`

如需添加公网域名，编辑 `gen.go` 中的 `DNSNames` 数组后重新生成。

## 使用方式

启动 storm-server 时通过环境变量指定证书路径：

```bash
# 从项目根目录运行（默认自动启用 TLS）
go run ./example/storm-server/

# 或手动指定证书路径
TLS_CERT_FILE=example/storm-server/cert/web/server.crt TLS_KEY_FILE=example/storm-server/cert/web/server.key go run ./example/storm-server/
```

服务器将监听 `https://localhost:9998/`。

## Conformance Suite 集成

自签证书可直接用于自托管的 OIDF conformance suite 测试：

1. `config.yml` 中已设置 `verify_ssl: false`，API 调用不验证证书
2. Selenium 浏览器自动化需在 conformance suite 的 browser options 中加 `--ignore-certificate-errors`
3. `config.yml` 中的 `discoveryUrl` 和 `browser.match` 需改为 HTTPS 地址

## 为什么不用 Let's Encrypt？

自签证书对 conformance 测试完全够用。Let's Encrypt 仅在需要公网可验证的正式认证时才必要。
