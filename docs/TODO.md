# KexCore OIDC TODO

## 国密算法适配（GM/T 0125 系列）

### 已完成
- [x] `pkg/crypto/sm2.go` — SM2 密钥生成、签名、验签、加解密
- [x] `pkg/crypto/sm3.go` — SM3 哈希及 HMAC
- [x] `pkg/crypto/sm4.go` — SM4 CBC/GCM/CCM 多模式加解密
- [x] `pkg/crypto/sm9.go` — SM9 密钥生成、签名、验签、加解密、密钥封装
- [x] `pkg/crypto/jwe.go` — SM2+SM4-GCM / SM9+SM4-GCM/CCM JWE 实现（符合 GM/T 0125.3）
- [x] `pkg/crypto/hash.go` — 算法标识符统一为 SGD 标准（移除 SM2 别名，统一 SGD_SM3_SM2）
- [x] `pkg/crypto/jwk.go` — SM2 JWK 构建、JWS 签名验证、签名输入构建、算法判断（抽取公共 util）
- [x] `pkg/op/op.go` — SM2 JWS 签名验证使用 `crypto.VerifySM2JWSSignature` + `crypto.BuildSM2SigningInput`
- [x] `pkg/op/verifier_jwt_profile.go` — 同上，移除重复代码
- [x] `pkg/client/rp/jwks.go` — 同上，移除重复代码
- [x] `pkg/op/keys.go` — JWKS 返回 SM2 公钥（手动构建 JSON map 绕过 jwx 不支持 SM2 曲线问题）
- [x] `pkg/op/op.go` — `NewProvider` 自动从 `storage.SignatureAlgorithms()` 填充 `SupportedSignAlgorithms`，修复 discovery 各字段不一致问题
- [x] `pkg/op/crypto.go` — 新增 `NewSM4Crypto` 支持 SM4 token 加解密
- [x] `example/server/config/config.go` — 新增 `SIGNING_ALGORITHMS` 和 `CRYPTO_METHOD` 环境变量配置
- [x] `example/server/storage/storage.go` — `NewStorageWithAlgorithms` 支持 RS256/RS384/RS512/ES256/ES384/ES512/EdDSA/SGD_SM3_SM2 动态配置
- [x] `example/server/crypto.go` — `myCrypto` 支持 SM4 加解密选项
- [x] 集成测试修复 — `SetupServer` 签名变更、RP 侧仅用 RS256 避免 jwx 解析 SM2 JWK 失败
- [x] `pkg/crypto/hash.go` — 添加 `SGD_SM3_SM9` 算法标识符
- [x] `pkg/crypto/jwk.go` — 添加 `SM9SignJWK`、`NewSM9SignJWK`、`ParseSM9SignMasterPublicKey`、`VerifySM9JWSSignature`、`IsSM9Algorithm`
- [x] `pkg/op/keys.go` — JWKS 支持 SM9 签名主公钥导出
- [x] `pkg/op/op.go` — OP 端 SM9 签名验证（`verifySM9Signature`，从 JWS header 读取 `uid` 参数）
- [x] `example/server/storage/storage.go` — SM9 签名密钥加入 `signingKey` switch（生成 master key + user key）
- [x] `pkg/crypto/jwk.go` — 添加 `ParseJWKSBytes` 专用 JWKS 解析、`FindJWKSKey` 查找、`SM2PublicKeyFromJWK` 解析（绕过 jwx 不支持 SM2/SM9 的限制）
- [x] `pkg/client/rp/jwks.go` — RP 端 SM2/SM9 签名验证（`verifyGMSignature`，自定义 JWKS 解析替代 jwx）
- [x] `pkg/crypto/test/jwk_test.go` — JWK 相关测试覆盖（SM2/SM9 JWK 构建、公钥解析、JWKS 解析、签名验证等 14 个测试用例）
- [x] 依赖安全审计 — `go mod tidy` + `govulncheck ./...`
- [x] `pkg/op/crypto.go` — AES256GCM JWE 加密增加 SM4-GCM 选项（`sm4GCMCrypto`，dir 模式 + SGD_SM4_GCM）
- [x] `pkg/crypto/hash.go` — 注册 GM/T 算法到 jwx（`RegisterSignatureAlgorithm`/`RegisterKeyEncryptionAlgorithm`/`RegisterContentEncryptionAlgorithm`），使 `jws.Parse`/`jwe.Parse` 可识别 `SGD_SM3_SM2`/`SGD_SM3_SM9`/`SGD_SM9_3`/`SGD_SM4_GCM` 等算法
- [x] 国密算法端到端集成测试 — `pkg/op/gm_e2e_test.go`（SM2/SM9 签名令牌 → 验证器检查，错误密钥、错误发行人、过期令牌、错误 UID 等场景，共 6 个测试用例）

### 待完成
- [ ] SM2/SM9 JWK 的 x5c / x5t 证书链支持
- [ ] JWE 加密集成到 OIDC token 流程（id_token / userinfo 响应加密）
  - SM2 JWE（`SGD_SM2_3` + `SGD_SM4_GCM`）作为 id_token 加密方式
  - SM9 JWE（`SGD_SM9_3` + `SGD_SM4_GCM/CCM`）作为 id_token 加密方式
  - Discovery 文档声明 `id_token_encryption_alg_values_supported` 和 `id_token_encryption_enc_values_supported`
  - RP 客户端支持解密 SM2/SM9 JWE 加密的 id_token

---

## 🔴 协议功能（SDK 应提供）

### 1. Dynamic Client Registration (DCR)
- [ ] 实现 `ClientRegistration` Storage 接口方法
- [ ] 添加 `/register` 端点处理
- [ ] 在 Discovery 文档中声明 `registration_endpoint`
- [ ] 编写 DCR 测试用例

### 2. mTLS 支持（RFC 8705）
- [ ] 实现客户端证书认证
- [ ] 添加 `tls_client_auth` 授权方法
- [ ] 在 Discovery 文档中声明 `mtls_endpoint_aliases`

### 3. 密钥管理
- [ ] 提供密钥轮换回调接口
- [ ] 支持 KMS 密钥加载抽象（如 AWS KMS、Azure Key Vault）

---

## 🛠 测试与示例

### 4. 压力测试
- [ ] 编写并发认证请求测试
- [ ] 编写 token 刷新高并发测试
- [ ] 记录基准测试结果

### 5. 示例 server 完善
- [ ] 移除硬编码 crypto key，支持从环境变量 `CRYPTO_KEY` 读取
- [ ] 支持 `TLS_CERT` / `TLS_KEY` 环境变量读取证书
- [ ] 生产环境默认禁用 `--insecure`

---

## 🟢 低优先级

### 6. 文档与仓库
- [ ] 清理 README 上游引用（badge、contributors 图、license 链接）
- [ ] 列出与上游 zitadel/oidc 的差异
- [ ] 添加迁移指南（从上游迁移到本分支）

---

## 备注

- 当前状态：已通过 OIDF Basic Profile + Config Profile 认证
- 全量测试通过：`go test ./...` ✅
- 核心覆盖率：`pkg/op` 72.1%, `pkg/oidc` 69.2%
- 已删除的弃用接口：`ValidateAuthRequest`, `SetUserinfoFromScopes`, `UserFormURL`
- 与上游 zitadel/oidc 的兼容性：已破坏，作为独立分支维护
- 国密算法底层实现完成（SM2/SM3/SM4/SM9/JWE），OIDC 协议层集成完成（OP 签发/验证 SM2+SM9，RP 验证 SM2+SM9，JWKS 导出 SM2+SM9 公钥）