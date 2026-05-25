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
- [x] JWE 加密集成到 OIDC token 流程（id_token / userinfo 响应加密）
  - [x] `dir` 模式对称加密（`SGD_SM4_GCM` / `A256GCM` / `A128GCM`）— 通过 `EncryptToken` / `EncryptTokenA256GCM` / `EncryptTokenA128GCM`
  - [x] OP 端 `encryptIDToken()` 根据客户端声明的 `enc` 自动选择加密算法
  - [x] RP 端 `DecryptToken` / `DecryptTokenWithKey` 解密 JWE 加密的 ID Token
  - [x] `TokenEncryptionKeyProvider` 接口 — Crypto 实现类暴露对称密钥
  - [x] `IDTokenEncryptionClient` 接口 — 客户端声明加密偏好（alg + enc）
  - [x] JWE 常量定义（`JWEAlgDir`/`JWEAlgA256GCMKW`/`JWEEncSM4GCM`/`JWEEncA256GCM`/`JWEEncA128GCM`）
  - [x] 修复 `decryptDirMode` 密钥长度推断 BUG — 改为基于 JWE header `enc` 字段分发
  - [x] SM2 JWE（`SGD_SM2_3` + `SGD_SM4_GCM`）作为 id_token 加密方式
    - `EncryptTokenSM2(signedToken, publicKey)` — OP 端使用 RP 的 SM2 公钥加密
    - `SM2TokenEncryptionPublicKeyProvider` 接口 — Crypto 实现类暴露 SM2 公钥
    - `encryptIDToken()` 自动根据 `alg=SGD_SM2_3` 分发到 `EncryptTokenSM2`
    - RP 端解密通过 `crypto.SM2DecryptJWE(privateKey, compact)`（`pkg/crypto/jwe.go`）
  - [x] SM9 JWE（`SGD_SM9_3` + `SGD_SM4_GCM/CCM`）作为 id_token 加密方式
    - `EncryptTokenSM9(signedToken, masterPubKey, uid)` — OP 端使用 RP 的 SM9 主公钥加密
    - `SM9TokenEncryptionPublicKeyProvider` 接口 — Crypto 实现类暴露 SM9 主公钥和 UID
    - `encryptIDToken()` 自动根据 `alg=SGD_SM9_3` 分发到 `EncryptTokenSM9`
    - RP 端解密通过 `crypto.SM9DecryptJWE(userKey, uid, compact)`（`pkg/crypto/jwe.go`）
  - [x] 重构：AES-GCM/SM4-GCM 加解密函数从 `oidc/verifier.go` 抽取到 `pkg/crypto/jwe.go`
    - `crypto.AESGCMEncrypt` / `crypto.AESGCMDecrypt` — AES-GCM 通用加解密
    - `crypto.ParseJWECompact` — JWE compact 解析（原 `parseJWECompact` 导出）
    - `verifier.go` 移除本地 `aesGCMEncrypt`/`aesGCMDecrypt`/`sm4GCMEncrypt`/`sm4GCMDecrypt`/`sm4NewCipher`，改用 `crypto` 包函数
  - [x] Discovery 文档声明 `id_token_encryption_alg_values_supported` 和 `id_token_encryption_enc_values_supported`

### ⚠️ 已知限制（TODO 待解决）
- [x] **SM9 签名在 OIDC JWS flow 中集成**
  - `crypto.Signer` 已扩展支持 SM9（`sm9Priv` 字段 + `signSM9` 方法），JWS header 中携带 `uid` 参数
  - `op.SM9SigningKey` 接口 + `op.SignerFromKey` 自动通过类型断言设置 `uid`
  - `example/server/storage` 的 `signingKey` 已实现 `SM9SigningKey` 接口
  - `op.SM9JWTProfileKeyStorage` 接口 + `verifier_jwt_profile.go` 中 SM9 验证路径已实现
  - `example/server/storage` 已实现 `SM9JWTProfileKeyStorage` 接口（`GetSM9MasterPublicKeyByIDAndClientID`）
- [x] **JWE 加密（SGD_SM2_3 / SGD_SM9_3）在 OIDC token flow 中已集成**
  - `pkg/op/token.go` 的 `EncryptToken` 已支持 SM2/SM9 加密（通过 `TokenEncryptionKeyProvider` / `SM2TokenEncryptionPublicKeyProvider` / `SM9TokenEncryptionPublicKeyProvider` 接口）
  - example server 的 `myCrypto` 已实现 `SM2TokenEncryptionPublicKeyProvider` 和 `SM9TokenEncryptionPublicKeyProvider` 接口
  - `Client` 已实现 `IDTokenEncryptionClient` 接口（`IDTokenEncryptionAlg` / `IDTokenEncryptionEnc`）
  - 已注册 3 个 JWE 加密演示客户端：`web-dir-sm4`（dir+SM4）、`web-sm2`（SGD_SM2_3+SM4）、`web-sm9`（SGD_SM9_3+SM4）

---

## 🔙 Back-Channel Logout（OpenID Connect Back-Channel Logout 1.0）

### 已完成
- [x] `pkg/op/client.go` — `BackChannelLogoutClient` 接口（`BackChannelLogoutURI()`）
- [x] `pkg/op/op.go` — `Endpoints.BackChannelLogout` 端点定义
- [x] `pkg/op/backchannel_logout.go` — OP 端 BCL 端点处理器（请求解析、会话终止、Logout Token 生成与推送）
- [x] `pkg/op/backchannel_logout.go` — `BackChannelLogoutStorage` 接口（`ClientsForSession` 查询会话关联客户端）
- [x] `pkg/op/server_http.go` — 条件注册 `/backchannel_logout` 端点（仅当 server 实现 `BackChannelLogoutHandler`）
- [x] `pkg/oidc/token.go` — `LogoutTokenClaims` 结构体（实现 `Claims` 接口，含 `GetIssuer`/`GetSubject`/`GetAudience` 等方法）
- [x] `pkg/oidc/token.go` — `BackChannelLogoutEventKey` 常量
- [x] `pkg/client/rp/backchannel_logout.go` — RP 端 `BackChannelLogoutHandler`、`LogoutTokenVerifier`、`VerifyLogoutToken`
- [x] `pkg/op/test/backchannel_logout_test.go` — 11 个测试用例（JWE 加解密、Logout Token 生成、BCL 推送、Crypto 密钥暴露）

### 待完成
- [ ] Logout Token `typ` header 设为 `logout+jwt`（OIDC 规范 RECOMMENDED，当前 Signer 不支持自定义 JWT header）
- [ ] 并行推送 Logout Token 到多个 RP（OIDC 规范 encouraged，当前串行）
- [ ] Logout Token 加密支持（OIDC 规范 MAY，当前仅签名）
- [ ] **Example server 集成 Back-Channel Logout 演示**
  - `example/server/storage` 实现 `op.BackChannelLogoutStorage` 接口（`ClientsForSession` 方法）
  - `example/server/exampleop/op.go` 在 `Config` 中启用 `BackChannelLogoutSupported: true`
  - `example/server/main.go` 注册支持 `backchannel_logout_uri` 的客户端
  - 确认 `/backchannel_logout` 端点默认启用逻辑：仅当 server 实现 `BackChannelLogoutHandler` 时注册（当前 `server_http.go` 已支持），但 Discovery 字段 `backchannel_logout_supported` 默认 `false`，需显式开启

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

### 3. SM9 JWT Profile 验证（`verifier_jwt_profile.go`）
- [x] **`SM9JWTProfileKeyStorage` 接口已新增，SM9 JWT Profile 验证路径已实现**
  - 新增 `SM9JWTProfileKeyStorage` 接口（`GetSM9MasterPublicKeyByIDAndClientID`），通过接口断言与原 `JWTProfileKeyStorage` 兼容
  - `verifier_jwt_profile.go` 中 SM9 签名验证：从 header 提取 `uid`，调用 `crypto.VerifySM9JWSSignature`
  - `example/server/storage` 已实现 `SM9JWTProfileKeyStorage` 接口

### 4. 密钥管理
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