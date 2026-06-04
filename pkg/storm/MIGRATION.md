# StormEngine Migration Status & Architecture

## Architecture Overview

```
pkg/storm/
├── engine.go          # Engine 核心：插件注册、路由编排、冲突检测
├── plugin.go          # Plugin + DiscoveryContributor 接口定义
├── storage.go         # 按功能拆分的存储接口（ClientStore, AuthStore, TokenStore 等）
├── codec/
│   ├── decode.go      # 表单解码器（替代 zitadel/schema Decoder）
│   ├── encode.go      # 表单编码器（替代 zitadel/schema Encoder）
│   └── test/
│       └── decode_test.go
├── shared/
│   ├── clientauth.go  # 客户端认证辅助（Basic Auth + POST body）
│   ├── cookie.go      # 安全 Cookie 处理（整合自 pkg/util/http/cookie.go）
│   ├── error.go       # OIDC 错误响应 + StatusError
│   ├── issuer.go      # Issuer 注入中间件 + Context 传递
│   ├── marshal.go     # JSON 序列化 + JSON 合并（整合自 pkg/util/http/marshal.go）
│   └── response.go    # JSON/Redirect/NoContent 响应工具
├── plugins/
│   ├── authorization/   # /authorize
│   ├── token/           # /token
│   ├── introspection/   # /introspect
│   ├── userinfo/        # /userinfo
│   ├── revocation/      # /revoke
│   ├── endsession/      # /endsession
│   ├── device/          # /device_authorization
│   ├── par/             # /par
│   ├── backchannel/     # /backchannel_logout
│   ├── dcr/             # /register
│   ├── discovery/       # /.well-known/openid-configuration
│   └── keys/            # /.well-known/jwks.json
└── test/
    └── engine_test.go
```

## Core Design Principles

1. **Engine 不懂 OIDC**：Engine 仅负责 HTTP 路由、中间件和插件编排，所有 OIDC 协议逻辑下沉到插件
2. **插件完全自主**：每个插件拥有自己的路由、请求解析、业务逻辑和错误处理
3. **存储接口按功能拆分**：ClientStore、AuthStore、TokenStore 等小接口，插件按需依赖
4. **Discovery 贡献者模式**：插件实现 `DiscoveryContributor` 接口，Engine 聚合并做冲突检测
5. **黑盒测试**：测试仅基于公开接口，不依赖内部实现细节
6. **函数式优先**：避免过度面向对象，优先使用纯函数和接口组合

## Migration Status

### Legend
- ✅ 已迁移：核心逻辑已实现，编译通过
- ⚠️ 部分迁移：框架已搭建，但存在 TODO/placeholder
- ❌ 未迁移：尚未开始
- ➖ 不适用：旧架构中不存在此功能

---

### 1. Core Framework

| Component | pkg/op (旧) | pkg/storm (新) | Status | Notes |
|-----------|-------------|----------------|--------|-------|
| Engine/Provider | `OpenIDProvider` + `webServer` | `Engine` | ✅ | Engine 不含业务逻辑 |
| Plugin System | 无（硬编码路由） | `Plugin` interface | ✅ | 注册式插件体系 |
| Discovery Aggregation | `discovery.go` (静态) | `DiscoveryContributor` | ✅ | 插件贡献 + 冲突检测 |
| Storage Interface | 巨型 `Storage` interface | 按功能拆分的小接口 | ✅ | ClientStore, AuthStore, TokenStore 等 |
| Codec (schema) | `zitadel/schema` | `storm/codec` | ✅ | 支持 storm 标签 + Converter |
| Issuer Injection | `IssuerFromRequest` | `shared.IssuerMiddleware` | ✅ | Context 传递 |
| Health Probes | `probes.go` | Engine 内置 `/healthz` + `/ready` | ✅ | |
| CORS | `WithCORSOptions` | `WithCORS` EngineOption | ✅ | |
| Middleware | `HttpInterceptor` | `WithMiddleware` EngineOption | ✅ | |

### 2. OIDC Endpoints

| Endpoint | OIDC Standard | pkg/op (旧) | pkg/storm (新) | Status | Notes |
|----------|---------------|-------------|----------------|--------|-------|
| `/authorize` | RFC 6749 §3.2, OIDC Core §3.1.3.1 | `auth_request.go` | `authorization/` | ⚠️ | 框架完成，token 解析/加密待补全 |
| `/token` (authorization_code) | RFC 6749 §3.2 | `token_code.go` | `token/` | ⚠️ | 核心流程完成，opaque token 解密待实现 |
| `/token` (refresh_token) | RFC 6749 §6 | `token_refresh.go` | `token/` | ⚠️ | 核心流程完成 |
| `/token` (client_credentials) | RFC 6749 §4.4 | `token_client_credentials.go` | `token/` | ⚠️ | 核心流程完成 |
| `/token` (jwt-bearer) | RFC 7523 §2.1 | `token_jwt_profile.go` | `token/` | ❌ | JWT 断言解析和验证未实现 |
| `/token` (token-exchange) | RFC 8693 | `token_exchange.go` | — | ❌ | 未迁移 |
| `/token` (device_code) | RFC 8628 §3.4 | `device.go` | — | ❌ | device_code grant 在 token 端点未实现 |
| `/introspect` | RFC 7662 §2 | `token_intospection.go` | `introspection/` | ⚠️ | 框架完成，token 解析待实现 |
| `/userinfo` | OIDC Core §5.3 | `userinfo.go` | `userinfo/` | ⚠️ | 框架完成，token 解析待实现 |
| `/revoke` | RFC 7009 §2 | `token_revocation.go` | `revocation/` | ⚠️ | 框架完成，token 解析待实现 |
| `/endsession` | OIDC Session Mgmt §5 | `session.go` | `endsession/` | ⚠️ | 框架完成，id_token_hint 验证待实现 |
| `/device_authorization` | RFC 8628 §3.1 | `device.go` | `device/` | ⚠️ | 框架完成，crypto 生成待替换 placeholder |
| `/par` | RFC 9126 §3 | `par.go` | `par/` | ⚠️ | 框架完成 |
| `/register` | RFC 7591 §3 | `dcr.go` + `dcr_management.go` | `dcr/` | ⚠️ | CRUD 完成，crypto 生成待替换 placeholder |
| `/backchannel_logout` | OIDC Back-Channel §4 | `backchannel_logout.go` | `backchannel/` | ⚠️ | 框架完成，logout token 推送未实现 |
| `/.well-known/openid-configuration` | OIDC Discovery | `discovery.go` | `discovery/` + Engine 内置 | ✅ | 插件贡献 + 冲突检测 |
| `/.well-known/jwks.json` | RFC 7517 | `keys.go` | `keys/` | ✅ | |

### 3. Supporting Components

| Component | pkg/op (旧) | pkg/storm (新) | Status | Notes |
|-----------|-------------|----------------|--------|-------|
| Client Auth Helper | 内联在各 handler | `shared.ClientAuthHelper` | ✅ | 统一 Basic Auth + POST body |
| Cookie Handler | `pkg/util/http/cookie.go` | `shared/cookie.go` | ✅ | 已整合 |
| JSON Marshal | `pkg/util/http/marshal.go` | `shared/marshal.go` | ✅ | 已整合 |
| Error Handling | `error.go` | `shared/error.go` | ✅ | StatusError + oidc.Error |
| Issuer Middleware | `config.go` | `shared/issuer.go` | ✅ | |

### 4. Verifiers (Token Validation)

| Verifier | pkg/op (旧) | pkg/storm (新) | Status | Notes |
|----------|-------------|----------------|--------|-------|
| Access Token Verifier | `verifier_access_token.go` | — | ❌ | 未迁移 |
| ID Token Hint Verifier | `verifier_id_token_hint.go` | — | ❌ | 未迁移 |
| JWT Profile Verifier | `verifier_jwt_profile.go` | — | ❌ | 未迁移 |

### 5. Crypto & Signing

| Component | pkg/op (旧) | pkg/storm (新) | Status | Notes |
|-----------|-------------|----------------|--------|-------|
| Crypto Interface | `crypto.go` | `storm.Crypto` | ✅ | 接口定义完成 |
| GM/T Crypto Interface | 无 | `storm.GMCrypto` | ✅ | 国密扩展接口（SM4/JWE/签名） |
| GM/T Signing Key | 无 | `storm.GMSigningKey` | ✅ | 国密签名密钥接口 |
| GM/T JWK | 无 | `storm.GMJWK` | ✅ | 国密 JWK 序列化接口 |
| Signer | `signer.go` | — | ⚠️ | 标准 JWS 签名未迁移，国密签名通过 GMSigningKey 支持 |
| Key Management | `keys.go` | `storm.KeyStore` | ✅ | 接口定义完成 |

### 6. pkg/oidc Types

| Change | Status | Notes |
|--------|--------|-------|
| `NewEncoder()` 替换 `schema.NewEncoder()` | ✅ | 自实现 Encoder，不再依赖 zitadel/schema |
| `schema` 标签保留 | ✅ | 新 Encoder 读取 `schema` tag 保持兼容 |
| `zitadel/schema` 从 `pkg/oidc` 移除 | ✅ | import 已清理 |

### 7. Dependencies Status

| Dependency | Status | Notes |
|------------|--------|-------|
| `github.com/zitadel/schema` | ⚠️ 部分移除 | `pkg/oidc` 已移除，`pkg/op` 仍在使用 |
| `github.com/go-chi/chi/v5` | ✅ | 保留，作为路由引擎 |
| `github.com/gorilla/securecookie` | ✅ | 保留，用于 Cookie 加密 |
| `github.com/lestrrat-go/jwx/v4` | ✅ | 保留，用于 JWT/JWK 处理 |
| `github.com/rs/cors` | ✅ | 保留，CORS 中间件 |

---

## Key Architecture Differences: pkg/op vs pkg/storm

### pkg/op (V1/V2)
```
OpenIDProvider (V1)          Server interface (V2)
    │                            │
    ├─ Storage (巨型接口)         ├─ webServer (路由+业务混合)
    │                            │
    └─ 硬编码路由                 └─ 业务逻辑泄漏到路由层
```

### pkg/storm (StormEngine)
```
Engine (纯路由编排)
    │
    ├─ Plugin (自主路由+业务)
    │   ├─ authorization
    │   ├─ token
    │   ├─ introspection
    │   └─ ...
    │
    ├─ Storage (按功能拆分)
    │   ├─ ClientStore
    │   ├─ AuthStore
    │   ├─ TokenStore
    │   └─ ...
    │
    └─ Shared (跨切面工具)
        ├─ ClientAuthHelper
        ├─ CookieHandler
        ├─ IssuerMiddleware
        └─ ErrorHandling
```

## Remaining Work (Priority Order)

### P0 - Critical
1. **Opaque Token 解密/解析**：introspection、userinfo、revocation 插件中的 `resolveToken()` 已实现国密 JWE + 标准解密双路径，但 JWT access token 验证尚未实现
2. **JWT Profile Grant**：`urn:ietf:params:oauth:grant-type:jwt-bearer` 在 token 插件中未实现
3. **Access Token Verifier**：JWT/opaque token 验证逻辑未迁移
4. ~~**国密（GM/T）算法集成**~~：✅ 已完成（见下方国密集成详情）

### P1 - High
5. **Token Exchange Grant**：RFC 8693 `urn:ietf:params:oauth:grant-type:token-exchange` 未迁移
6. **Device Code Grant on Token Endpoint**：device 插件只实现了 `/device_authorization`，token 端点的 `device_code` grant 未实现
7. **ID Token Hint Verifier**：endsession 插件需要验证 id_token_hint
8. **Signer**：JWT 签名逻辑未迁移（标准 JWS 签名，国密签名已通过 GMSigningKey 接口支持）
9. **Crypto Placeholder 替换**：dcr 和 device 插件中的 `randomHex()` 需要用 `crypto/rand` 替换
10. ~~**国密 JWE Token 加密**~~：✅ 已完成 — token 插件支持 SM2+SM4-GCM JWE 加密 opaque token

### P2 - Medium
11. **Back-Channel Logout Token 推送**：当前仅框架，未实现 logout token 创建和推送
12. **Form Post 模板**：`form_post.html.tmpl` 未迁移
13. **Client 接口扩展**：旧架构 Client 接口方法较多（RedirectURIs, GrantTypes 等），新架构 Client 接口较精简
14. **Request Object 解析**：`ParseRequestObject`（JWT-based authorization request）未迁移
15. ~~**国密 Discovery 声明**~~：✅ 已完成 — discovery 插件从 KeyStore 动态获取算法列表

### P3 - Low
16. **pkg/op 完全移除**：等 storm 完全替代后，删除 `pkg/op` 目录
17. **pkg/util/http 清理**：客户端工具（FormRequest, HttpRequest 等）保留在 `pkg/util/http`，服务端工具已整合到 `storm/shared`
18. **zitadel/schema 从 go.mod 移除**：等 `pkg/op` 删除后执行 `go mod tidy`
19. **Mock 清理**：`pkg/op/mock/` 目录在旧架构删除后一并清理

## Storage Interface Mapping

| pkg/op Storage Method | pkg/storm Interface | Migrated |
|-----------------------|---------------------|----------|
| `GetClientByClientID` | `ClientStore.GetClientByClientID` | ✅ |
| `AuthorizeClientIDSecret` | `ClientStore.AuthorizeClientIDSecret` | ✅ |
| `CreateAuthRequest` | `AuthStore.CreateAuthRequest` | ✅ |
| `AuthRequestByID` | `AuthStore.AuthRequestByID` | ✅ |
| `AuthRequestByCode` | `AuthStore.AuthRequestByCode` | ✅ |
| `SaveAuthCode` | `AuthStore.SaveAuthCode` | ✅ |
| `DeleteAuthRequest` | `AuthStore.DeleteAuthRequest` | ✅ |
| `CreateAccessToken` | `TokenStore.CreateAccessToken` | ✅ |
| `CreateAccessAndRefreshTokens` | `TokenStore.CreateAccessAndRefreshTokens` | ✅ |
| `TokenRequestByRefreshToken` | `TokenStore.TokenRequestByRefreshToken` | ✅ |
| `SetIntrospectionFromToken` | `IntrospectStore.SetIntrospectionFromToken` | ✅ |
| `SetUserinfoFromToken` | `UserinfoStore.SetUserinfoFromToken` | ✅ |
| `RevokeToken` | `RevocationStore.RevokeToken` | ✅ |
| `GetRefreshTokenInfo` | `RevocationStore.GetRefreshTokenInfo` | ✅ |
| `TerminateSession` | `SessionStore.TerminateSession` | ✅ |
| `StoreDeviceAuthorization` | `DeviceAuthStore.StoreDeviceAuthorization` | ✅ |
| `GetDeviceAuthorizationState` | `DeviceAuthStore.GetDeviceAuthorizationState` | ✅ |
| `StorePushedAuthRequest` | `PARStore.StorePushedAuthRequest` | ✅ |
| `CreateClient` (DCR) | `DCRStore.CreateClient` | ✅ |
| `GetClientRegistration` | `DCRStore.GetClientRegistration` | ✅ |
| `UpdateClientRegistration` | `DCRStore.UpdateClientRegistration` | ✅ |
| `DeleteClientRegistration` | `DCRStore.DeleteClientRegistration` | ✅ |
| `ClientsForSession` | `BackChannelStore.ClientsForSession` | ✅ |
| `ClientCredentials` | `ClientCredentialsStore.ClientCredentials` | ✅ |
| `ValidateJWTProfileScopes` | `JWTProfileStore.ValidateJWTProfileScopes` | ✅ |
| `ValidateTokenExchangeRequest` | `TokenExchangeStore.ValidateTokenExchangeRequest` | ✅ |
| `KeySet` | `KeyStore.KeySet` | ✅ |
| `Health` | `Storage.Health` | ✅ |
| `SignatureAlgorithms` | `KeyStore.SignatureAlgorithms` | ✅ |
| `SigningKey` | `KeyStore.SigningKey` | ✅ |

## GM/T (国密) Integration Details

StormEngine 通过接口扩展模式集成国密算法，不修改现有标准接口，确保向后兼容。

### 接口扩展

| 接口 | 用途 | 状态 |
|------|------|------|
| `storm.GMCrypto` | 扩展 `Crypto`，增加 SM4 加解密、SM2 JWE、签名 | ✅ |
| `storm.GMSigningKey` | 扩展 `SigningKey`，提供国密签名能力 | ✅ |
| `storm.GMJWK` | 国密 JWK 序列化接口（SM2/SM9 不兼容 jwx） | ✅ |
| `storm.GMTokenSigner` | 国密 token 签名器，封装 `pkg/crypto.Signer` | ✅ |
| `storm.Signer` | 通用签名接口（仅签名，不含加密） | ✅ |

### 插件集成

| 插件 | 国密支持 | 实现方式 |
|------|----------|----------|
| `token` | ✅ SM2+SM4-GCM JWE 加密 opaque token；SM2/SM9 签名 ID Token | 检测 `GMCrypto` / `GMSigningKey` 接口 |
| `keys` | ✅ JWKS 包含 SM2/SM9 公钥 | 检测 `Key.GMJWK()` 返回值 |
| `discovery` | ✅ 动态声明 `SGD_SM3_SM2` 等算法 | 从 `KeyStore.SignatureAlgorithms()` 获取 |
| `introspection` | ✅ SM2 JWE 解密 opaque token | 检测 `GMCrypto` 接口，优先 JWE 解密 |
| `userinfo` | ✅ SM2 JWE 解密 opaque token | 同上 |
| `revocation` | ✅ SM2 JWE 解密 opaque token | 同上 |

### 使用方式

```go
// Storage 实现者只需实现 storm.GMCrypto 接口即可启用国密
type myCrypto struct{}

func (c *myCrypto) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) { ... }
func (c *myCrypto) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) { ... }
func (c *myCrypto) SM4Encrypt(ctx context.Context, plaintext []byte, mode string) ([]byte, error) { ... }
func (c *myCrypto) SM4Decrypt(ctx context.Context, ciphertext []byte, mode string) ([]byte, error) { ... }
func (c *myCrypto) SM2EncryptJWE(ctx context.Context, plaintext []byte) (string, error) { ... }
func (c *myCrypto) SM2DecryptJWE(ctx context.Context, compact string) ([]byte, error) { ... }
func (c *myCrypto) Sign(ctx context.Context, keyID string, payload []byte) (string, error) { ... }

// Key 实现者需同时实现 GMJWK() 方法
type mySM2Key struct{}

func (k *mySM2Key) ID() string              { return "sm2-key-1" }
func (k *mySM2Key) Algorithm() string       { return "SGD_SM3_SM2" }
func (k *mySM2Key) Use() string             { return "sig" }
func (k *mySM2Key) Key() jwk.Key            { return nil } // 不兼容 jwx
func (k *mySM2Key) GMJWK() storm.GMJWK      { return sm2JWK{...} }
```

### 依赖关系

```
pkg/crypto (底层国密实现)
    ├── SM2/SM3/SM4/SM9 算法
    ├── Signer (JWS 签名)
    ├── JWE (SM2+SM4-GCM/CCM 加密)
    ├── JWK (SM2/SM9 JWK 序列化)
    └── Hash (SM3 哈希)

pkg/storm (插件接口层)
    ├── GMCrypto 接口 → 调用 pkg/crypto
    ├── GMSigningKey 接口 → 调用 pkg/crypto.Signer
    ├── GMJWK 接口 → 调用 pkg/crypto SM2JWK/SM9SignJWK
    └── GMTokenSigner → 封装 pkg/crypto.Signer.Sign()
```
