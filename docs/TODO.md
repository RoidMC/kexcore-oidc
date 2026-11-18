# KexCore OIDC TODO

> 最后核对：2026-11-19（对照工作区代码）
>
> 本文件只维护**当前未完成项**。功能状态以 `README.md` 的 Features 表为准，
> 变更历史以 git log / release notes 为准。原文件中的历史完成清单可用 `git show` 查看旧版本。

## 维护约定

- V3 移除了 v2 的 `pkg/op` 与 `example/server`；`pkg/client/rp` 仍保留（基于上游 zitadel/oidc 的 RP），不要再按“已移除”处理。
- 当前结构：`pkg/protocol`（协议层）、`pkg/storm`（OP 引擎）、`pkg/client`（RP/RS）、`pkg/crypto`（国密与 JWE）、`example/storm-server`（示例 OP）、`example/testsuite`（conformance）。
- 勾掉一项时请同步更新 `README.md` 的对应状态，避免两处口径不一致。

## P2 测试与示例

- [ ] **端到端并发 / 压力测试**
      原 TODO 要求的"并发认证请求测试""token 刷新高并发测试""记录基准结果"仍未做。目前 `pkg` 下只有局部 benchmark（`plugins/pairwise/pairwise_test.go`、`plugins/dpop/evict_bench_test.go`），没有覆盖认证与 token 刷新链路的并发用例，也没有基准数据记录。

- [ ] **Optional 分类缺少内置用例**
      v3.4.0 引入 `CategoryOptional` / `PluginDescriptor` 后，Optional 的装配分支只有单测覆盖；目前没有任何内置插件声明 Optional，EE / build-tag 裁剪也缺少真实样例。需要决定哪些能力应改为 opt-in，或补一个示例插件。

- [ ] **云 KMS provider 实现与使用文档**
      `pkg/crypto/registry.go` 已有 `SignProvider` / `VerifyProvider` / `JWEEncryptProvider` 等接口和 `DefaultRegistry` / `Override*` 覆盖点，`pkg/crypto/registry_wrap.go` 也提供了 HSM/KMS 适配辅助；
      但仓库内仍没有 AWS KMS、Azure Key Vault 等具体 provider 实现和接入示例，`README.md` 的 "HSM/KMS support" 目前只到接口层。
      需要按云厂商引入 SDK、凭证链和集成测试，依赖与维护成本高于其他项；在此之前可先在 `example/` 提供一个基于 `OverrideSigner` 的桩实现。

## 已归档（不再作为待办）

以下条目在旧版 TODO 中逐条列出，现均已落地或随 V3 移除，状态以 `README.md` 为准：

- 国密 SM2/SM3/SM4/SM9、JWE 全链路、OP 签发与验证、RP 验证、JWKS 公钥导出 → `README.md` GM/T 章节与 Features 表
- Back-Channel Logout、PAR、DCR、mTLS、JARM、DPoP、CIBA、WebFinger、FAPI 2.0 相关能力 → `README.md` Features 表
- JWE 加密 ID Token / UserInfo 响应、`TokenEncryptionKeyProvider` 等接口 → `pkg/storm/storage.go`
- OIDF 认证：RP 已过 `oidf-basic` / `oidf-config`，OP 已过 `oidf-backchannel` → `README.md:23-24`
- 原 TODO 中 `pkg/op` / `example/server` 的实现清单 → 随 V3 移除，仅保留在 git 历史中
- `.github/ISSUE_TEMPLATE` 清理（2026-11-18）：移除 ZITADEL chat / Cloud 选项、非法 `type`、失效的 CONTRIBUTING 链接，补充 SDK/Go 版本、受影响区域与日志字段
- README / CONTRIBUTING / SECURITY / `.github/workflows/issue.yml` 上游残留清理（2026-11-18）：替换 ZITADEL 链接与示例邮箱、删除指向 `orgs/zitadel/projects/2` 的 workflow；`zitadel/oidc` 的 attribution（版权头、`Based on zitadel/oidc`、License/NOTICE）保留
- README 补充 v3.4.0 插件装配章节（2026-11-18）：`PluginDescriptor` / `RegisterPluginWith` / `CategoryUnspecified`、Core 不可禁用、重名 panic、`Enable/Disable` 按 `Name()` 匹配
- SM2/SM9 JWK 证书字段支持（2026-11-18）：`NewSM2JWKWithChain` / `NewSM9SignJWKWithChain` 生成 `x5c` / `x5t` / `x5t#S256`（`x5c` 用标准 base64，指纹用 base64url），`x5u` 开放给调用方填写；不做链校验
- 签名密钥轮换 SDK 钩子（2026-11-18）：新增 `storm.SigningKeyRotator` 与 `Engine.RotateSigningKey(ctx)`，校验新 key 已生效且在 `KeySet` 中，旧 key 提前移除时告警；示例服务器改为实现该接口
- 示例服务器 TLS 与对称密钥配置（2026-11-18）：`ENABLE_SELF_SIGN_SSL` / `ENABLE_SKIP_TLS_CERT_VERIFY` 改为环境变量，CIBA 通知默认校验证书；新增 `CRYPTO_KEY` 注入 token 加密密钥
- `claims` 参数实现（2026-11-18）：`protocol.ApplyClaimsRequest` 执行 `essential` / `value` / `values`；ID Token 在合并扩展 claim 后校验，UserInfo 在组装后校验；新增可选 `storm.ClaimsRequestStore`，discovery 依据存储能力宣告 `claims_parameter_supported`；KexCore 在 `oidc_access_tokens` 增加 `claims` 列（迁移 `20261118142453`），refresh 轮换时新 access token 继承旧 token 的 claims；`claims.id_token` 在刷新重新签发 ID Token 时同样执行（按 refresh token ID 反查）；KexCore 另在 `oauth_refresh_tokens` 增加 `claims` 列（迁移 `20261118144450`），使 claims 沿 refresh 链传递（JWT access token 路径的 refresh 行不持有 access token ID）
- 安全审计修复（2026-11-19）：
  - token 端点支持 `client_secret_jwt`（HS256/384/512）：断言按 header alg 路由到 `shared.AuthenticateClientSecretJWT`；KexCore 的 `pgClient` 实现 `ClientSecret()`
  - UserInfo 签名 fail-closed：注册了 `userinfo_signed_response_alg` 时签名失败返回 500，指定 alg 无对应 key 不再静默回退
  - JWT access token 校验：`aud` 必须存在且（配置了期望值时）命中，签名算法由 KeyStore 派生、空集合 fail-closed；`storm.ResolveToken` 新增 `WithResolveTokenAudience`
  - Refresh token rotation 默认开启，新增 `token.Config.DisableRefreshRotation` 显式关闭（`InvalidateRefreshOnUse` 标记为 deprecated）
  - Device 审批页补 subject 输入，并新增 `device.Config.SubjectResolver` 绑定已认证会话
  - CIBA 支持 `id_token_hint`（用 OP 密钥验签）与 `login_hint_token`（解析 sub 并校验 exp）
  - Back-Channel Logout 移除无实现的入站端点与 discovery 声明（OP 只负责推送）；JARM / logout token 签名改走 `crypto` provider registry
  - DCR 默认要求 initial access token：新增 `InitialAccessTokenValidator` 与静态 `InitialAccessToken`，存储可用 `OpenRegistrationPolicy` 显式开放；示例服务器显式开放
  - DPoP 支持 proof `nonce` 校验（`Config.RequireNonce`，失败回发新 nonce）、`htu` 端口参与比较、可插拔 `NonceStore` / `ReplayStore`
  - PAR `request_uri` 一次性消费：新增可选 `storm.PushedAuthRequestConsumer`，示例存储实现删除
  - 示例 introspection 绑定调用方 clientID，修正 `nbf` 误写为 expiration
  - `/authorize/complete` 新增 `SetCompletionAuthorizer` 钩子用于调用方认证
  - discovery 仅在存储实现 `storm.PairwiseTransformer` 时声明 `pairwise`
