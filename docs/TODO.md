# KexCore OIDC TODO

> 最后核对：2026-11-10（对照 V3.3.0 代码与 `README.md`）
>
> 本文件只维护**当前未完成项**。功能状态以 `README.md` 的 Features 表为准，
> 变更历史以 git log 为准。原文件中的历史完成清单可用 `git show` 查看旧版本。

## 维护约定

- V3 已移除 v2 的 `pkg/op`、`pkg/client/rp`、`example/server`；原 TODO 里指向这些路径的条目已全部归档，不要再按旧路径找代码。
- 当前结构：`pkg/protocol`（协议层）、`pkg/storm`（OP 引擎）、`pkg/client`（RP）、`pkg/crypto`（国密与 JWE）、`example/storm-server`（示例 OP）、`example/testsuite`（conformance）。
- 勾掉一项时请同步更新 `README.md` 的对应状态，避免两处口径不一致。

## P1 协议与密钥

- [ ] **SM2/SM9 JWK 的 `x5c` / `x5t` 证书链支持**
      `pkg/crypto/jwk.go` 目前只构建公钥字段，没有 `x5c` / `x5t` / `x5u`。
      注意 `pkg/storm/shared/context.go` 里的 `cnf.x5t#S256` 是 mTLS token 绑定指纹（RFC 8705 §3.1），不是 JWK 证书链，两者不要混为一谈。

- [ ] **云 KMS provider 实现与使用文档**
      `pkg/crypto/registry.go` 已有 `SignProvider` / `VerifyProvider` / `JWEEncryptProvider` 等接口和 `DefaultRegistry` / `Override*` 覆盖点，`README.md` 也已声明 HSM/KMS support；但仓库内没有 AWS KMS、Azure Key Vault 等具体 provider 实现和接入示例。

- [ ] **签名密钥轮换的 SDK 层钩子**
      现状是三层拼起来的：`pkg/storm/storage.go` 的 `KeySet` 契约（旧密钥必须保留到签发令牌全部过期）、`pkg/storm/validate.go` 的轮换安全检查、以及仅存在于示例层的 `example/storm-server/storage/storage.go` 的 `RotateSigningKey()` + `POST /admin/rotate-keys`。SDK 本身没有统一的轮换接口，接入方需要各自实现。

## P2 测试与示例

- [ ] **端到端并发 / 压力测试**
      原 TODO 要求的"并发认证请求测试""token 刷新高并发测试""记录基准结果"仍未做。目前 `pkg` 下只有局部 benchmark（`plugins/pairwise/pairwise_test.go`、`plugins/dpop/evict_bench_test.go`），没有覆盖认证与 token 刷新链路的并发用例，也没有基准数据记录。

- [ ] **示例服务器去掉硬编码的 TLS 跳过校验**
      `example/storm-server/config/config.go` 把 `EnableSkipTLSCertVerify`、`EnableSelfSignSSL` 写成常量 `"true"`；`example/storm-server/storage/ciba.go` 的 CIBA notification HTTP client 硬编码 `InsecureSkipVerify: true`。应改为可配置且生产默认关闭。

- [ ] **示例服务器对称加密密钥支持环境变量注入**
      `config/config.go` 已支持 `SIGNING_ALGORITHMS`、`CRYPTO_METHOD`、`TLS_CERT_FILE`、`TLS_KEY_FILE`，但没有 `CRYPTO_KEY`（token 对称加密密钥）。

## P3 开源门面与文档

- [ ] **清理 README 中无意义的上游残留**
      例如示例用户邮箱 `@zitadel.ch`、`<!--zitadel/oidc issue reference-->` 注释、仅指向上游文档的资源链接等。
      对 `zitadel/oidc` 的 attribution（版权头、`Based on zitadel/oidc`、License/NOTICE）属于合规要求，**必须保留**。

- [ ] **补一份从 `zitadel/oidc` 迁移的指南**
      目前只有 `README.md` 的 semver 段落指向 release notes，以及 "Why another library" 里一句差异说明；没有独立的迁移文档（RP 侧兼容边界、OP 侧从 `pkg/op` 到 `pkg/storm` 的映射）。

## 已归档（不再作为待办）

以下条目在旧版 TODO 中逐条列出，现均已落地或随 V3 移除，状态以 `README.md` 为准：

- 国密 SM2/SM3/SM4/SM9、JWE 全链路、OP 签发与验证、RP 验证、JWKS 公钥导出 → `README.md` GM/T 章节与 Features 表
- Back-Channel Logout、PAR、DCR、mTLS、JARM、DPoP、CIBA、WebFinger、FAPI 2.0 相关能力 → `README.md` Features 表
- JWE 加密 ID Token / UserInfo 响应、`TokenEncryptionKeyProvider` 等接口 → `pkg/storm/storage.go`
- OIDF 认证：RP 已过 `oidf-basic` / `oidf-config`，OP 已过 `oidf-backchannel` → `README.md:23-24`
- 原 TODO 中 `pkg/op` / `pkg/client/rp` / `example/server` 的实现清单 → 随 V3 移除，仅保留在 git 历史中
