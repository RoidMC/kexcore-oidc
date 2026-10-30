# OIDF Conformance Suite 本地 Docker 环境

本目录用于在本机启动 **OpenID Foundation 官方一致性测试套件（Conformance Suite）**，
配合 `example/storm-server` 这个 OP 跑 OIDC / FAPI 认证测试。

上层目录的 [test.py](../test.py) + [config.yml](../config.yml) 通过套件的 REST API
创建测试计划、执行模块，并使用套件内置的 Selenium 自动完成登录/授权/登出等浏览器交互。
本目录只负责把套件本身拉起来。

## 服务组成

| 服务 | 镜像 | 说明 |
| --- | --- | --- |
| `mongodb` | `mongo:6.0.13` | 套件的结果/计划存储，数据落在 `./mongo-data` |
| `server` | `registry.gitlab.com/openid/conformance-suite:latest` | 套件主程序（Java/Spring Boot），内部监听 8080 |
| `nginx` | `registry.gitlab.com/openid/conformance-suite/nginx:latest` | 对外 HTTPS 入口，映射 8443（普通）与 8444（mTLS） |

两个关键环境变量（在 `server` 上）：

- `BASE_URL`：套件对外地址（浏览器、测试回调都基于它），默认 `https://192.168.2.133:8443`
- `BASE_MTLS_URL`：套件 mTLS 端点地址，默认 `https://192.168.2.133:8444`

> 这两个值必须改成**运行测试机自己能被容器和浏览器访问到的 IP**。
> 如果本机 IP 不是 `192.168.2.133`，需要同时修改：
> 本文件 `docker-compose.yml`、[config.yml](../config.yml) 的 `vars.suite_url` / `issuer_url`，
> 以及 `example/storm-server/main.go` 里硬编码的 OIDF 回调地址。

## 启动 / 停止

```powershell
# 在仓库根目录（c:\Users\chenc\Desktop\KexCore\kexcore-oidc）
docker compose -f example/testsuite/docker/docker-compose.yml pull
docker compose -f example/testsuite/docker/docker-compose.yml up -d

# 查看状态
docker compose -f example/testsuite/docker/docker-compose.yml ps

# 停止（加 -v 可同时清理 mongo 数据卷）
docker compose -f example/testsuite/docker/docker-compose.yml down
```

套件起来后：

- Web 界面：<https://192.168.2.133:8443>（自签名证书，浏览器需忽略告警）
- API：`https://192.168.2.133:8443/api/plan` 返回 200 即正常

自建套件不需要 API token；只有跑官方 `certification.openid.net` 时才需要。

## 跑测试的完整流程

1. 启动本目录的套件容器（见上）
2. 启动被测 OP（仓库根目录）：

   ```powershell
   $env:ISSUER="https://192.168.2.133:9998"; $env:PORT="9998"; go run ./example/storm-server
   ```

3. 进入 `example/testsuite`，按分组执行：

   ```powershell
   cd example/testsuite
   python test.py --group oidc_core
   python test.py --group all
   ```

## testcase 部分

测试计划的定义分两层：

- **[config.yml](../config.yml) 的 `plan_config`**：所有计划共用的被测 OP 信息
  （`server.discoveryUrl`）、静态客户端凭据（`Test Client 1/2`）、mTLS 证书、
  FAPI 客户端 JWKS、浏览器自动化脚本（`browser` / `override`）、以及全局 `skip_modules`。
  其中定义的 YAML 锚点（`&fapi_client`、`&fapi_client_mtls` 等）供 testcase 文件复用。
- **本目录上层的 [testcase/](../testcase) 目录**：每个文件是一个测试计划分组，
  [test.py](../test.py) 会把 `config.yml` 和所有 `testcase/*.yml` 拼接后解析，
  分组名就是文件里的顶层 key，也是 `--group` 的取值。

现有分组：

| 分组（`--group`） | 文件 | 覆盖内容 |
| --- | --- | --- |
| `oidc_core` | `testcase/oidc_core.yml` | OIDC Core：`oidcc-config`（discovery 元数据校验）、`3rdparty-init-login`、`basic`、`implicit`、`hybrid`、`formpost-basic`、`dynamic`，每个计划区分 `dynamic_client` / `static_client` 变体 |
| `oidc_logout` | `testcase/oidc_logout.yml` | 登出：`oidcc-backchannel-rp-initiated-logout`（使用 `BCL Client 1/2`）、`oidcc-rp-initiated-logout` |
| `fapi2_security_private_key_jwt` | `testcase/fapi2_security_private_key_jwt.yml` | FAPI2 Security Profile，`private_key_jwt` 客户端认证，覆盖 `sender_constrain`（dpop/mtls）、`openid`（openid_connect/plain_oauth）、client_credentials 等组合 |
| `fapi2_security_mtls` | `testcase/fapi2_security_mtls.yml` | FAPI2 Security Profile，`mtls`（tls_client_auth）客户端认证的各种 `sender_constrain` / `fapi_profile` 组合 |
| `fapi2_message_signing` | `testcase/fapi2_message_signing.yml` | FAPI2 Message Signing：强制使用签名 request object（`fapi_request_method: signed_non_repudiation`），私钥 JWT 与 mTLS 客户端认证各自的变体 |
| `fapi2_ciba` | `testcase/fapi2_ciba.yml` | FAPI-CIBA：`private_key_jwt` / `mtls` 认证 × `poll` / `ping` 模式 |

写法要点：

- `planName` 是套件里的测试计划 ID（如 `oidcc-basic-certification-test-plan`）。
- 每个 `testcase` 下是一个命名变体，`variant` 里的字段直接传给套件。
- `client` / `client_secret_post` / `client2` 可在此处覆盖 `plan_config` 中的客户端配置。
- 以 `_range` / `-range` 结尾的字段会被 [test.py](../test.py) 自动展开为多次运行，
  例如 `sender_constrain_range: [dpop, mtls]` 会分别跑 `dpop` 和 `mtls` 两个变体。
- 不写 `testcase` 的计划（如 `oidcc-config-certification-test-plan`）只跑一次基础变体。
- `skip_modules` 中的模块名（见 [config.yml](../config.yml)）会在运行时跳过，
  `oidcc-server-rotate-keys` 则通过 `rotate_key_endpoint` 钩子自动调用 OP 的
  `/admin/rotate-keys`。

## 已知问题

套件自身行为导致的失败与变通方案记录在 [../docs/issues.md](../docs/issues.md)。
