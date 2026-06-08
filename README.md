# KexCore OpenID Connect SDK (client and server) for Go

[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
[![Release](https://github.com/roidmc/kexcore-oidc/workflows/Release/badge.svg)](https://github.com/roidmc/kexcore-oidc/actions)
[![Go Reference](https://pkg.go.dev/badge/github.com/roidmc/kexcore-oidc.svg)](https://pkg.go.dev/github.com/roidmc/kexcore-oidc)
[![license](https://badgen.net/github/license/roidmc/kexcore-oidc/)](https://github.com/roidmc/kexcore-oidc/blob/master/LICENSE)
[![release](https://badgen.net/github/release/roidmc/kexcore-oidc/stable)](https://github.com/roidmc/kexcore-oidc/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/roidmc/kexcore-oidc)](https://goreportcard.com/report/github.com/roidmc/kexcore-oidc)
[![codecov](https://codecov.io/gh/roidmc/kexcore-oidc/branch/main/graph/badge.svg)](https://codecov.io/gh/roidmc/kexcore-oidc)

[![openid_certified](https://cloud.githubusercontent.com/assets/1454075/7611268/4d19de32-f97b-11e4-895b-31b2455a7ca6.png)](https://openid.net/certification/)

## What Is It

A full-stack OAuth 2.1 / OpenID Connect Core 1.0 SDK for Go — **OP + RP** — with a plugin-based
server engine ([StormEngine]) and **Chinese Commercial Cryptography** (SM2/SM3/SM4/SM9).

Based on [zitadel/oidc] (RP client), with self-developed components:

- **StormEngine** (`/pkg/storm`) — plugin-based OP, each RFC endpoint is an independent plugin
- **GM/T national cryptography** (`/pkg/crypto`) — SM2/SM3/SM4/SM9 full suite, HSM/KMS support
- **Shared protocol layer** (`/pkg/protocol`) — zero dependency, single source of truth

The RP is certified for the [oidf-basic] and [oidf-config] profile.
The OP is certified for the [oidf-backchannel] profile.

[zitadel/oidc]: https://github.com/zitadel/oidc
[StormEngine]: /pkg/storm

## Basic Overview

The most important packages of the library:

<pre>
/pkg
    /protocol          OAuth 2.1 / OIDC types, errors, verifiers (zero dependency)
    /storm             Plugin-based OIDC server engine
        /plugins       Individual RFC endpoint plugins
    /client            RP client (based on zitadel/oidc)
        /rp            OIDC Relying Party
        /rs            OAuth Resource Server
    /crypto            SM2/SM3/SM4/SM9 + HSM/KMS provider registry

/example
    /storm-server      StormEngine-based OP
    /client/app        RP web app (authorization code flow)
    /client/api        Resource server with token introspection
</pre>

### Semver

This package uses [semver](https://semver.org/) for [releases](https://github.com/roidmc/kexcore-oidc/releases). Major releases ship breaking changes. Starting with the `v2` to `v3` increment we provide an [upgrade guide](UPGRADING.md) to ease migration to a newer version.

## How To Use It

Check the `/example` folder where example code for different scenarios is located.

```bash
# start oidc op server
# oidc discovery http://localhost:9998/.well-known/openid-configuration
go run github.com/roidmc/kexcore-oidc/example/server
# start oidc web client (in a new terminal)
CLIENT_ID=web CLIENT_SECRET=secret ISSUER=http://localhost:9998/ SCOPES="openid profile" PORT=9999 go run github.com/roidmc/kexcore-oidc/example/client/app
```

- open http://localhost:9999/login in your browser
- you will be redirected to op server and the login UI
- login with user `test-user@localhost` and password `verysecure`
- the OP will redirect you to the client app, which displays the user info

for the dynamic issuer, just start it with:

```bash
go run github.com/roidmc/kexcore-oidc/example/server/dynamic
```

the oidc web client above will still work, but if you add `oidc.local` (pointing to 127.0.0.1) in your hosts file you can also start it with:

```bash
CLIENT_ID=web CLIENT_SECRET=secret ISSUER=http://oidc.local:9998/ SCOPES="openid profile" PORT=9999 go run github.com/roidmc/kexcore-oidc/example/client/app
```

> Note: Usernames are suffixed with the hostname (`test-user@localhost` or `test-user@oidc.local`)


### Build Tags

The library uses build tags to enable or disable features. The following build tags are available:

| Build Tag | Description                                                                                                                                                              |
|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `no_otel`  | Disables the OTel instrumentation, which is enabled by default. This is useful if you do not want to use OTel or if you want to use a different instrumentation library. |

### Server configuration

Example server allows extra configuration using environment variables and could be used for end-to-end testing of your services.

| Name               | Format                           | Description                                                      |
| ------------------ | -------------------------------- | ---------------------------------------------------------------- |
| PORT               | Number between 1 and 65535       | OIDC listen port                                                 |
| REDIRECT_URI       | Comma-separated URIs             | List of allowed redirect URIs                                    |
| USERS_FILE         | Path to json in local filesystem | Users with their data and credentials                            |
| ISSUER             | URL                              | Issuer identifier (e.g. `https://your-domain.com/`)              |
| SIGNING_ALGORITHMS | Comma-separated algorithms       | Enabled JWS algorithms (default: `RS256,RS384,RS512,EdDSA,SGD_SM3_SM2,SGD_SM3_SM9`) |

Here is json equivalent for one of the default users

```json
{
  "id2": {
    "ID": "id2",
    "Username": "test-user2",
    "Password": "verysecure",
    "FirstName": "Test",
    "LastName": "User2",
    "Email": "test-user2@zitadel.ch",
    "EmailVerified": true,
    "Phone": "",
    "PhoneVerified": false,
    "PreferredLanguage": "DE",
    "IsAdmin": false
  }
}
```

## Features

### OpenID Provider (`/pkg/storm`) — StormEngine

Plugin-based OIDC server framework.

| Feature | Plugin | RFC / Spec | Status |
|---|---|---|---|
| Authorization Code Grant | `authorization` | OpenID Connect Core 1.0, [Section 3.1][1] | ✅ |
| Refresh Token + Rotation | `token` | OpenID Connect Core 1.0, [Section 12][5] + OAuth 2.1 §6.1 | ✅ |
| Client Credentials | `token` | OpenID Connect Core 1.0, [Section 9][4] | ✅ |
| JWT Bearer Grant | `token` | [RFC 7523][7] | ✅ |
| PKCE (S256) | `token` | [RFC 7636][8] | ✅ |
| Token Introspection | `introspection` | [RFC 7662][16] | ✅ |
| Token Revocation | `revocation` | [RFC 7009][17] | ✅ |
| UserInfo Endpoint | `userinfo` | OpenID Connect Core 1.0, [Section 5.6][18] | ✅ |
| Discovery Document | `discovery` | OpenID Connect [Discovery][6] 1.0 | ✅ |
| JWKS Endpoint | `keys` | OpenID Connect Core 1.0, [Section 7.3][19] | ✅ |
| Dynamic Client Registration | `dcr` | [RFC 7591][20] | ✅ |
| End Session | `endsession` | OpenID Connect Session [Section 5][21] | ✅ |
| Device Authorization | `device` | [RFC 8628][10] | ✅ |
| Token Exchange | `token` | [RFC 8693][9] | ✅ |
| PAR (Pushed Auth Request) | `par` | [RFC 9126][15] | ✅ |
| mTLS Client Auth + Cert-Bound | `mtls` | [RFC 8705][11] | ✅ |
| DPoP Proof Validation | `dpop` | [RFC 9449][14] | ✅ |
| Private Key JWT Auth | `token` | [RFC 7523][7] §2.2, OIDC Core §9 | ✅ |
| Request Object (JWT) | `authorization` | OpenID Connect Core 1.0, [Section 6.1][22] | ✅ |
| id_token_hint Validation | `authorization` | OpenID Connect Core 1.0, [Section 3.1.2.2][23] | ✅ |
| Implicit Flow (可选) | `authorization` | OpenID Connect Core 1.0, [Section 3.2][2] | ✅ 默认关闭 |
| Back-Channel Logout | `backchannel` | OpenID Connect [Back-Channel Logout][12] 1.0 | ✅ |
| Resource Indicators | `token` | [RFC 8707][24] | ✅ |
| HTTPS redirect_uri 强制 | `authorization` | OpenID Connect Core 1.0, [Section 15.6.3][25] | ✅ (localhost 豁免) |
| Pairwise Subject | `pairwise` | OpenID Connect Core 1.0, [Section 8.1][26] | ✅ |
| ID Token 签名 (RSA/ECDSA/EdDSA) | `token` | [RFC 7515][27] | ✅ |
| ID Token 签名 (SM2/SM9 国密) | `token` | [GM/T 0125][GM/T 0125.3-2022] | ✅ |
| JWE ID Token Encryption | `token` | [JWE (RFC 7516)][13] + [GM/T 0125.3-2022] | ✅ |
| OAuth 2.1 合规 Discovery | `discovery` | OAuth 2.1 | ✅ |
| Front-Channel Logout | — | OIDC Front-Channel | ❌ 不实现（纯后端 API 不需要） |
| Session Management (iframe) | — | OIDC Session Management §3 | ❌ 不实现（纯后端 API 不需要） |
| Hybrid Flow | — | OpenID Connect Core 1.0, [Section 3.3][3] | ❌ 不实现（OAuth 2.1 已移除） |

### Relying Party (`/pkg/client`)

| Feature | Specification |
|---|---|
| Code Flow | OpenID Connect Core 1.0, [Section 3.1][1] |
| Client Credentials | OpenID Connect Core 1.0, [Section 9][4] |
| Refresh Token | OpenID Connect Core 1.0, [Section 12][5] |
| Discovery | OpenID Connect [Discovery][6] 1.0 |
| JWT Profile | [RFC 7523][7] |
| PKCE | [RFC 7636][8] |
| Token Exchange | [RFC 8693][9] |
| Device Authorization | [RFC 8628][10] |
| JWE ID Token Encryption | [JWE (RFC 7516)][13] + [GM/T 0125.3-2022] (dir mode) |
| Back-Channel Logout | OpenID Connect [Back-Channel Logout][12] 1.0 |

> **Note on Chinese Commercial Cryptography (国密):** This library supports SM2, SM3, SM4, and SM9 algorithms via the `SGD_SM3_SM2`, `SGD_SM3_SM9`, and `SM4` identifiers. These are **not defined in RFC 7518** and therefore are **not recognized by the OpenID Foundation (OIDF) Conformance Test Suite**. When running OIDF certification tests, disable national-crypto algorithms by setting the environment variable `SIGNING_ALGORITHMS=RS256,RS384,RS512,EdDSA` so that the JWKS endpoint only returns standard JWKs.

[1]: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth "3.1. Authentication using the Authorization Code Flow"
[2]: https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth "3.2. Authentication using the Implicit Flow"
[3]: https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth "3.3. Authentication using the Hybrid Flow"
[4]: https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication "9. Client Authentication"
[5]: https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens "12. Using Refresh Tokens"
[6]: https://openid.net/specs/openid-connect-discovery-1_0.html "OpenID Connect Discovery 1.0 incorporating errata set 1"
[7]: https://www.rfc-editor.org/rfc/rfc7523.html "JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants"
[8]: https://www.rfc-editor.org/rfc/rfc7636.html "Proof Key for Code Exchange by OAuth Public Clients"
[9]: https://www.rfc-editor.org/rfc/rfc8693.html "OAuth 2.0 Token Exchange"
[10]: https://www.rfc-editor.org/rfc/rfc8628.html "OAuth 2.0 Device Authorization Grant"
[11]: https://www.rfc-editor.org/rfc/rfc8705.html "OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens"
[12]: https://openid.net/specs/openid-connect-backchannel-1_0.html "OpenID Connect Back-Channel Logout 1.0 incorporating errata set 1"
[13]: https://www.rfc-editor.org/rfc/rfc7516.html "JSON Web Encryption (JWE)"
[14]: https://www.rfc-editor.org/rfc/rfc9449.html "OAuth 2.0 Demonstrating Proof of Possession (DPoP)"
[15]: https://www.rfc-editor.org/rfc/rfc9126.html "OAuth 2.0 Pushed Authorization Requests (PAR)"
[GM/T 0125.3-2022]: http://www.gmbz.org.cn/file/2023-06-21/a34ff879-563b-4e91-96ea-57e4c15c944a.pdf "GM/T 0125.3-2022 JWE"
[16]: https://www.rfc-editor.org/rfc/rfc7662.html "OAuth 2.0 Token Introspection"
[17]: https://www.rfc-editor.org/rfc/rfc7009.html "OAuth 2.0 Token Revocation"
[18]: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo "5.3. UserInfo Endpoint"
[19]: https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys "10.2.1. Rotation of Asymmetric Signing Keys"
[20]: https://www.rfc-editor.org/rfc/rfc7591.html "OAuth 2.0 Dynamic Client Registration"
[21]: https://openid.net/specs/openid-connect-session-1_0.html#RPLogout "5. RP-Initiated Logout"
[22]: https://openid.net/specs/openid-connect-core-1_0.html#RequestsUseRefs "6.1. Passing a Request Object by Reference"
[23]: https://openid.net/specs/openid-connect-core-1_0.html#ImplicitValidation "3.1.2.2. ID Token Validation"
[24]: https://www.rfc-editor.org/rfc/rfc8707.html "Resource Indicators for OAuth 2.0"
[25]: https://openid.net/specs/openid-connect-core-1_0.html#HTTPSRequirements "15.6.3. TLS Requirements"
[26]: https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes "8.1. Pairwise Identifier Algorithm"
[27]: https://www.rfc-editor.org/rfc/rfc7515.html "JSON Web Signature (JWS)"

## Contributors

<a href="https://github.com/roidmc/kexcore-oidc/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=roidmc/kexcore-oidc" alt="Screen with contributors' avatars from contrib.rocks" />
</a>

Made with [contrib.rocks](https://contrib.rocks).

### Resources

For your convenience you can find the relevant guides linked below.

- [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html)
- [OIDC/OAuth Flow in Zitadel (using this library)](https://zitadel.com/docs/guides/integrate/login-users)

## Supported Go Versions

For security reasons, we only support and recommend the use of one of the latest two Go versions (:white_check_mark:).
Versions that also build are marked with :warning:.

| Version | Supported          |
| ------- | ------------------ |
| <1.26.3    | :x: |
| 1.26.3    | :white_check_mark: |

## Why another library

RP client based on [zitadel/oidc]. OP entirely self-developed with StormEngine plugin architecture.

### Goals

- [Certify this library as OP](https://openid.net/certification/#OPs)

### Other Go OpenID Connect libraries

| Library | OP | RP | Plugin-based | GM/T |
|---|---|---|---|---|
| [coreos/go-oidc](https://github.com/coreos/go-oidc) | ❌ | ✅ | ❌ | ❌ |
| [ory/fosite](https://github.com/ory/fosite) | ✅ | ❌ | ❌ | ❌ |
| [ory/hydra](https://github.com/ory/hydra) | ✅ | ❌ | ❌ | ❌ |
| [zitadel/oidc](https://github.com/zitadel/oidc) | ✅ | ✅ | ❌ | ❌ |
| **kexcore-oidc** | **✅** | **✅** | **✅** | **✅** |

## License

The full functionality of this library is and stays open source and free to use for everyone. Visit
our [website](https://www.roidmc.com) and get in touch.

See the exact licensing terms [here](LICENSE)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "
AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.

<!--zitadel/oidc issue reference-->
[^1]: https://github.com/zitadel/oidc/issues/135#issuecomment-950563892

[oidf-basic]: https://www.certification.openid.net/log-detail.html?log=SpSbfydiglCBorB&public=true
[oidf-config]: https://www.certification.openid.net/log-detail.html?log=ONiasADvOhTyslW&public=true
[oidf-backchannel]: https://www.certification.openid.net/plan-detail.html?plan=eD4txBOvstik4&public=true
[oidf-backchannel-dynamic]: https://www.certification.openid.net/log-detail.html?log=kXMjAHzAHyqaItK&public=true