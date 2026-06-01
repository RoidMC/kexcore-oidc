# KexCore OIDC — AI Context Document

## Project Overview

KexCore OIDC is a full-stack OIDC SDK (OP + RP) for Go, supporting OAuth 2.1,
OpenID Connect Core 1.0, and Chinese Commercial Cryptography (SM2/SM3/SM4/SM9).

The project contains **two OP (OpenID Provider) implementations**:

1. **Legacy Provider** (`/pkg/op`) — Based on zitadel/oidc, monolithic interface pattern
2. **StormEngine Provider** (`/pkg/storm`) — Plugin-based architecture, inspired by Caddy v2

### Independence from Upstream

The `protocol/` package is the **single source of truth** for OAuth 2.1 / OIDC protocol
primitives. The legacy `oidc/` package (Zitadel fork) has been **fully removed** — no files
remain in `pkg/oidc/`. All types, errors, verifiers, and tests now live in `protocol/`.

| Layer | Source | Status |
|---|---|---|
| `protocol/` | Self-developed (RoidMC) | **Active** — all protocol primitives |
| `storm/` | Self-developed (RoidMC) | New OP engine |
| `op/` | Zitadel fork | Legacy, to be replaced by StormEngine |
| `client/` | Zitadel fork | RP client, uses `protocol/` types |
| `oidc/` | Zitadel fork | **Removed** — fully migrated to `protocol/` |

The `protocol/` package has **zero dependency on Zitadel** — no imports, no type aliases
from `zitadel/oidc`, independent copyright (RoidMC Studios). It implements the same RFC
standards as Zitadel but with original code, original API design, and its own test suite.

`github.com/zitadel/schema` has been fully replaced by `protocol.Encoder` and `protocol.Decoder`
(self-developed, RoidMC copyright). The dependency is removed from `go.mod`.
`pkg/util/codec` has been removed — all StormEngine plugins now use `protocol.Decoder` directly.

`protocol/` defines:
- `AuthMethod` constants (`AuthMethodBasic`, `AuthMethodPost`, `AuthMethodNone`, `AuthMethodPrivateKeyJWT`)
- `DiscoveryEndpoint` constant (`"/.well-known/openid-configuration"`)
- Error types (23 error codes + 24 sentinel errors) with RoidMC copyright
- Discovery configuration with precise types (`string`/`[]string` instead of `any`)
- Authorization types (`AuthRequest`, `PushedAuthRequest/Response`, `RequestObject`)
- Session types (`EndSessionRequest`)
- Token types (`TokenClaims`, `AccessTokenClaims`, `IDTokenClaims`, `AccessTokenResponse`, `Tokens[C]`)
- JWT Profile types (`JWTProfileAssertionClaims`, `LogoutTokenClaims`, `ActorClaims`)
- Wire format types (`ResponseType`, `ResponseMode`, `Display`, `SpaceDelimitedArray`, `Locales`)
- OIDC constants (scopes, response types, response modes, prompts)
- Token verification (verifier interfaces, JWT parsing, signature checking, expiry, audience, etc.)
- Encryption (JWE encrypt/decrypt via `protocol.EncryptTokenJWE` / `DecryptTokenJWE`,
  dispatches to `crypto.DefaultRegistry` for GM/T algorithms; supports AES-GCM, SM4-GCM, SM2, SM9)
- Encoder (struct → url.Values using `schema` struct tags)
- Decoder (url.Values → struct using `schema` struct tags; replaces `zitadel/schema`)
- Introspection types (`IntrospectionResponse`, `IntrospectionRequest`)

## Package: protocol/ — OAuth 2.1 / OIDC Protocol Primitives

### Design

The `protocol/` package is the single source of truth for OAuth 2.1 / OIDC protocol-level
types, errors, and shared utilities. It is used by both StormEngine (OP) and the RP client.

```
/pkg/protocol/
    authorization.go — AuthRequest, PushedAuthRequest/Response, RequestObject, scope/prompt/response constants
    claims.go       — JWT claims interfaces (Claims, ClaimsSignature, IDClaims)
    device.go       — DeviceAuthorizationRequest/Response, DeviceAccessTokenRequest (RFC 8628)
    discovery.go    — DiscoveryConfiguration (OIDC Discovery 1.0 + OAuth 2.1 metadata)
    error.go        — Error types (RFC 6749 §5.2, OIDC Core §3.1.2.6, RFC 8628)
    jwe.go          — JWE interfaces (JWEService, SM9EncryptKey), EncryptTokenJWE/DecryptTokenJWE dispatch
    jws.go          — JWS interfaces (JWSSigner, JWSVerifier, JWSService), VerifySignatureWithRegistry dispatch
    keyset.go       — JWK KeySet abstraction
    pkce.go         — CodeChallengeMethod
    registry.go     — SignatureRegistry (user extension point, delegates to crypto.DefaultRegistry)
    session.go      — EndSessionRequest (OIDC RP-Initiated Logout 1.0)
    token.go        — TokenClaims, AccessTokenClaims, IDTokenClaims, Tokens[C], ActorClaims,
                      LogoutTokenClaims, JWTProfileAssertionClaims, AccessTokenResponse,
                      TokenExchangeResponse, JWT Profile helpers, ClaimHash, BearerToken consts
    token_request.go — Token request types (AccessTokenRequest, RefreshTokenRequest, JWTTokenRequest, etc.)
    introspection.go — IntrospectionResponse, IntrospectionRequest, ClientAssertionParams
    types.go        — Core types (AuthMethod, GrantType, Display, Locales, SpaceDelimitedArray,
                      Gender, Locale, Bool, Time, Audience, AMR, MaxAge, etc.)
    userinfo.go     — UserInfo, UserInfoProfile, UserInfoEmail, UserInfoPhone, UserInfoAddress
    util.go         — Internal utilities (mergeAndMarshalClaims, unmarshalJSONMulti, Encoder)
    verifier.go     — Token verification (Verifier interface, ACR/AZP verifiers, JWT parsing,
                      signature checking, expiry/issuer/audience/nonce/auth_time checks,
                      JWE constants (JWEAlg*, JWEEnc*), Encrypt/DecryptToken convenience funcs,
                      VerifyAccessToken, VerifyIDTokenHint, VerifyJWTAssertion,
                      VerifyAccessTokenGeneric[C], VerifyIDTokenHintGeneric[C],
                      AccessTokenVerifier, IDTokenHintVerifier, IDTokenHintExpiredError)
```

### Key Design Decisions

1. **Precise types, not `any`**: DiscoveryConfiguration fields use `string` / `[]string`
   instead of `any`, eliminating type-assertion boilerplate at call sites.

2. **`Extra map[string]any` for extensibility**: Standard fields have typed access; plugins
   contribute non-standard metadata via `Extra`. `MarshalJSON` merges both with defensive
   checks. `UnmarshalJSON` separates known fields from extras.

3. **Complete OIDC Discovery 1.0 compliance**: Fields ordered per spec (issuer first),
   `,omitempty` on optional fields. RFC 8705 mTLS fields (`mtls_endpoint_aliases`,
   `tls_client_certificate_bound_access_tokens`) included.

4. **Independent error type system**: 23 error codes with RFC annotations, 24 sentinel
   errors for internal validation failures, complete `DefaultToServerError` mapping.
   Copyright: RoidMC Studios (no Apache 2.0 contamination).

5. **Zero dependency on legacy `oidc/`**: All types, functions, errors, verifiers, and tests
   are self-contained in `protocol/`. No sentinel error mapping needed.

6. **Zero dependency on `gmsm` in `protocol/`**: The `protocol/` package has no import of
   `github.com/emmansun/gmsm`. All GM/T cryptographic operations (SM2/SM9 JWS verification,
   SM2/SM9 JWE encryption/decryption) are dispatched to `crypto.DefaultRegistry` via
   `VerifySignatureWithRegistry` (jws.go) and `EncryptTokenJWE` / `DecryptTokenJWE` (jwe.go).
   SM9 keys are abstracted behind `protocol.SM9EncryptKey` interface. This enables HSM/KMS
   vendors to provide custom implementations without touching the protocol layer.

### Test Coverage

- `protocol/util_test.go` — mergeAndMarshalClaims, unmarshalJSONMulti, Encoder
- `protocol/test/authorization_test.go` — LogValue, getters, JSON, constants
- `protocol/test/device_authorization_test.go` — verification_url/uri/uri_complete
- `protocol/test/userinfo_test.go` — AppendClaims, GetAddress, Marshal round-trip, Bool
- `protocol/test/keyset_test.go` — FindMatchingKey (18 sub-tests)
- `protocol/test/token_test.go` — TokenClaims, AccessTokenClaims, IDTokenClaims, LogoutTokenClaims, Tokens[C]
- `protocol/test/types_test.go` — Audience, AMR, Display, Locale, Locales, Scopes, Time
- `protocol/test/introspection_test.go` — SetUserInfo, GetAddress, MarshalJSON/UnmarshalJSON
- `protocol/test/verifier_test.go` — DecryptToken, ParseToken, CheckSubject/Issuer/Audience/AZP/Signature/Expiration/IssuedAt/Nonce/ACR/AuthTime, NewAccessTokenVerifier, VerifyAccessTokenGeneric, NewIDTokenHintVerifier, VerifyIDTokenHintGeneric, IDTokenHintExpiredError, ExampleVerifyAccessTokenGeneric_customClaims
- `protocol/test/discovery_test.go` — DiscoveryConfiguration round-trip
- `protocol/test/regression/` — Regression tests

## Architecture: StormEngine

### Design Philosophy

StormEngine is the **OIDC OP version of Caddy** — a plugin-based, embeddable OIDC server SDK.

Core principles:
- **Plugin = RFC Endpoint**: Each plugin maps to one RFC/OIDC Core section
- **Interface Isolation (ISP)**: Each plugin declares only the storage interfaces it needs
- **Capability Discovery**: Engine discovers storage capabilities via Go type assertions
- **Zero Breaking Changes**: New features = new plugin + new interface, never modify existing interfaces

### Why This Architecture

Go's implicit interface satisfaction naturally leads to "small interfaces + type assertion discovery".
This is the same pattern Caddy v2 uses, and is fundamentally different from Zitadel/oidc's approach
of growing monolithic interfaces (Caddy v1 pattern).

| Aspect | StormEngine (Caddy v2) | Zitadel/oidc (Caddy v1) |
|---|---|---|
| Adding features | New plugin + new interface | Modify existing interface |
| Storage requirement | Only what plugin uses | Everything at once |
| Type safety | Interface satisfaction checked at startup | Runtime type assertions in handler |
| Breaking changes | Impossible (new code only) | Common (interface changes) |

### Plugin System

Each plugin follows this pattern:

```go
type Plugin struct {
    config Config
}

type Config struct {
    // plugin-specific configuration
}

func New(config Config) *Plugin { return &Plugin{config: config} }
func (p *Plugin) Name() string { return "plugin-name" }
func (p *Plugin) Contribute(engine *Engine) error {
    // register endpoints, middleware, etc.
}
```

### Implemented Plugins

| Plugin | File | RFC/OIDC Section |
|---|---|---|
| Discovery | discovery | OIDC Discovery 1.0 |
| Authorization | authorization | OIDC Core §3 |
| Token | token | RFC 6749 §4 |
| UserInfo | userinfo | OIDC Core §5.3 |
| JWKS | keys | OIDC Core §7.3 |
| DCR | dcr | RFC 7591 |
| End Session | endsession | OIDC Session §5 |
| Device Authorization | device | RFC 8628 |
| Token Exchange | token | RFC 8693 |
| PAR | par | RFC 9101 |
| mTLS | mtls | RFC 8705 |
| DPoP | dpop | RFC 9449 |
| Private Key JWT | token | RFC 7523 §2.2 |
| Request Object | authorization | OIDC Core §6.1 |
| id_token_hint | authorization | OIDC Core §3.1.2.2 |
| Implicit Flow (disabled) | authorization | OIDC Core §3.2 |
| Back-Channel Logout | backchannel | OIDC Back-Channel §2.5 |
| Resource Indicators | token | RFC 8707 |
| HTTPS redirect_uri | authorization | OIDC Core §15.6.3 |
| Pairwise Subject | pairwise | OIDC Core §8.1 |
| ID Token signing (RSA/ECDSA/EdDSA) | token | RFC 7515 |
| ID Token signing (SM2/SM9) | token | GM/T 0125 |
| OAuth 2.1 Discovery | discovery | OAuth 2.1 |

### Not Implemented (by design)

| Feature | Reason |
|---|---|
| Front-Channel Logout | Pure backend API SDK, no browser iframes |
| Session Management (iframe) | Pure backend API SDK, no browser iframes |
| Hybrid Flow | Removed in OAuth 2.1 |

### Gaps for OIDF Basic Certification

| Gap | Location | What's Missing |
|---|---|---|
| `c_hash` claim | token.go `createIDToken` | Code hash, OIDC Core §3.3.2.11 |
| `auth_time` claim | token.go `createIDToken` | User authentication time |
| `acr` claim | token.go `createIDToken` | Authentication Context Class Reference |
| `amr` claim | token.go `createIDToken` | Authentication Methods References |
| `azp` claim | token.go `createIDToken` | Authorized Party |
| UserInfo scope filtering | userinfo.go | Return claims based on requested scopes |
| JWE ID Token encryption | `protocol.EncryptTokenJWE` | Implemented for dir/SM2/SM9 modes via crypto ProviderRegistry |
| CORS middleware | engine.go | Cross-Origin Resource Sharing headers |
| Tests | (all plugins) | Zero test files in storm package |

### Known Issues

- `UserinfoStore.SetUserinfoFromToken` lacks `scopes []string` parameter
- `TokenRequest` interface missing `GetAuthTime()`, `GetNonce()`, `GetACR()`, `GetAMR()`
- `Storage` interface defined but not enforced by `WithStorage(storage any)`
- `Client` interface too small, plugins define ad-hoc `xxxProvider` interfaces via type assertion
- `SigningService` partially extracted — JWS verification and JWE encrypt/decrypt now dispatch
  through `crypto.DefaultRegistry`; signing still done directly in plugins via `crypto.NewSigner`

## Package: crypto/ — Encryption Utilities

### Design

`pkg/crypto/` provides symmetric encryption (AES-GCM, SM4-GCM/CCM/CBC/ECB), asymmetric
encryption (SM2), signing (SM2, SM9), hashing (SM3), and key exchange (SM2/SM9).

It also contains `registry.go` — the **ProviderRegistry** that serves as the algorithm
implementation layer in the JCA-like architecture. HSM/KMS vendors register custom
providers here; the protocol layer dispatches through `DefaultRegistry`.

All encryption modes use **authenticated encryption** (GCM or CCM). The former AES-CTR
implementation (from Zitadel, no authentication tag) was replaced with AES-GCM to unify
with SM4-GCM and improve security. Copyright: RoidMC Studios.

### Key Functions

| Function | Mode | Notes |
|---|---|---|
| `EncryptAES` / `DecryptAES` | AES-256-GCM | String I/O, base64url encoded |
| `EncryptBytesAES` / `DecryptBytesAES` | AES-256-GCM | []byte I/O, raw binary |
| `EncryptSM4` / `DecryptSM4` | SM4-GCM | String I/O, base64url encoded |
| `SM4EncryptGCM` / `SM4DecryptGCM` | SM4-GCM | []byte I/O, nonce explicit |
| `SM4EncryptCBC` / `SM4DecryptCBC` | SM4-CBC | PKCS#7 padding |
| `SM4EncryptECB` / `SM4DecryptECB` | SM4-ECB | PKCS#7 padding |

### Wire Format (AES-GCM / SM4-GCM)

```
[nonce (12 bytes)] [ciphertext + GCM tag (16 bytes)]
```

Base64url encoded for string API. `ErrCipherTextTooShort` if input < 12 bytes.

## Crypto Architecture: JCA-like Provider Pattern

The project uses a **Java JCA-inspired** layered architecture for cryptographic operations.
`protocol/` acts as the unified interface layer (like `javax.crypto`), while `crypto/` provides
pluggable algorithm implementations (like JCA Providers).

### Layer Diagram

```
┌──────────────────────────────────────────────────────────────┐
│  Upper layers (op/, storm/, client/)                          │
│  Call protocol.EncryptTokenJWE / protocol.VerifySignature    │
└────────────────────────┬─────────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────────┐
│  protocol/ — JCA Interface Layer                              │
│                                                              │
│  jws.go: JWSSigner / JWSVerifier / JWSService interfaces     │
│  jwe.go: JWEService / SM9EncryptKey interfaces               │
│  registry.go: SignatureRegistry (user extension point)       │
│  verifier.go: EncryptToken/DecryptToken convenience funcs    │
│                                                              │
│  Dispatches to crypto.DefaultRegistry for GM/T algorithms    │
│  Falls back to jwx for standard algorithms (RSA, EC, EdDSA) │
│  **Zero dependency on gmsm**                                 │
└────────────────────────┬─────────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────────┐
│  crypto/ — Provider Implementation Layer                      │
│                                                              │
│  registry.go: ProviderRegistry + DefaultRegistry             │
│  Provider interfaces: SignProvider / VerifyProvider           │
│    JWEEncryptProvider / JWEDecryptProvider                    │
│                                                              │
│  Default: gmsm implementations (SM2/SM9/SM4)                 │
│  Extensible: HSM / KMS / any external crypto service         │
└──────────────────────────────────────────────────────────────┘
```

### Key Files

| File | Role |
|---|---|
| `protocol/jws.go` | JWS interfaces + `VerifySignatureWithRegistry` (central JWS dispatch) |
| `protocol/jwe.go` | JWE interfaces + `EncryptTokenJWE` / `DecryptTokenJWE` (central JWE dispatch) |
| `protocol/registry.go` | `SignatureRegistry` — user extension point for custom JWS verifiers |
| `protocol/verifier.go` | All verifier implementations: `AccessTokenVerifier`, `IDTokenHintVerifier`, `VerifyAccessTokenGeneric[C]`, `VerifyIDTokenHintGeneric[C]`, `VerifyJWTAssertion`, `IDTokenHintExpiredError` (soft error); JWE constants + `EncryptToken*`/`DecryptToken*` |
| `crypto/registry.go` | `ProviderRegistry` — algorithm provider registration + gmsm defaults |
| `crypto/sign.go` | SM2/SM9 signing implementations |
| `crypto/jwe.go` | SM2/SM9 JWE encrypt/decrypt implementations |

### Provider Interfaces (crypto/registry.go)

| Interface | Method | Purpose |
|---|---|---|
| `SignProvider` | `Sign(ctx, keyID, payload) → JWS` | External JWS signing (HSM, KMS) |
| `VerifyProvider` | `Verify(ctx, signingInput, signature, key) → error` | External JWS verification |
| `JWEEncryptProvider` | `Encrypt(ctx, plaintext, key) → JWE` | External JWE encryption |
| `JWEDecryptProvider` | `Decrypt(ctx, compact, key) → plaintext` | External JWE decryption |

### SM9 Key Abstraction

`protocol.SM9EncryptKey` (protocol layer) and `crypto.SM9EncryptKey` (crypto layer) hide
`*sm9.EncryptMasterPublicKey` from upper layers. The canonical implementation is
`crypto.SM9MasterPublicKey`, which implements both interfaces. HSM/KMS vendors implement
`protocol.SM9EncryptKey` to provide their own SM9 key material without importing gmsm.

| Interface | Layer | Methods | Purpose |
|---|---|---|---|
| `protocol.SM9EncryptKey` | protocol | `MarshalBinary()`, `GetUID()` | gmsm-free abstraction for OP/RP |
| `crypto.SM9EncryptKey` | crypto | `Resolve() → (*sm9.EncryptMasterPublicKey, []byte, error)` | gmsm-aware for Provider dispatch |
| `crypto.SM9MasterPublicKey` | crypto | implements both | Concrete wrapper |

### Registered Providers (init())

| Algorithm | Sign | Verify | JWE Encrypt | JWE Decrypt |
|---|---|---|---|---|
| `SGD_SM3_SM2` | `sm2SignProvider` (stub) | `sm2VerifyProvider` ✅ | — | — |
| `SGD_SM3_SM9` | `sm9SignProvider` (stub) | `sm9VerifyProvider` (stub) | — | — |
| `SGD_SM2_3` | — | — | `sm2JWEProvider` ✅ | `sm2JWEProvider` ✅ |
| `SGD_SM9_3` | — | — | `sm9JWEProvider` ✅ | `sm9JWEProvider` ✅ |

Standard algorithms (RSA, ECDSA, EdDSA, AES-GCM, A256GCMKW) are handled by jwx directly,
not through the Provider registry.

### JWE Algorithm Constants (protocol/verifier.go)

| Constant | Value | Key Wrapping | Content Encryption | Status |
|---|---|---|---|---|
| `JWEAlgDir` | `"dir"` | Direct symmetric | SM4-GCM / AES-GCM | ✅ |
| `JWEAlgA256GCMKW` | `"A256GCMKW"` | AES-256-GCM | AES-256-GCM | ✅ |
| `JWEAlgSM23` | `"SGD_SM2_3"` | SM2 | SM4-GCM | ✅ |
| `JWEAlgSM93` | `"SGD_SM9_3"` | SM9 | SM4-GCM | ✅ |
| `JWEEncSM4GCM` | `"SGD_SM4_GCM"` | — | SM4-GCM | ✅ |
| `JWEEncA256GCM` | `"A256GCM"` | — | AES-256-GCM | ✅ |
| `JWEEncA128GCM` | `"A128GCM"` | — | AES-128-GCM | ✅ |

### How to Register a Custom Provider

```go
// Example: Register an HSM-based SM2 signer
hsmProvider := myHSMProvider{client: hsmClient}
crypto.DefaultRegistry.RegisterSigner("SGD_SM3_SM2", hsmProvider)

// Example: Register a KMS-based JWE encryptor
kmsProvider := myKMSProvider{client: kmsClient}
crypto.DefaultRegistry.RegisterJWEEncryptor("SGD_SM2_3", kmsProvider)
```

Once registered, all `protocol.EncryptTokenJWE` / `VerifySignatureWithRegistry` calls
for that algorithm will automatically dispatch to the custom provider.

## Key Dependencies

| Package | Version | Purpose |
|---|---|---|
| github.com/lestrrat-go/jwx/v4 | v4 | JWK, JWS, JWA, JWT |
| github.com/go-chi/chi/v5 | v5 | HTTP routing |
| github.com/emmansun/gmsm | latest | SM2/SM3/SM4/SM9 |
| github.com/rs/cors | latest | CORS (used in legacy only) |

## Building and Running

```bash
# Build all
go build ./...

# Run storm-server example
go run ./example/storm-server/

# Discovery
curl http://localhost:9998/.well-known/openid-configuration

# JWKS
curl http://localhost:9998/.well-known/jwks.json
```

## Conventions

- Code comments follow the language of the conversation (Chinese for architecture discussion)
- No comments in code unless asked
- Follow existing code style when editing
- Use `shared.IssuerURL(ctx, "/path")` for endpoint URLs (avoids double slashes)
- Use `shared.IssuerFromContext(ctx)` for issuer string
- All OAuth errors use `protocol.ErrXxx().WithDescription("...").WithParent(err)` pattern
- Plugin structure: `Plugin` struct + `Config` struct + `New(Config)` + `Name()` + `Contribute()`
- `protocol/` is the single source of truth for all OAuth/OIDC type definitions
- `protocol/verifier.go` is the single source of truth for **all verifier implementations** (AccessTokenVerifier, IDTokenHintVerifier, generic + non-generic verify functions)
- `op/` uses `protocol.AccessTokenVerifier` / `protocol.IDTokenHintVerifier` directly (no wrapper); only `op.JWTProfileVerifier` is OP-specific (has SM9 support)
- `op/WithAccessTokenVerifierOpts` / `op/WithIDTokenHintVerifierOpts` accept `protocol.AccessTokenVerifierOpt` / `protocol.IDTokenHintVerifierOpt`
- `storm/shared/verifier.go` re-exports `protocol.VerifyAccessToken` / `protocol.VerifyIDTokenHint` (non-generic) for storm plugins
- Generic functions (`VerifyAccessTokenGeneric[C]`, `VerifyIDTokenHintGeneric[C]`) cannot be assigned to variables in Go — use them directly: `protocol.VerifyAccessTokenGeneric[*MyClaims](ctx, token, v)`
- `protocol/authorization.go` defines `AuthRequest`, `PushedAuthRequest/Response`, `RequestObject`, and all OIDC constants
- `protocol/token.go` defines all token types including `Tokens[C]` (generic OAuth2+OIDC token wrapper)
- `protocol/util.go` defines `Encoder` (struct → url.Values) and `Decoder` (url.Values → struct) via `schema` tags; replaces `zitadel/schema` and `pkg/util/codec`
- `Decoder.RegisterParser` allows StormEngine plugins to register custom type parsers at runtime
- `protocol/session.go` defines `EndSessionRequest` for RP-Initiated Logout

### protocol.Encoder / protocol.Decoder vs zitadel/schema

| Feature | `zitadel/schema` (original) | `protocol.Decoder/Encoder` (replacement) |
|---|---|---|
| Struct tag | `schema` | `schema` (unified) |
| Custom type parsing | Global `Converter` registry | Instance-level `RegisterParser` |
| Ignore unknown keys | `IgnoreUnknownKeys(bool)` | `IgnoreUnknownKeys(bool)` |
| `omitempty` support | Native | Supported |
| `encoding.TextMarshaler` / `TextUnmarshaler` | Native | Supported |
| Pointer auto-init | Native | Supported |
| Slice decoding | Full `[]T` support | `[]string` via `strings.Fields` |
| Error aggregation | `schema.MultiError` (collects all field errors) | `fmt.Errorf` (returns first error only) |
| Nested struct | Supported | **Not supported** (flat structs only) |
| `[]string` encoding | Per-element encoding | `fmt.Sprintf("%v", v)` |

**Limitations** (acceptable for OIDC/OAuth form parsing):
1. **No nested struct support** — All `protocol/` request types are flat; no nesting needed.
2. **No `MultiError`** — HTTP form parsing reports the first error; sufficient for OAuth error responses.
3. **Slice encoding simplified** — `Encoder` uses `fmt.Sprintf("%v", v)` for non-custom types; `protocol/` types use `SpaceDelimitedArray` which has a custom encoder.
4. **Error type simplified** — Returns `fmt.Errorf` instead of `schema.MultiError`; call sites use `errors.Is` where needed.
