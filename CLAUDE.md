# KexCore OIDC — AI Context Document

## Project Overview

KexCore OIDC is a full-stack OIDC SDK (OP + RP) for Go, supporting OAuth 2.1,
OpenID Connect Core 1.0, and Chinese Commercial Cryptography (SM2/SM3/SM4/SM9).

Two OP implementations:
1. **Legacy Provider** (`/pkg/op`) — Zitadel fork, monolithic interface, to be replaced
2. **StormEngine Provider** (`/pkg/storm`) — Plugin-based, inspired by Caddy v2

| Layer | Source | Status |
|---|---|---|
| `protocol/` | Self-developed (RoidMC) | **Active** — all OAuth/OIDC types, errors, verifiers |
| `storm/` | Self-developed (RoidMC) | New OP engine |
| `op/` | Zitadel fork | Legacy |
| `client/` | Zitadel fork | RP client, uses `protocol/` types |
| `crypto/` | Self-developed | SM2/SM3/SM4/SM9 + HSM/KMS provider registry |

`protocol/` is the single source of truth — zero Zitadel dependency, independent copyright.
`zitadel/schema` replaced by `protocol.Encoder`/`protocol.Decoder`.

## Architecture: StormEngine

### Design Philosophy

- **Plugin = RFC Endpoint**: Each plugin maps to one RFC/OIDC Core section
- **Interface Isolation (ISP)**: Each plugin declares only the storage interfaces it needs
- **Capability Discovery**: Engine discovers storage capabilities via Go type assertions
- **Zero Breaking Changes**: New features = new plugin + new interface

### Plugin Pattern

```go
type Plugin struct { /* dependencies */ }
type Config struct { /* plugin-specific config */ }
func NewWithConfig(cfg Config) *Plugin
func (p *Plugin) Name() string
func (p *Plugin) Contribute(engine *Engine) error
```

### Implemented Plugins

| Plugin | RFC/OIDC Section |
|---|---|
| Discovery | OIDC Discovery 1.0 |
| Authorization | OIDC Core §3 (code/implicit/hybrid, PKCE, PAR, Request Object) |
| Token | RFC 6749 §4 (code exchange, refresh, JWT Profile, Token Exchange) |
| UserInfo | OIDC Core §5.3 |
| JWKS | OIDC Core §7.3 |
| DCR | RFC 7591 |
| End Session | OIDC Session §5 |
| Device Authorization | RFC 8628 |
| PAR | RFC 9101 |
| mTLS | RFC 8705 |
| DPoP | RFC 9449 |
| Back-Channel Logout | OIDC Back-Channel §2.5 (implemented, PushLogoutTokens) |
| Pairwise Subject | OIDC Core §8.1 |

### Authorization Plugin Extension Points

**Client-level (per-client behavior):**

| Extension | Interface | Description |
|---|---|---|
| Extra ID token claims | `IDTokenClaimsExtender` | AuthRequest → `ExtraIDTokenClaims() map[string]any` |
| ID token lifetime | `IDTokenLifetimeProvider` | Client → `IDTokenLifetime() time.Duration` (default: 1h) |
| Redirect URI list | `RedirectURIClient` | Client → `RedirectURIs() []string` |
| Glob redirect URI | `RedirectURIGlobClient` | Client → `RedirectURIGlobs() []string` |
| Application type | `ApplicationTypeClient` | Client → `ApplicationType()` (web/native/user_agent) |
| Dev mode | `DevModeClient` | Client → `DevMode() bool` |
| Scope validation | `ScopeValidationClient` | Client → `StrictScopeValidation() bool` |
| Custom validation | `AuthorizeValidatorClient` | Client → `AuthorizeValidator() AuthorizeValidator` |
| Response types | `responseTypesProvider` | Client → `ResponseTypes() []ResponseType` |

**Tenant-level (global per Engine):**

| Extension | Config field | Description |
|---|---|---|
| Custom auth code | `Config.CreateAuthCode` | Hook for authorization code generation |
| Implicit flow | `Config.EnableImplicit` | Enable/disable (default: disabled per OAuth 2.1) |
| PAR | `Config.PARStore` | Pushed Authorization Requests |
| Session management | `Config.SessionProvider` | `prompt=none` enforcement (OIDC Core §3.1.2.6). Optional; when nil, `prompt=none` is not enforced. Auto-discovered from storage via type assertion. |

Standard claims (`iss`, `sub`, `aud`, `iat`, `exp`, `nonce`, `at_hash`) cannot be overridden
by `IDTokenClaimsExtender` — they always take precedence.

### Multi-tenant Support

Two modes, both supported by the same SDK:

1. **Multi-Engine**: Each tenant = own Engine + issuer + storage. `IssuerMiddleware` routes by URL.
2. **Single-Engine**: One Engine, one issuer. Storage maps `client_id` → tenant config internally.
   Client objects implement optional interfaces for per-tenant behavior.

### Not Implemented (by design)

| Feature | Reason |
|---|---|
| Front-Channel Logout | Backend SDK, no browser iframes |
| Session Management (iframe) | Backend SDK, no browser iframes |
| Hybrid Flow | Removed in OAuth 2.1 |

## Gaps for OIDF Basic Certification

| Gap | Can inject via `IDTokenClaimsExtender`? |
|---|---|
| `c_hash` claim | Yes |
| `auth_time` claim | Yes |
| `acr` claim | Yes |
| `amr` claim | Yes |
| `azp` claim | Yes |
| UserInfo scope filtering | No — needs `userinfo.go` change |
| CORS middleware | No — needs `engine.go` change |

## Known Issues

- `UserinfoStore.SetUserinfoFromToken` lacks `scopes []string` parameter
- `TokenRequest` interface missing `GetAuthTime()`, `GetNonce()`, `GetACR()`, `GetAMR()`
- `op/` package still contains legacy mock files — to be removed after migration

## Gaps Fixed (2026-06-07)

| Issue | Status |
|---|---|
| `Bool(false)` omitted by `omitempty` (`email_verified`, `phone_number_verified`) | Fixed — removed `omitempty` from `UserInfoEmail.EmailVerified` and `UserInfoPhone.PhoneNumberVerified` |
| `prompt=none` not enforced (OIDC Core §3.1.2.6) | Fixed — `SessionProvider` interface in authorization plugin |
| `profile` scope missing claims (`nickname`, `zoneinfo`, `updated_at`, etc.) | Fixed — example `SetUserinfoFromToken` populates all OIDC Core §5.4 claims |
| `address` scope not handled | Fixed — example `SetUserinfoFromToken` returns `UserInfoAddress` |
| `phone` scope missing `phone_number` (empty string omitted) | Fixed — example test user has phone number |
| Access token not decryptable (SHA256 hash → AES-GCM) | Fixed — `TokenCrypto.Encrypt/Decrypt` uses AES-GCM |
| ID token missing from token response (signing with public key) | Fixed — `signingKey.Key()` returns private key; `createIDToken` uses `crypto.SignJWS` |
| UserInfo returning 400 for invalid tokens (should be 401) | Fixed — RFC 6750 §3.1 `WWW-Authenticate` header |
| OIDC Core §5.5 `claims` parameter not supported | Fixed — `ClaimsRequest` type, `GetClaims()` interface, ID Token + UserInfo claims injection |
| Authorization code reuse token tracking used encrypted token instead of UUID | Fixed — `createAccessToken` returns `tokenID`; `TrackTokenForAuthRequest` uses UUID |
| UserInfo/Introspection returned 500 for revoked tokens | Fixed — UserInfo: 401 + `WWW-Authenticate`; Introspection: `{"active": false}` |
| Unregistered redirect_uri redirected errors to attacker URI | Fixed — redirect_uri validated before other params; unregistered → HTTP 400 direct |
| Token endpoint Cache-Control headers missing | Fixed — `shared.JSONResponse` sets `Cache-Control: no-store` + `Pragma: no-cache` |
| Refresh token not issued for authorization_code grant | Fixed — `createAccessToken` returns `refreshToken` from `CreateAccessAndRefreshTokens` |
| `c_hash` missing in ID token (token endpoint) | Fixed — `createTokenResponseFromTokenRequest` passes `code` to `createIDToken` |
| JWE algorithms incomplete (RSA-OAEP, ECDH-ES, KW, CBC-HS) | Fixed — all RFC 7518 alg/enc algorithms implemented |
| DCR endpoint not registered | Fixed — `dcr.init()` auto-registration + JSON tags + json.RawMessage JWKS |
| ID Token encryption only supported SM2/SM9/dir | Fixed — `encryptIDToken` supports RSA-OAEP, ECDH-ES, A256GCMKW etc. |
| Default signing algorithm was ES256 instead of RS256 | Fixed — RS256 moved to front of DefaultSigningAlgorithms |
| End Session state not returned in redirect | Fixed — state appended to post_logout_redirect_uri |
| End Session invalid redirect_uri redirects to `/` (404) | Fixed — shows error page for invalid, logout page for no redirect_uri |
| Hybrid flow (`code id_token token`) returns unauthorized_client | Fixed — hybrid flow constants, `WithImplicit()`, `authResponseHybrid()` |
| DCR client hardcoded `responseTypes: [code]` | Fixed — uses requested response_types and grant_types |
| DCR client missing post_logout_redirect_uris | Fixed — saved from registration request |
| Session not deleted on logout (prompt=none still succeeds) | Fixed — `TerminateSession` deletes session + clientSessions |
| `prompt=none` not returning error when user not logged in | **Open** — SessionProvider implemented but conformance test still fails |
| Token TTL (tokenTTL/refreshTTL) fields unused | **Open** — fields exist in Storage but not used in token creation |
| Client EncryptionKey not stored from DCR JWKS | **Open** — DCR stores JWKS in registration but doesn't propagate to client |

## TODO

- **InMemoryStorage** — Default storage for dev/testing
- **Client Builder** — Move client helpers to `storm/client` package
- **CORS middleware** in `engine.go`
- **Test coverage**: authorization 30+ tests, token 35 tests done
- **prompt=none enforcement** — Debug why conformance test still fails despite SessionProvider
- **DCR JWKS → ClientKeyProvider** — Propagate JWKS from DCR registration to client encryption key

## Security Audit (2026-06-04)

| Issue | Severity | Status |
|---|---|---|
| XSS in form_post template | High | Fixed — `html/template` |
| Open redirect via unvalidated redirect_uri | High | Fixed — `shared.WriteError` |
| Fragment URL in Go 1.22+ | Medium | Fixed — manual `#fragment` |
| `isLocalhost` included `0.0.0.0` | Medium | Fixed |
| Implicit Flow missing `access_token` | High | Fixed |
| `writeAuthError` ignored `response_mode` | High | Fixed |
| `validateIDTokenHint` didn't extract subject | Medium | Fixed |
| IDTokenClaimsExtender override protection | None | N/A — standard claims take precedence |

## Conventions

- Code comments follow conversation language (Chinese for architecture)
- No comments in code unless asked
- Use `shared.IssuerURL(ctx, "/path")` for endpoint URLs
- Use `shared.IssuerFromContext(ctx)` for issuer string
- OAuth errors: `protocol.ErrXxx().WithDescription("...").WithParent(err)`
- Plugin: `Plugin` struct + `Config` struct + `NewWithConfig(Config)` + `Name()` + `Contribute()`
- `protocol/` is single source of truth for all OAuth/OIDC types
- Use `protocol.CheckSignatureWithKeyStore()` for KeyStore-based signature verification
- For `IDTokenHintVerifier`, set `verifier.KeyStore = keyStore`
- Generic functions: use directly, cannot assign to variables

## Key Dependencies

| Package | Purpose |
|---|---|
| `lestrrat-go/jwx/v4` | JWK, JWS, JWA, JWT |
| `go-chi/chi/v5` | HTTP routing |
| `emmansun/gmsm` | SM2/SM3/SM4/SM9 |

## Building

```bash
go build ./...
go run ./example/storm-server/
curl http://localhost:9998/.well-known/openid-configuration
```
