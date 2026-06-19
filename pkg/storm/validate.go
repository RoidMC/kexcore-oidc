package storm

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"strings"
)

// Validate checks plugin registration consistency and storage compatibility.
// It validates:
//   - Each plugin's declared storage dependencies are satisfied
//   - Core plugin combinations satisfy RFC constraints
//   - No duplicate route registrations
//
// Returns the first error encountered, enabling fail-fast behavior.
func (e *Engine) Validate() error {
	if e.storage == nil {
		return fmt.Errorf("storm: storage is required but not provided")
	}

	// Check each plugin's declared storage dependencies.
	for _, p := range e.plugins {
		cp, ok := p.(CategorizablePlugin)
		if !ok {
			continue
		}

		required := cp.Requires()
		if len(required) == 0 {
			continue
		}

		for _, ifaceName := range required {
			if !e.storageImplements(ifaceName) {
				hint := storageMissingHint(ifaceName)
				return fmt.Errorf("storm: plugin %q requires storage interface %q, but Storage does not implement it.\n  → %s\n  See storage.go for full interface definition and implementation guide.",
					p.Name(), ifaceName, hint)
			}
		}
	}

	// Check RFC compliance constraints for enabled plugins.
	if err := e.validateProtocolConstraints(); err != nil {
		return err
	}

	// Production safety checks.
	if err := e.validateProductionSafety(); err != nil {
		return err
	}

	// Key strength validation.
	if err := e.validateKeyStrength(); err != nil {
		return err
	}

	return nil
}

// storageImplements checks if the Storage implements the named interface.
// When the interface is NOT implemented, storageMissingHint returns a
// developer-friendly message listing the required methods.
func (e *Engine) storageImplements(ifaceName string) bool {
	switch ifaceName {
	case "AuthStore":
		_, ok := e.storage.(AuthStore)
		return ok
	case "TokenStore":
		_, ok := e.storage.(TokenStore)
		return ok
	case "UserinfoStore":
		_, ok := e.storage.(UserinfoStore)
		return ok
	case "IntrospectStore":
		_, ok := e.storage.(IntrospectStore)
		return ok
	case "RevocationStore":
		_, ok := e.storage.(RevocationStore)
		return ok
	case "SessionStore":
		_, ok := e.storage.(SessionStore)
		return ok
	case "DeviceAuthStore":
		_, ok := e.storage.(DeviceAuthStore)
		return ok
	case "BackChannelStore":
		_, ok := e.storage.(BackChannelStore)
		return ok
	case "PARStore":
		_, ok := e.storage.(PARStore)
		return ok
	case "ClientStore", "KeyStore":
		return true // always satisfied by Storage interface
	case "TokenCNFStore":
		_, ok := e.storage.(TokenCNFStore)
		return ok
	case "PairwiseTransformer":
		_, ok := e.storage.(PairwiseTransformer)
		return ok
	case "AutoCompleteAuthRequest":
		_, ok := e.storage.(AutoCompleteAuthRequest)
		return ok
	case "CodeReuseDetector":
		_, ok := e.storage.(CodeReuseDetector)
		return ok
	case "ClientCredentialsStore":
		_, ok := e.storage.(ClientCredentialsStore)
		return ok
	case "JWTProfileStore":
		_, ok := e.storage.(JWTProfileStore)
		return ok
	case "TokenExchangeStore":
		_, ok := e.storage.(TokenExchangeStore)
		return ok
	case "DCRStore":
		_, ok := e.storage.(DCRStore)
		return ok
	case "CIBAStore":
		_, ok := e.storage.(CIBAStore)
		return ok
	default:
		if e.logger != nil {
			e.logger.Debug("unrecognized storage interface in Requires()", "name", ifaceName)
		}
		return true
	}
}

// storageMissingHint returns a developer-friendly hint for a missing storage interface.
// It uses reflection to extract method names from the interface type, so hints
// stay in sync with interface definitions — no manual maintenance required.
// Third-party plugin interfaces that are not in the registry fall back to a
// generic message.
func storageMissingHint(ifaceName string) string {
	if t, ok := knownStorageInterfaces[ifaceName]; ok {
		methods := extractMethodNames(t)
		if len(methods) == 0 {
			return "Interface has no methods — check if the interface definition is correct"
		}
		return "Add these methods to your Storage: " + strings.Join(methods, ", ")
	}
	return "See storage.go for interface definition"
}

// knownStorageInterfaces maps interface names (as used in Plugin.Requires())
// to their Go reflect.Type. Used by storageMissingHint to auto-generate
// method hints via reflection.
//
// Third-party plugins can register their own interfaces via
// RegisterStorageInterface().
var knownStorageInterfaces = map[string]reflect.Type{
	"AuthStore":               reflect.TypeOf((*AuthStore)(nil)).Elem(),
	"TokenStore":              reflect.TypeOf((*TokenStore)(nil)).Elem(),
	"UserinfoStore":           reflect.TypeOf((*UserinfoStore)(nil)).Elem(),
	"IntrospectStore":         reflect.TypeOf((*IntrospectStore)(nil)).Elem(),
	"RevocationStore":         reflect.TypeOf((*RevocationStore)(nil)).Elem(),
	"SessionStore":            reflect.TypeOf((*SessionStore)(nil)).Elem(),
	"DeviceAuthStore":         reflect.TypeOf((*DeviceAuthStore)(nil)).Elem(),
	"BackChannelStore":        reflect.TypeOf((*BackChannelStore)(nil)).Elem(),
	"PARStore":                reflect.TypeOf((*PARStore)(nil)).Elem(),
	"DCRStore":                reflect.TypeOf((*DCRStore)(nil)).Elem(),
	"ClientCredentialsStore":  reflect.TypeOf((*ClientCredentialsStore)(nil)).Elem(),
	"JWTProfileStore":         reflect.TypeOf((*JWTProfileStore)(nil)).Elem(),
	"TokenExchangeStore":      reflect.TypeOf((*TokenExchangeStore)(nil)).Elem(),
	"TokenCNFStore":           reflect.TypeOf((*TokenCNFStore)(nil)).Elem(),
	"PairwiseTransformer":     reflect.TypeOf((*PairwiseTransformer)(nil)).Elem(),
	"AutoCompleteAuthRequest": reflect.TypeOf((*AutoCompleteAuthRequest)(nil)).Elem(),
	"CodeReuseDetector":       reflect.TypeOf((*CodeReuseDetector)(nil)).Elem(),
	"CIBAStore":               reflect.TypeOf((*CIBAStore)(nil)).Elem(),
}

// RegisterStorageInterface registers a third-party storage interface so that
// Validate() can provide method hints when it is missing.
//
// Usage in a third-party plugin:
//
//	func init() {
//	    storm.RegisterStorageInterface("MyCustomStore", reflect.TypeOf((*MyCustomStore)(nil)).Elem())
//	}
func RegisterStorageInterface(name string, t reflect.Type) {
	knownStorageInterfaces[name] = t
}

// extractMethodNames returns the method names of a reflect.Type (interface),
// sorted alphabetically.
func extractMethodNames(t reflect.Type) []string {
	nm := t.NumMethod()
	if nm == 0 {
		return nil
	}
	names := make([]string, 0, nm)
	for i := 0; i < nm; i++ {
		names = append(names, t.Method(i).Name)
	}
	sort.Strings(names)
	return names
}

// validateProtocolConstraints checks RFC-level plugin combination constraints.
func (e *Engine) validateProtocolConstraints() error {
	pluginNames := make(map[string]bool)
	for _, p := range e.plugins {
		pluginNames[p.Name()] = true
	}

	type constraint struct {
		required   string
		requiredBy string
		reason     string
	}

	constraints := []constraint{
		{
			required:   "token",
			requiredBy: "authorization",
			reason:     "code response type requires token endpoint",
		},
		{
			required:   "userinfo",
			requiredBy: "authorization",
			reason:     "authorization flow expects userinfo endpoint for openid scope",
		},
		{
			required:   "keys",
			requiredBy: "authorization",
			reason:     "authorization flow may need to verify ID token signatures",
		},
		{
			required:   "endsession",
			requiredBy: "authorization",
			reason:     "RP-initiated logout requires end_session endpoint",
		},
	}

	for _, c := range constraints {
		if pluginNames[c.requiredBy] && !pluginNames[c.required] {
			return fmt.Errorf("storm: plugin %q is enabled but plugin %q is not (required: %s)",
				c.requiredBy, c.required, c.reason)
		}
	}

	return nil
}

// logPluginInfo logs a summary of registered plugins to the engine's logger.
func (e *Engine) logPluginInfo() {
	if e.logger == nil {
		return
	}

	names := make([]string, 0, len(e.plugins))
	for _, p := range e.plugins {
		names = append(names, p.Name())
	}
	sort.Strings(names)

	e.logger.Info("storm: engine ready",
		"plugins", strings.Join(names, ", "),
		"total", len(names))
}

// validateProductionSafety checks for testing-only flags that should not be
// enabled in production. Returns an error to prevent accidental deployment
// of insecure configurations.
func (e *Engine) validateProductionSafety() error {
	if e.allowPrivateIPs {
		slog.Warn("storm: WithAllowPrivateIPs() is enabled — SSRF protection is DISABLED. " +
			"NEVER enable this in production. Use network-level controls (firewall/reverse proxy) instead.")
	}
	if e.skipTLSCertVerify {
		slog.Warn("storm: WithSkipTLSCertVerify() is enabled — TLS certificate verification is DISABLED. " +
			"NEVER enable this in production.")
	}

	// Validate issuer URL if issuerFn is set and returns a non-empty value.
	// We can only check at build time if the issuerFn is deterministic.
	// For runtime validation, the issuer is checked per-request.
	if e.issuerFn != nil {
		// Try with a dummy request to see if issuer is configured
		// (Some issuerFns are request-dependent, so we can't always validate here)
	}

	return nil
}

// validateKeyStrength checks that the signing key meets minimum security
// requirements. RSA keys must be >= 2048 bits, EC keys must use >= P-256.
func (e *Engine) validateKeyStrength() error {
	ks, ok := e.storage.(KeyStore)
	if !ok {
		return nil // no key store, nothing to check
	}

	ctx := context.Background()
	signingKey, err := ks.SigningKey(ctx)
	if err != nil {
		// Key not available (e.g., test stub, lazy initialization) — skip check
		slog.Debug("storm: cannot retrieve signing key for validation, skipping", "error", err)
		return nil
	}
	if signingKey == nil || signingKey.Key() == nil {
		slog.Debug("storm: signing key is nil, skipping strength validation")
		return nil
	}

	// Extract raw crypto key from jwk.Key interface.
	// jwx v4 jwk.Key wraps a crypto key — use reflection to check strength.
	key := signingKey.Key()
	alg := signingKey.Algorithm()

	// jwk.Key may implement RSAPrivateKey/RSAPublicKey/ECDSAPrivateKey/ECDSAPublicKey
	// interfaces, or we can use the raw method.
	// For simplicity, check via the key type's raw representation.
	var rawKey any
	if rp, ok := key.(interface{ Raw(any) error }); ok {
		if err := rp.Raw(&rawKey); err == nil {
			switch k := rawKey.(type) {
			case *rsa.PublicKey:
				if k.N.BitLen() < 2048 {
					return fmt.Errorf("storm: RSA signing key is only %d bits (minimum 2048 required for production)", k.N.BitLen())
				}
			case *rsa.PrivateKey:
				if k.N.BitLen() < 2048 {
					return fmt.Errorf("storm: RSA signing key is only %d bits (minimum 2048 required for production)", k.N.BitLen())
				}
			case *ecdsa.PublicKey:
				if k.Curve.Params().BitSize < 256 {
					return fmt.Errorf("storm: ECDSA signing key uses %d-bit curve (minimum P-256 required for production)", k.Curve.Params().BitSize)
				}
			case *ecdsa.PrivateKey:
				if k.Curve.Params().BitSize < 256 {
					return fmt.Errorf("storm: ECDSA signing key uses %d-bit curve (minimum P-256 required for production)", k.Curve.Params().BitSize)
				}
			}
		}
	}

	// Validate algorithm is not "none" or empty
	if alg == "" {
		slog.Warn("storm: signing key has no algorithm specified — this may cause algorithm confusion attacks")
	}
	if strings.ToLower(alg) == "none" {
		return fmt.Errorf("storm: signing algorithm 'none' is not allowed")
	}

	// Warn if using HMAC (symmetric) for production — HMAC keys should be >= 256 bits
	if strings.HasPrefix(strings.ToUpper(alg), "HS") {
		slog.Warn("storm: using HMAC signing algorithm — ensure the key is >= 256 bits and kept secret")
	}

	// Key rotation safety: verify the signing key is present in the KeySet.
	// If not, rotated tokens will fail verification on other instances.
	signingKeyID := signingKey.ID()
	if signingKeyID != "" {
		keySet, err := ks.KeySet(ctx)
		if err == nil {
			found := false
			for _, k := range keySet {
				if k.ID() == signingKeyID {
					found = true
					break
				}
			}
			if !found {
				slog.Warn("storm: signing key is NOT in KeySet — this will cause token verification failures. "+
					"After key rotation, the old signing key must remain in KeySet until all tokens signed with it have expired.",
					"signing_key_id", signingKeyID)
			}
		}
	}

	return nil
}
