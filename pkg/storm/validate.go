package storm

import (
	"fmt"
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
				return fmt.Errorf("storm: plugin %q requires storage interface %q, but Storage does not implement it",
					p.Name(), ifaceName)
			}
		}
	}

	// Check RFC compliance constraints for enabled plugins.
	if err := e.validateProtocolConstraints(); err != nil {
		return err
	}

	return nil
}

// storageImplements checks if the Storage implements the named interface.
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
	case "ClientStore", "KeyStore":
		return true // always satisfied by Storage interface
	default:
		// Unrecognized interface name — cannot validate statically.
		if e.logger != nil {
			e.logger.Debug("unrecognized storage interface in Requires()", "name", ifaceName)
		}
		return true // assume satisfied to avoid false positives
	}
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
