// Package webfinger implements the WebFinger endpoint (RFC 7033).
//
// It serves GET /.well-known/webfinger, returning the OP issuer
// for a given resource identifier (typically acct: URIs).
//
// WebFinger is used by OpenID Connect Discovery to allow clients
// to discover the issuer for a given user identifier.
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
package webfinger

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm/shared"
)

// Plugin implements the WebFinger endpoint (RFC 7033).
type Plugin struct{}

// NewWithConfig creates a new WebFinger plugin.
func NewWithConfig() *Plugin {
	return &Plugin{}
}

// init self-registers the WebFinger plugin in the global registry.
func init() {
	storm.RegisterPlugin("webfinger", storm.PriorityWebFinger, func(ctx *storm.PluginContext) storm.Plugin {
		return NewWithConfig()
	})
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "webfinger" }

// Register installs the GET /.well-known/webfinger route.
func (p *Plugin) Register(r chi.Router) {
	r.Get("/.well-known/webfinger", p.handle)
}

// handle processes GET /.well-known/webfinger requests.
// RFC 7033 §4.2 — Performing a WebFinger Query
func (p *Plugin) handle(w http.ResponseWriter, r *http.Request) {
	resource := r.URL.Query().Get("resource")
	if resource == "" {
		writeJRDError(w, http.StatusBadRequest, "resource parameter required")
		return
	}

	// Validate resource format: must be acct: URI or https: URI
	// RFC 7033 §4.5 — WebFinger and URIs
	if !strings.HasPrefix(resource, "acct:") && !strings.HasPrefix(resource, "https://") {
		writeJRDError(w, http.StatusBadRequest, "unsupported resource scheme")
		return
	}

	// Extract host from the resource identifier
	host := extractHost(resource)
	if host == "" {
		writeJRDError(w, http.StatusBadRequest, "invalid resource format")
		return
	}

	issuer := shared.IssuerFromContext(r.Context())
	if issuer == "" {
		writeJRDError(w, http.StatusInternalServerError, "issuer not configured")
		return
	}

	// Verify the issuer host matches the resource host
	// RFC 7033 §4.2: the host SHOULD match the "host" portion of the query target
	issuerHost := extractHost(issuer)
	if issuerHost != "" && !strings.EqualFold(host, issuerHost) {
		writeJRDError(w, http.StatusNotFound, "resource host does not match issuer")
		return
	}

	// Build all available links
	allLinks := []link{
		{
			Rel:  "http://openid.net/specs/connect/1.0/issuer",
			Href: issuer,
		},
	}

	// RFC 7033 §4.3 — The "rel" Parameter
	// If the "rel" parameter is present, filter links to only include
	// those matching the requested relation types.
	// The "rel" parameter can appear multiple times.
	relParams := r.URL.Query()["rel"]
	if len(relParams) > 0 {
		relSet := make(map[string]bool, len(relParams))
		for _, rel := range relParams {
			relSet[rel] = true
		}
		filtered := make([]link, 0, len(allLinks))
		for _, l := range allLinks {
			if relSet[l.Rel] {
				filtered = append(filtered, l)
			}
		}
		allLinks = filtered
	}

	// RFC 7033 §4.4 — The JSON Resource Descriptor (JRD)
	resp := webFingerResponse{
		Subject: resource,
		Links:   allLinks,
	}

	w.Header().Set("Content-Type", "application/jrd+json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// Response already partially written; best-effort logging only.
		slog.Default().Warn("webfinger: failed to encode JRD response", "error", err)
	}
}

// writeJRDError writes an error response in JRD format.
// RFC 7033 §10.2: The media type is application/jrd+json.
func writeJRDError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/jrd+json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		slog.Default().Warn("webfinger: failed to encode JRD error", "error", err)
	}
}

// extractHost extracts the host from a URI.
// For acct:user@host returns "host".
// For https://host/path returns "host".
func extractHost(uri string) string {
	if strings.HasPrefix(uri, "acct:") {
		parts := strings.SplitN(strings.TrimPrefix(uri, "acct:"), "@", 2)
		if len(parts) == 2 {
			return parts[1]
		}
		return ""
	}
	// Only https: URIs reach here (acct: handled above, other schemes rejected earlier).
	uri = strings.TrimPrefix(uri, "https://")
	if idx := strings.Index(uri, "/"); idx >= 0 {
		return uri[:idx]
	}
	if idx := strings.Index(uri, "?"); idx >= 0 {
		return uri[:idx]
	}
	return uri
}

// webFingerResponse represents a WebFinger JRD response.
// RFC 7033 §4.4 — The JRD Format
type webFingerResponse struct {
	Subject string `json:"subject"`
	Links   []link `json:"links,omitempty"`
}

type link struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
	Type string `json:"type,omitempty"`
}
