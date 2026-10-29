// Package builtin provides the default StormEngine plugin set as an
// explicit, ordered factory list.
//
// Unlike the individual plugin packages (which self-register in the global
// registry via init()), importing this package has no registration side
// effects. Pass the result of All() to storm.New explicitly:
//
//	engine := storm.New(storage, issuerFn, storm.WithPlugins(builtin.All()...))
//
// This keeps engine construction explicit and testable — no hidden global
// state determines which plugins run.
package builtin

import (
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm"

	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/plugins/authorization"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/plugins/backchannel"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/plugins/ciba"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/plugins/dcr"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/plugins/device"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/plugins/discovery"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/plugins/dpop"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/plugins/endsession"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/plugins/introspection"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/plugins/jarm"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/plugins/keys"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/plugins/mtls"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/plugins/par"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/plugins/revocation"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/plugins/token"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/plugins/userinfo"
	"github.com/roidmc/kexcore-oidc/v3/pkg/storm/plugins/webfinger"
)

// All returns the default plugin set in priority order (the Engine sorts
// again, so the literal order here is documentation only).
//
// Each factory receives the Engine's PluginContext; plugins whose storage
// capabilities are not satisfied decline by returning nil and are skipped.
func All() []storm.NamedPluginFactory {
	return []storm.NamedPluginFactory{
		{Name: "authorization", Priority: storm.PriorityAuthorization, Factory: storm.FactoryOf(authorization.New)},
		{Name: "token", Priority: storm.PriorityToken, Factory: storm.FactoryOf(token.New)},
		{Name: "keys", Priority: storm.PriorityKeys, Factory: storm.FactoryOf(keys.New)},
		{Name: "discovery", Priority: storm.PriorityDiscovery, Factory: storm.FactoryOf(discovery.New)},
		{Name: "userinfo", Priority: storm.PriorityUserinfo, Factory: storm.FactoryOf(userinfo.New)},
		{Name: "introspection", Priority: storm.PriorityIntrospection, Factory: storm.FactoryOf(introspection.New)},
		{Name: "revocation", Priority: storm.PriorityRevocation, Factory: storm.FactoryOf(revocation.New)},
		{Name: "endsession", Priority: storm.PriorityEndSession, Factory: storm.FactoryOf(endsession.New)},
		{Name: "backchannel", Priority: storm.PriorityBackChannel, Factory: storm.FactoryOf(backchannel.New)},
		{Name: "device", Priority: storm.PriorityDevice, Factory: storm.FactoryOf(device.New)},
		{Name: "par", Priority: storm.PriorityPAR, Factory: storm.FactoryOf(par.New)},
		{Name: "dpop", Priority: storm.PriorityDPoP, Factory: storm.FactoryOf(dpop.New)},
		{Name: "jarm", Priority: storm.PriorityJARM, Factory: storm.FactoryOf(jarm.New)},
		{Name: "dcr", Priority: storm.PriorityDCR, Factory: storm.FactoryOf(dcr.New)},
		{Name: "ciba", Priority: storm.PriorityCIBA, Factory: storm.FactoryOf(ciba.New)},
		{Name: "mtls", Priority: storm.PriorityMTLS, Factory: storm.FactoryOf(mtls.New)},
		{Name: "webfinger", Priority: storm.PriorityWebFinger, Factory: storm.FactoryOf(webfinger.New)},
	}
}
