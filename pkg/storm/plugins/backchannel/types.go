package backchannel

import "github.com/roidmc/kexcore-oidc/v2/pkg/storm"

// BackChannelLogoutClient is optionally implemented by clients that support
// back-channel logout. When implemented, the plugin sends logout tokens
// to the client's back-channel logout URI.
type BackChannelLogoutClient interface {
	storm.Client
	BackChannelLogoutURI() string
}
