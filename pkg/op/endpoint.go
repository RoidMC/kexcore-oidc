package op

import (
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

type Endpoint = protocol.Endpoint

var NewEndpoint = protocol.NewEndpoint
var NewEndpointWithURL = protocol.NewEndpointWithURL
var ErrNilEndpoint = protocol.ErrNilEndpoint
