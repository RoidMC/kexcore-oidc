package mock

import (
	"testing"

	gomock "github.com/golang/mock/gomock"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	op "github.com/roidmc/kexcore-oidc/pkg/op"
)

func NewHasRedirectGlobs(t *testing.T) op.HasRedirectGlobs {
	return NewMockHasRedirectGlobs(gomock.NewController(t))
}

func NewHasRedirectGlobsWithConfig(t *testing.T, uri []string, appType op.ApplicationType, responseTypes []protocol.ResponseType, devMode bool) op.HasRedirectGlobs {
	c := NewHasRedirectGlobs(t)
	m := c.(*MockHasRedirectGlobs)
	m.EXPECT().RedirectURIs().AnyTimes().Return(uri)
	m.EXPECT().RedirectURIGlobs().AnyTimes().Return(uri)
	m.EXPECT().ApplicationType().AnyTimes().Return(appType)
	m.EXPECT().ResponseTypes().AnyTimes().Return(responseTypes)
	m.EXPECT().DevMode().AnyTimes().Return(devMode)
	return c
}
