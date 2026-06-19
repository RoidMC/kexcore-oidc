package cli

import (
	"context"
	"net/http"

	"github.com/roidmc/kexcore-oidc/v2/pkg/client/rp"
	httphelper "github.com/roidmc/kexcore-oidc/v2/pkg/util/http"
	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
)

const (
	loginPath = "/login"
)

func CodeFlow[C protocol.IDClaims](ctx context.Context, relyingParty rp.RelyingParty, callbackPath, port string, stateProvider func() string) *protocol.Tokens[C] {
	codeflowCtx, codeflowCancel := context.WithCancel(ctx)
	defer codeflowCancel()

	tokenChan := make(chan *protocol.Tokens[C], 1)

	callback := func(w http.ResponseWriter, r *http.Request, tokens *protocol.Tokens[C], state string, rp rp.RelyingParty) {
		tokenChan <- tokens
		msg := "<p><strong>Success!</strong></p>"
		msg = msg + "<p>You are authenticated and can now return to the CLI.</p>"
		w.Write([]byte(msg))
	}
	http.Handle(loginPath, rp.AuthURLHandler(stateProvider, relyingParty))
	http.Handle(callbackPath, rp.CodeExchangeHandler(callback, relyingParty))

	httphelper.StartServer(codeflowCtx, ":"+port)

	OpenBrowser("http://localhost:" + port + loginPath)

	return <-tokenChan
}
