package op

import (
	"context"
	"net/http"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

type key int

const (
	issuerKey key = 0
)

type IssuerInterceptor struct {
	issuerFromRequest IssuerFromRequest
}

func NewIssuerInterceptor(issuerFromRequest IssuerFromRequest) *IssuerInterceptor {
	return &IssuerInterceptor{
		issuerFromRequest: issuerFromRequest,
	}
}

func (i *IssuerInterceptor) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i.setIssuerCtx(w, r, next)
	})
}

func (i *IssuerInterceptor) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		i.setIssuerCtx(w, r, next)
	}
}

func IssuerFromContext(ctx context.Context) string {
	return protocol.IssuerFromContext(ctx)
}

func ContextWithIssuer(ctx context.Context, issuer string) context.Context {
	return protocol.ContextWithIssuer(ctx, issuer)
}

func (i *IssuerInterceptor) setIssuerCtx(w http.ResponseWriter, r *http.Request, next http.Handler) {
	r = r.WithContext(ContextWithIssuer(r.Context(), i.issuerFromRequest(r)))
	next.ServeHTTP(w, r)
}
