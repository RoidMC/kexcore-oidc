package protocol

import "context"

type issuerContextKey struct{}

func ContextWithIssuer(ctx context.Context, issuer string) context.Context {
	return context.WithValue(ctx, issuerContextKey{}, issuer)
}

func IssuerFromContext(ctx context.Context) string {
	s, _ := ctx.Value(issuerContextKey{}).(string)
	return s
}
