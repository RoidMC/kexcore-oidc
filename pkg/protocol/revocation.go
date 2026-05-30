package protocol

// RFC 7009 §2.1 - Token Revocation Request
//
// The client constructs the request by including the following
// parameters using the "application/x-www-form-urlencoded" format:
//
//	token           REQUIRED. The token that the client wants to get revoked.
//	token_type_hint OPTIONAL. A hint about the type of the token submitted for revocation.
//
// Per RFC 7009 §2.2, the response is always HTTP 200 with an empty body
// on success, or an error response per RFC 6749 §5.2 on failure.
type RevocationRequest struct {
	Token         string `schema:"token"`
	TokenTypeHint string `schema:"token_type_hint,omitempty"`
}
