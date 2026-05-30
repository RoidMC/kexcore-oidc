package protocol

// OIDC RP-Initiated Logout 1.0 §4 — RP-Initiated Logout Request
//
//	https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
//
// Parameters (application/x-www-form-urlencoded):
//
//	id_token_hint           RECOMMENDED. Previously issued ID Token.
//	logout_hint             OPTIONAL. Hint to the OP about the End-User.
//	client_id               OPTIONAL. OAuth 2.0 Client Identifier.
//	post_logout_redirect_uri OPTIONAL. URI to redirect after logout.
//	state                   OPTIONAL. Opaque value for state maintenance.
//	ui_locales              OPTIONAL. End-User's preferred languages (space-separated BCP47 tags).
type EndSessionRequest struct {
	IdTokenHint           string  `json:"-" schema:"id_token_hint"`
	LogoutHint            string  `json:"-" schema:"logout_hint"`
	ClientID              string  `json:"-" schema:"client_id"`
	PostLogoutRedirectURI string  `json:"-" schema:"post_logout_redirect_uri"`
	State                 string  `json:"-" schema:"state"`
	UILocales             Locales `json:"-" schema:"ui_locales"`
}
