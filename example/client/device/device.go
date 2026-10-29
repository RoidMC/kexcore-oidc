// Command device is an example Oauth2 Device Authorization Grant app.
// It creates a new Device Authorization request on the Issuer and then polls for tokens.
// The user is then prompted to visit a URL and enter the user code.
// Or, the complete URL can be used instead to omit manual entry.
// In practice then can be a "magic link" in the form or a QR.
//
// The following environment variables are used for configuration:
//
//	ISSUER: URL to the OP, required.
//	CLIENT_ID: ID of the application, required.
//	CLIENT_SECRET: Secret to authenticate the app using basic auth. Only required if the OP expects this type of authentication.
//	KEY_PATH: Path to a private key file, used to for JWT authentication of the App. Only required if the OP expects this type of authentication.
//	SCOPES: Scopes of the Authentication Request. Optional.
//
// Basic usage:
//
//	cd example/client/device
//	export ISSUER="http://localhost:9000" CLIENT_ID="246048465824634593@demo"
//
// Get an Access Token:
//
//	SCOPES="email profile" go run .
//
// Get an Access Token and ID Token:
//
//	SCOPES="email profile openid" go run .
//
// Get an Access Token and Refresh Token
//
//	SCOPES="email profile offline_access" go run .
//
// Get Access, Refresh and ID Tokens:
//
//	SCOPES="email profile offline_access openid" go run .
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/roidmc/kexcore-oidc/v2/pkg/client/rp"
	httphelper "github.com/roidmc/kexcore-oidc/v2/pkg/util/http"
	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
)

var (
	key = []byte("test1234test1234")
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT)
	defer stop()

	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	keyPath := os.Getenv("KEY_PATH")
	keyID := os.Getenv("KEY_ID")
	issuer := os.Getenv("ISSUER")
	scopes := strings.Split(os.Getenv("SCOPES"), " ")

	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())

	var options []rp.Option
	if clientSecret == "" {
		options = append(options, rp.WithPKCE(cookieHandler))
	}
	if keyPath != "" {
		signingKey, err := os.ReadFile(keyPath)
		if err != nil {
			slog.Error(fmt.Sprintf("error reading key file %s", err.Error()))
			os.Exit(1)
		}
		options = append(options, rp.WithJWTProfile(rp.SignerFromKeyAndKeyID(signingKey, keyID)))
	}

	provider, err := rp.NewRelyingPartyOIDC(ctx, issuer, clientID, clientSecret, "", scopes, options...)
	if err != nil {
		slog.Error(fmt.Sprintf("error creating provider %s", err.Error()))
		os.Exit(1)
	}

	slog.Info("starting device authorization flow")
	resp, err := rp.DeviceAuthorization(ctx, scopes, provider, nil)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	slog.Info("resp", "resp", resp)
	fmt.Printf("\nPlease browse to %s and enter code %s\n", resp.VerificationURI, resp.UserCode)

	slog.Info("start polling")
	token, err := rp.DeviceAccessToken(ctx, resp.DeviceCode, time.Duration(resp.Interval)*time.Second, provider)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	slog.Info(fmt.Sprintf("successfully obtained token: %#v", token))

	slog.Info("Going to refresh token")
	refreshedToken, err := rp.RefreshTokens[*protocol.IDTokenClaims](ctx, provider, token.RefreshToken, "", "")
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	slog.Info(fmt.Sprintf("refreshedToken: %#v", refreshedToken.Token))

	slog.Info("Going to revoke token")
	err = rp.RevokeToken(ctx, provider, token.AccessToken, "refresh_token")
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	slog.Info("Token revoked")
}
