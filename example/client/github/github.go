package main

import (
	"context"
	"fmt"
	"io"
	stdhttp "net/http"
	"os"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	githubOAuth "golang.org/x/oauth2/github"

	"github.com/roidmc/kexcore-oidc/v2/pkg/client/rp"
	"github.com/roidmc/kexcore-oidc/v2/pkg/client/rp/cli"
	httphelper "github.com/roidmc/kexcore-oidc/v2/pkg/util/http"
	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
)

var (
	callbackPath = "/orbctl/github/callback"
	key          = []byte("test1234test1234")
)

func main() {
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	port := os.Getenv("PORT")

	rpConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  fmt.Sprintf("http://localhost:%v%v", port, callbackPath),
		Scopes:       []string{"repo", "repo_deployment"},
		Endpoint:     githubOAuth.Endpoint,
	}

	ctx := context.Background()
	cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())
	relyingParty, err := rp.NewRelyingPartyOAuth(rpConfig, rp.WithCookieHandler(cookieHandler))
	if err != nil {
		fmt.Printf("error creating relaying party: %v", err)
		return
	}
	state := func() string {
		return uuid.New().String()
	}
	token := cli.CodeFlow[*protocol.IDTokenClaims](ctx, relyingParty, callbackPath, port, state)

	// Call the GitHub API directly with the OAuth2 client,
	// replacing the former github.com/google/go-github dependency.
	// GET https://api.github.com/user returns the authenticated user,
	// equivalent to the former client.Users.Get(ctx, "") call.
	client := relyingParty.OAuthConfig().Client(ctx, token.Token)

	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		fmt.Printf("error %v", err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("error %v", err)
		return
	}
	if resp.StatusCode != stdhttp.StatusOK {
		fmt.Printf("error %s: %s", resp.Status, body)
		return
	}
	fmt.Println("call succeeded")
}
