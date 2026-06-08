package rs_test

import (
	"context"
	"fmt"

	"github.com/roidmc/kexcore-oidc/pkg/client/rs"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

type IntrospectionResponse struct {
	Active     bool                     `json:"active"`
	Scope      protocol.SpaceDelimitedArray `json:"scope,omitempty"`
	ClientID   string                   `json:"client_id,omitempty"`
	TokenType  string                   `json:"token_type,omitempty"`
	Expiration protocol.Time                `json:"exp,omitempty"`
	IssuedAt   protocol.Time                `json:"iat,omitempty"`
	NotBefore  protocol.Time                `json:"nbf,omitempty"`
	Subject    string                   `json:"sub,omitempty"`
	Audience   protocol.Audience            `json:"aud,omitempty"`
	Issuer     string                   `json:"iss,omitempty"`
	JWTID      string                   `json:"jti,omitempty"`
	Username   string                   `json:"username,omitempty"`
	protocol.UserInfoProfile
	protocol.UserInfoEmail
	protocol.UserInfoPhone
	Address *protocol.UserInfoAddress `json:"address,omitempty"`

	// Foo and Bar are custom claims
	Foo string `json:"foo,omitempty"`
	Bar struct {
		Val1 string `json:"val_1,omitempty"`
		Val2 string `json:"val_2,omitempty"`
	} `json:"bar,omitempty"`

	// Claims are all the combined claims, including custom.
	Claims map[string]any `json:"-,omitempty"`
}

func ExampleIntrospect_custom() {
	rss, err := rs.NewResourceServerClientCredentials(context.TODO(), "http://localhost:8080", "clientid", "clientsecret")
	if err != nil {
		panic(err)
	}

	resp, err := rs.Introspect[*IntrospectionResponse](context.TODO(), rss, "accesstokenstring")
	if err != nil {
		panic(err)
	}

	fmt.Println(resp)
}
