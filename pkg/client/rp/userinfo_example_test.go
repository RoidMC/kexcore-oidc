// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package rp_test

import (
	"context"
	"fmt"

	"github.com/roidmc/kexcore-oidc/pkg/client/rp"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

type UserInfo struct {
	Subject string `json:"sub,omitempty"`
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

func (u *UserInfo) GetSubject() string {
	return u.Subject
}

func ExampleUserinfo_custom() {
	rpo, err := rp.NewRelyingPartyOIDC(context.TODO(), "http://localhost:8080", "clientid", "clientsecret", "http://example.com/redirect", []string{protocol.ScopeOpenID, protocol.ScopeProfile, protocol.ScopeEmail, protocol.ScopePhone})
	if err != nil {
		panic(err)
	}

	info, err := rp.Userinfo[*UserInfo](context.TODO(), "accesstokenstring", "Bearer", "userid", rpo)
	if err != nil {
		panic(err)
	}

	fmt.Println(info)
}
