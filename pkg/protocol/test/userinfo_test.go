// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package protocol_test

import (
	"encoding/json"
	"testing"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/stretchr/testify/assert"
)

func TestUserInfo_AppendClaims(t *testing.T) {
	u := new(protocol.UserInfo)
	u.AppendClaims("a", "b")
	want := map[string]any{"a": "b"}
	assert.Equal(t, want, u.Claims)

	u.AppendClaims("d", "e")
	want["d"] = "e"
	assert.Equal(t, want, u.Claims)
}

func TestUserInfo_GetAddress(t *testing.T) {
	u := new(protocol.UserInfo)
	assert.Equal(t, &protocol.UserInfoAddress{}, u.GetAddress())

	u.Address = &protocol.UserInfoAddress{PostalCode: "1234"}
	assert.Equal(t, u.Address, u.GetAddress())
}

func TestUserInfoMarshal(t *testing.T) {
	userinfo := &protocol.UserInfo{
		Subject: "test",
		Address: &protocol.UserInfoAddress{
			StreetAddress: "Test 789\nPostfach 2",
		},
		UserInfoEmail: protocol.UserInfoEmail{
			Email:         "test",
			EmailVerified: true,
		},
		UserInfoPhone: protocol.UserInfoPhone{
			PhoneNumber:         "0791234567",
			PhoneNumberVerified: true,
		},
		UserInfoProfile: protocol.UserInfoProfile{
			Name: "Test",
		},
		Claims: map[string]any{"private_claim": "test"},
	}

	marshal, err := json.Marshal(userinfo)
	assert.NoError(t, err)

	out := new(protocol.UserInfo)
	assert.NoError(t, json.Unmarshal(marshal, out))
	expected, err := json.Marshal(out)

	assert.NoError(t, err)
	assert.Equal(t, expected, marshal)

	out2 := new(protocol.UserInfo)
	assert.NoError(t, json.Unmarshal(expected, out2))
	assert.Equal(t, out, out2)
}

func TestUserInfoVerifiedFieldsUnmarshal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		json              string
		wantEmailVerified protocol.Bool
		wantPhoneVerified protocol.Bool
	}{
		{
			name:              "booleans true",
			json:              `{"email_verified": true, "phone_number_verified": true}`,
			wantEmailVerified: true,
			wantPhoneVerified: true,
		},
		{
			name:              "booleans false",
			json:              `{"email_verified": false, "phone_number_verified": false}`,
			wantEmailVerified: false,
			wantPhoneVerified: false,
		},
		{
			name:              "strings true",
			json:              `{"email_verified": "true", "phone_number_verified": "true"}`,
			wantEmailVerified: true,
			wantPhoneVerified: true,
		},
		{
			name:              "strings false",
			json:              `{"email_verified": "false", "phone_number_verified": "false"}`,
			wantEmailVerified: false,
			wantPhoneVerified: false,
		},
		{
			name:              "mixed bool/string",
			json:              `{"email_verified": true, "phone_number_verified": "false"}`,
			wantEmailVerified: true,
			wantPhoneVerified: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got protocol.UserInfo
			err := json.Unmarshal([]byte(tt.json), &got)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantEmailVerified, got.EmailVerified)
			assert.Equal(t, tt.wantPhoneVerified, got.PhoneNumberVerified)
		})
	}
}

func TestBoolUnmarshal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    protocol.Bool
		wantErr bool
	}{
		{
			name:  "bool true",
			input: `true`,
			want:  true,
		},
		{
			name:  "bool false",
			input: `false`,
			want:  false,
		},
		{
			name:  "string true",
			input: `"true"`,
			want:  true,
		},
		{
			name:  "string false",
			input: `"false"`,
			want:  false,
		},
		{
			name:    "invalid string",
			input:   `"yes"`,
			wantErr: true,
		},
		{
			name:    "number",
			input:   `1`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got protocol.Bool
			err := json.Unmarshal([]byte(tt.input), &got)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
