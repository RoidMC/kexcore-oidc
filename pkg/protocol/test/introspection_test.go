package protocol_test

import (
	"encoding/json"
	"testing"

	"github.com/muhlemmer/gu"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntrospectionResponse_SetUserInfo(t *testing.T) {
	userInfo := &protocol.UserInfo{
		Subject: "kexcore@example.com",
		UserInfoProfile: protocol.UserInfoProfile{
			PreferredUsername: "testuser",
		},
		Claims: map[string]any{"foo": "bar"},
	}

	tests := []struct {
		name  string
		start *protocol.IntrospectionResponse
		want  *protocol.IntrospectionResponse
	}{
		{
			name:  "nil claims",
			start: &protocol.IntrospectionResponse{},
			want: &protocol.IntrospectionResponse{
				Subject:         userInfo.Subject,
				Username:        userInfo.PreferredUsername,
				UserInfoProfile: userInfo.UserInfoProfile,
				Claims:          gu.MapCopy(userInfo.Claims),
			},
		},
		{
			name: "merge claims",
			start: &protocol.IntrospectionResponse{
				Claims: map[string]any{
					"hello": "world",
				},
			},
			want: &protocol.IntrospectionResponse{
				Subject:         userInfo.Subject,
				Username:        userInfo.PreferredUsername,
				UserInfoProfile: userInfo.UserInfoProfile,
				Claims: map[string]any{
					"foo":   "bar",
					"hello": "world",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.start.SetUserInfo(userInfo)
			assert.Equal(t, tt.want, tt.start)
		})
	}
}

func TestIntrospectionResponse_GetAddress(t *testing.T) {
	i := new(protocol.IntrospectionResponse)
	assert.Equal(t, &protocol.UserInfoAddress{}, i.GetAddress())

	i.Address = &protocol.UserInfoAddress{PostalCode: "1234"}
	assert.Equal(t, i.Address, i.GetAddress())
}

func TestIntrospectionResponse_MarshalJSON(t *testing.T) {
	got, err := json.Marshal(&protocol.IntrospectionResponse{
		UserInfoProfile: protocol.UserInfoProfile{
			PreferredUsername: "testuser",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, `{"active":false,"username":"testuser","preferred_username":"testuser"}`, string(got))
}

func TestIntrospectionResponse_UnmarshalJSON_StringAMR(t *testing.T) {
	var got protocol.IntrospectionResponse
	err := json.Unmarshal([]byte(`{"active":true,"sub":"kexcore@example.com","amr":"pwd"}`), &got)
	assert.NoError(t, err)
	assert.Equal(t, protocol.AuthenticationMethodsReferences{"pwd"}, got.AuthenticationMethodsReferences)
}
