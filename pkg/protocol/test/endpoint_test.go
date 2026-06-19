package protocol_test

import (
	"testing"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func TestEndpoint_Path(t *testing.T) {
	tests := []struct {
		name string
		e    *protocol.Endpoint
		want string
	}{
		{
			"without starting /",
			protocol.NewEndpoint("test"),
			"/test",
		},
		{
			"with starting /",
			protocol.NewEndpoint("/test"),
			"/test",
		},
		{
			"with url",
			protocol.NewEndpointWithURL("/test", "http://test.com/test"),
			"/test",
		},
		{
			"nil",
			nil,
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.Relative(); got != tt.want {
				t.Errorf("Endpoint.Relative() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEndpoint_Absolute(t *testing.T) {
	type args struct {
		host string
	}
	tests := []struct {
		name string
		e    *protocol.Endpoint
		args args
		want string
	}{
		{
			"no /",
			protocol.NewEndpoint("test"),
			args{"https://host"},
			"https://host/test",
		},
		{
			"endpoint without /",
			protocol.NewEndpoint("test"),
			args{"https://host/"},
			"https://host/test",
		},
		{
			"host without /",
			protocol.NewEndpoint("/test"),
			args{"https://host"},
			"https://host/test",
		},
		{
			"both /",
			protocol.NewEndpoint("/test"),
			args{"https://host/"},
			"https://host/test",
		},
		{
			"with url",
			protocol.NewEndpointWithURL("test", "https://test.com/test"),
			args{"https://host"},
			"https://test.com/test",
		},
		{
			"nil",
			nil,
			args{"https://host"},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.Absolute(tt.args.host); got != tt.want {
				t.Errorf("Endpoint.Absolute() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEndpoint_Validate(t *testing.T) {
	tests := []struct {
		name    string
		e       *protocol.Endpoint
		wantErr error
	}{
		{
			"nil",
			nil,
			protocol.ErrNilEndpoint,
		},
		{
			"valid",
			protocol.NewEndpoint("test"),
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.e.Validate()
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
