package protocol

import (
	"context"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

type KeyStore interface {
	KeySet(ctx context.Context) ([]Key, error)
	SignatureAlgorithms(ctx context.Context) ([]string, error)
}

type Key interface {
	ID() string
	Algorithm() string
	Use() string
	Key() jwk.Key
}

type SigningKey interface {
	ID() string
	Algorithm() string
	Key() jwk.Key
}