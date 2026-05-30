package protocol

import (
	"context"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
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

const KeyUseSignature = "sig"

type KeySet interface {
	VerifySignature(ctx context.Context, rawToken []byte) (payload []byte, err error)
}

func GetKeyIDAndAlg(jwsMsg *jws.Message) (string, string) {
	keyID := ""
	alg := ""
	for _, sig := range jwsMsg.Signatures() {
		keyID, _ = sig.ProtectedHeaders().KeyID()
		sigAlg, _ := sig.ProtectedHeaders().Algorithm()
		alg = sigAlg.String()
		break
	}
	return keyID, alg
}

func FindMatchingKey(keyID, use, expectedAlg string, keys ...jwk.Key) (key jwk.Key, err error) {
	var validKeys []jwk.Key
	for _, k := range keys {
		keyUsage, _ := k.KeyUsage()
		if keyUsage != use && keyUsage != "" {
			continue
		}
		if !algToKeyType(k, expectedAlg) {
			continue
		}
		kid, _ := k.KeyID()
		if kid == keyID && keyID != "" {
			return k, nil
		}
		if kid == "" || keyID == "" {
			validKeys = append(validKeys, k)
		}
	}
	if len(validKeys) == 1 {
		return validKeys[0], nil
	}
	if len(validKeys) > 1 {
		return nil, ErrKeyMultiple
	}
	return nil, ErrKeyNone
}

func algToKeyType(key jwk.Key, alg string) bool {
	kty := key.KeyType()
	if strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS") {
		return kty == jwa.RSA()
	}
	if strings.HasPrefix(alg, "ES") || alg == "SGD_SM3_SM2" {
		return kty == jwa.EC()
	}
	if alg == "EdDSA" {
		return kty == jwa.OKP()
	}
	return false
}
