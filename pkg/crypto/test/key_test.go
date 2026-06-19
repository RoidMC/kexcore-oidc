// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package crypto_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"

	gmsm "github.com/emmansun/gmsm/sm2"

	zcrypto "github.com/roidmc/kexcore-oidc/v2/pkg/crypto"
)

var oidSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}

type pkcs8Key struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func sm2PrivateKeyToPEM(sm2Key *gmsm.PrivateKey) ([]byte, error) {
	ecdhKey, err := sm2Key.ECDH()
	if err != nil {
		return nil, err
	}
	privBytes := ecdhKey.Bytes()

	pubKey := sm2Key.PublicKey
	pubBytes := make([]byte, 1+2*32)
	pubBytes[0] = 4
	pubKey.X.FillBytes(pubBytes[1 : 1+32])
	pubKey.Y.FillBytes(pubBytes[1+32 : 1+2*32])

	inner, err := asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    privBytes,
		NamedCurveOID: oidSM2,
		PublicKey:     asn1.BitString{Bytes: pubBytes, BitLength: 8 * len(pubBytes)},
	})
	if err != nil {
		return nil, err
	}

	outer, err := asn1.Marshal(pkcs8Key{
		Version: 0,
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  oidSM2,
			Parameters: asn1.NullRawValue,
		},
		PrivateKey: inner,
	})
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: outer}), nil
}

func TestBytesToPrivateKey(t *testing.T) {
	type args struct {
		key []byte
	}
	type want struct {
		key       crypto.Signer
		algorithm string
		err       error
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "PEMDecodeError",
			args: args{
				key: []byte("The non-PEM sequence"),
			},
			want: want{
				err: zcrypto.ErrPEMDecode,
			},
		},
		{
			name: "PKCS#1 RSA",
			args: args{
				key: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
-----END RSA PRIVATE KEY-----`),
			},
			want: want{
				key:       &rsa.PrivateKey{},
				algorithm: "RS256",
				err:       nil,
			},
		},
		{
			name: "PKCS#8 RSA",
			args: args{
				key: []byte(`-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCfaDB7pK/fmP/I
7IusSK8lTCBnPZghqIbVLt2QHYAMoEF1CaF4F4rxo2vl1Mt8gwsq4T3osQFZMvnL
YHb7KNyUoJgTjLxJQADv2u4Q3U38heAzK5Tp4ry4MCnuyJIqAPK1GiruwEq4zQrx
+WzVix8otO37SuW9tzklqlNGMiAYBL0TBKHvS5XMbjP1idBMB8erMz29w/TVQnEB
Kj0vCdZjrbVPKygptt5kcSrL5f4xCZwU+ufz7cp0GLwpRMJ+shG9YJJFBxb0itPF
sy51vAyEtdBC7jgAU96ZVeQ06nryDq1D2EpoVMElqNyL46Jo3lnKbGquGKzXzQYU
BN32/scDAgMBAAECggEBAJE/mo3PLgILo2YtQ8ekIxNVHmF0Gl7w9IrjvTdH6hmX
HI3MTLjkmtI7GmG9V/0IWvCjdInGX3grnrjWGRQZ04QKIQgPQLFuBGyJjEsJm7nx
MqztlS7YTyV1nX/aenSTkJO8WEpcJLnm+4YoxCaAMdAhrIdBY71OamALpv1bRysa
FaiCGcemT2yqZn0GqIS8O26Tz5zIqrTN2G1eSmgh7DG+7FoddMz35cute8R10xUG
hF5YU+6fcXiRQ/Kh7nlxelPGqdZFPMk7LpVHzkQKwdJ+N0P23lPDIfNsvpG1n0OP
3g5km7gHSrSU2yZ3eFl6DB9x1IFNS9BaQQuSxYJtKwECgYEA1C8jjzpXZDLvlYsV
2jlMzkrbsIrX2dzblVrNsPs2jRbjYU8mg2DUDO6lOhtxHfqZG6sO+gmWi/zvoy9l
yolGbXe1Jqx66p9fznIcecSwar8+ACa356Wk74Nt1PlBOfCMqaJnYLOLaFJa29Vy
u5ClZVzKd5AVXl7yFVd4XfLv/WECgYEAwFMMtFoasdF92c0d31rZ1uoPOtFz6xq6
uQggdm5zzkhnfwUAGqppS/u1CHcJ7T/74++jLbFTsaohGr4jEzWSGvJpomEUChy3
r25YofMclUhJ5pCEStsLtqiCR1Am6LlI8HMdBEP1QDgEC5q8bQW4+UHuew1E1zxz
osZOhe09WuMCgYEA0G9aFCnwjUqIFjQiDFP7gi8BLqTFs4uE3Wvs4W11whV42i+B
ms90nxuTjchFT3jMDOT1+mOO0wdudLRr3xEI8SIF/u6ydGaJG+j21huEXehtxIJE
aDdNFcfbDbqo+3y1ATK7MMBPMvSrsoY0hdJq127WqasNgr3sO1DIuima3SECgYEA
nkM5TyhekzlbIOHD1UsDu/D7+2DkzPE/+oePfyXBMl0unb3VqhvVbmuBO6gJiSx/
8b//PdiQkMD5YPJaFrKcuoQFHVRZk0CyfzCEyzAts0K7XXpLAvZiGztriZeRjSz7
srJnjF0H8oKmAY6hw+1Tm/n/b08p+RyL48TgVSE2vhUCgYA3BWpkD4PlCcn/FZsq
OrLFyFXI6jIaxskFtsRW1IxxIlAdZmxfB26P/2gx6VjLdxJI/RRPkJyEN2dP7CbR
BDjb565dy1O9D6+UrY70Iuwjz+OcALRBBGTaiF2pLn6IhSzNI2sy/tXX8q8dBlg9
OFCrqT/emes3KytTPfa5NZtYeQ==
-----END PRIVATE KEY-----`),
			},
			want: want{
				key:       &rsa.PrivateKey{},
				algorithm: "RS256",
				err:       nil,
			},
		},
		{
			name: "PKCS#8 ECDSA",
			args: args{
				key: []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwwOZSU4GlP7ps/Wp
V6o0qRwxultdfYo/uUuj48QZjSuhRANCAATMiI2Han+ABKmrk5CNlxRAGC61w4d3
G4TAeuBpyzqJ7x/6NjCxoQzJzZHtNjIfjVATI59XFZWF59GhtSZbShAr
-----END PRIVATE KEY-----`),
			},
			want: want{
				key:       &ecdsa.PrivateKey{},
				algorithm: "ES256",
				err:       nil,
			},
		},
		{
			name: "PKCS#8 ED25519",
			args: args{
				key: []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHu6ZtDsjjauMasBxnS9Fg87UJwKfcT/oiq6S0ktbky8
-----END PRIVATE KEY-----`),
			},
			want: want{
				key:       ed25519.PrivateKey{},
				algorithm: "EdDSA",
				err:       nil,
			},
		},
		{
			name: "PKCS#8 SM2",
			args: args{
				key: func() []byte {
					sm2Key, _ := gmsm.GenerateKey(rand.Reader)
					pem, _ := sm2PrivateKeyToPEM(sm2Key)
					return pem
				}(),
			},
			want: want{
				key:       &gmsm.PrivateKey{},
				algorithm: zcrypto.SGD_SM3_SM2,
				err:       nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotAlgorithm, err := zcrypto.BytesToPrivateKey(tt.args.key)
			if tt.want.err != nil {
				assert.ErrorIs(t, err, tt.want.err)
				return
			}
			assert.NoError(t, err)
			assert.IsType(t, tt.want.key, gotKey)
			assert.Equal(t, tt.want.algorithm, gotAlgorithm)
		})
	}
}
