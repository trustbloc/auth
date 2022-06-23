/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwksignature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
)

const (
	es256Alg = "ES256"
	es384Alg = "ES384"
	es512Alg = "ES512"
)

func TestSignatureAlgorithm_Algorithm(t *testing.T) {
	mockAlg := "mock-alg"

	alg := NewJWKAlgorithm(mockAlg)

	require.Equal(t, mockAlg, alg.Algorithm())
}

func TestSignatureAlgorithm_Create(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		_, privData := secretPair(t, es256Alg, elliptic.P256())

		msg := []byte("the quick brown fox jumps over the lazy dog")

		alg := NewJWKAlgorithm(es256Alg)

		sig, err := alg.Create(privData, msg)
		require.NoError(t, err)
		require.NotEmpty(t, sig)
	})

	t.Run("unmarshal error", func(t *testing.T) {
		privData := httpsignatures.Secret{
			PrivateKey: "foo bar baz",
		}

		alg := NewJWKAlgorithm(es256Alg)

		sig, err := alg.Create(privData, nil)
		require.Nil(t, sig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing secret")
	})

	t.Run("unsupported key type", func(t *testing.T) {
		privData := httpsignatures.Secret{
			PrivateKey: `{
					"kty": "OKP",
					"use": "enc",
					"crv": "Ed25519",
					"kid": "sample@sample.id",
					"x": "sEHL6KXs8bUz9Ss2qSWWjhhRMHVjrog0lzFENM132R8",
					"alg": "EdDSA"
				}`,
		}

		alg := NewJWKAlgorithm(es256Alg)

		sig, err := alg.Create(privData, nil)
		require.Nil(t, sig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key type not supported")
	})
}

func TestSignatureAlgorithm_Verify(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		publicKey := `{
	"kty": "EC",
	"kid": "key1",
	"crv": "P-256",
	"alg": "ES256",
	"x": "igkN3pcl8OZ9bfzrLCRbflZ9cVmQVKfwXSHDbgN3G6U",
	"y": "0qhuWhPxLeXgEWZnfUXObCZBb-n_wckAE-M5_4tGhWk"
}`

		pubData := httpsignatures.Secret{
			KeyID:      "key1",
			PrivateKey: publicKey,
			Algorithm:  es256Alg,
		}

		sigString := `z4few6IW83cySeJa+JUsyAOpP3hfpL7BkXMiGyN7RS9kMzLDMIJ8PMULomGu3X3iMsQOqFH+B7EdUQdY7IDixA==`

		sig, err := base64.StdEncoding.DecodeString(sigString)
		require.NoError(t, err)

		msg := []byte("the quick brown fox jumps over the lazy dog")

		alg := NewJWKAlgorithm(es256Alg)

		err = alg.Verify(pubData, msg, sig)
		require.NoError(t, err)

	})

	t.Run("unmarshal error", func(t *testing.T) {
		privData := httpsignatures.Secret{
			PrivateKey: "foo bar baz",
		}

		alg := NewJWKAlgorithm(es256Alg)

		err := alg.Verify(privData, nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing public key")
	})

	t.Run("unsupported key type", func(t *testing.T) {
		privData := httpsignatures.Secret{
			PrivateKey: `{
					"kty": "OKP",
					"use": "enc",
					"crv": "Ed25519",
					"kid": "sample@sample.id",
					"x": "sEHL6KXs8bUz9Ss2qSWWjhhRMHVjrog0lzFENM132R8",
					"alg": "EdDSA"
				}`,
		}

		alg := NewJWKAlgorithm(es256Alg)

		err := alg.Verify(privData, nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key type not supported")
	})
}

func Test_SignVerify(t *testing.T) {
	tests := []struct {
		name string
		crv  elliptic.Curve
	}{
		{
			name: es256Alg,
			crv:  elliptic.P256(),
		},
		{
			name: es384Alg,
			crv:  elliptic.P384(),
		},
		{
			name: es512Alg,
			crv:  elliptic.P521(),
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(fmt.Sprintf("success SignVerify %s", tc.name), func(t *testing.T) {
			pubData, privData := secretPair(t, tc.name, tc.crv)

			msg := []byte("the quick brown fox jumps over the lazy dog")

			alg := NewJWKAlgorithm(tc.name)

			sig, err := alg.Create(privData, msg)
			require.NoError(t, err)

			err = alg.Verify(pubData, msg, sig)
			require.NoError(t, err)
		})
	}
}

func secretPair(t *testing.T, alg string, crv elliptic.Curve) (pub, priv httpsignatures.Secret) {
	t.Helper()

	ecKey, err := ecdsa.GenerateKey(crv, rand.Reader)
	require.NoError(t, err)

	kid := "key1"

	privJWK := &jwk.JWK{
		JSONWebKey: jose.JSONWebKey{
			Key:       ecKey,
			KeyID:     kid,
			Algorithm: alg,
		},
		Kty: "EC",
		Crv: crv.Params().Name,
	}

	privBytes, err := json.Marshal(privJWK)
	require.NoError(t, err)

	pubJWK := privJWK.Public()

	pubBytes, err := json.Marshal(&pubJWK)
	require.NoError(t, err)

	return httpsignatures.Secret{
			KeyID:      kid,
			PrivateKey: string(pubBytes),
			Algorithm:  alg,
		}, httpsignatures.Secret{
			KeyID:      kid,
			PrivateKey: string(privBytes),
			Algorithm:  alg,
		}
}
