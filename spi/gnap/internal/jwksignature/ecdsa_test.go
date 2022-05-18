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
	"math/big"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
)

func Test_ecdsaSign(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		msg := []byte("the quick brown fox jumps over the lazy dog")

		sig, err := ecdsaSign(msg, ecKey, es256Alg)
		require.NoError(t, err)
		require.NotEmpty(t, sig)
	})

	t.Run("alg not supported", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		sig, err := ecdsaSign(nil, ecKey, "blah blah")
		require.Error(t, err)
		require.Nil(t, sig)
		require.Contains(t, err.Error(), "alg not supported")
	})

	t.Run("signing error", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		ecKey.PublicKey.Curve = &elliptic.CurveParams{
			N: &big.Int{}, // make key invalid so ecdsa.Sign returns an error
		}

		sig, err := ecdsaSign(nil, ecKey, es256Alg)
		require.Error(t, err)
		require.Nil(t, sig)
		require.Contains(t, err.Error(), "error signing with ecdsa")
	})
}

func Test_ecdsaVerify(t *testing.T) {
	publicKey := `{
	"kty": "EC",
	"kid": "key1",
	"crv": "P-256",
	"alg": "ES256",
	"x": "igkN3pcl8OZ9bfzrLCRbflZ9cVmQVKfwXSHDbgN3G6U",
	"y": "0qhuWhPxLeXgEWZnfUXObCZBb-n_wckAE-M5_4tGhWk"
}`

	publicKeyJWK := &jwk.JWK{}

	err := json.Unmarshal([]byte(publicKey), publicKeyJWK)
	require.NoError(t, err)

	sigString := `z4few6IW83cySeJa+JUsyAOpP3hfpL7BkXMiGyN7RS9kMzLDMIJ8PMULomGu3X3iMsQOqFH+B7EdUQdY7IDixA==`

	sig, err := base64.StdEncoding.DecodeString(sigString)
	require.NoError(t, err)

	msg := []byte("the quick brown fox jumps over the lazy dog")

	t.Run("success", func(t *testing.T) {
		err = ecdsaVerifier(publicKeyJWK, msg, sig)
		require.NoError(t, err)
	})

	t.Run("alg not supported", func(t *testing.T) {
		pk := &jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Algorithm: "blah blah",
			},
		}

		err := ecdsaVerifier(pk, nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "alg not supported")
	})

	t.Run("invalid key type", func(t *testing.T) {
		pk := &jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key:       []byte{},
				Algorithm: "ES256",
			},
		}

		err := ecdsaVerifier(pk, nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid public key type")
	})

	t.Run("invalid signature size", func(t *testing.T) {
		err := ecdsaVerifier(publicKeyJWK, nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signature size")
	})

	t.Run("asn.1 unmarshal error", func(t *testing.T) {
		badSig := make([]byte, len(sig)*2)

		err := ecdsaVerifier(publicKeyJWK, nil, badSig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "asn.1 unmarshal")
	})

	t.Run("invalid signature", func(t *testing.T) {
		badSig := make([]byte, len(sig))

		err := ecdsaVerifier(publicKeyJWK, nil, badSig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signature")
	})
}
