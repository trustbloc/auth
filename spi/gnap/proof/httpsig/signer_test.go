/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/auth/spi/gnap/internal/digest"
)

func TestSigner(t *testing.T) {
	t.Run("ProofType", func(t *testing.T) {
		require.Equal(t, "httpsig", (&Signer{}).ProofType())
	})

	t.Run("Sign", func(t *testing.T) {
		body := []byte("foo bar baz")

		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", bytes.NewReader(body))

		req.Header.Add("Authorization", "Bearer OPEN-SESAME")

		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		privJWK := &jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key:       priv,
				KeyID:     "key1",
				Algorithm: "ES256",
			},
			Kty: "EC",
			Crv: "P-256",
		}

		signer := &Signer{
			SigningKey: privJWK,
		}

		req, err = signer.Sign(req, body)
		require.NoError(t, err)
	})

}

func TestSign(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		body := []byte("foo bar baz")

		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", bytes.NewReader(body))

		req.Header.Add("Authorization", "Bearer OPEN-SESAME")

		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		privJWK := &jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key:       priv,
				KeyID:     "key1",
				Algorithm: "ES256",
			},
			Kty: "EC",
			Crv: "P-256",
		}

		req, err = Sign(req, body, privJWK, digest.SHA256)
		require.NoError(t, err)
	})

	t.Run("jwk marshal error", func(t *testing.T) {
		body := []byte("foo bar baz")

		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", bytes.NewReader(body))

		req.Header.Add("Authorization", "Bearer OPEN-SESAME")

		privJWK := &jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key:       []byte{},
				KeyID:     "key1",
				Algorithm: "ES256",
			},
			Kty: "OKP", // incorrect type data, to force a marshalling error
			Crv: "X25519",
		}

		_, err := Sign(req, body, privJWK, digest.SHA256)
		require.Error(t, err)
		require.Contains(t, err.Error(), "marshalling signing key")
	})

	t.Run("unsupported digest", func(t *testing.T) {
		body := []byte("foo bar baz")

		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", bytes.NewReader(body))

		req.Header.Add("Authorization", "Bearer OPEN-SESAME")

		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		privJWK := &jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key:       priv,
				KeyID:     "key1",
				Algorithm: "ES256",
			},
			Kty: "EC",
			Crv: "P-256",
		}

		req, err = Sign(req, body, privJWK, "unknown digest")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported digest")
	})

	t.Run("fail to sign", func(t *testing.T) {
		body := []byte("foo bar baz")

		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", bytes.NewReader(body))

		req.Header.Add("Authorization", "Bearer OPEN-SESAME")

		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		privJWK := &jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key:       &priv.PublicKey, // jwk algorithm will fail to sign given a public key
				KeyID:     "key1",
				Algorithm: "ES256",
			},
			Kty: "EC",
			Crv: "P-256",
		}

		req, err = Sign(req, body, privJWK, digest.SHA256)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign")
	})
}
