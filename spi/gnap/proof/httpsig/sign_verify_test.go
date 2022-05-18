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
	"github.com/trustbloc/auth/spi/gnap"
)

func TestSignVerify(t *testing.T) {
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

		pubJWK := jwk.JWK{
			JSONWebKey: privJWK.Public(),
			Kty:        "EC",
			Crv:        "P-256",
		}

		req, err = Sign(req, body, privJWK, "sha-256")
		require.NoError(t, err)

		v := NewVerifier(req)

		err = v.Verify(&gnap.ClientKey{
			Proof: "httpsig",
			JWK:   pubJWK,
		})
		require.NoError(t, err)
	})
}
