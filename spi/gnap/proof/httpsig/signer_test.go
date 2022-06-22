/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"bytes"
	"crypto/elliptic"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
)

func TestProofType(t *testing.T) {
	require.Equal(t, "httpsig", (&Signer{}).ProofType())
}

func TestSign(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		priv, _ := jwkPairECDSA(t, "ES256", elliptic.P256())

		body := []byte("foo bar baz")

		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", bytes.NewReader(body))

		// include an auth header to be signed as well
		req.Header.Add("Authorization", "FOO bar")

		signer := Signer{
			SigningKey: priv,
		}

		signedReq, err := signer.Sign(req, body)
		require.NoError(t, err)

		sig := signedReq.Header.Get("signature")
		require.NotEmpty(t, sig)
		sigParams := signedReq.Header.Get("signature-input")
		require.NotEmpty(t, sigParams)
	})

	t.Run("fail to create signer", func(t *testing.T) {
		priv := &jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Algorithm: "foo",
			},
		}

		body := []byte("foo bar baz")

		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", bytes.NewReader(body))

		signer := Signer{
			SigningKey: priv,
		}

		_, err := signer.Sign(req, body)
		require.Error(t, err)
		require.Contains(t, err.Error(), "creating signer")
	})

	t.Run("fail to sign invalid request", func(t *testing.T) {
		priv, _ := jwkPairECDSA(t, "ES256", elliptic.P256())

		body := []byte("")

		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", nil)

		req.Header.Add("@invalid-header", "foo")

		signer := Signer{
			SigningKey: priv,
		}

		_, err := signer.Sign(req, body)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signing request")
	})
}
