/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"bytes"
	"crypto/elliptic"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/auth/spi/gnap"
)

func TestVerify(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		priv, pub := jwkPairECDSA(t, "ES256", elliptic.P256())

		body := []byte("foo bar baz")

		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", bytes.NewReader(body))

		// include an auth header to be verified as well
		req.Header.Add("Authorization", "FOO bar")

		signer := Signer{
			SigningKey: priv,
		}

		signedReq, err := signer.Sign(req, body)
		require.NoError(t, err)

		verifier := NewVerifier(signedReq)

		require.NoError(t, verifier.Verify(&gnap.ClientKey{
			JWK: pub,
		}))
	})

	t.Run("fail to read malformed body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", badBody("fail to read body"))

		verifier := NewVerifier(req)

		err := verifier.Verify(&gnap.ClientKey{
			JWK: jwk.JWK{},
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "fail to read body")
	})

	t.Run("fail to create httpsign verifier", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", nil)

		verifier := NewVerifier(req)

		err := verifier.Verify(&gnap.ClientKey{
			JWK: jwk.JWK{},
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "creating verifier")
	})

	t.Run("verification error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", nil)

		_, pub := jwkPairECDSA(t, "ES256", elliptic.P256())

		verifier := NewVerifier(req)

		err := verifier.Verify(&gnap.ClientKey{
			JWK: pub,
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "verifying request")
	})
}

type badBody string

func (b badBody) Read([]byte) (int, error) {
	return 0, errors.New(string(b))
}
