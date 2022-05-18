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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/auth/spi/gnap"
	"github.com/trustbloc/auth/spi/gnap/internal/digest"
)

func TestNewVerifier(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/example/path", nil)

	v := NewVerifier(req)

	require.NotNil(t, v)
	require.Equal(t, req, v.req)
}

func TestVerifier_Verify(t *testing.T) {
	t.Run("jwk marshal error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/example/path", nil)

		v := NewVerifier(req)

		err := v.Verify(&gnap.ClientKey{
			JWK: jwk.JWK{
				JSONWebKey: jose.JSONWebKey{
					Key:       []byte{},
					KeyID:     "key1",
					Algorithm: "ES256",
				},
				Kty: "OKP", // incorrect type data, to force a marshalling error
				Crv: "X25519",
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "marshalling verification key")
	})

	t.Run("fail to read body", func(t *testing.T) {
		expectErr := errors.New("expected error")

		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", &errorReader{err: expectErr})

		v := NewVerifier(req)

		err := v.Verify(clientKey(t))
		require.Error(t, err)
		require.ErrorIs(t, err, expectErr)
	})

	t.Run("has body but no content-digest", func(t *testing.T) {
		body := []byte("foo bar baz")

		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", bytes.NewReader(body))

		v := NewVerifier(req)

		err := v.Verify(clientKey(t))
		require.Error(t, err)
		require.Contains(t, err.Error(), "should have a content-digest")
	})

	t.Run("content-digest header has invalid format", func(t *testing.T) {
		body := []byte("foo bar baz")

		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", bytes.NewReader(body))

		req.Header.Set("content-digest", "foo")

		v := NewVerifier(req)

		err := v.Verify(clientKey(t))
		require.Error(t, err)
		require.Contains(t, err.Error(), "content-digest header should have name and value")
	})

	t.Run("unsupported content-digest algorithm", func(t *testing.T) {
		body := []byte("foo bar baz")

		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", bytes.NewReader(body))

		req.Header.Set("content-digest", "foo:bar:")

		v := NewVerifier(req)

		err := v.Verify(clientKey(t))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported digest")
	})

	t.Run("invalid digest value", func(t *testing.T) {
		body := []byte("foo bar baz")

		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", bytes.NewReader(body))

		req.Header.Set("content-digest", digest.SHA256+"=:#&^^%##$:")

		v := NewVerifier(req)

		err := v.Verify(clientKey(t))
		require.Error(t, err)
		require.Contains(t, err.Error(), "decoding digest value")
	})

	t.Run("digest does not match", func(t *testing.T) {
		body := []byte("foo bar baz")

		req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", bytes.NewReader(body))

		req.Header.Set("content-digest", digest.SHA256+"=:eyJk:")

		v := NewVerifier(req)

		err := v.Verify(clientKey(t))
		require.Error(t, err)
		require.Contains(t, err.Error(), "content-digest header does not match digest")
	})

	t.Run("signature verification error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://foo.bar/baz", nil)

		v := NewVerifier(req)

		err := v.Verify(clientKey(t))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed verification")
	})

}

func clientKey(t *testing.T) *gnap.ClientKey {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return &gnap.ClientKey{
		JWK: jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key:       &(priv.PublicKey),
				KeyID:     "key1",
				Algorithm: "ES256",
			},
			Kty: "EC",
			Crv: "P-256",
		},
	}
}

type errorReader struct {
	err error
}

func (e *errorReader) Read([]byte) (int, error) {
	return 0, e.err
}
