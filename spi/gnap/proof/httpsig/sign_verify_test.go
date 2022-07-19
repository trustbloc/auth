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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/auth/spi/gnap"
)

func TestSignVerify(t *testing.T) {
	tests := []struct {
		crv        elliptic.Curve
		alg        string
		digestName string
		body       []byte
	}{
		{
			crv:        elliptic.P256(),
			alg:        "ES256",
			digestName: "sha-256",
			body:       []byte("foo bar baz"),
		},
		{
			crv:        elliptic.P384(),
			alg:        "ES384",
			digestName: "sha-512", // sha-384 is not a supported digest algorithm in the http-digest-headers spec.
			body:       []byte("foo bar baz"),
		},
		{
			crv:        elliptic.P521(),
			alg:        "ES512",
			digestName: "sha-512",
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(fmt.Sprintf("success %s", tc.alg), func(t *testing.T) {
			var req *http.Request
			if len(tc.body) > 0 {
				req = httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", bytes.NewReader(tc.body))
			} else {
				req = httptest.NewRequest(http.MethodGet, "http://foo.bar/baz", nil)
			}

			req.Header.Add("Authorization", "Bearer OPEN-SESAME")

			privJWK, pubJWK := jwkPairECDSA(t, tc.alg, tc.crv)

			req, err := Sign(req, tc.body, privJWK, tc.digestName)
			require.NoError(t, err)

			v := NewVerifier(req)

			err = v.Verify(&gnap.ClientKey{
				Proof: "httpsig",
				JWK:   pubJWK,
			})
			require.NoError(t, err)
		})
	}
}

func jwkPairECDSA(t *testing.T, alg string, crv elliptic.Curve) (*jwk.JWK, jwk.JWK) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(crv, rand.Reader)
	require.NoError(t, err)

	privJWK := &jwk.JWK{
		JSONWebKey: jose.JSONWebKey{
			Key:       priv,
			KeyID:     "key1",
			Algorithm: alg,
		},
		Kty: "EC",
		Crv: crv.Params().Name,
	}

	pubJWK := jwk.JWK{
		JSONWebKey: privJWK.Public(),
		Kty:        "EC",
		Crv:        crv.Params().Name,
	}

	return privJWK, pubJWK
}
