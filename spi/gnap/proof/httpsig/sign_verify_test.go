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
	}{
		{
			crv:        elliptic.P256(),
			alg:        "ES256",
			digestName: "sha-256",
		},
		{
			crv:        elliptic.P384(),
			alg:        "ES384",
			digestName: "sha-384",
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
			body := []byte("foo bar baz")

			req := httptest.NewRequest(http.MethodPost, "http://foo.bar/baz", bytes.NewReader(body))

			req.Header.Add("Authorization", "Bearer OPEN-SESAME")

			priv, err := ecdsa.GenerateKey(tc.crv, rand.Reader)
			require.NoError(t, err)

			privJWK := &jwk.JWK{
				JSONWebKey: jose.JSONWebKey{
					Key:       priv,
					KeyID:     "key1",
					Algorithm: tc.alg,
				},
				Kty: "EC",
				Crv: tc.crv.Params().Name,
			}

			pubJWK := jwk.JWK{
				JSONWebKey: privJWK.Public(),
				Kty:        "EC",
				Crv:        tc.crv.Params().Name,
			}

			req, err = Sign(req, body, privJWK, tc.digestName)
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
