/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwksignature

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/igor-pavlenko/httpsignatures-go"
)

// SignatureAlgorithm provides http-signature JWK signatures.
type SignatureAlgorithm struct {
	alg string
}

// NewJWKAlgorithm
func NewJWKAlgorithm(alg string) *SignatureAlgorithm {
	return &SignatureAlgorithm{
		alg: alg,
	}
}

// Algorithm returns the SignatureAlgorithm's algorithm.
func (s *SignatureAlgorithm) Algorithm() string {
	return s.alg
}

// Create implements http-signatures' Signer API.
func (s *SignatureAlgorithm) Create(secret httpsignatures.Secret, data []byte) ([]byte, error) {
	priv := &jwk.JWK{}

	err := priv.UnmarshalJSON([]byte(secret.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("parsing secret into JWK: %w", err)
	}

	switch k := priv.Key.(type) {
	case *ecdsa.PrivateKey:
		return ecdsaSign(data, k, priv.Algorithm)
	default:
		return nil, errors.New("key type not supported")
	}
}

func (s *SignatureAlgorithm) Verify(secret httpsignatures.Secret, data []byte, signature []byte) error {
	pub := &jwk.JWK{}

	// Note: httpsignatures-go uses PrivateKey value to store public key too.
	err := pub.UnmarshalJSON([]byte(secret.PrivateKey))
	if err != nil {
		return fmt.Errorf("parsing public key into JWK: %w", err)
	}

	switch pub.Key.(type) {
	case *ecdsa.PublicKey, *ecdsa.PrivateKey:
		return ecdsaVerifier(pub, data, signature)
	default:
		return errors.New("key type not supported")
	}
}
