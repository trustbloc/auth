/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwksignature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
)

// copied from afgo:pkg/doc/util/signature/internal/signer/ecdsa.go
//nolint:gomnd
func ecdsaSign(msg []byte, privateKey *ecdsa.PrivateKey, alg string) ([]byte, error) {
	var hash crypto.Hash

	switch alg {
	case "ES256":
		hash = crypto.SHA256
	default:
		return nil, errors.New("alg not supported")
	}

	hasher := hash.New()
	_, err := hasher.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("ecdsa hash error: %w", err)
	}

	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
	if err != nil {
		return nil, fmt.Errorf("error signing with ecdsa: %w", err)
	}

	curveBits := privateKey.Curve.Params().BitSize

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	copyPadded := func(source []byte, size int) []byte {
		dest := make([]byte, size)
		copy(dest[size-len(source):], source)

		return dest
	}

	return append(copyPadded(r.Bytes(), keyBytes), copyPadded(s.Bytes(), keyBytes)...), nil
}

func ecdsaVerifier(pubKeyJWK *jwk.JWK, msg, signature []byte) error {
	switch pubKeyJWK.Algorithm {
	case "ES256":
		return ecdsaVerify(pubKeyJWK, msg, signature, 32, crypto.SHA256)
	}

	return errors.New("ecdsa alg not supported")
}

// copied (with amendments) from afgo:pkg/doc/signature/verifier/public_key_verifier.go
func ecdsaVerify(pubKeyJWK *jwk.JWK, msg, signature []byte, keySize int, hash crypto.Hash) error {
	ecdsaPubKey, ok := pubKeyJWK.Key.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("invalid public key type")
	}

	if len(signature) < 2*keySize {
		return errors.New("invalid signature size")
	}

	hasher := hash.New()

	_, err := hasher.Write(msg)
	if err != nil {
		return errors.New("hash error")
	}

	hashValue := hasher.Sum(nil)

	r := big.NewInt(0).SetBytes(signature[:keySize])
	s := big.NewInt(0).SetBytes(signature[keySize:])

	if len(signature) > 2*keySize {
		var esig struct {
			R, S *big.Int
		}

		if _, err := asn1.Unmarshal(signature, &esig); err != nil {
			return fmt.Errorf("asn.1 unmarshal: %w", err)
		}

		r = esig.R
		s = esig.S
	}

	verified := ecdsa.Verify(ecdsaPubKey, hashValue, r, s)
	if !verified {
		return errors.New("invalid signature")
	}

	return nil
}
