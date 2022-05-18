/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package digest

import (
	"crypto"
	_ "crypto/sha256"
	"errors"
)

const (
	SHA256 = "sha-256"
)

// Digest computes the content-digest of the given message.
type Digest func([]byte) ([]byte, error)

// GetDigest returns the Digest matching the given name.
func GetDigest(name string) (Digest, error) {
	switch name {
	case SHA256:
		return hashToDigest(crypto.SHA256), nil
	default:
		return nil, errors.New("unsupported digest")
	}
}

func hashToDigest(hash crypto.Hash) Digest {
	return func(msg []byte) ([]byte, error) {
		h := hash.New()
		_, err := h.Write(msg)
		if err != nil {
			return nil, err
		}

		return h.Sum(nil), nil
	}
}
