/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gnap

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// MakeNonce generates a base64-encoded 12-bit random nonce.
func MakeNonce() (string, error) {
	r := make([]byte, 12)

	if _, err := rand.Read(r); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(r), nil
}
