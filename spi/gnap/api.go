/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gnap

// Signer api for GNAP http signatures.
type Signer interface {
	Sign(msg []byte) ([]byte, error)
}

// Verifier api for GNAP http signatures verification.
type Verifier interface {
	Verify(msg, sig []byte) error
}
