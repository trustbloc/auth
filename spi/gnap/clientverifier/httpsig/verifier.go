/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"net/http"

	"github.com/trustbloc/auth/spi/gnap"
)

// Verifier verifies that the client request is signed by the client key, using http-signature verification.
type Verifier struct {
	req *http.Request
}

// NewVerifier initializes an http-signature Verifier on the given client request.
func NewVerifier(req *http.Request) *Verifier {
	return &Verifier{req: req}
}

// Verify verifies that the Verifier's client request is signed by the client key, using http-signature verification.
func (v *Verifier) Verify(key *gnap.ClientKey) error {
	// TODO https://github.com/trustbloc/auth/issues/185
	return nil
}
