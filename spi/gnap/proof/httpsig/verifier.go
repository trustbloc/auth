/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/trustbloc/auth/spi/gnap"
	"github.com/yaronf/httpsign"
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
	verKey := key.JWK

	fields := httpsign.Headers("@request-target")

	if v.req.Header.Get("Authorization") != "" {
		fields.AddHeader("Authorization")
	}

	if v.req.Body != nil {
		bodyBytes, err := ioutil.ReadAll(v.req.Body)
		if err != nil {
			return err
		}

		v.req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

		if len(bodyBytes) > 0 {
			fields.AddHeader("content-digest")
		}
	}

	verifier, err := httpsign.NewJWSVerifier(
		jwa.SignatureAlgorithm(verKey.Algorithm),
		verKey.Key,
		verKey.KeyID,
		nil,
		fields,
	)
	if err != nil {
		return fmt.Errorf("creating verifier: %w", err)
	}

	err = httpsign.VerifyRequest(defaultSignatureName, *verifier, v.req)
	if err != nil {
		return fmt.Errorf("verifying request: %w", err)
	}

	return nil
}
