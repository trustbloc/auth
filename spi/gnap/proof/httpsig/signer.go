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

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/yaronf/httpsign"

	"github.com/trustbloc/auth/spi/gnap/internal/digest"
)

// Signer signs GNAP http requests using http-signature.
type Signer struct {
	SigningKey *jwk.JWK
}

const defaultSignatureName = "sig1"

// ProofType returns "httpsig", the GNAP proof type of the http-signature proof method.
func (s *Signer) ProofType() string {
	return "httpsig"
}

// Sign signs the given request using sha-256 for a content digest, and http-signature to sign headers.
func (s *Signer) Sign(request *http.Request, requestBody []byte) (*http.Request, error) {
	return Sign(request, requestBody, s.SigningKey, digest.SHA256)
}

func Sign(req *http.Request, bodyBytes []byte, signingKey *jwk.JWK, digestName string) (*http.Request, error) {
	conf := httpsign.NewSignConfig().SignAlg(false)

	fields := httpsign.Headers("@request-target")

	if len(bodyBytes) > 0 {
		body := ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

		cdHeader, err := httpsign.GenerateContentDigestHeader(&body, []string{digestName})
		if err != nil {
			return nil, err
		}

		req.Header.Add("content-digest", cdHeader)

		fields.AddHeader("content-digest")
	}

	authHeader := req.Header.Get("Authorization")

	if authHeader != "" {
		fields.AddHeader("Authorization")
	}

	signer, err := httpsign.NewJWSSigner(
		jwa.SignatureAlgorithm(signingKey.Algorithm),
		signingKey.KeyID,
		signingKey.Key,
		conf,
		fields,
	)
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}

	sigInput, sig, err := httpsign.SignRequest(defaultSignatureName, *signer, req)
	if err != nil {
		return nil, fmt.Errorf("signing request: %w", err)
	}

	req.Header.Add("Signature", sig)
	req.Header.Add("Signature-Input", sigInput)

	return req, nil
}
