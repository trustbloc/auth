/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/igor-pavlenko/httpsignatures-go"

	"github.com/trustbloc/auth/spi/gnap"
	"github.com/trustbloc/auth/spi/gnap/internal/digest"
	"github.com/trustbloc/auth/spi/gnap/internal/jwksignature"
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
	keyBytes, err := json.Marshal(&key.JWK)
	if err != nil {
		return fmt.Errorf("marshalling verification key: %w", err)
	}

	ss := httpsignatures.NewSimpleSecretsStorage(map[string]httpsignatures.Secret{
		key.JWK.KeyID: {
			KeyID:      key.JWK.KeyID,
			PublicKey:  "",
			PrivateKey: string(keyBytes),
			Algorithm:  key.JWK.Algorithm,
		},
	})
	hs := httpsignatures.NewHTTPSignatures(ss)
	hs.SetSignatureHashAlgorithm(jwksignature.NewJWKAlgorithm(key.JWK.Algorithm))

	var bodyBytes []byte

	if v.req.Body != nil {
		bodyBytes, err = ioutil.ReadAll(v.req.Body)
		if err != nil {
			return err
		}

		v.req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

		if len(bodyBytes) > 0 {
			err = verifyDigest(v.req, bodyBytes)
			if err != nil {
				return err
			}

			// TODO: confirm that the content-digest header is included in the http-signature input.
		}
	}

	err = hs.Verify(v.req)
	if err != nil {
		return fmt.Errorf("failed verification: %w", err)
	}

	return nil
}

func verifyDigest(req *http.Request, bodyBytes []byte) error {
	contentDigest := req.Header.Get("Content-Digest")
	if len(contentDigest) == 0 {
		return errors.New("request with body should have a content-digest header")
	}

	digestParts := strings.Split(contentDigest, ":")
	if len(digestParts) < 2 {
		return errors.New("content-digest header should have name and value")
	}

	digestName := strings.Trim(digestParts[0], "=")

	digestAlg, err := digest.GetDigest(digestName)
	if err != nil {
		return err
	}

	digestValue, err := base64.StdEncoding.DecodeString(digestParts[1])
	if err != nil {
		return fmt.Errorf("decoding digest value: %w", err)
	}

	computedDigest, err := digestAlg(bodyBytes)
	if err != nil {
		return fmt.Errorf("computing expected digest: %w", err)
	}

	if !bytes.Equal(computedDigest, digestValue) {
		return errors.New("content-digest header does not match digest of request body")
	}

	return nil
}
