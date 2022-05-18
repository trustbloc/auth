/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/trustbloc/auth/spi/gnap/internal/digest"
	"github.com/trustbloc/auth/spi/gnap/internal/jwksignature"
)

// Signer signs GNAP http requests using http-signature.
type Signer struct {
	SigningKey *jwk.JWK
}

// ProofType returns "httpsig", the GNAP proof type of the http-signature proof method.
func (s *Signer) ProofType() string {
	return "httpsig"
}

// Sign signs the given request using sha-256 for a content digest, and http-signature to sign headers.
func (s *Signer) Sign(request *http.Request, requestBody []byte) (*http.Request, error) {
	return Sign(request, requestBody, s.SigningKey, digest.SHA256)
}

// Sign signs a GNAP http request, adding http-signature headers.
func Sign(req *http.Request, bodyBytes []byte, signingKey *jwk.JWK, digestName string) (*http.Request, error) {
	keyBytes, err := json.Marshal(signingKey)
	if err != nil {
		return nil, fmt.Errorf("marshalling signing key: %w", err)
	}

	ss := httpsignatures.NewSimpleSecretsStorage(map[string]httpsignatures.Secret{
		signingKey.KeyID: {
			KeyID:      signingKey.KeyID,
			PublicKey:  "",
			PrivateKey: string(keyBytes),
			Algorithm:  signingKey.Algorithm,
		},
	})
	hs := httpsignatures.NewHTTPSignatures(ss)
	hs.SetSignatureHashAlgorithm(jwksignature.NewJWKAlgorithm(signingKey.Algorithm))

	coveredComponents := []string{
		"(request-target)", // in this implementation, this string is the code for method + target-uri
	}

	if len(bodyBytes) != 0 {
		digestAlgorithm, err := digest.GetDigest(digestName)
		if err != nil {
			return nil, err
		}

		contentDigest, err := digestAlgorithm(bodyBytes)
		if err != nil {
			return nil, fmt.Errorf("creating content-digest: %w", err)
		}

		digestValue := digestName + "=:" + base64.StdEncoding.EncodeToString(contentDigest) + ":"

		req.Header.Add("Content-Digest", digestValue)

		coveredComponents = append(coveredComponents, "content-digest")
	}

	if req.Header.Get("Authorization") != "" {
		coveredComponents = append(coveredComponents, "authorization")
	}

	hs.SetDefaultSignatureHeaders(coveredComponents)

	err = hs.Sign(signingKey.KeyID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return req, nil
}
