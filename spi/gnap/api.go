/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gnap

import (
	"net/http"
)

// Signer api for GNAP http signatures.
type Signer interface {
	ProofType() string
	Sign(request *http.Request, requestBody []byte) (*http.Request, error)
}
