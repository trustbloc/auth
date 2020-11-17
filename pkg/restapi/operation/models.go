/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

// BootstrapData is the user's bootstrap data.
type BootstrapData struct {
	SDSURL            string   `json:"sdsURL"`
	SDSPrimaryVaultID string   `json:"sdsPrimaryVaultID"`
	KeyServerURL      string   `json:"keyServerURL"`
	KeyStoreIDs       []string `json:"keyStoreIDs"`
}

type oidcClaims struct {
	Sub string `json:"sub"`
}

// UpdateBootstrapDataRequest is a request to update bootstrap data.
type UpdateBootstrapDataRequest struct {
	SDSPrimaryVaultID string   `json:"sdsPrimaryVaultID,omitempty"`
	KeyStoreIDs       []string `json:"keyStoreIDs,omitempty"`
}

// SetSecretRequest is the payload of a request to set a secret.
type SetSecretRequest struct {
	Secret []byte `json:"secret"`
}

// GetSecretResponse is the response's payload to a request to get a secret.
type GetSecretResponse struct {
	Secret string `json:"secret"`
}
