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
