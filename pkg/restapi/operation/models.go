/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import "github.com/ory/hydra-client-go/client/admin"

type bootstrapData struct {
	SDSURL            string   `json:"sdsURL"`
	SDSPrimaryVaultID string   `json:"sdsPrimaryVaultID"`
	KeyServerURL      string   `json:"keyServerURL"`
	KeyStoreIDs       []string `json:"keyStoreIDs"`
}

type oidcClaims struct {
	Sub string `json:"sub"`
}

type loginCtx struct {
	HydraLoginRequest *admin.GetLoginRequestOK
}
