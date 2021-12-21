/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

// BootstrapData is the user's bootstrap data.
type BootstrapData struct {
	DocumentSDSVaultURL string            `json:"documentSDSURL"`
	KeySDSVaultURL      string            `json:"keySDSURL"`
	AuthZKeyServerURL   string            `json:"authzKeyServerURL"`
	OpsKeyServerURL     string            `json:"opsKeyServerURL"`
	Data                map[string]string `json:"data,omitempty"`
}

type oidcClaims struct {
	Sub string `json:"sub"`
}

// UpdateBootstrapDataRequest is a request to update bootstrap data.
type UpdateBootstrapDataRequest struct {
	Data map[string]string `json:"data"`
}

// SetSecretRequest is the payload of a request to set a secret.
type SetSecretRequest struct {
	Secret []byte `json:"secret"`
}

// GetSecretResponse is the response's payload to a request to get a secret.
type GetSecretResponse struct {
	Secret string `json:"secret"`
}

type authProviders struct {
	Providers []authProvider `json:"authProviders"`
}

type authProvider struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	SignUpLogoURL string `json:"signUpLogoUrl"`
	SignInLogoURL string `json:"signInLogoUrl"`
	Order         int    `json:"order"`
}
