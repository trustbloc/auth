/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gnap

type authProviders struct {
	Providers []authProvider `json:"authProviders"`
}

type authProvider struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	SignUpIconURL map[string]string `json:"signUpIconUrl"`
	SignInIconURL map[string]string `json:"signInIconUrl"`
	Order         int               `json:"order"`
}
