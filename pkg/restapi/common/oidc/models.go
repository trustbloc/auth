/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package oidc

// Config holds the OIDC configuration.
type Config struct {
	CallbackURL string
	Providers   map[string]*ProviderConfig
}

// ProviderConfig holds the configuration for a single OIDC provider.
type ProviderConfig struct {
	URL             string
	ClientID        string
	ClientSecret    string
	Name            string
	SignUpIconURL   map[string]string
	SignInIconURL   map[string]string
	Order           int
	SkipIssuerCheck bool
	Scopes          []string
}
