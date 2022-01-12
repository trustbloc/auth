/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"net/url"

	"github.com/trustbloc/hub-auth/pkg/restapi/operation"
)

type authRestParameters struct {
	hostURL          string
	logLevel         string
	databaseType     string
	databaseURL      string
	databasePrefix   string
	startupTimeout   uint64
	tlsParams        *tlsParams
	oidcParams       *oidcParams
	bootstrapParams  *bootstrapParams
	devicecertParams *deviceCertParams
	staticFiles      string
	secretsAPIToken  string
	staticImages     string
	keys             *keyParameters
}

type tlsParams struct {
	useSystemCertPool bool
	caCerts           []string
	serveCertPath     string
	serveKeyPath      string
}

type deviceCertParams struct {
	useSystemCertPool bool
	caCerts           []string
}

type oidcParams struct {
	hydraURL    *url.URL
	callbackURL string
	providers   map[string]*operation.OIDCProviderConfig
}

type oidcProvidersConfig struct {
	Providers map[string]*oidcProviderConfig `yaml:"providers"`
}

type oidcProviderConfig struct {
	URL             string   `yaml:"url"`
	ClientID        string   `yaml:"clientID"`
	ClientSecret    string   `yaml:"clientSecret"`
	Name            string   `yaml:"name"`
	SignUpLogoURL   string   `yaml:"signUpLogoURL"`
	SignInLogoURL   string   `yaml:"signInLogoURL"`
	Order           int      `yaml:"order"`
	SkipIssuerCheck bool     `yaml:"skipIssuerCheck"`
	Scopes          []string `yaml:"scopes"`
}

type bootstrapParams struct {
	documentSDSVaultURL string
	keySDSVaultURL      string
	authZKeyServerURL   string
	opsKeyServerURL     string
}

type keyParameters struct {
	sessionCookieAuthKey []byte
	sessionCookieEncKey  []byte
}
