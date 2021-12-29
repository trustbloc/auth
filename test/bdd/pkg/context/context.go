/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"crypto/tls"

	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
)

// BDDContext is a global context shared between different test suites in bddtests.
type BDDContext struct {
	tlsConfig   *tls.Config
	accessToken string
}

// NewBDDContext create new BDDContext.
func NewBDDContext(caCertPath string) (*BDDContext, error) {
	var tlsConfig *tls.Config

	if caCertPath != "" {
		rootCAs, err := tlsutils.GetCertPool(false, []string{caCertPath})
		if err != nil {
			return nil, err
		}

		tlsConfig = &tls.Config{
			RootCAs: rootCAs, MinVersion: tls.VersionTLS12,
		}
	}

	return &BDDContext{tlsConfig: tlsConfig}, nil
}

// TLSConfig return tls config.
func (b *BDDContext) TLSConfig() *tls.Config {
	return b.tlsConfig
}

// SetAccessToken set access token
func (b *BDDContext) SetAccessToken(accessToken string) {
	b.accessToken = accessToken
}

// AccessToken get access token
func (b *BDDContext) AccessToken() string {
	return b.accessToken
}
