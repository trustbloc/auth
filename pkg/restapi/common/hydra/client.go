/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package hydra

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"

	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
)

// Hydra is the client used to interface with the Hydra service.
type hydra interface {
	GetLoginRequest(params *admin.GetLoginRequestParams,
		opts ...admin.ClientOption) (*admin.GetLoginRequestOK, error)
	AcceptLoginRequest(params *admin.AcceptLoginRequestParams,
		opts ...admin.ClientOption) (*admin.AcceptLoginRequestOK, error)
	GetConsentRequest(params *admin.GetConsentRequestParams,
		opts ...admin.ClientOption) (*admin.GetConsentRequestOK, error)
	AcceptConsentRequest(params *admin.AcceptConsentRequestParams,
		opts ...admin.ClientOption) (*admin.AcceptConsentRequestOK, error)
	CreateOAuth2Client(params *admin.CreateOAuth2ClientParams,
		opts ...admin.ClientOption) (*admin.CreateOAuth2ClientCreated, error)
	IntrospectOAuth2Token(params *admin.IntrospectOAuth2TokenParams,
		opts ...admin.ClientOption) (*admin.IntrospectOAuth2TokenOK, error)
}

// Client decorates the default hydra admin client with TLS configuration.
type Client struct {
	hydraClient hydra
	httpClient  *http.Client
}

// NewClient returns a new Client.
func NewClient(hydraURL *url.URL, rootCAs *x509.CertPool) *Client {
	return &Client{
		hydraClient: client.NewHTTPClientWithConfig(
			nil,
			&client.TransportConfig{
				Schemes:  []string{hydraURL.Scheme},
				Host:     hydraURL.Host,
				BasePath: hydraURL.Path,
			},
		).Admin,
		httpClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{ //nolint:gosec
			RootCAs: rootCAs,
		}}},
	}
}

// GetLoginRequest fetches the login request at hydra.
func (c *Client) GetLoginRequest(params *admin.GetLoginRequestParams,
	_ ...admin.ClientOption) (*admin.GetLoginRequestOK, error) {
	params.SetHTTPClient(c.httpClient)

	return c.hydraClient.GetLoginRequest(params)
}

// AcceptLoginRequest accepts the login request at hydra.
func (c *Client) AcceptLoginRequest(params *admin.AcceptLoginRequestParams,
	_ ...admin.ClientOption) (*admin.AcceptLoginRequestOK, error) {
	params.SetHTTPClient(c.httpClient)

	return c.hydraClient.AcceptLoginRequest(params)
}

// GetConsentRequest fetches the consent request at hydra.
func (c *Client) GetConsentRequest(params *admin.GetConsentRequestParams,
	_ ...admin.ClientOption) (*admin.GetConsentRequestOK, error) {
	params.SetHTTPClient(c.httpClient)

	return c.hydraClient.GetConsentRequest(params)
}

// AcceptConsentRequest accepts the consent request at hydra.
func (c *Client) AcceptConsentRequest(params *admin.AcceptConsentRequestParams,
	_ ...admin.ClientOption) (*admin.AcceptConsentRequestOK, error) {
	params.SetHTTPClient(c.httpClient)

	return c.hydraClient.AcceptConsentRequest(params)
}

// CreateOAuth2Client creates an oauth2 client at hydra.
func (c *Client) CreateOAuth2Client(params *admin.CreateOAuth2ClientParams,
	_ ...admin.ClientOption) (*admin.CreateOAuth2ClientCreated, error) {
	params.SetHTTPClient(c.httpClient)

	return c.hydraClient.CreateOAuth2Client(params)
}

// IntrospectOAuth2Token and return the introspection.
func (c *Client) IntrospectOAuth2Token(params *admin.IntrospectOAuth2TokenParams,
	_ ...admin.ClientOption) (*admin.IntrospectOAuth2TokenOK, error) {
	params.SetHTTPClient(c.httpClient)

	return c.hydraClient.IntrospectOAuth2Token(params)
}
