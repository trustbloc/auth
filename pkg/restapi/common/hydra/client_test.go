/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package hydra

import (
	"crypto/x509"
	"net/http"
	"net/url"
	"testing"

	"github.com/ory/hydra-client-go/client/admin"
	"github.com/stretchr/testify/require"
)

func Test_SetsHTTPClient(t *testing.T) {
	check := func(c *http.Client) {
		require.NotNil(t, c)
		require.NotNil(t, c.Transport)
	}

	t.Run("get login request", func(t *testing.T) {
		c := NewClient(testURL(t), x509.NewCertPool())
		c.hydraClient = &stubHydra{
			getLoginFunc: func(params *admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
				check(params.HTTPClient)

				return nil, nil
			},
		}
		_, err := c.GetLoginRequest(admin.NewGetLoginRequestParams()) //nolint:errcheck
		require.NoError(t, err)
	})

	t.Run("accept login request", func(t *testing.T) {
		c := NewClient(testURL(t), x509.NewCertPool())
		c.hydraClient = &stubHydra{
			acceptLoginFunc: func(params *admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error) {
				check(params.HTTPClient)

				return nil, nil
			},
		}
		_, err := c.AcceptLoginRequest(admin.NewAcceptLoginRequestParams()) //nolint:errcheck
		require.NoError(t, err)
	})

	t.Run("get consent request", func(t *testing.T) {
		c := NewClient(testURL(t), x509.NewCertPool())
		c.hydraClient = &stubHydra{
			getConsentFunc: func(params *admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error) {
				check(params.HTTPClient)

				return nil, nil
			},
		}
		_, err := c.GetConsentRequest(admin.NewGetConsentRequestParams()) //nolint:errcheck
		require.NoError(t, err)
	})

	t.Run("accept consent request", func(t *testing.T) {
		c := NewClient(testURL(t), x509.NewCertPool())
		c.hydraClient = &stubHydra{
			acceptConsentFunc: func(params *admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error) {
				check(params.HTTPClient)

				return nil, nil
			},
		}
		_, err := c.AcceptConsentRequest(admin.NewAcceptConsentRequestParams()) //nolint:errcheck
		require.NoError(t, err)
	})

	t.Run("create oauth2 client", func(t *testing.T) {
		c := NewClient(testURL(t), x509.NewCertPool())
		c.hydraClient = &stubHydra{
			createClientFunc: func(params *admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error) {
				check(params.HTTPClient)

				return nil, nil
			},
		}
		_, err := c.CreateOAuth2Client(admin.NewCreateOAuth2ClientParams()) //nolint:errcheck
		require.NoError(t, err)
	})

	t.Run("introspect oauth token", func(t *testing.T) {
		c := NewClient(testURL(t), x509.NewCertPool())
		c.hydraClient = &stubHydra{
			introspectFunc: func(params *admin.IntrospectOAuth2TokenParams) (*admin.IntrospectOAuth2TokenOK, error) {
				check(params.HTTPClient)

				return nil, nil
			},
		}
	})
}

type stubHydra struct {
	getLoginFunc      func(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error)
	acceptLoginFunc   func(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error)
	getConsentFunc    func(*admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error)
	acceptConsentFunc func(*admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error)
	createClientFunc  func(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error)
	introspectFunc    func(params *admin.IntrospectOAuth2TokenParams) (*admin.IntrospectOAuth2TokenOK, error)
}

func (s *stubHydra) GetLoginRequest(params *admin.GetLoginRequestParams,
	_ ...admin.ClientOption) (*admin.GetLoginRequestOK, error) {
	return s.getLoginFunc(params)
}

func (s *stubHydra) AcceptLoginRequest(params *admin.AcceptLoginRequestParams,
	_ ...admin.ClientOption) (*admin.AcceptLoginRequestOK, error) {
	return s.acceptLoginFunc(params)
}

func (s *stubHydra) GetConsentRequest(params *admin.GetConsentRequestParams,
	_ ...admin.ClientOption) (*admin.GetConsentRequestOK, error) {
	return s.getConsentFunc(params)
}

func (s *stubHydra) AcceptConsentRequest(params *admin.AcceptConsentRequestParams,
	_ ...admin.ClientOption) (*admin.AcceptConsentRequestOK, error) {
	return s.acceptConsentFunc(params)
}

func (s *stubHydra) CreateOAuth2Client(params *admin.CreateOAuth2ClientParams,
	_ ...admin.ClientOption) (*admin.CreateOAuth2ClientCreated, error) {
	return s.createClientFunc(params)
}

func (s *stubHydra) IntrospectOAuth2Token(params *admin.IntrospectOAuth2TokenParams,
	_ ...admin.ClientOption) (*admin.IntrospectOAuth2TokenOK, error) {
	return s.introspectFunc(params)
}

func testURL(t *testing.T) *url.URL {
	t.Helper()

	u, err := url.Parse("http://test.com/some/path")
	require.NoError(t, err)

	return u
}
