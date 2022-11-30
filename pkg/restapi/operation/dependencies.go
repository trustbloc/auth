/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"context"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ory/hydra-client-go/client/admin"
	"golang.org/x/oauth2"
)

type oidcProvider interface {
	Name() string
	OAuth2Config(scope ...string) oauth2Config
	Endpoint() oauth2.Endpoint
	Verify(context.Context, string) (idToken, error)
}

type oidcProviderImpl struct {
	name            string
	clientID        string
	clientSecret    string
	callback        string
	skipIssuerCheck bool
	op              *oidc.Provider
	httpClient      *http.Client
}

func (o *oidcProviderImpl) Name() string {
	return o.name
}

func (o *oidcProviderImpl) OAuth2Config(scope ...string) oauth2Config {
	return &oauth2ConfigImpl{
		client: o.httpClient,
		oc: &oauth2.Config{
			ClientID:     o.clientID,
			ClientSecret: o.clientSecret,
			Endpoint:     o.op.Endpoint(),
			RedirectURL:  o.callback,
			Scopes:       scope,
		},
	}
}

func (o *oidcProviderImpl) Endpoint() oauth2.Endpoint {
	return o.op.Endpoint()
}

func (o *oidcProviderImpl) Verify(ctx context.Context, rawToken string) (idToken, error) {
	return o.op.Verifier(&oidc.Config{ClientID: o.clientID, SkipIssuerCheck: o.skipIssuerCheck}).Verify(ctx, rawToken)
}

type idToken interface {
	Claims(interface{}) error
}

type oauth2Config interface {
	AuthCodeURL(string, ...oauth2.AuthCodeOption) string
	Exchange(context.Context, string, ...oauth2.AuthCodeOption) (oauth2Token, error)
}

type oauth2ConfigImpl struct {
	oc     *oauth2.Config
	client *http.Client
}

func (o *oauth2ConfigImpl) AuthCodeURL(state string, options ...oauth2.AuthCodeOption) string {
	return o.oc.AuthCodeURL(state, options...)
}

func (o *oauth2ConfigImpl) Exchange(
	ctx context.Context, code string, options ...oauth2.AuthCodeOption) (oauth2Token, error) {
	return o.oc.Exchange(
		context.WithValue(ctx, oauth2.HTTPClient, o.client),
		code,
		options...,
	)
}

type oauth2Token interface {
	Extra(string) interface{}
}

// Hydra is the client used to interface with the Hydra service.
type Hydra interface {
	GetLoginRequest(params *admin.GetLoginRequestParams, opts ...admin.ClientOption) (*admin.GetLoginRequestOK, error)
	AcceptLoginRequest(params *admin.AcceptLoginRequestParams,
		opts ...admin.ClientOption) (*admin.AcceptLoginRequestOK, error)
	GetConsentRequest(params *admin.GetConsentRequestParams,
		opts ...admin.ClientOption) (*admin.GetConsentRequestOK, error)
	AcceptConsentRequest(params *admin.AcceptConsentRequestParams,
		opts ...admin.ClientOption) (*admin.AcceptConsentRequestOK, error)
	IntrospectOAuth2Token(params *admin.IntrospectOAuth2TokenParams,
		opts ...admin.ClientOption) (*admin.IntrospectOAuth2TokenOK, error)
}
