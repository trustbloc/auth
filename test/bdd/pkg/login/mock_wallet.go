/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package login

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"golang.org/x/oauth2"
)

type mockWallet struct {
	oidcProvider     *oidc.Provider
	httpClient       *http.Client
	clientID         string
	clientSecret     string
	scope            []string
	server           *httptest.Server
	oauth2Config     oauth2.Config
	receivedCallback bool
	userData         *UserClaims
	callbackErr      error
	accessToken      string
}

func (m *mockWallet) requestUserAuthentication() (*http.Response, error) {
	m.oauth2Config = oauth2.Config{
		ClientID:     m.clientID,
		ClientSecret: m.clientSecret,
		Endpoint:     m.oidcProvider.Endpoint(),
		RedirectURL:  m.server.URL,
		Scopes:       m.scope,
	}

	redirectURL := m.oauth2Config.AuthCodeURL("dont_care_about_state")

	response, err := m.httpClient.Get(redirectURL)
	if err != nil {
		return nil, fmt.Errorf("failed to send authentication request %s: %w", redirectURL, err)
	}

	return response, nil
}

func (m *mockWallet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.receivedCallback = true

	code := r.URL.Query().Get("code")
	if code == "" {
		m.callbackErr = errors.New("did not get a code in the callback")

		return
	}

	token, err := m.oauth2Config.Exchange(
		context.WithValue(r.Context(), oauth2.HTTPClient, m.httpClient),
		code,
	)
	if err != nil {
		m.callbackErr = fmt.Errorf("failed to exchange code for token: %w", err)

		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		m.callbackErr = errors.New("missing id_token")

		return
	}

	idToken, err := m.oidcProvider.Verifier(&oidc.Config{ClientID: m.clientID}).Verify(r.Context(), rawIDToken)
	if err != nil {
		m.callbackErr = fmt.Errorf("failed to verify id_token: %w", err)

		return
	}

	m.userData = &UserClaims{}

	err = idToken.Claims(m.userData)
	if err != nil {
		m.callbackErr = fmt.Errorf("failed to extract claims from id_token: %w", err)

		return
	}

	_, err = w.Write([]byte("mock wallet authenticated the user!"))
	if err != nil {
		m.callbackErr = fmt.Errorf("failed to render mock UI to the user: %w", err)

		return
	}

	// store access token
	m.accessToken = token.AccessToken
}

func newMockWallet(clientRegistrationURL, oidcProviderURL string, httpClient *http.Client) (*mockWallet, error) {
	oidcProvider, err := oidc.NewProvider(
		oidc.ClientContext(context.Background(), httpClient),
		oidcProviderURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to init oidc provider: %w", err)
	}

	wallet := &mockWallet{
		oidcProvider: oidcProvider,
		httpClient:   httpClient,
		clientID:     uuid.New().String(),
		clientSecret: uuid.New().String(),
		scope:        []string{oidc.ScopeOpenID},
	}
	wallet.server = httptest.NewServer(wallet)

	request := admin.NewCreateOAuth2ClientParams()
	request.SetHTTPClient(wallet.httpClient)
	request.SetBody(&models.OAuth2Client{
		ClientID:      wallet.clientID,
		ClientSecret:  wallet.clientSecret,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code", "id_token"},
		Scope:         strings.Join(wallet.scope, " "),
		RedirectUris:  []string{wallet.server.URL},
	})

	hydraAdminURL, err := url.Parse(clientRegistrationURL)
	if err != nil {
		return nil, fmt.Errorf("invalid hydra admin url: %s", clientRegistrationURL)
	}

	hydraClient := client.NewHTTPClientWithConfig(nil,
		&client.TransportConfig{
			Host:     hydraAdminURL.Host,
			BasePath: hydraAdminURL.Path,
			Schemes:  []string{hydraAdminURL.Scheme},
		},
	).Admin

	_, err = hydraClient.CreateOAuth2Client(request)
	if err != nil {
		return nil, fmt.Errorf("failed to register mock wallet as an oidc client of hub auth: %w", err)
	}

	return wallet, nil
}
