/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package login

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/square/go-jose/v3"
	"github.com/trustbloc/auth/component/gnap/as"
	"github.com/trustbloc/auth/spi/gnap"
	"github.com/trustbloc/auth/spi/gnap/proof/httpsig"
	"golang.org/x/oauth2"

	"github.com/trustbloc/auth/pkg/restapi/operation"
)

type MockWallet struct {
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
	authHeader       string
	ReceivedCallback bool
	UserData         *UserClaims
	CallbackErr      error
	Secret           string
	gnap             *gnapParams
}

type gnapParams struct {
	pubJWK      *jwk.JWK
	signer      *httpsig.Signer
	client      *as.Client
	authResp    *gnap.AuthResponse
	interactRef string
	token       string
}

func (m *MockWallet) RequestUserAuthentication() (*http.Response, error) {
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

func (m *MockWallet) GNAPLogin(authServerURL string) error {
	err := m.setupGNAP(authServerURL)
	if err != nil {
		return err
	}

	err = m.gnapReqAccess()
	if err != nil {
		return err
	}

	err = m.gnapInteract()
	if err != nil {
		return err
	}

	err = m.gnapContinueRequest()
	if err != nil {
		return err
	}

	return nil
}

func (m *MockWallet) setupGNAP(authServerURL string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	privJWK := &jwk.JWK{
		JSONWebKey: jose.JSONWebKey{
			Key:       priv,
			KeyID:     "key1",
			Algorithm: "ES256",
		},
		Kty: "EC",
		Crv: "P-256",
	}

	pubJWK := &jwk.JWK{
		JSONWebKey: privJWK.Public(),
		Kty:        "EC",
		Crv:        "P-256",
	}

	signer := &httpsig.Signer{SigningKey: privJWK}

	// create gnap as client
	gnapClient, err := as.NewClient(
		signer,
		m.httpClient,
		authServerURL,
	)
	if err != nil {
		return fmt.Errorf("failed to create gnap as go-client: %w", err)
	}

	m.gnap = &gnapParams{
		pubJWK: pubJWK,
		signer: signer,
		client: gnapClient,
	}

	return nil
}

const mockClientFinishURI = "https://mock.client.example.com/"

func (m *MockWallet) gnapReqAccess() error {
	req := &gnap.AuthRequest{
		Client: &gnap.RequestClient{
			Key: &gnap.ClientKey{
				Proof: "httpsig",
				JWK:   *m.gnap.pubJWK,
			},
		},
		AccessToken: []*gnap.TokenRequest{
			{
				Access: []gnap.TokenAccess{
					{
						IsReference: true,
						Ref:         "example-token-type",
					},
				},
			},
		},
		Interact: &gnap.RequestInteract{
			Start: []string{"redirect"},
			Finish: gnap.RequestFinish{
				Method: "redirect",
				URI:    mockClientFinishURI,
			},
		},
	}

	authResp, err := m.gnap.client.RequestAccess(req)
	if err != nil {
		return fmt.Errorf("failed to gnap go-client: %w", err)
	}

	m.gnap.authResp = authResp

	return nil
}

const (
	authServerURL       = "https://auth.trustbloc.local:8070"
	expectedInteractURL = authServerURL + "/gnap/interact"

	oidcProviderSelectorURL = authServerURL + "/oidc/login"
	oidcCallbackURLURL      = authServerURL + "/oidc/callback"
	authServerSignUpURL     = authServerURL + "/ui/sign-up"

	gnapOIDCProviderName = "mockbank" // providers.yaml
)

func (m *MockWallet) gnapInteract() error {
	// initialise the browser
	interactURL, err := url.Parse(m.gnap.authResp.Interact.Redirect)
	if err != nil {
		return err
	}

	txnID := interactURL.Query().Get("txnID")

	// redirect to interact url
	response, err := m.httpClient.Get(m.gnap.authResp.Interact.Redirect)
	if err != nil {
		return err
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			fmt.Printf("WARNING - failed to close http response body: %s\n", closeErr.Error())
		}
	}()

	signUpURL := authServerSignUpURL + "?txnID=" + txnID

	// validate the redirect url
	if response.Request.URL.String() != signUpURL {
		return fmt.Errorf(
			"invalid ui redirect url: expected=%s actual=%s", signUpURL, response.Request.URL.String(),
		)
	}

	// select provider
	request := fmt.Sprintf("%s?provider=%s&txnID=%s", oidcProviderSelectorURL, gnapOIDCProviderName, txnID)

	prevCheckRedirect := m.httpClient.CheckRedirect

	m.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	result, err := m.httpClient.Get(request)
	if err != nil {
		return fmt.Errorf("failed to redirect to OIDC provider url %s: %w", request, err)
	}

	request = result.Header.Get("Location")

	result, err = m.httpClient.Get(request)
	if err != nil {
		return fmt.Errorf("failed to redirect to OIDC provider url %s: %w", request, err)
	}

	request = result.Header.Get("Location")

	result, err = m.httpClient.Get(request)
	if err != nil {
		return fmt.Errorf("failed to redirect to login url %s: %w", request, err)
	}

	// login to third party oidc
	loginResp, err := m.httpClient.Post(result.Request.URL.String(), "", nil)
	if err != nil {
		return err
	}

	request = loginResp.Header.Get("Location")

	result, err = m.httpClient.Get(request)
	if err != nil {
		return fmt.Errorf("failed to redirect to post-login oauth url %s: %w", request, err)
	}

	request = result.Header.Get("Location")

	result, err = m.httpClient.Get(request)
	if err != nil {
		return fmt.Errorf("failed to redirect to consent url %s: %w", request, err)
	}

	request = result.Header.Get("Location")

	result, err = m.httpClient.Get(request)
	if err != nil {
		return fmt.Errorf("failed to redirect to post-consent oauth url %s: %w", request, err)
	}

	request = result.Header.Get("Location")

	result, err = m.httpClient.Get(request)
	if err != nil {
		return fmt.Errorf("failed to redirect to auth callback url %s: %w", request, err)
	}

	clientRedirect := result.Header.Get("Location")

	// TODO validate the client finishURL
	if !strings.HasPrefix(clientRedirect, mockClientFinishURI) {
		return fmt.Errorf(
			"invalid client finish redirect prefix expected=%s actual=%s",
			mockClientFinishURI, clientRedirect)
	}

	crURL, err := url.Parse(clientRedirect)
	if err != nil {
		return err
	}

	m.gnap.interactRef = crURL.Query().Get("interact_ref")

	m.httpClient.CheckRedirect = prevCheckRedirect

	return nil
}

func (m *MockWallet) gnapContinueRequest() error {
	req := &gnap.ContinueRequest{
		InteractRef: m.gnap.interactRef,
	}

	authResp, err := m.gnap.client.Continue(req, m.gnap.authResp.Continue.AccessToken.Value)
	if err != nil {
		return fmt.Errorf("failed to call continue request: %w", err)
	}

	m.gnap.authResp = authResp

	if len(authResp.AccessToken) < 1 {
		return fmt.Errorf("expected a GNAP token to be granted")
	}

	m.gnap.token = authResp.AccessToken[0].Value

	m.setGNAPAccessToken(m.gnap.token)

	if m.UserData == nil {
		m.UserData = &UserClaims{}
	}

	if len(authResp.Subject.SubIDs) > 0 {
		m.UserData.Sub = authResp.Subject.SubIDs[0].ID
	}

	return nil
}

func (m *MockWallet) FetchBootstrapData(endpoint string) (*operation.BootstrapData, error) {
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct http request: %w", err)
	}

	err = m.addAuthHeaders(request, nil)
	if err != nil {
		return nil, err
	}

	response, err := m.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to invoke bootstrap data endpoint: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			fmt.Printf("WARNING - failed to close http response body: %s\n", closeErr.Error())
		}
	}()

	if response.StatusCode != http.StatusOK {
		msg, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Printf("WARNING - failed to read response body: %s\n", err.Error())
		}

		return nil, fmt.Errorf(
			"unexpected response: code=%d msg=%s", response.StatusCode, msg,
		)
	}

	data := &operation.BootstrapData{}

	return data, json.NewDecoder(response.Body).Decode(data)
}

func (m *MockWallet) UpdateBootstrapData(endpoint string, update *operation.UpdateBootstrapDataRequest) error {
	payload, err := json.Marshal(update)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}

	err = m.addAuthHeaders(request, payload)
	if err != nil {
		return err
	}

	response, err := m.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("failed to invoke bootstrap data endpoint: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			fmt.Printf("WARNING - failed to close http response body: %s\n", closeErr.Error())
		}
	}()

	if response.StatusCode != http.StatusOK {
		msg, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Printf("WARNING - failed to read response body: %s\n", err.Error())
		}

		return fmt.Errorf(
			"unexpected response: code=%d msg=%s", response.StatusCode, msg,
		)
	}

	return nil
}

func (m *MockWallet) CreateAndPushSecretToHubAuth(endpoint string) error {
	m.Secret = uuid.New().String()

	payload, err := json.Marshal(&operation.SetSecretRequest{
		Secret: []byte(m.Secret),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}

	err = m.addAuthHeaders(request, payload)
	if err != nil {
		return err
	}

	response, err := m.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("failed to push secret to auth: %w", err)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			fmt.Printf("WARNING - failed to close response body: %s\n", closeErr.Error())
		}
	}()

	if response.StatusCode != http.StatusOK {
		msg, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Printf("WARNING - failed to read response body: %s\n", err.Error())
		}

		return fmt.Errorf(
			"unexpected response: code=%d msg=%s", response.StatusCode, msg,
		)
	}

	return nil
}

func (m *MockWallet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.ReceivedCallback = true

	code := r.URL.Query().Get("code")
	if code == "" {
		m.CallbackErr = errors.New("did not get a code in the callback")

		return
	}

	token, err := m.oauth2Config.Exchange(
		context.WithValue(r.Context(), oauth2.HTTPClient, m.httpClient),
		code,
	)
	if err != nil {
		m.CallbackErr = fmt.Errorf("failed to exchange code for token: %w", err)

		return
	}

	m.accessToken = token.AccessToken
	m.setOIDCAccessToken(token.AccessToken)

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		m.CallbackErr = errors.New("missing id_token")

		return
	}

	idToken, err := m.oidcProvider.Verifier(&oidc.Config{ClientID: m.clientID}).Verify(r.Context(), rawIDToken)
	if err != nil {
		m.CallbackErr = fmt.Errorf("failed to verify id_token: %w", err)

		return
	}

	m.UserData = &UserClaims{}

	err = idToken.Claims(m.UserData)
	if err != nil {
		m.CallbackErr = fmt.Errorf("failed to extract claims from id_token: %w", err)

		return
	}

	_, err = w.Write([]byte("mock wallet authenticated the user!"))
	if err != nil {
		m.CallbackErr = fmt.Errorf("failed to render mock UI to the user: %w", err)

		return
	}

	// store access token
	m.accessToken = token.AccessToken
	m.setOIDCAccessToken(token.AccessToken)
}

func (m *MockWallet) setOIDCAccessToken(token string) {
	m.authHeader = fmt.Sprintf("Bearer %s", base64.StdEncoding.EncodeToString([]byte(token)))
}

func (m *MockWallet) setGNAPAccessToken(token string) {
	m.authHeader = fmt.Sprintf("GNAP %s", token)
}

func (m *MockWallet) addAuthHeaders(r *http.Request, body []byte) error {
	r.Header.Set("authorization", m.authHeader)

	if !strings.HasPrefix(m.authHeader, "GNAP") || m.gnap == nil {
		return nil
	}

	// if GNAP, we sign the request
	var err error
	r, err = m.gnap.signer.Sign(r, body)
	if err != nil {
		return err
	}

	return nil
}

func NewMockWallet(clientRegistrationURL, oidcProviderURL string, httpClient *http.Client) (*MockWallet, error) {
	oidcProvider, err := oidc.NewProvider(
		oidc.ClientContext(context.Background(), httpClient),
		oidcProviderURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to init oidc provider: %w", err)
	}

	wallet := &MockWallet{
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
