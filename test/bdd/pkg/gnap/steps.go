/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gnap

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strings"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/trustbloc/auth/component/gnap/as"
	"github.com/trustbloc/auth/component/gnap/rs"
	"github.com/trustbloc/auth/spi/gnap"

	bddctx "github.com/trustbloc/auth/test/bdd/pkg/context"
)

const (
	authServerURL       = "https://auth.trustbloc.local:8070"
	expectedInteractURL = authServerURL + "/gnap/interact"

	oidcProviderSelectorURL = authServerURL + "/oidc/login"
	oidcCallbackURLURL      = authServerURL + "/oidc/callback"
	authServerSignUpURL     = authServerURL + "/ui/sign-up"

	mockOIDCProviderName = "mockbank1" // providers.yaml
)

type Steps struct {
	ctx          *bddctx.BDDContext
	gnapClient   *as.Client
	gnapRSClient *rs.Client
	pubKeyJWK    jwk.JWK
	authResp     *gnap.AuthResponse
	browser      *http.Client
}

func NewSteps(ctx *bddctx.BDDContext) *Steps {
	return &Steps{
		ctx: ctx,
	}
}

func (s *Steps) RegisterSteps(gs *godog.ScenarioContext) {
	gs.Step(`^the client creates a gnap go-client$`, s.createGNAPClient)
	gs.Step(`^the client calls the tx request with httpsign and gets back a redirect interaction$`, s.txnRequest)
	gs.Step(`^client redirects to the interaction URL, user logs into the external oidc provider and the client receives a redirect back$`, s.interactRedirect)
	gs.Step(`^client calls continue API and gets back the access token$`, s.continueRequest)
	gs.Step(`^resource server validates the gnap access token$`, s.introspection)
}

func (s *Steps) createGNAPClient() error {
	// create http client
	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: s.ctx.TLSConfig()},
	}

	// create key-pair
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to create ed25519 key-pair: %w", err)
	}

	pubKeyJWK, err := jwksupport.JWKFromKey(pub)
	if err != nil {
		return fmt.Errorf("failed to create jwk from key: %w", err)
	}

	// create gnap as client
	gnapClient, err := as.NewClient(
		&Signer{
			PrivateKey: private,
		},
		httpClient,
		authServerURL,
	)
	if err != nil {
		return fmt.Errorf("failed to create gnap as go-client: %w", err)
	}

	// create gnap rs client
	gnapRSClient, err := rs.NewClient(
		&Signer{
			PrivateKey: private,
		},
		httpClient,
		authServerURL,
	)
	if err != nil {
		return fmt.Errorf("failed to create gnap rs go-client: %w", err)
	}

	s.gnapClient = gnapClient
	s.gnapRSClient = gnapRSClient
	s.pubKeyJWK = *pubKeyJWK

	return nil
}

func (s *Steps) txnRequest() error {
	req := &gnap.AuthRequest{
		Client: &gnap.RequestClient{
			Key: &gnap.ClientKey{
				JWK: s.pubKeyJWK,
			},
		},
	}

	authResp, err := s.gnapClient.RequestAccess(req)
	if err != nil {
		return fmt.Errorf("failed to gnap go-client: %w", err)
	}

	if authResp.Interact.Redirect != expectedInteractURL {
		return fmt.Errorf(
			"invalid interact url: expected=%s actual=%s",
			expectedInteractURL, authResp.Interact.Redirect,
		)
	}

	s.authResp = authResp

	return nil
}

func (s *Steps) interactRedirect() error {
	// initialise the browser
	s.initBrowser()

	// redirect to interact url
	response, err := s.browser.Get(s.authResp.Interact.Redirect)
	if err != nil {
		return err
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			fmt.Printf("WARNING - failed to close http response body: %s\n", closeErr.Error())
		}
	}()

	// validate the redirect url
	if response.Request.URL.String() != authServerSignUpURL {
		return fmt.Errorf(
			"invalid ui redirect url: expected=%s actual=%s", authServerSignUpURL, response.Request.URL.String(),
		)
	}

	// select provider
	request := fmt.Sprintf("%s?provider=%s", oidcProviderSelectorURL, mockOIDCProviderName)

	fmt.Println(request)

	result, err := s.browser.Get(fmt.Sprintf("%s?provider=%s", oidcProviderSelectorURL, mockOIDCProviderName))
	if err != nil {
		return fmt.Errorf("failed to redirect to OIDC provider url %s: %w", request, err)
	}

	// login to third party oidc
	loginResp, err := s.browser.Post(result.Request.URL.String(), "", nil)
	if err != nil {
		return err
	}

	// TODO validate the client finishURL
	if !strings.HasPrefix(loginResp.Request.URL.String(), authServerURL) {
		return fmt.Errorf(
			"invalid oidc callbackURL prefix expected=%s actual=%s",
			oidcCallbackURLURL, loginResp.Request.URL.String(),
		)
	}

	return nil
}

func (s *Steps) continueRequest() error {
	req := &gnap.ContinueRequest{
		InteractRef: uuid.NewString(),
	}

	authResp, err := s.gnapClient.Continue(req, s.authResp.Continue.AccessToken.Value)
	if err != nil {
		return fmt.Errorf("failed to call continue request: %w", err)
	}

	// TODO validate acess token

	s.authResp = authResp

	return nil
}

func (s *Steps) introspection() error {
	req := &gnap.IntrospectRequest{}

	_, err := s.gnapRSClient.Introspect(req)
	if err != nil {
		return fmt.Errorf("failed to call continue request: %w", err)
	}

	// TODO validate introspection data

	return nil
}

func (s *Steps) initBrowser() error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("failed to init cookie jar: %w", err)
	}

	s.browser = &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: s.ctx.TLSConfig()},
	}

	return nil
}
