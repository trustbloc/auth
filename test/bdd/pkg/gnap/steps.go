/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gnap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/square/go-jose/v3"

	"github.com/trustbloc/auth/component/gnap/as"
	"github.com/trustbloc/auth/component/gnap/rs"
	"github.com/trustbloc/auth/spi/gnap"
	"github.com/trustbloc/auth/spi/gnap/proof/httpsig"

	bddctx "github.com/trustbloc/auth/test/bdd/pkg/context"
)

const (
	authServerURL       = "https://auth.trustbloc.local:8070"
	expectedInteractURL = authServerURL + "/gnap/interact"

	oidcProviderSelectorURL = authServerURL + "/oidc/login"
	authServerSignUpURL     = authServerURL + "/ui/sign-up"

	mockOIDCProviderName = "mockbank" // providers.yaml
)

type Steps struct {
	ctx          *bddctx.BDDContext
	gnapClient   *as.Client
	gnapRSClient *rs.Client

	clientPubKey *jwk.JWK
	rsPubKey     *jwk.JWK
	authResp     *gnap.AuthResponse
	interactRef  string
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

	{
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

		// create gnap as client
		gnapClient, err := as.NewClient(
			&httpsig.Signer{SigningKey: privJWK},
			httpClient,
			authServerURL,
		)
		if err != nil {
			return fmt.Errorf("failed to create gnap as go-client: %w", err)
		}

		s.gnapClient = gnapClient
		s.clientPubKey = pubJWK
	}

	{
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

		// create gnap rs client
		gnapRSClient, err := rs.NewClient(
			&httpsig.Signer{SigningKey: privJWK},
			httpClient,
			authServerURL,
		)
		if err != nil {
			return fmt.Errorf("failed to create gnap rs go-client: %w", err)
		}

		s.gnapRSClient = gnapRSClient
		s.rsPubKey = pubJWK
	}

	return nil
}

const mockClientFinishURI = "https://mock.client.example.com/"

func (s *Steps) txnRequest() error {
	req := &gnap.AuthRequest{
		Client: &gnap.RequestClient{
			Key: &gnap.ClientKey{
				Proof: "httpsig",
				JWK:   *s.clientPubKey,
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

	authResp, err := s.gnapClient.RequestAccess(req)
	if err != nil {
		return fmt.Errorf("failed to gnap go-client: %w", err)
	}

	actualURL, err := url.Parse(authResp.Interact.Redirect)
	if err != nil {
		return fmt.Errorf("parsing interact redirect url: %w", err)
	}

	// clear query, then compare
	actualURL.RawQuery = ""

	if actualURL.String() != expectedInteractURL {
		return fmt.Errorf(
			"invalid interact url: expected=%s actual=%s",
			expectedInteractURL, actualURL.String(),
		)
	}

	s.authResp = authResp

	return nil
}

func (s *Steps) interactRedirect() error {
	// initialise the browser
	err := s.initBrowser()
	if err != nil {
		return err
	}

	interactURL, err := url.Parse(s.authResp.Interact.Redirect)
	if err != nil {
		return err
	}

	txnID := interactURL.Query().Get("txnID")

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

	signUpURL := authServerSignUpURL + "?txnID=" + txnID

	// validate the redirect url
	if response.Request.URL.String() != signUpURL {
		return fmt.Errorf(
			"invalid ui redirect url: expected=%s actual=%s", signUpURL, response.Request.URL.String(),
		)
	}

	// select provider
	request := fmt.Sprintf("%s?provider=%s&txnID=%s", oidcProviderSelectorURL, mockOIDCProviderName, txnID)

	s.browser.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	result, err := s.browser.Get(request)
	if err != nil {
		return fmt.Errorf("failed to redirect to OIDC provider url %s: %w", request, err)
	}

	request = result.Header.Get("Location")

	result, err = s.browser.Get(request)
	if err != nil {
		return fmt.Errorf("failed to redirect to OIDC provider url %s: %w", request, err)
	}

	request = result.Header.Get("Location")

	result, err = s.browser.Get(request)
	if err != nil {
		return fmt.Errorf("failed to redirect to login url %s: %w", request, err)
	}

	// login to third party oidc
	loginResp, err := s.browser.Post(result.Request.URL.String(), "", nil)
	if err != nil {
		return err
	}

	request = loginResp.Header.Get("Location")

	result, err = s.browser.Get(request)
	if err != nil {
		return fmt.Errorf("failed to redirect to post-login oauth url %s: %w", request, err)
	}

	request = result.Header.Get("Location")

	result, err = s.browser.Get(request)
	if err != nil {
		return fmt.Errorf("failed to redirect to consent url %s: %w", request, err)
	}

	request = result.Header.Get("Location")

	result, err = s.browser.Get(request)
	if err != nil {
		return fmt.Errorf("failed to redirect to post-consent oauth url %s: %w", request, err)
	}

	request = result.Header.Get("Location")

	result, err = s.browser.Get(request)
	if err != nil {
		return fmt.Errorf("failed to redirect to auth callback url %s: %w", request, err)
	}

	clientRedirect := result.Header.Get("Location")

	body, err := ioutil.ReadAll(result.Body)
	if err != nil {
		return fmt.Errorf("failed to read result body: %w", err)
	}

	rx := regexp.MustCompile("window.opener.location.href = '(.*)';")
	res := rx.FindStringSubmatch(string(body))

	clientRedirect = res[1]
	clientRedirect = strings.Replace(clientRedirect, "\\u0026", "\u0026", -1)
	clientRedirect = strings.Replace(clientRedirect, "\\/", "/", -1)

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

	s.interactRef = crURL.Query().Get("interact_ref")

	return nil
}

func (s *Steps) continueRequest() error {
	req := &gnap.ContinueRequest{
		InteractRef: s.interactRef,
	}

	authResp, err := s.gnapClient.Continue(req, s.authResp.Continue.AccessToken.Value)
	if err != nil {
		return fmt.Errorf("failed to call continue request: %w", err)
	}

	// TODO validate access token

	s.authResp = authResp

	return nil
}

func (s *Steps) introspection() error {
	tok := s.authResp.AccessToken[0]

	req := &gnap.IntrospectRequest{
		ResourceServer: &gnap.RequestClient{
			Key: &gnap.ClientKey{
				JWK:   *s.rsPubKey,
				Proof: "httpsig",
			},
		},
		Proof:       "httpsig",
		AccessToken: tok.Value,
	}

	resp, err := s.gnapRSClient.Introspect(req)
	if err != nil {
		return fmt.Errorf("failed to call introspect request: %w", err)
	}

	// TODO validate introspection data

	if !resp.Active {
		return fmt.Errorf("access token should be active")
	}

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
