/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package login

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"strings"

	"github.com/cucumber/godog"
	"github.com/google/uuid"

	bddctx "github.com/trustbloc/hub-auth/test/bdd/pkg/context"
)

const (
	HUB_AUTH_HOST                   = "https://localhost:8070"
	hubAuthHydraAdminURL            = "https://localhost:4445"
	hubAuthOIDCProviderURL          = "https://localhost:4444/"
	hubAuthOIDCProviderSelectionURL = HUB_AUTH_HOST + "/ui"
	hubAuthSelectOIDCProviderURL    = HUB_AUTH_HOST + "/oauth2/login"
	mockLoginURL                    = "https://localhost:8099/mock/login"
	mockAuthenticationURL           = "https://localhost:8099/mock/authn"
	mockConsentURL                  = "https://localhost:8099/mock/consent"
	mockAuthorizationURL            = "https://localhost:8099/mock/authz"
	mockOIDCProviderName            = "mockbank" // providers.yaml
)

// defines the payload expected by the mock login consent server's /authn endpoint
type userAuthenticationConfig struct {
	Sub  string `json:"sub"`
	Fail bool   `json:"fail,omitempty"`
}

type userAuthorizationConfig struct {
	UserClaims *UserClaims `json:"user_claims,omitempty"`
	Fail       bool        `json:"fail,omitempty"`
}

// BDD tests can configure
type UserClaims struct {
	Sub        string `json:"sub"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Email      string `json:"email"`
}

func NewSteps(ctx *bddctx.BDDContext) *Steps {
	return &Steps{ctx: ctx}
}

type Steps struct {
	browser          *http.Client
	ctx              *bddctx.BDDContext
	wallet           *MockWallet
	expectedUserData *UserClaims
}

func (s *Steps) RegisterSteps(gs *godog.Suite) {
	gs.Step("the wallet is registered as an OIDC client", s.registerWallet)
	gs.Step("the wallet redirects the user to authenticate at hub-auth", s.walletRedirectsUserToAuthenticate)
	gs.Step("the user picks their third party OIDC provider", s.userSelectsThirdPartyOIDCProvider)
	gs.Step("the user authenticates with the third party OIDC provider", s.userAuthenticatesAtThirdPartyProvider)
	gs.Step("the user is redirected back to the wallet", s.userRedirectedBackToWallet)
	gs.Step("the user has authenticated to the wallet", s.userHasAuthenticatedToTheWallet)
}

// NewWalletLogin returns a new common.MockWallet that is logged in.
func (s *Steps) NewWalletLogin() (*MockWallet, error) {
	err := s.registerWallet()
	if err != nil {
		return nil, err
	}

	err = s.walletRedirectsUserToAuthenticate()
	if err != nil {
		return nil, err
	}

	err = s.userSelectsThirdPartyOIDCProvider()
	if err != nil {
		return nil, err
	}

	err = s.userAuthenticatesAtThirdPartyProvider()
	if err != nil {
		return nil, err
	}

	err = s.userRedirectedBackToWallet()
	if err != nil {
		return nil, err
	}

	return s.wallet, s.userHasAuthenticatedToTheWallet()
}

func (s *Steps) registerWallet() error {
	err := s.initBrowser()
	if err != nil {
		return fmt.Errorf("failed to register wallet: %w", err)
	}

	s.wallet, err = NewMockWallet(hubAuthHydraAdminURL, hubAuthOIDCProviderURL, s.browser)
	if err != nil {
		return fmt.Errorf("failed to register mock wallet: %w", err)
	}

	return nil
}

func (s *Steps) walletRedirectsUserToAuthenticate() error {
	result, err := s.wallet.RequestUserAuthentication()
	if err != nil {
		return fmt.Errorf("mock wallet failed to redirect user for authentication: %w", err)
	}

	if result.Request.URL.String() != hubAuthOIDCProviderSelectionURL {
		return fmt.Errorf(
			"the user ended up at the wrong login URL; expected %s got %s",
			mockLoginURL, result.Request.URL.String(),
		)
	}

	return nil
}

func (s *Steps) userSelectsThirdPartyOIDCProvider() error {
	request := fmt.Sprintf("%s?provider=%s", hubAuthSelectOIDCProviderURL, mockOIDCProviderName)

	result, err := s.browser.Get(request)
	if err != nil {
		return fmt.Errorf("user failed to select OIDC provider using request %s: %w", request, err)
	}

	if !strings.HasPrefix(result.Request.URL.String(), mockLoginURL) {
		return fmt.Errorf(
			"user at wrong third party OIDC provider; expected %s got %s",
			mockLoginURL, result.Request.URL.String(),
		)
	}

	return nil
}

func (s *Steps) userAuthenticatesAtThirdPartyProvider() error {
	s.expectedUserData = &UserClaims{
		Sub:        uuid.New().String(),
		Name:       "John Smith",
		GivenName:  "John",
		FamilyName: "Smith",
		Email:      "john.smith@example.org",
	}

	authn, err := json.Marshal(&userAuthenticationConfig{
		Sub: s.expectedUserData.Sub,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal user authn config: %w", err)
	}

	response, err := s.browser.Post(mockAuthenticationURL, "application/json", bytes.NewReader(authn))
	if err != nil {
		return fmt.Errorf("user failed to send authentication data: %w", err)
	}

	if !strings.HasPrefix(response.Request.URL.String(), mockConsentURL) {
		return fmt.Errorf(
			"user is at the wrong third party consent url; expected %s got %s",
			mockConsentURL, response.Request.URL.String(),
		)
	}

	authz, err := json.Marshal(&userAuthorizationConfig{
		UserClaims: s.expectedUserData,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal user authz config: %w", err)
	}

	response, err = s.browser.Post(mockAuthorizationURL, "application/json", bytes.NewReader(authz))
	if err != nil {
		return fmt.Errorf("user failed to send authorization data: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		msg, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		return fmt.Errorf(
			"unexpected status code; expected %d got %d msg=%s",
			http.StatusOK, response.StatusCode, msg,
		)
	}

	return nil
}

func (s *Steps) userRedirectedBackToWallet() error {
	if !s.wallet.ReceivedCallback {
		return fmt.Errorf("the wallet has not received a callback")
	}

	return nil
}

func (s *Steps) userHasAuthenticatedToTheWallet() error {
	if s.wallet.CallbackErr != nil {
		return fmt.Errorf("wallet failed to execute callback successfully: %w", s.wallet.CallbackErr)
	}

	if s.wallet.UserData.Sub != s.expectedUserData.Sub {
		return fmt.Errorf(
			"wallet received a different user idenfitier than expected; expected %s got %s",
			s.expectedUserData.Sub, s.wallet.UserData.Sub,
		)
	}

	s.ctx.SetAccessToken(s.wallet.accessToken)

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
