/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package login

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"

	bddctx "github.com/trustbloc/auth/test/bdd/pkg/context"
)

const (
	AUTH_HOST                       = "https://auth.trustbloc.local:8070"
	hubAuthHydraAdminURL            = "https://localhost:4445"
	hubAuthOIDCProviderURL          = "https://localhost:4444/"
)

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

// NewWalletLogin returns a new common.MockWallet that is logged in.
func (s *Steps) NewWalletLoginGNAP() (*MockWallet, error) {
	err := s.registerWallet()
	if err != nil {
		return nil, err
	}

	err = s.wallet.GNAPLogin(authServerURL)
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

func (s *Steps) userHasAuthenticatedToTheWallet() error {
	if s.wallet.CallbackErr != nil {
		return fmt.Errorf("wallet failed to execute callback successfully: %w", s.wallet.CallbackErr)
	}

	if len(s.wallet.UserData.Sub) == 0 {
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
