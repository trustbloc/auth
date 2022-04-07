/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secrets

import (
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	"github.com/trustbloc/auth/test/bdd/pkg/login"

	bddctx "github.com/trustbloc/auth/test/bdd/pkg/context"
)

const (
	secretsEndpoint = login.AUTH_HOST + "/secret"
	apiToken        = "test_token"
)

func NewSteps(ctx *bddctx.BDDContext) *Steps {
	return &Steps{
		ctx:       ctx,
		keyServer: NewMockKeyServer(apiToken, ctx.TLSConfig()),
	}
}

type Steps struct {
	ctx             *bddctx.BDDContext
	wallet          *login.MockWallet
	keyServer       *MockKeyServer
	updateSecretErr error
}

func (s *Steps) RegisterSteps(gs *godog.Suite) {
	gs.Step("a user logged in with their wallet", s.userLogin)
	gs.Step("the wallet stores the secret in auth", s.walletStoresSecretInHubAuth)
	gs.Step("the key server queries auth for the secret", s.keyServerFetchesSecret)
	gs.Step("the key server receives the secret", s.keyServerReceivesTheSameSecret)
	gs.Step("the wallet attempts to store the secret again", s.walletAttemptsStoringSecretAgain)
	gs.Step("auth returns an error", s.updateSecretResultsInError)
}

func (s *Steps) userLogin() error {
	var err error

	s.wallet, err = login.NewSteps(s.ctx).NewWalletLogin()
	if err != nil {
		return fmt.Errorf("wallet failed to login: %w", err)
	}

	return nil
}

func (s *Steps) walletStoresSecretInHubAuth() error {
	err := s.wallet.CreateAndPushSecretToHubAuth(secretsEndpoint)
	if err != nil {
		return fmt.Errorf("wallet failed to store secret in auth: %w", err)
	}

	return nil
}

func (s *Steps) keyServerFetchesSecret() error {
	err := s.keyServer.FetchSecretShare(fmt.Sprintf("%s?sub=%s", secretsEndpoint, s.wallet.UserData.Sub))
	if err != nil {
		return fmt.Errorf("key server failed to fetch the user's secret: %w", err)
	}

	return nil
}

func (s *Steps) keyServerReceivesTheSameSecret() error {
	if s.keyServer.UserSecret != s.wallet.Secret {
		return fmt.Errorf(
			"keyServer received an unexpected secret: expected %s got %s",
			s.wallet.Secret, s.keyServer.UserSecret,
		)
	}

	return nil
}

func (s *Steps) walletAttemptsStoringSecretAgain() error {
	s.updateSecretErr = s.wallet.CreateAndPushSecretToHubAuth(secretsEndpoint)
	if s.updateSecretErr == nil {
		return fmt.Errorf("expected an error while pushing the secrets again but got nil")
	}

	return nil
}

func (s *Steps) updateSecretResultsInError() error {
	if !strings.Contains(s.updateSecretErr.Error(), "secret already set") {
		return fmt.Errorf("unexpected error message from auth: %s", s.updateSecretErr.Error())
	}

	return nil
}
