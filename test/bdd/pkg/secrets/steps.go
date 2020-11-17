/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secrets

import (
	"fmt"

	"github.com/cucumber/godog"
	"github.com/trustbloc/hub-auth/test/bdd/pkg/login"

	bddctx "github.com/trustbloc/hub-auth/test/bdd/pkg/context"
)

const (
	secretsEndpoint = login.HUB_AUTH_HOST + "/secret"
	apiToken        = "test_token"
)

func NewSteps(ctx *bddctx.BDDContext) *Steps {
	return &Steps{
		ctx:       ctx,
		keyServer: NewMockKeyServer(apiToken, ctx.TLSConfig()),
	}
}

type Steps struct {
	ctx       *bddctx.BDDContext
	wallet    *login.MockWallet
	keyServer *MockKeyServer
}

func (s *Steps) RegisterSteps(gs *godog.Suite) {
	gs.Step("a user logged in with their wallet", s.userLogin)
	gs.Step("the wallet stores the secret in hub-auth", s.walletStoresSecretInHubAuth)
	gs.Step("the key server queries hub-auth for the secret", s.keyServerFetchesSecret)
	gs.Step("the key server receives the secret", s.keyServerReceivesTheSameSecret)
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
		return fmt.Errorf("wallet failed to store secret in hub-auth: %w", err)
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
