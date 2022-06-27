/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bootstrap

import (
	"fmt"
	"net/http"
	"reflect"

	"github.com/cucumber/godog"
	"github.com/google/uuid"

	"github.com/trustbloc/auth/pkg/restapi/operation"
	bddctx "github.com/trustbloc/auth/test/bdd/pkg/context"
	"github.com/trustbloc/auth/test/bdd/pkg/login"
)

const (
	bootstrapDataPath = login.AUTH_HOST + "/bootstrap"
	docsSDSURL        = "https://TODO.docs.sds.org"
	keysSDSURL        = "https://TODO.keys.sds.org"
	authKeyServerURL  = "https://TODO.auth.keyserver.org"
	opsKeyServerURL   = "https://TODO.ops.keyserver.org"
)

type Steps struct {
	browser             *http.Client
	ctx                 *bddctx.BDDContext
	wallet              *login.MockWallet
	bootstrapDataResult *operation.BootstrapData
	data                map[string]string
}

func NewSteps(ctx *bddctx.BDDContext) *Steps {
	return &Steps{ctx: ctx}
}

func (s *Steps) RegisterSteps(gs *godog.ScenarioContext) {
	gs.Step("a wallet that has logged in", s.userLoggedIn)
	gs.Step("a wallet that has logged in with GNAP", s.userLoggedInGNAP)
	gs.Step("the wallet executes an HTTP GET on the bootstrap endpoint", s.walletFetchesBootstrapData)
	gs.Step("auth returns the SDS and KeyServer URLs", s.hubAuthReturnsSDSAndKeyServerURLs)
	gs.Step("the wallet executes an HTTP POST on the bootstrap endpoint", s.walletUpdatesBootstrapData)
	gs.Step("auth returns the updated bootstrap data", s.hubAuthReturnsUpdatedBootstrapData)
}

func (s *Steps) userLoggedIn() error {
	var err error

	s.wallet, err = login.NewSteps(s.ctx).NewWalletLogin()
	if err != nil {
		return fmt.Errorf("failed to login user: %w", err)
	}

	return nil
}

func (s *Steps) userLoggedInGNAP() error {
	var err error

	s.wallet, err = login.NewSteps(s.ctx).NewWalletLoginGNAP()
	if err != nil {
		return fmt.Errorf("failed to login user: %w", err)
	}

	return nil
}

func (s *Steps) walletFetchesBootstrapData() error {
	var err error

	s.bootstrapDataResult, err = s.wallet.FetchBootstrapData(bootstrapDataPath)
	if err != nil {
		return fmt.Errorf("wallet failed to fetch bootstrap data: %w", err)
	}

	return nil
}

func (s *Steps) hubAuthReturnsSDSAndKeyServerURLs() error {
	if s.bootstrapDataResult.DocumentSDSVaultURL != docsSDSURL {
		return fmt.Errorf(
			"invalid documents SDS URL: expected %s got %s", docsSDSURL, s.bootstrapDataResult.DocumentSDSVaultURL,
		)
	}

	if s.bootstrapDataResult.KeySDSVaultURL != keysSDSURL {
		return fmt.Errorf(
			"invalid keys SDS URL: expected %s got %s", keysSDSURL, s.bootstrapDataResult.KeySDSVaultURL,
		)
	}

	if s.bootstrapDataResult.AuthZKeyServerURL != authKeyServerURL {
		return fmt.Errorf(
			"invalid auth keyserver URL: expected %s got %s", authKeyServerURL, s.bootstrapDataResult.AuthZKeyServerURL,
		)
	}

	if s.bootstrapDataResult.OpsKeyServerURL != opsKeyServerURL {
		return fmt.Errorf(
			"invalid keyServer URL: expected %s got %s", opsKeyServerURL, s.bootstrapDataResult.OpsKeyServerURL,
		)
	}

	return nil
}

func (s *Steps) walletUpdatesBootstrapData() error {
	s.data = map[string]string{
		"docs vault":    fmt.Sprintf("%s/vault/%s", docsSDSURL, uuid.New().String()),
		"keys vault":    fmt.Sprintf("%s/vault/%s", keysSDSURL, uuid.New().String()),
		"auth keystore": fmt.Sprintf("%s/vault/%s", authKeyServerURL, uuid.New().String()),
		"ops keystore":  fmt.Sprintf("%s/vault/%s", opsKeyServerURL, uuid.New().String()),
	}

	err := s.wallet.UpdateBootstrapData(bootstrapDataPath, &operation.UpdateBootstrapDataRequest{
		Data: s.data,
	})
	if err != nil {
		return fmt.Errorf("wallet failed to update bootstrap data: %w", err)
	}

	return nil
}

func (s *Steps) hubAuthReturnsUpdatedBootstrapData() error {
	err := s.walletFetchesBootstrapData()
	if err != nil {
		return err
	}

	err = s.hubAuthReturnsSDSAndKeyServerURLs()
	if err != nil {
		return err
	}

	if !reflect.DeepEqual(s.bootstrapDataResult.Data, s.data) {
		return fmt.Errorf(
			"unexpected bootstrap data received: expected %+v got %+v",
			s.data, s.bootstrapDataResult.Data,
		)
	}

	return nil
}
