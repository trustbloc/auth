/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bootstrap

import (
	"fmt"
	"github.com/google/uuid"
	"net/http"

	"github.com/trustbloc/hub-auth/pkg/restapi/operation"

	"github.com/cucumber/godog"

	bddctx "github.com/trustbloc/hub-auth/test/bdd/pkg/context"
	"github.com/trustbloc/hub-auth/test/bdd/pkg/login"
)

const (
	bootstrapDataPath = login.HUB_AUTH_HOST + "/bootstrap"
	sdsURL            = "https://TODO.sds.org/"
	keyServerURL      = "https://TODO.keyserver.org/"
)

type Steps struct {
	browser             *http.Client
	ctx                 *bddctx.BDDContext
	wallet              *login.MockWallet
	bootstrapDataResult *operation.BootstrapData
	sdsVaultID   		string
	keyStoreID          []string
}

func NewSteps(ctx *bddctx.BDDContext) *Steps {
	return &Steps{ctx: ctx}
}

func (s *Steps) RegisterSteps(gs *godog.Suite) {
	gs.Step("a wallet that has logged in", s.userLoggedIn)
	gs.Step("the wallet executes an HTTP GET on the bootstrap endpoint", s.walletFetchesBootstrapData)
	gs.Step("hub-auth returns the SDS and KeyServer URLs", s.hubAuthReturnsSDSAndKeyServerURLs)
	gs.Step("the wallet executes an HTTP POST on the bootstrap endpoint", s.walletUpdatesBootstrapData)
	gs.Step("hub-auth returns the updated bootstrap data", s.hubAuthReturnsUpdatedBootstrapData)
}

func (s *Steps) userLoggedIn() error {
	var err error

	s.wallet, err = login.NewSteps(s.ctx).NewWalletLogin()
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
	if s.bootstrapDataResult.SDSURL != sdsURL {
		return fmt.Errorf(
			"invalid SDS URL: expected %s got %s", sdsURL, s.bootstrapDataResult.SDSURL,
		)
	}

	if s.bootstrapDataResult.KeyServerURL != keyServerURL {
		return fmt.Errorf(
			"invalid keyServer URL: expected %s got %s", keyServerURL, s.bootstrapDataResult.KeyServerURL,
		)
	}

	return nil
}

func (s *Steps) walletUpdatesBootstrapData() error {
	s.sdsVaultID = fmt.Sprintf("%s/vault/%s", sdsURL, uuid.New().String())
	s.keyStoreID = []string{fmt.Sprintf("%s/keystores/%s", keyServerURL, uuid.New().String())}

	err := s.wallet.UpdateBootstrapData(bootstrapDataPath, &operation.UpdateBootstrapDataRequest{
		SDSPrimaryVaultID: s.sdsVaultID,
		KeyStoreIDs:       s.keyStoreID,
	})
	if err != nil {
		return fmt.Errorf("wallet failed to update bootstrap data: %w", err)
	}

	return nil
}

func (s *Steps) hubAuthReturnsUpdatedBootstrapData() error {
	err := s.hubAuthReturnsSDSAndKeyServerURLs()
	if err != nil {
		return err
	}

	if s.bootstrapDataResult.SDSPrimaryVaultID != s.sdsVaultID {
		return fmt.Errorf(
			"unexpected SDS primary vault ID: expected %s got %s",
			s.sdsVaultID, s.bootstrapDataResult.SDSPrimaryVaultID,
		)
	}

	if !equalStrings(s.keyStoreID, s.bootstrapDataResult.KeyStoreIDs) {
		return fmt.Errorf(
			"unexpected keystore IDs returned: expected %+v got %+v",
			s.keyStoreID, s.bootstrapDataResult.KeyStoreIDs,
		)
	}

	return nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
