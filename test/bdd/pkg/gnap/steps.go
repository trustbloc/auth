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

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/trustbloc/auth/component/gnap/as"
	"github.com/trustbloc/auth/spi/gnap"

	bddctx "github.com/trustbloc/auth/test/bdd/pkg/context"
)

const (
	authServerURL       = "https://auth.trustbloc.local:8070"
	expectedInteractURL = authServerURL + "/gnap/interact"
)

type Steps struct {
	ctx        *bddctx.BDDContext
	gnapClient *as.Client
	pubKeyJWK  jwk.JWK
	authResp   *gnap.AuthResponse
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
		return fmt.Errorf("failed to gnap go-client: %w", err)
	}

	s.gnapClient = gnapClient
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
			"invalid interact url: expected %s got %s",
			expectedInteractURL, authResp.Interact.Redirect,
		)
	}

	s.authResp = authResp

	return nil
}

func (s *Steps) interactRedirect() error {
	// TODO get interact url

	// TODO use browser to redirect

	// TODO select provider

	// TODO login to third party oidc

	// TODO get the redirect back

	return nil
}

func (s *Steps) continueRequest() error {
	// TODO get continue req API url

	// TODO call continue API

	// TODO validate acess token

	return nil
}
