/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"
	"golang.org/x/oauth2"

	"github.com/trustbloc/hub-auth/pkg/bootstrap/user"
	"github.com/trustbloc/hub-auth/pkg/internal/common/support"
)

const (
	oauth2GetRequestPath = "/oauth2/request"
	oauth2CallbackPath   = "/oauth2/callback"
	// api path params
	scopeQueryParam = "scope"

	transientStoreName = "hub-auth-rest-transient"
	bootstrapStoreName = "bootstrap-data"
)

var logger = log.New("hub-auth-restapi")

type oidcClaims struct {
	Sub string `json:"sub"`
}

// Handler http handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type oidcProvider interface {
	Endpoint() oauth2.Endpoint
	Verifier(*oidc.Config) verifier
}

type verifier interface {
	Verify(context.Context, string) (idToken, error)
}

type oidcProviderImpl struct {
	op *oidc.Provider
}

func (o *oidcProviderImpl) Verifier(config *oidc.Config) verifier {
	return &verifierImpl{v: o.op.Verifier(config)}
}

type verifierImpl struct {
	v *oidc.IDTokenVerifier
}

func (v *verifierImpl) Verify(ctx context.Context, token string) (idToken, error) {
	return v.v.Verify(ctx, token)
}

func (o *oidcProviderImpl) Endpoint() oauth2.Endpoint {
	return o.op.Endpoint()
}

type idToken interface {
	Claims(interface{}) error
}

type oauth2Config interface {
	AuthCodeURL(string, ...oauth2.AuthCodeOption) string
	Exchange(context.Context, string, ...oauth2.AuthCodeOption) (oauth2Token, error)
}

type oauth2ConfigImpl struct {
	oc *oauth2.Config
}

func (o *oauth2ConfigImpl) AuthCodeURL(state string, options ...oauth2.AuthCodeOption) string {
	return o.oc.AuthCodeURL(state, options...)
}

func (o *oauth2ConfigImpl) Exchange(
	ctx context.Context, code string, options ...oauth2.AuthCodeOption) (oauth2Token, error) {
	return o.oc.Exchange(ctx, code, options...)
}

type oauth2Token interface {
	Extra(string) interface{}
}

// Operation defines handlers.
type Operation struct {
	client           httpClient
	requestTokens    map[string]string
	transientStore   storage.Store
	oidcProvider     oidcProvider
	oidcClientID     string
	oidcClientSecret string
	oidcCallbackURL  string
	oauth2ConfigFunc func(...string) oauth2Config
	bootstrapStore   storage.Store
}

// Config defines configuration for rp operations.
type Config struct {
	TLSConfig              *tls.Config
	RequestTokens          map[string]string
	OIDCProviderURL        string
	OIDCClientID           string
	OIDCClientSecret       string
	OIDCCallbackURL        string
	TransientStoreProvider storage.Provider
	StoreProvider          storage.Provider
}

type createOIDCRequestResponse struct {
	Request string `json:"request"`
}

// New returns rp operation instance.
func New(config *Config) (*Operation, error) {
	svc := &Operation{
		client:           &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
		requestTokens:    config.RequestTokens,
		oidcClientID:     config.OIDCClientID,
		oidcClientSecret: config.OIDCClientSecret,
		oidcCallbackURL:  config.OIDCCallbackURL,
	}
	// TODO remove this empty string check. This is just here temporarily to allow for testing of other parts
	// while the OIDC stuff is in development
	if config.OIDCProviderURL != "" {
		idp, err := oidc.NewProvider(
			oidc.ClientContext(
				context.Background(),
				&http.Client{
					Transport: &http.Transport{TLSClientConfig: config.TLSConfig},
				},
			),
			config.OIDCProviderURL,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to init oidc provider with url [%s]: %w", config.OIDCProviderURL, err)
		}

		svc.oidcProvider = &oidcProviderImpl{op: idp}

		svc.transientStore, err = createStore(config.TransientStoreProvider)
		if err != nil {
			return nil, fmt.Errorf("failed to create store : %w", err)
		}

		svc.oauth2ConfigFunc = func(scopes ...string) oauth2Config {
			config := &oauth2.Config{
				ClientID:     svc.oidcClientID,
				ClientSecret: svc.oidcClientSecret,
				Endpoint:     svc.oidcProvider.Endpoint(),
				RedirectURL:  fmt.Sprintf("%s%s", svc.oidcCallbackURL, oauth2CallbackPath),
				Scopes:       []string{oidc.ScopeOpenID},
			}

			if len(scopes) > 0 {
				config.Scopes = append(config.Scopes, scopes...)
			}

			return &oauth2ConfigImpl{oc: config}
		}
	}

	bootstrapStore, err := openBootstrapStore(config.StoreProvider)
	if err != nil {
		return nil, err
	}

	svc.bootstrapStore = bootstrapStore

	return svc, nil
}

func openBootstrapStore(provider storage.Provider) (storage.Store, error) {
	err := provider.CreateStore(bootstrapStoreName)
	if err == nil {
		logger.Infof(fmt.Sprintf("Created %s store.", bootstrapStoreName))
	} else {
		if !errors.Is(err, storage.ErrDuplicateStore) {
			return nil, err
		}

		logger.Infof(fmt.Sprintf("%s store already exists. Skipping creation.", bootstrapStoreName))
	}

	return provider.OpenStore(bootstrapStoreName)
}

func (c *Operation) createOIDCRequest(w http.ResponseWriter, r *http.Request) {
	scope := r.URL.Query().Get(scopeQueryParam)
	if scope == "" {
		c.writeErrorResponse(w, http.StatusBadRequest, "missing scope")

		return
	}

	// TODO #24 validate scope
	state := uuid.New().String()
	redirectURL := c.oauth2Config(scope).AuthCodeURL(state, oauth2.AccessTypeOnline)

	logger.Debugf("redirectURL: %s", redirectURL)

	response, err := json.Marshal(&createOIDCRequestResponse{
		Request: redirectURL,
	})
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to marshal response : %s", err))

		return
	}

	err = c.transientStore.Put(state, []byte(state))
	if err != nil {
		c.writeErrorResponse(w,
			http.StatusInternalServerError, fmt.Sprintf("failed to write state to transient store : %s", err))

		return
	}

	w.Header().Set("content-type", "application/json")

	_, err = w.Write(response)
	if err != nil {
		logger.Errorf("failed to write response : %s", err)
	}
}

func (c *Operation) handleOIDCCallback(w http.ResponseWriter, r *http.Request) { //nolint:funlen,gocyclo
	state := r.URL.Query().Get("state")
	if state == "" {
		handleAuthError(w, http.StatusBadRequest, "missing state")

		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		handleAuthError(w, http.StatusBadRequest, "missing code")

		return
	}

	_, err := c.transientStore.Get(state)
	if errors.Is(err, storage.ErrValueNotFound) {
		handleAuthError(w, http.StatusBadRequest, "invalid state parameter")

		return
	}

	if err != nil {
		handleAuthError(w, http.StatusInternalServerError, fmt.Sprintf("failed to query transient store for state : %s", err))

		return
	}

	oauthToken, err := c.oauth2Config().Exchange(r.Context(), code)
	if err != nil {
		handleAuthError(w, http.StatusBadGateway, fmt.Sprintf("failed to exchange oauth2 code for token : %s", err))

		return
	}

	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		handleAuthError(w, http.StatusBadGateway, "missing id_token")

		return
	}

	oidcToken, err := c.oidcProvider.Verifier(&oidc.Config{
		ClientID: c.oidcClientID,
	}).Verify(r.Context(), rawIDToken)
	if err != nil {
		handleAuthError(w, http.StatusForbidden, fmt.Sprintf("failed to verify id_token : %s", err))

		return
	}

	claims := &oidcClaims{}

	err = oidcToken.Claims(claims)
	if err != nil {
		handleAuthError(w, http.StatusInternalServerError, fmt.Sprintf("failed to extract claims from id_token : %s", err))

		return
	}

	userProfile, err := user.NewStore(c.bootstrapStore).Get(claims.Sub)
	if errors.Is(err, storage.ErrValueNotFound) {
		userProfile, err = c.onboardUser(claims.Sub)
		if err != nil {
			handleAuthError(w, http.StatusInternalServerError, fmt.Sprintf("failed to onboard new user : %s", err))

			return
		}
	}

	if err != nil {
		handleAuthError(w, http.StatusInternalServerError, fmt.Sprintf("failed to fetch user profile from store : %s", err))

		return
	}

	handleAuthResult(w, r, userProfile)
}

// TODO onboard user at key server and SDS: https://github.com/trustbloc/hub-auth/issues/38
func (c *Operation) onboardUser(id string) (*user.Profile, error) {
	userProfile := &user.Profile{
		ID: id,
	}

	err := user.NewStore(c.bootstrapStore).Save(userProfile)
	if err != nil {
		return nil, fmt.Errorf("failed to save user profile : %w", err)
	}

	return userProfile, nil
}

// TODO redirect to the UI: https://github.com/trustbloc/hub-auth/issues/39
func handleAuthResult(w http.ResponseWriter, r *http.Request, _ *user.Profile) {
	http.Redirect(w, r, "", http.StatusFound)
}

func handleAuthError(w http.ResponseWriter, status int, msg string) {
	// todo #issue-25 handle user data
	logger.Errorf(msg)

	w.WriteHeader(status)

	_, err := w.Write([]byte(msg))
	if err != nil {
		logger.Errorf("failed to write error response : %w", err)
	}
}

// writeResponse writes interface value to response.
func (c *Operation) writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	logger.Errorf(msg)

	rw.WriteHeader(status)

	if _, err := rw.Write([]byte(msg)); err != nil {
		logger.Errorf("Unable to send error message, %s", err)
	}
}

// GetRESTHandlers get all controller API handler available for this service.
func (c *Operation) GetRESTHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(oauth2GetRequestPath, http.MethodGet, c.createOIDCRequest),
		support.NewHTTPHandler(oauth2CallbackPath, http.MethodGet, c.handleOIDCCallback),
	}
}

func (c *Operation) oauth2Config(scopes ...string) oauth2Config {
	return c.oauth2ConfigFunc(scopes...)
}

func createStore(p storage.Provider) (storage.Store, error) {
	err := p.CreateStore(transientStoreName)
	if err != nil && !errors.Is(err, storage.ErrDuplicateStore) {
		return nil, fmt.Errorf("failed to create store [%s] : %w", transientStoreName, err)
	}

	return p.OpenStore(transientStoreName)
}
