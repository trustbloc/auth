/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	"golang.org/x/oauth2"

	"github.com/trustbloc/hub-auth/pkg/bootstrap/user"
	"github.com/trustbloc/hub-auth/pkg/internal/common/support"
	"github.com/trustbloc/hub-auth/pkg/restapi/common"
)

const (
	hydraLoginPath          = "/hydra/login"
	oauth2GetRequestPath    = "/oauth2/request"
	oauth2CallbackPath      = "/oauth2/callback"
	bootstrapGetRequestPath = "/bootstrap"
	deviceCertPath          = "/device"
	// api path params
	scopeQueryParam = "scope"

	transientStoreName = "hub-auth-rest-transient"
	bootstrapStoreName = "bootstrap-data"

	// redirect url parameter
	userProfileQueryParam  = "up"
	loginRequestQueryParam = "h"
)

var logger = log.New("hub-auth-restapi")

// Operation defines handlers.
type Operation struct {
	client           httpClient
	requestTokens    map[string]string
	transientStore   storage.Store
	oidcProvider     oidcProvider
	oidcClientID     string
	oidcClientSecret string
	oidcCallbackURL  string
	uiEndpoint       string
	oauth2ConfigFunc func(...string) oauth2Config
	bootstrapStore   storage.Store
	bootstrapConfig  *BootstrapConfig
	hydra            Hydra
	deviceRootCerts  *x509.CertPool
}

// Config defines configuration for rp operations.
type Config struct {
	TLSConfig              *tls.Config
	RequestTokens          map[string]string
	OIDCProviderURL        string
	OIDCClientID           string
	OIDCClientSecret       string
	OIDCCallbackURL        string
	UIEndpoint             string
	TransientStoreProvider storage.Provider
	StoreProvider          storage.Provider
	BootstrapConfig        *BootstrapConfig
	Hydra                  Hydra
	DeviceRootCerts        []string
	DeviceCertSystemPool   bool
}

// BootstrapConfig holds user bootstrap-related config.
type BootstrapConfig struct {
	SDSURL       string
	KeyServerURL string
}

// New returns rp operation instance.
func New(config *Config) (*Operation, error) {
	svc := &Operation{
		client:           &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
		requestTokens:    config.RequestTokens,
		oidcClientID:     config.OIDCClientID,
		oidcClientSecret: config.OIDCClientSecret,
		oidcCallbackURL:  config.OIDCCallbackURL,
		bootstrapConfig:  config.BootstrapConfig,
		hydra:            config.Hydra,
		uiEndpoint:       config.UIEndpoint,
	}

	// TODO implement retries: https://github.com/trustbloc/hub-auth/issues/45
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
		return nil, fmt.Errorf("failed to create store: %w", err)
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

	svc.bootstrapStore, err = openBootstrapStore(config.StoreProvider)
	if err != nil {
		return nil, err
	}

	svc.deviceRootCerts, err = tlsutils.GetCertPool(config.DeviceCertSystemPool, config.DeviceRootCerts)
	if err != nil {
		return nil, err
	}

	return svc, nil
}

// GetRESTHandlers get all controller API handler available for this service.
func (c *Operation) GetRESTHandlers() []common.Handler {
	return []common.Handler{
		support.NewHTTPHandler(hydraLoginPath, http.MethodGet, c.hydraLoginHandler),
		support.NewHTTPHandler(oauth2GetRequestPath, http.MethodGet, c.createOIDCRequest),
		support.NewHTTPHandler(oauth2CallbackPath, http.MethodGet, c.handleOIDCCallback),
		support.NewHTTPHandler(bootstrapGetRequestPath, http.MethodGet, c.handleBootstrapDataRequest),
		support.NewHTTPHandler(deviceCertPath, http.MethodPost, c.deviceCertHandler),
	}
}

func (c *Operation) hydraLoginHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("handling login request: %s", r.URL.String())

	challenge := r.URL.Query().Get("login_challenge")
	if challenge == "" {
		common.WriteErrorResponsef(w, logger, http.StatusBadRequest, "missing challenge on login request")

		return
	}

	req := admin.NewGetLoginRequestParams()

	req.SetLoginChallenge(challenge)

	login, err := c.hydra.GetLoginRequest(req)
	if err != nil {
		common.WriteErrorResponsef(w, logger,
			http.StatusBadGateway, "failed to fetch login request from hydra: %s", err.Error())

		return
	}

	// TODO need to check if the relying party (login.Payload.Client.ClientID) is registered:
	//  https://github.com/trustbloc/hub-auth/issues/53.

	handle := url.QueryEscape(uuid.New().String())

	err = newTransientData(c.transientStore).Put(handle, &loginCtx{
		HydraLoginRequest: login,
	})
	if err != nil {
		common.WriteErrorResponsef(w, logger,
			http.StatusInternalServerError, "failed to save login ctx: %s", err.Error())

		return
	}

	redirectURL := fmt.Sprintf("%s?%s=%s", c.uiEndpoint, loginRequestQueryParam, handle)

	http.Redirect(w, r, redirectURL, http.StatusFound)
	logger.Debugf("redirected to: %s", redirectURL)
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

	profileBytes, err := json.Marshal(userProfile)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to marshal user profile data : %s", err))

		return
	}

	c.handleAuthResult(w, r, profileBytes)
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

func (c *Operation) handleBootstrapDataRequest(w http.ResponseWriter, r *http.Request) {
	handle := r.URL.Query().Get(userProfileQueryParam)
	if handle == "" {
		handleAuthError(w, http.StatusBadRequest, "missing handle")

		return
	}

	profile, err := user.NewStore(c.transientStore).Get(handle)
	if errors.Is(err, storage.ErrValueNotFound) {
		handleAuthError(w, http.StatusBadRequest, "invalid handle")

		return
	}

	if err != nil {
		handleAuthError(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to query transient store for handle: %s", err))

		return
	}

	response, err := json.Marshal(&bootstrapData{
		SDSURL:            c.bootstrapConfig.SDSURL,
		SDSPrimaryVaultID: profile.SDSPrimaryVaultID,
		KeyServerURL:      c.bootstrapConfig.KeyServerURL,
		KeyStoreIDs:       profile.KeyStoreIDs,
	})
	if err != nil {
		handleAuthError(w, http.StatusInternalServerError, fmt.Sprintf("failed to marshal bootstrap data: %s", err))

		return
	}

	// TODO We should delete the handle from the transient store after writing the response,
	//  but edge-core store API doesn't have a Delete() operation: https://github.com/trustbloc/edge-core/issues/45
	_, err = w.Write(response)
	if err != nil {
		logger.Errorf("failed to write bootstrap data to output: %s", err)
	}
}

type certHolder struct {
	X5C    []string `json:"x5c"`
	Sub    string   `json:"sub"`
	AAGUID string   `json:"aaguid,omitempty"`
}

func (c *Operation) deviceCertHandler(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(r.Body)

	var ch certHolder

	err := dec.Decode(&ch)
	if err != nil {
		handleAuthError(w, http.StatusBadRequest, "cert request invalid json")
		return
	}

	userProfile, err := user.NewStore(c.bootstrapStore).Get(ch.Sub)
	if errors.Is(err, storage.ErrValueNotFound) {
		handleAuthError(w, http.StatusBadRequest, "invalid user profile id")
		return
	} else if err != nil {
		handleAuthError(w, http.StatusInternalServerError, "failed to load user profile")
		return
	}

	err = c.verifyDeviceCert(&ch)
	if err != nil {
		handleAuthError(w, http.StatusBadRequest, err.Error())
	}

	userProfile.AAGUID = ch.AAGUID

	profileBytes, err := json.Marshal(userProfile)
	if err != nil {
		c.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to marshal user profile data : %s", err))
		return
	}

	c.handleAuthResult(w, r, profileBytes)
}

func (c *Operation) verifyDeviceCert(ch *certHolder) error {
	if len(ch.X5C) == 0 {
		return errors.New("missing device certificate")
	}

	var certs = []*x509.Certificate{}

	for _, x5c := range ch.X5C {
		block, _ := pem.Decode([]byte(x5c))
		if block == nil || block.Bytes == nil {
			return errors.New("can't parse certificate PEM")
		}

		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return errors.New("can't parse certificate")
		}

		certs = append(certs, cert)
	}

	// first element is cert to verify
	deviceCert := certs[0]
	// any additional certs are intermediate certs
	intermediateCerts := certs[1:]

	intermediatePool := x509.NewCertPool()

	for _, iCert := range intermediateCerts {
		intermediatePool.AddCert(iCert)
	}

	_, err := deviceCert.Verify(x509.VerifyOptions{Intermediates: intermediatePool, Roots: c.deviceRootCerts})
	if err != nil {
		return errors.New("cert chain fails to authenticate")
	}

	return nil
}

func (c *Operation) handleAuthResult(w http.ResponseWriter, r *http.Request, profileBytes []byte) {
	handle := url.QueryEscape(uuid.New().String())

	err := c.transientStore.Put(handle, profileBytes)
	if err != nil {
		c.writeErrorResponse(w,
			http.StatusInternalServerError, fmt.Sprintf("failed to write handle to transient store: %s", err))

		return
	}

	redirectURL := fmt.Sprintf("%s?%s=%s", c.uiEndpoint, userProfileQueryParam, handle)

	http.Redirect(w, r, redirectURL, http.StatusFound)
	logger.Debugf("redirected to: %s", redirectURL)
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
