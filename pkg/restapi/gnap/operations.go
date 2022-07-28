/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gnap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/square/go-jose/v3"
	"golang.org/x/oauth2"

	"github.com/trustbloc/auth/pkg/bootstrap/user"
	"github.com/trustbloc/auth/pkg/gnap/accesspolicy"
	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/pkg/gnap/authhandler"
	"github.com/trustbloc/auth/pkg/internal/common/support"
	"github.com/trustbloc/auth/pkg/restapi/common"
	oidcmodel "github.com/trustbloc/auth/pkg/restapi/common/oidc"
	"github.com/trustbloc/auth/spi/gnap"
	"github.com/trustbloc/auth/spi/gnap/proof/httpsig"
)

var logger = log.New("auth-restapi") //nolint:gochecknoglobals

const (
	gnapBasePath = "/gnap"
	// AuthRequestPath endpoint for GNAP authorization request.
	AuthRequestPath = gnapBasePath + "/auth"
	// AuthContinuePath endpoint for GNAP authorization continuation.
	AuthContinuePath = gnapBasePath + "/continue"
	// AuthIntrospectPath endpoint for GNAP token introspection.
	AuthIntrospectPath = gnapBasePath + "/introspect"
	// InteractPath endpoint for GNAP interact.
	InteractPath = gnapBasePath + "/interact"

	bootstrapPath = gnapBasePath + "/bootstrap"

	// oidc api handlers.
	authProvidersPath = "/oidc/providers"
	oidcLoginPath     = "/oidc/login"
	oidcCallbackPath  = "/oidc/callback"

	// GNAP error response codes.
	errInvalidRequest = "invalid_request"
	errRequestDenied  = "request_denied"

	// api path params.
	providerQueryParam = "provider"
	txnQueryParam      = "txnID"

	transientStoreName = "gnap_transient"
	bootstrapStoreName = "bootstrapdata"

	// client redirect query params.
	interactRefQueryParam  = "interact_ref"
	responseHashQueryParam = "hash"

	gnapScheme = "GNAP "
)

// TODO: figure out what logic should go in the access policy vs operation handlers.

// BootstrapData is the user's bootstrap data.
type BootstrapData struct {
	DocumentSDSVaultURL string            `json:"documentSDSURL"`
	KeySDSVaultURL      string            `json:"keySDSURL"`
	OpsKeyServerURL     string            `json:"opsKeyServerURL"`
	Data                map[string]string `json:"data,omitempty"`
}

// UpdateBootstrapDataRequest is a request to update bootstrap data.
type UpdateBootstrapDataRequest struct {
	Data map[string]string `json:"data"`
}

// Operation defines Auth Server GNAP handlers.
type Operation struct {
	authHandler         *authhandler.AuthHandler
	interactionHandler  api.InteractionHandler
	introspectHandler   common.Introspecter
	uiEndpoint          string
	closePopupHTML      string
	authProviders       []authProvider
	oidcProvidersConfig map[string]*oidcmodel.ProviderConfig
	cachedOIDCProviders map[string]oidcProvider
	cachedOIDCProvLock  sync.RWMutex
	tlsConfig           *tls.Config
	callbackURL         string
	timeout             uint64
	transientStore      storage.Store
	bootstrapStore      storage.Store
	bootstrapConfig     *BootstrapConfig
	gnapRSClient        *gnap.RequestClient
}

// Config defines configuration for GNAP operations.
type Config struct {
	StoreProvider          storage.Provider
	AccessPolicyConfig     *accesspolicy.Config
	BaseURL                string
	ClosePopupHTML         string
	InteractionHandler     api.InteractionHandler
	UIEndpoint             string
	OIDC                   *oidcmodel.Config
	StartupTimeout         uint64
	TransientStoreProvider storage.Provider
	TLSConfig              *tls.Config
	DisableHTTPSigVerify   bool
	BootstrapConfig        *BootstrapConfig
}

// BootstrapConfig holds user bootstrap-related config.
type BootstrapConfig struct {
	DocumentSDSVaultURL string
	KeySDSVaultURL      string
	OpsKeyServerURL     string
}

// New creates GNAP operation handler.
func New(config *Config) (*Operation, error) {
	authProviders := make([]authProvider, 0)

	for k, v := range config.OIDC.Providers {
		prov := authProvider{
			ID: k, Name: v.Name, SignUpIconURL: v.SignUpIconURL,
			SignInIconURL: v.SignInIconURL, Order: v.Order,
		}

		authProviders = append(authProviders, prov)
	}

	auth, err := authhandler.New(&authhandler.Config{
		StoreProvider:      config.StoreProvider,
		AccessPolicyConfig: config.AccessPolicyConfig,
		ContinuePath:       config.BaseURL + AuthContinuePath,
		InteractionHandler: config.InteractionHandler,
		DisableHTTPSig:     config.DisableHTTPSigVerify,
	})
	if err != nil {
		return nil, err
	}

	transientStore, err := createStore(config.TransientStoreProvider, transientStoreName)
	if err != nil {
		return nil, err
	}

	bootstrapStore, err := createStore(config.StoreProvider, bootstrapStoreName)
	if err != nil {
		return nil, err
	}

	introspectHandler := func(req *gnap.IntrospectRequest) (*gnap.IntrospectResponse, error) {
		return auth.HandleIntrospection(req, &skipVerify{})
	}

	gnapRSClient, err := createGNAPClient()
	if err != nil {
		return nil, err
	}

	return &Operation{
		authHandler:         auth,
		uiEndpoint:          config.UIEndpoint,
		authProviders:       authProviders,
		oidcProvidersConfig: config.OIDC.Providers,
		cachedOIDCProviders: make(map[string]oidcProvider),
		callbackURL:         config.BaseURL + oidcCallbackPath,
		timeout:             config.StartupTimeout,
		transientStore:      transientStore,
		bootstrapStore:      bootstrapStore,
		tlsConfig:           config.TLSConfig,
		interactionHandler:  config.InteractionHandler,
		closePopupHTML:      config.ClosePopupHTML,
		bootstrapConfig:     config.BootstrapConfig,
		introspectHandler:   introspectHandler,
		gnapRSClient:        gnapRSClient,
	}, nil
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []common.Handler {
	return []common.Handler{
		support.NewHTTPHandler(AuthRequestPath, http.MethodPost, o.authRequestHandler),
		// TODO add txn_id to url path
		support.NewHTTPHandler(InteractPath, http.MethodGet, o.interactHandler),
		support.NewHTTPHandler(AuthContinuePath, http.MethodPost, o.authContinueHandler),
		support.NewHTTPHandler(AuthIntrospectPath, http.MethodPost, o.authIntrospectHandler),

		support.NewHTTPHandler(authProvidersPath, http.MethodGet, o.authProvidersHandler),
		support.NewHTTPHandler(oidcLoginPath, http.MethodGet, o.oidcLoginHandler),
		support.NewHTTPHandler(oidcCallbackPath, http.MethodGet, o.oidcCallbackHandler),

		support.NewHTTPHandler(bootstrapPath, http.MethodGet, o.getBootstrapDataHandler),
		support.NewHTTPHandler(bootstrapPath, http.MethodPost, o.postBootstrapDataHandler),
	}
}

// SetIntrospectHandler sets the GNAP introspection handler for Operation's APIs.
func (o *Operation) SetIntrospectHandler(i common.Introspecter) {
	o.introspectHandler = i
}

func (o *Operation) authRequestHandler(w http.ResponseWriter, req *http.Request) {
	logger.Debugf("handling auth request to URL: %s", req.URL.String())

	authRequest := &gnap.AuthRequest{}

	bodyBytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Errorf("error reading request body: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		o.writeResponse(w, &gnap.ErrorResponse{
			Error: errRequestDenied,
		})

		return
	}

	req.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))

	if err = json.Unmarshal(bodyBytes, authRequest); err != nil {
		logger.Errorf("failed to parse gnap auth request: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		o.writeResponse(w, &gnap.ErrorResponse{
			Error: errInvalidRequest,
		})

		return
	}

	v := httpsig.NewVerifier(req)

	resp, err := o.authHandler.HandleAccessRequest(authRequest, v, "")
	if err != nil {
		logger.Errorf("access policy failed to handle access request: %s", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		o.writeResponse(w, &gnap.ErrorResponse{
			Error: errRequestDenied,
		})

		return
	}

	o.writeResponse(w, resp)
}

func (o *Operation) interactHandler(w http.ResponseWriter, req *http.Request) {
	// TODO validate txnID
	txnID := req.URL.Query().Get(txnQueryParam)

	redirURL, err := url.Parse(o.uiEndpoint + "/sign-up")
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to construct redirect url")

		return
	}

	q := redirURL.Query()

	q.Add(txnQueryParam, txnID)

	redirURL.RawQuery = q.Encode()

	// redirect to UI
	http.Redirect(w, req, redirURL.String(), http.StatusFound)
}

func (o *Operation) authProvidersHandler(w http.ResponseWriter, _ *http.Request) {
	o.writeResponse(w, &authProviders{Providers: o.authProviders})
}

type oidcTransientData struct {
	Provider string `json:"provider,omitempty"`
	TxnID    string `json:"txnID,omitempty"`
}

func (o *Operation) oidcLoginHandler(w http.ResponseWriter, r *http.Request) { // nolint: funlen
	logger.Debugf("handling request: %s", r.URL.String())

	providerID := r.URL.Query().Get(providerQueryParam)
	if providerID == "" {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing provider")

		return
	}

	interactTxnID := r.URL.Query().Get(txnQueryParam)
	if interactTxnID == "" {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing transaction ID")

		return
	}

	provider, err := o.getProvider(providerID)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest, "get provider: %s", err.Error())

		return
	}

	provConfig, ok := o.oidcProvidersConfig[providerID]
	if !ok {
		o.writeErrorResponse(w, http.StatusInternalServerError, "provider not supported: %s", providerID)

		return
	}

	scopes := []string{oidc.ScopeOpenID}
	if len(provConfig.Scopes) != 0 {
		scopes = append(scopes, provConfig.Scopes...)
	} else {
		scopes = append(scopes, "profile", "email")
	}

	state := uuid.New().String()

	data := &oidcTransientData{
		Provider: providerID,
		TxnID:    interactTxnID,
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to marshal oidc txn data : %s", err))

		return
	}

	err = o.transientStore.Put(state, dataBytes)
	if err != nil {
		o.writeErrorResponse(w,
			http.StatusInternalServerError, fmt.Sprintf("failed to write state data to transient store: %s", err))

		return
	}

	authOption := oauth2.SetAuthURLParam(providerQueryParam, providerID)
	redirectURL := provider.OAuth2Config(
		scopes...,
	).AuthCodeURL(state, oauth2.AccessTypeOnline, authOption)

	http.Redirect(w, r, redirectURL, http.StatusFound)

	logger.Debugf("redirected to: %s", redirectURL)
}

func (o *Operation) oidcCallbackHandler(w http.ResponseWriter, r *http.Request) { // nolint:funlen,gocyclo
	state := r.URL.Query().Get("state")
	if state == "" {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing state")

		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing code")

		return
	}

	// get state and provider details from transient store
	dataBytes, err := o.transientStore.Get(state)
	if err != nil {
		o.writeErrorResponse(w,
			http.StatusBadRequest, fmt.Sprintf("failed to get state data to transient store: %s", err))

		return
	}

	data := &oidcTransientData{}

	err = json.Unmarshal(dataBytes, data)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to parse oidc txn data : %s", err))

		return
	}

	providerID := data.Provider

	provider, err := o.getProvider(providerID)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest, "get provider : %s", err.Error())

		return
	}

	oauthToken, err := provider.OAuth2Config().Exchange(r.Context(), code)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadGateway,
			fmt.Sprintf("failed to exchange oauth2 code for token : %s", err))

		return
	}

	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		o.writeErrorResponse(w, http.StatusBadGateway, "missing id_token")

		return
	}

	oidcToken, err := provider.Verify(r.Context(), rawIDToken)
	if err != nil {
		o.writeErrorResponse(w, http.StatusForbidden, fmt.Sprintf("failed to verify id_token : %s", err))

		return
	}

	claims := &oidcClaims{}

	err = oidcToken.Claims(claims)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to extract claims from id_token : %s", err))

		return
	}

	_, err = user.NewStore(o.bootstrapStore).Get(claims.Sub)
	if errors.Is(err, storage.ErrDataNotFound) {
		_, err = o.onboardUser(claims.Sub)
		if err != nil {
			o.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to onboard new user : %s", err))

			return
		}
	}

	interactRef, responseHash, clientInteract, err := o.interactionHandler.CompleteInteraction(
		data.TxnID,
		&api.ConsentResult{
			SubjectData: map[string]string{
				"sub": claims.Sub,
			},
		},
	)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to complete GNAP interaction : %s", err))

		return
	}

	clientURI, err := url.Parse(clientInteract.Finish.URI)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest, "client provided invalid redirect URI : %s", err.Error())

		return
	}

	// TODO: validate clientURI for security

	q := clientURI.Query()

	q.Add(interactRefQueryParam, interactRef)
	q.Add(responseHashQueryParam, responseHash)

	clientURI.RawQuery = q.Encode()

	redirect := clientURI.String()

	t, err := template.ParseFiles(o.closePopupHTML)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to parse template : %s", err.Error())

		return
	}

	if err := t.Execute(w, map[string]interface{}{
		"RedirectURI": redirect,
	}); err != nil {
		logger.Errorf(fmt.Sprintf("failed execute html template: %s", err.Error()))
	}
}

func (o *Operation) authContinueHandler(w http.ResponseWriter, req *http.Request) {
	logger.Debugf("handling continue request to URL: %s", req.URL.String())

	tokHeader := strings.Split(strings.Trim(req.Header.Get("Authorization"), " "), " ")

	if len(tokHeader) < 2 || tokHeader[0] != "GNAP" {
		logger.Errorf("GNAP continuation endpoint requires GNAP token")
		w.WriteHeader(http.StatusUnauthorized)
		o.writeResponse(w, &gnap.ErrorResponse{
			Error: errRequestDenied,
		})

		return
	}

	token := tokHeader[1]

	continueRequest := &gnap.ContinueRequest{}

	bodyBytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Errorf("error reading request body: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		o.writeResponse(w, &gnap.ErrorResponse{
			Error: errRequestDenied,
		})

		return
	}

	req.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))

	if err = json.Unmarshal(bodyBytes, continueRequest); err != nil {
		logger.Errorf("failed to parse gnap continue request: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		o.writeResponse(w, &gnap.ErrorResponse{
			Error: errInvalidRequest,
		})

		return
	}

	v := httpsig.NewVerifier(req)

	resp, err := o.authHandler.HandleContinueRequest(continueRequest, token, v)
	if err != nil {
		logger.Errorf("access policy failed to handle continue request: %s", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		o.writeResponse(w, &gnap.ErrorResponse{
			Error: errRequestDenied,
		})

		return
	}

	o.writeResponse(w, resp)
}

func (o *Operation) getBootstrapDataHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("handling request")

	subject, proceed := o.subject(w, r)
	if !proceed {
		return
	}

	profile, err := user.NewStore(o.bootstrapStore).Get(subject)
	if errors.Is(err, storage.ErrDataNotFound) {
		o.writeErrorResponse(w, http.StatusBadRequest, "invalid handle")

		return
	}

	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to query bootstrap store for handle: %s", err))

		return
	}

	response, err := json.Marshal(&BootstrapData{
		DocumentSDSVaultURL: o.bootstrapConfig.DocumentSDSVaultURL,
		KeySDSVaultURL:      o.bootstrapConfig.KeySDSVaultURL,
		OpsKeyServerURL:     o.bootstrapConfig.OpsKeyServerURL,
		Data:                profile.Data,
	})
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("failed to marshal bootstrap data: %s", err))

		return
	}

	// TODO We should delete the handle from the transient store after writing the response,
	//  but edge-core store API doesn't have a Delete() operation: https://github.com/trustbloc/edge-core/issues/45
	_, err = w.Write(response)
	if err != nil {
		logger.Errorf("failed to write bootstrap data to output: %s", err)
	}

	logger.Debugf("finished handling request")
}

func (o *Operation) postBootstrapDataHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("handling request")

	subject, proceed := o.subject(w, r)
	if !proceed {
		return
	}

	update := &UpdateBootstrapDataRequest{}

	err := json.NewDecoder(r.Body).Decode(update)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest, "failed to decode request: %s", err.Error())

		return
	}

	existing, err := user.NewStore(o.bootstrapStore).Get(subject)
	if errors.Is(err, storage.ErrDataNotFound) {
		o.writeErrorResponse(w, http.StatusConflict, "associated bootstrap data not found")

		return
	}

	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to query storage: %s", err.Error())

		return
	}

	err = user.NewStore(o.bootstrapStore).Save(merge(existing, update))
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to update storage: %s", err.Error())

		return
	}

	logger.Debugf("finished handling request")
}

type skipVerify struct{}

// Verify skip request verification when introspecting internally through Go.
func (s skipVerify) Verify(_ *gnap.ClientKey) error {
	return nil
}

// InternalIntrospectHandler returns a handler that allows the auth server's handlers to perform GNAP introspection
// with itself as the AS and RS.
func (o *Operation) InternalIntrospectHandler() common.Introspecter {
	return o.introspectHandler
}

func (o *Operation) authIntrospectHandler(w http.ResponseWriter, req *http.Request) {
	logger.Debugf("handling introspect request to URL: %s", req.URL.String())

	introspectRequest := &gnap.IntrospectRequest{}

	bodyBytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Errorf("error reading request body: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		o.writeResponse(w, &gnap.ErrorResponse{
			Error: errRequestDenied,
		})

		return
	}

	req.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))

	if err = json.Unmarshal(bodyBytes, introspectRequest); err != nil {
		logger.Errorf("failed to parse gnap introspection request: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		o.writeResponse(w, &gnap.ErrorResponse{
			Error: errInvalidRequest,
		})

		return
	}

	v := httpsig.NewVerifier(req)

	resp, err := o.authHandler.HandleIntrospection(introspectRequest, v)
	if err != nil {
		logger.Errorf("failed to handle gnap introspection request: %s", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		o.writeResponse(w, &gnap.ErrorResponse{
			Error: errRequestDenied,
		})

		return
	}

	o.writeResponse(w, resp)
}

// WriteResponse writes interface value to response.
func (o *Operation) writeResponse(rw http.ResponseWriter, v interface{}) {
	rw.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(rw).Encode(v)
	if err != nil {
		logger.Errorf("Unable to send response: %s", err.Error())
	}
}

// writeResponse writes interface value to response.
func (o *Operation) writeErrorResponse(rw http.ResponseWriter, status int, msg string, args ...interface{}) {
	msg = fmt.Sprintf(msg, args...)
	logger.Errorf(msg)

	rw.WriteHeader(status)

	if _, err := rw.Write([]byte(msg)); err != nil {
		logger.Errorf("Unable to send error message, %s", err)
	}
}

func (o *Operation) getProvider(providerID string) (oidcProvider, error) {
	o.cachedOIDCProvLock.RLock()
	prov, ok := o.cachedOIDCProviders[providerID]
	o.cachedOIDCProvLock.RUnlock()

	if ok {
		return prov, nil
	}

	provider, ok := o.oidcProvidersConfig[providerID]
	if !ok {
		return nil, fmt.Errorf("provider not supported: %s", providerID)
	}

	prov, err := o.initOIDCProvider(providerID, provider)
	if err != nil {
		return nil, fmt.Errorf("failed to init oidc provider: %w", err)
	}

	o.cachedOIDCProvLock.Lock()
	o.cachedOIDCProviders[providerID] = prov
	o.cachedOIDCProvLock.Unlock()

	return prov, nil
}

func (o *Operation) initOIDCProvider(providerID string, config *oidcmodel.ProviderConfig) (oidcProvider, error) {
	var idp *oidc.Provider

	err := backoff.RetryNotify(
		func() error {
			var idpErr error

			ctx := context.Background()

			if config.SkipIssuerCheck {
				ctx = oidc.InsecureIssuerURLContext(context.Background(), config.URL)
			}

			idp, idpErr = oidc.NewProvider(
				oidc.ClientContext(
					ctx,
					&http.Client{
						Transport: &http.Transport{TLSClientConfig: o.tlsConfig},
					},
				),
				config.URL,
			)

			return idpErr
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), o.timeout),
		func(retryErr error, t time.Duration) {
			logger.Warnf(
				"failed to connect to the [%s] OIDC provider, will sleep for %s before trying again : %s",
				providerID, t, retryErr)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to init oidc provider [%s] with url [%s]: %w", providerID, config.URL, err)
	}

	return &oidcProviderImpl{
		name:            providerID,
		clientID:        config.ClientID,
		clientSecret:    config.ClientSecret,
		callback:        o.callbackURL,
		skipIssuerCheck: config.SkipIssuerCheck,
		op:              idp,
		httpClient: &http.Client{Transport: &http.Transport{
			TLSClientConfig: o.tlsConfig,
		}},
	}, nil
}

func createStore(p storage.Provider, name string) (storage.Store, error) {
	s, err := p.OpenStore(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open store [%s]: %w", name, err)
	}

	return s, nil
}

func createGNAPClient() (*gnap.RequestClient, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("creating public key for GNAP RS role: %w", err)
	}

	return &gnap.RequestClient{
		IsReference: false,
		Key: &gnap.ClientKey{
			Proof: "httpsig",
			JWK: jwk.JWK{
				JSONWebKey: jose.JSONWebKey{
					Key:       &priv.PublicKey,
					KeyID:     "key2",
					Algorithm: "ES256",
				},
				Kty: "EC",
				Crv: "P-256",
			},
		},
	}, nil
}

func (o *Operation) onboardUser(sub string) (*user.Profile, error) {
	userProfile := &user.Profile{
		ID:   sub,
		Data: make(map[string]string),
	}

	err := user.NewStore(o.bootstrapStore).Save(userProfile)
	if err != nil {
		return nil, fmt.Errorf("failed to save user profile : %w", err)
	}

	return userProfile, nil
}

func (o *Operation) subject(w http.ResponseWriter, r *http.Request) (string, bool) {
	authHeader := strings.TrimSpace(r.Header.Get("authorization"))
	if authHeader == "" {
		o.writeErrorResponse(w, http.StatusForbidden, "no credentials")

		return "", false
	}

	switch {
	case strings.HasPrefix(authHeader, gnapScheme):
		return o.gnapSub(w, r, authHeader)
	default:
		o.writeErrorResponse(w, http.StatusBadRequest, "invalid authorization scheme")

		return "", false
	}
}

func (o *Operation) gnapSub(w http.ResponseWriter, _ *http.Request, authHeader string) (string, bool) {
	token := authHeader[len(gnapScheme):]

	introspection, err := o.introspectHandler(&gnap.IntrospectRequest{
		AccessToken:    token,
		ResourceServer: o.gnapRSClient,
	})
	if err != nil {
		o.writeErrorResponse(w, http.StatusUnauthorized, "failed to introspect token: %s", err.Error())

		return "", false
	}

	if sub, ok := introspection.SubjectData["sub"]; ok {
		return sub, true
	}

	o.writeErrorResponse(w, http.StatusUnauthorized, "token does not grant access to subject id")

	return "", false
}

func merge(existing *user.Profile, update *UpdateBootstrapDataRequest) *user.Profile {
	merged := &user.Profile{
		ID:     existing.ID,
		AAGUID: existing.AAGUID,
		Data:   existing.Data,
	}

	if merged.Data == nil {
		merged.Data = make(map[string]string)
	}

	for k, v := range update.Data {
		if _, found := merged.Data[k]; !found {
			merged.Data[k] = v
		}
	}

	return merged
}
