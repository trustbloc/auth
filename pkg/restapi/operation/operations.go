/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/trustbloc/edge-core/pkg/log"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	"golang.org/x/oauth2"

	"github.com/trustbloc/hub-auth/pkg/bootstrap/user"
	"github.com/trustbloc/hub-auth/pkg/internal/common/support"
	"github.com/trustbloc/hub-auth/pkg/restapi/common"
	"github.com/trustbloc/hub-auth/pkg/restapi/common/store/cookie"
)

const (
	hydraLoginPath    = "/hydra/login"
	hydraConsentPath  = "/hydra/consent"
	oidcLoginPath     = "/oauth2/login"
	oidcCallbackPath  = "/oauth2/callback"
	bootstrapPath     = "/bootstrap"
	secretsPath       = "/secret"
	deviceCertPath    = "/device"
	authProvidersPath = "/oauth2/providers"
	// api path params
	providerQueryParam        = "provider"
	stateCookie               = "oauth2_state"
	providerCookie            = "oauth2_provider"
	hydraLoginChallengeCookie = "hydra_login_challenge"

	transientStoreName = "transient"
	bootstrapStoreName = "bootstrapdata"
	secretsStoreName   = "secrets"

	// redirect url parameter
	userProfileQueryParam = "up"
)

var logger = log.New("hub-auth-restapi")

// Operation defines handlers.
type Operation struct {
	client              httpClient
	requestTokens       map[string]string
	transientStore      storage.Store
	oidcProvidersConfig map[string]OIDCProviderConfig
	cachedOIDCProviders map[string]oidcProvider
	uiEndpoint          string
	bootstrapStore      storage.Store
	secretsStore        storage.Store
	bootstrapConfig     *BootstrapConfig
	hydra               Hydra
	deviceRootCerts     *x509.CertPool
	cookies             cookie.Store
	secretsToken        string
	tlsConfig           *tls.Config
	callbackURL         string
	timeout             uint64
	cachedOIDCProvLock  sync.RWMutex
	authProviders       []authProvider
}

// Config defines configuration for rp operations.
type Config struct {
	TLSConfig              *tls.Config
	RequestTokens          map[string]string
	OIDC                   *OIDCConfig
	UIEndpoint             string
	TransientStoreProvider storage.Provider
	StoreProvider          storage.Provider
	BootstrapConfig        *BootstrapConfig
	Hydra                  Hydra
	DeviceRootCerts        []string
	DeviceCertSystemPool   bool
	Cookies                *CookieConfig
	StartupTimeout         uint64
	SecretsToken           string
}

// OIDCConfig holds the OIDC configuration.
type OIDCConfig struct {
	CallbackURL string
	Providers   map[string]OIDCProviderConfig
}

// OIDCProviderConfig holds the configuration for a single OIDC provider.
type OIDCProviderConfig struct {
	URL          string
	ClientID     string
	ClientSecret string
	Name         string
	LogoURL      string
}

// CookieConfig holds cookie configuration.
type CookieConfig struct {
	AuthKey []byte
	EncKey  []byte
}

// BootstrapConfig holds user bootstrap-related config.
type BootstrapConfig struct {
	DocumentSDSVaultURL string
	KeySDSVaultURL      string
	AuthZKeyServerURL   string
	OpsKeyServerURL     string
}

// New returns rp operation instance.
func New(config *Config) (*Operation, error) {
	authProviders := make([]authProvider, 0)

	for _, v := range config.OIDC.Providers {
		prov := authProvider{ID: v.ClientID, Name: v.Name, LogoURL: v.LogoURL}
		fmt.Println(prov)

		authProviders = append(authProviders, prov)
	}

	svc := &Operation{
		client:              &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
		requestTokens:       config.RequestTokens,
		bootstrapConfig:     config.BootstrapConfig,
		hydra:               config.Hydra,
		uiEndpoint:          config.UIEndpoint,
		cookies:             cookie.NewStore(config.Cookies.AuthKey, config.Cookies.EncKey),
		secretsToken:        config.SecretsToken,
		oidcProvidersConfig: config.OIDC.Providers,
		tlsConfig:           config.TLSConfig,
		callbackURL:         config.OIDC.CallbackURL,
		cachedOIDCProviders: make(map[string]oidcProvider),
		timeout:             config.StartupTimeout,
		authProviders:       authProviders,
	}

	var err error

	svc.transientStore, err = createStore(config.TransientStoreProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	svc.bootstrapStore, err = openStore(config.StoreProvider, bootstrapStoreName)
	if err != nil {
		return nil, err
	}

	svc.deviceRootCerts, err = tlsutils.GetCertPool(config.DeviceCertSystemPool, config.DeviceRootCerts)
	if err != nil {
		return nil, err
	}

	svc.secretsStore, err = openStore(config.StoreProvider, secretsStoreName)
	if err != nil {
		return nil, err
	}

	return svc, nil
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []common.Handler {
	return []common.Handler{
		support.NewHTTPHandler(authProvidersPath, http.MethodGet, o.authProvidersHandler),
		support.NewHTTPHandler(hydraLoginPath, http.MethodGet, o.hydraLoginHandler),
		support.NewHTTPHandler(oidcLoginPath, http.MethodGet, o.oidcLoginHandler),
		support.NewHTTPHandler(oidcCallbackPath, http.MethodGet, o.oidcCallbackHandler),
		support.NewHTTPHandler(hydraConsentPath, http.MethodGet, o.hydraConsentHandler),
		support.NewHTTPHandler(bootstrapPath, http.MethodGet, o.getBootstrapDataHandler),
		support.NewHTTPHandler(bootstrapPath, http.MethodPost, o.postBootstrapDataHandler),
		support.NewHTTPHandler(secretsPath, http.MethodPost, o.postSecretHandler),
		support.NewHTTPHandler(secretsPath, http.MethodGet, o.getSecretHandler),
		support.NewHTTPHandler(deviceCertPath, http.MethodPost, o.deviceCertHandler),
	}
}

func (o *Operation) authProvidersHandler(w http.ResponseWriter, _ *http.Request) {
	o.writeResponse(w, &authProviders{Providers: o.authProviders})
}

func (o *Operation) hydraLoginHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("handling login request: %s", r.URL.String())

	challenge := r.URL.Query().Get("login_challenge")
	if challenge == "" {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing challenge on login request")

		return
	}

	req := admin.NewGetLoginRequestParams()

	req.SetLoginChallenge(challenge)

	// ensure login request is valid
	_, err := o.hydra.GetLoginRequest(req) // nolint:errcheck // don't know why errcheck is complaining
	if err != nil {
		o.writeErrorResponse(w,
			http.StatusBadGateway, "failed to fetch login request from hydra: %s", err.Error())

		return
	}

	jar, err := o.cookies.Open(r)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to open cookie store: %s", err.Error())

		return
	}

	jar.Set(hydraLoginChallengeCookie, challenge)

	err = jar.Save(r, w)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to save hydra login cookie: %s", err.Error())

		return
	}

	// TODO need to check if the relying party (login.Payload.Client.ClientID) is registered:
	//  https://github.com/trustbloc/hub-auth/issues/53.

	redirectURL := o.uiEndpoint

	http.Redirect(w, r, redirectURL, http.StatusFound)
	logger.Debugf("redirected to: %s", redirectURL)
}

func (o *Operation) oidcLoginHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("handling request: %s", r.URL.String())

	providerID := r.URL.Query().Get(providerQueryParam)
	if providerID == "" {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing provider")

		return
	}

	provider, err := o.getProvider(providerID)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest, "get provider: %s", err.Error())

		return
	}

	state := uuid.New().String()

	jar, err := o.cookies.Open(r)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to open session cookies: %s", err.Error())

		return
	}

	jar.Set(stateCookie, state)
	jar.Set(providerCookie, provider.Name())

	err = jar.Save(r, w)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to persist session cookies: %w", err.Error())

		return
	}

	redirectURL := provider.OAuth2Config(
		oidc.ScopeOpenID,
		"profile",
		"email",
	).AuthCodeURL(state, oauth2.AccessTypeOnline)

	http.Redirect(w, r, redirectURL, http.StatusFound)

	logger.Debugf("redirected to: %s", redirectURL)
}

func (o *Operation) oidcCallbackHandler(w http.ResponseWriter, r *http.Request) { //nolint:funlen,gocyclo
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

	jar, err := o.cookies.Open(r)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to get cookies: %s", err.Error())

		return
	}

	cookieState, found := jar.Get(stateCookie)
	if !found {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing state cookie")

		return
	}

	if state != cookieState {
		o.writeErrorResponse(w, http.StatusBadRequest, "invalid state parameter")

		return
	}

	cookieProvider, found := jar.Get(providerCookie)
	if !found {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing provider cookie")

		return
	}

	hydraLoginChallenge, found := jar.Get(hydraLoginChallengeCookie)
	if !found {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing hydra login challenge cookie")

		return
	}

	provider, err := o.getProvider(fmt.Sprintf("%s", cookieProvider))
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

	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to fetch user profile from store : %s", err))

		return
	}

	jar.Delete(hydraLoginChallengeCookie)
	jar.Delete(stateCookie)
	jar.Delete(providerCookie)

	err = jar.Save(r, w)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to delete cookies: %s", err.Error())

		return
	}

	accept := admin.NewAcceptLoginRequestParams()

	accept.SetLoginChallenge(fmt.Sprintf("%s", hydraLoginChallenge))
	accept.SetBody(&models.AcceptLoginRequest{
		Subject: &claims.Sub,
	})

	loginResponse, err := o.hydra.AcceptLoginRequest(accept)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadGateway,
			"hydra failed to accept login request : %s", err.Error())

		return
	}

	redirectURL := *loginResponse.Payload.RedirectTo

	http.Redirect(w, r, redirectURL, http.StatusFound)
	logger.Debugf("redirected to: %s", redirectURL)
}

func (o *Operation) hydraConsentHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("handling request: %s", r.URL.String())

	challenge := r.URL.Query().Get("consent_challenge")
	if challenge == "" {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing consent_challenge")

		return
	}

	req := admin.NewGetConsentRequestParamsWithContext(r.Context())
	req.SetConsentChallenge(challenge)

	consent, err := o.hydra.GetConsentRequest(req)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadGateway,
			"failed to fetch consent request from hydra : %s", err)

		return
	}

	// ensure user exists
	_, err = user.NewStore(o.bootstrapStore).Get(consent.Payload.Subject)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to query for user profile: %s", err.Error())

		return
	}

	params := admin.NewAcceptConsentRequestParams()

	params.SetContext(r.Context())
	params.SetConsentChallenge(challenge)
	params.SetBody(&models.AcceptConsentRequest{
		GrantAccessTokenAudience: consent.Payload.RequestedAccessTokenAudience,
		GrantScope:               consent.Payload.RequestedScope,
		HandledAt:                models.NullTime(time.Now()),
		Remember:                 true,
		Session:                  nil,
	})

	accepted, err := o.hydra.AcceptConsentRequest(params)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadGateway, "hydra failed to accept consent request: %s", err.Error())

		return
	}

	redirectURL := *accepted.Payload.RedirectTo

	http.Redirect(w, r, redirectURL, http.StatusFound)
	logger.Debugf("redirected to: %s", redirectURL)
}

// TODO onboard user at key server and SDS: https://github.com/trustbloc/hub-auth/issues/38
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
		AuthZKeyServerURL:   o.bootstrapConfig.AuthZKeyServerURL,
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

func (o *Operation) postSecretHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("handling request")

	subject, proceed := o.subject(w, r)
	if !proceed {
		return
	}

	// ensure user exists
	_, err := user.NewStore(o.bootstrapStore).Get(subject)
	if errors.Is(err, storage.ErrDataNotFound) {
		o.writeErrorResponse(w, http.StatusConflict, "no such user")

		return
	}

	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to query bootstrap store: %s", err.Error())

		return
	}

	// ensure secret is not set already
	_, err = o.secretsStore.Get(subject)
	if err == nil {
		o.writeErrorResponse(w, http.StatusConflict, "secret already set")

		return
	}

	if !errors.Is(err, storage.ErrDataNotFound) {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to query secrets store: %s", err.Error())

		return
	}

	payload := &SetSecretRequest{}

	err = json.NewDecoder(r.Body).Decode(payload)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest, "failed to decode payload: %s", err.Error())

		return
	}

	err = o.secretsStore.Put(subject, payload.Secret)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to save to secrets store: %s", err.Error())

		return
	}

	logger.Debugf("finished handling request")
}

func (o *Operation) getSecretHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("handling request")

	token, proceed := o.bearerToken(w, r)
	if !proceed {
		return
	}

	if token != o.secretsToken {
		o.writeErrorResponse(w, http.StatusForbidden, "unauthorized")

		return
	}

	sub := r.URL.Query().Get("sub")
	if sub == "" {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing parameter")

		return
	}

	secret, err := o.secretsStore.Get(sub)
	if errors.Is(err, storage.ErrDataNotFound) {
		o.writeErrorResponse(w, http.StatusBadRequest, "non-existent user")

		return
	}

	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to query secrets store: %s", err.Error())

		return
	}

	response, err := json.Marshal(&GetSecretResponse{
		Secret: base64.StdEncoding.EncodeToString(secret),
	})
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to encode response: %s", err.Error())

		return
	}

	_, err = w.Write(response)
	if err != nil {
		logger.Errorf("failed to write response: %s", err.Error())

		return
	}

	logger.Debugf("finished handling request")
}

type certHolder struct {
	X5C    []string `json:"x5c"`
	Sub    string   `json:"sub"`
	AAGUID string   `json:"aaguid,omitempty"`
}

func (o *Operation) deviceCertHandler(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(r.Body)

	var ch certHolder

	err := dec.Decode(&ch)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest, "cert request invalid json")
		return
	}

	userProfile, err := user.NewStore(o.bootstrapStore).Get(ch.Sub)
	if errors.Is(err, storage.ErrDataNotFound) {
		o.writeErrorResponse(w, http.StatusBadRequest, "invalid user profile id")
		return
	} else if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to load user profile")
		return
	}

	err = o.verifyDeviceCert(&ch)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest, err.Error())
	}

	userProfile.AAGUID = ch.AAGUID

	profileBytes, err := json.Marshal(userProfile)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to marshal user profile data : %s", err))
		return
	}

	o.handleAuthResult(w, r, profileBytes)
}

func (o *Operation) verifyDeviceCert(ch *certHolder) error {
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

	_, err := deviceCert.Verify(x509.VerifyOptions{Intermediates: intermediatePool, Roots: o.deviceRootCerts})
	if err != nil {
		return errors.New("cert chain fails to authenticate")
	}

	return nil
}

func (o *Operation) handleAuthResult(w http.ResponseWriter, r *http.Request, profileBytes []byte) {
	handle := url.QueryEscape(uuid.New().String())

	err := o.transientStore.Put(handle, profileBytes)
	if err != nil {
		o.writeErrorResponse(w,
			http.StatusInternalServerError, fmt.Sprintf("failed to write handle to transient store: %s", err))

		return
	}

	redirectURL := fmt.Sprintf("%s?%s=%s", o.uiEndpoint, userProfileQueryParam, handle)

	http.Redirect(w, r, redirectURL, http.StatusFound)
	logger.Debugf("redirected to: %s", redirectURL)
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

// WriteResponse writes interface value to response.
func (o *Operation) writeResponse(rw http.ResponseWriter, v interface{}) {
	rw.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(rw).Encode(v)
	if err != nil {
		logger.Errorf("Unable to send response, %s", err.Error())
	}
}

func (o *Operation) subject(w http.ResponseWriter, r *http.Request) (string, bool) {
	token, proceed := o.bearerToken(w, r)
	if !proceed {
		return "", false
	}

	request := admin.NewIntrospectOAuth2TokenParams()
	request.SetContext(r.Context())
	request.SetToken(token)

	introspection, err := o.hydra.IntrospectOAuth2Token(request)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadGateway, "failed to introspect token: %s", err.Error())

		return "", false
	}

	return introspection.Payload.Sub, true
}

func (o *Operation) bearerToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	const scheme = "Bearer "

	// https://tools.ietf.org/html/rfc6750#section-2.1
	authHeader := strings.TrimSpace(r.Header.Get("authorization"))
	if authHeader == "" {
		o.writeErrorResponse(w, http.StatusForbidden, "no credentials")

		return "", false
	}

	if !strings.HasPrefix(authHeader, scheme) {
		o.writeErrorResponse(w, http.StatusBadRequest, "invalid authorization scheme")

		return "", false
	}

	encoded := authHeader[len(scheme):]

	token, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		o.writeErrorResponse(w, http.StatusBadRequest, "failed to decode token: %s", err.Error())

		return "", false
	}

	return string(token), true
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

	prov, err := o.initOIDCProvider(providerID, &provider)
	if err != nil {
		return nil, fmt.Errorf("failed to init oidc provider: %w", err)
	}

	o.cachedOIDCProvLock.Lock()
	o.cachedOIDCProviders[providerID] = prov
	o.cachedOIDCProvLock.Unlock()

	return prov, nil
}

func createStore(p storage.Provider) (storage.Store, error) {
	s, err := p.OpenStore(transientStoreName)
	if err != nil {
		return nil, fmt.Errorf("failed to open store [%s] : %w", transientStoreName, err)
	}

	return s, nil
}

func openStore(provider storage.Provider, name string) (storage.Store, error) {
	s, err := provider.OpenStore(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open store [%s] : %w", transientStoreName, err)
	}

	return s, nil
}

func (o *Operation) initOIDCProvider(providerID string, config *OIDCProviderConfig) (oidcProvider, error) {
	var idp *oidc.Provider

	err := backoff.RetryNotify(
		func() error {
			var idpErr error

			idp, idpErr = oidc.NewProvider(
				oidc.ClientContext(
					context.Background(),
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
		name:         providerID,
		clientID:     config.ClientID,
		clientSecret: config.ClientSecret,
		callback:     o.callbackURL,
		op:           idp,
		httpClient: &http.Client{Transport: &http.Transport{
			TLSClientConfig: o.tlsConfig,
		}},
	}, nil
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
