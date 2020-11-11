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
	"time"

	"github.com/cenkalti/backoff"
	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	"golang.org/x/oauth2"

	"github.com/trustbloc/hub-auth/pkg/bootstrap/user"
	"github.com/trustbloc/hub-auth/pkg/internal/common/support"
	"github.com/trustbloc/hub-auth/pkg/restapi/common"
	"github.com/trustbloc/hub-auth/pkg/restapi/common/store/cookie"
)

const (
	hydraLoginPath          = "/hydra/login"
	hydraConsentPath        = "/hydra/consent"
	oidcLoginPath           = "/oauth2/login"
	oidcCallbackPath        = "/oauth2/callback"
	bootstrapGetRequestPath = "/bootstrap"
	deviceCertPath          = "/device"
	// api path params
	providerQueryParam        = "provider"
	stateCookie               = "oauth2_state"
	hydraLoginChallengeCookie = "hydra_login_challenge"

	transientStoreName = "transient"
	bootstrapStoreName = "bootstrapdata"

	// redirect url parameter
	userProfileQueryParam = "up"
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
	cookies          cookie.Store
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
	Cookies                *CookieConfig
	StartupTimeout         uint64
}

// CookieConfig holds cookie configuration.
type CookieConfig struct {
	AuthKey []byte
	EncKey  []byte
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
		cookies:          cookie.NewStore(config.Cookies.AuthKey, config.Cookies.EncKey),
	}

	idp, err := initOIDCProvider(config)
	if err != nil {
		return nil, fmt.Errorf("failed to init oidc provider with url [%s]: %w", config.OIDCProviderURL, err)
	}

	svc.oidcProvider = &oidcProviderImpl{op: idp}

	svc.transientStore, err = createStore(config.TransientStoreProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	svc.oauth2ConfigFunc = func(scopes ...string) oauth2Config {
		oauth2Config := &oauth2.Config{
			ClientID:     svc.oidcClientID,
			ClientSecret: svc.oidcClientSecret,
			Endpoint:     svc.oidcProvider.Endpoint(),
			RedirectURL:  svc.oidcCallbackURL,
			Scopes:       append([]string{oidc.ScopeOpenID}, scopes...),
		}

		return &oauth2ConfigImpl{
			oc:     oauth2Config,
			client: &http.Client{Transport: &http.Transport{TLSClientConfig: config.TLSConfig}},
		}
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
func (o *Operation) GetRESTHandlers() []common.Handler {
	return []common.Handler{
		support.NewHTTPHandler(hydraLoginPath, http.MethodGet, o.hydraLoginHandler),
		support.NewHTTPHandler(oidcLoginPath, http.MethodGet, o.oidcLoginHandler),
		support.NewHTTPHandler(oidcCallbackPath, http.MethodGet, o.oidcCallbackHandler),
		support.NewHTTPHandler(hydraConsentPath, http.MethodGet, o.hydraConsentHandler),
		support.NewHTTPHandler(bootstrapGetRequestPath, http.MethodGet, o.handleBootstrapDataRequest),
		support.NewHTTPHandler(deviceCertPath, http.MethodPost, o.deviceCertHandler),
	}
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

	provider := r.URL.Query().Get(providerQueryParam)
	if provider == "" {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing provider")

		return
	}

	// TODO support multiple OIDC providers: https://github.com/trustbloc/hub-auth/issues/61
	state := uuid.New().String()

	jar, err := o.cookies.Open(r)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to open session cookies: %s", err.Error())

		return
	}

	jar.Set(stateCookie, state)

	err = jar.Save(r, w)
	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError, "failed to persist session cookies: %w", err.Error())

		return
	}

	// TODO hard-coding google's scope values (that are actually part of the standard):
	//  https://developers.google.com/identity/protocols/oauth2/openid-connect#scope-param
	//  need to support multiple OIDC providers - see https://github.com/trustbloc/hub-auth/issues/61.
	redirectURL := o.oauth2Config("profile email").AuthCodeURL(state, oauth2.AccessTypeOnline)

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

	hydraLoginChallenge, found := jar.Get(hydraLoginChallengeCookie)
	if !found {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing hydra login challenge cookie")

		return
	}

	loginChallenge, ok := hydraLoginChallenge.(string)
	if !ok {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			"should not have happened: hydra login challenge is not a string")
	}

	oauthToken, err := o.oauth2Config().Exchange(r.Context(), code)
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

	oidcToken, err := o.oidcProvider.Verifier(&oidc.Config{
		ClientID: o.oidcClientID,
	}).Verify(r.Context(), rawIDToken)
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
	if errors.Is(err, storage.ErrValueNotFound) {
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

	req := admin.NewGetLoginRequestParams()
	req.SetLoginChallenge(loginChallenge)

	accept := admin.NewAcceptLoginRequestParams()

	accept.SetLoginChallenge(loginChallenge)
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
func (o *Operation) onboardUser(id string) (*user.Profile, error) {
	userProfile := &user.Profile{
		ID: id,
	}

	err := user.NewStore(o.bootstrapStore).Save(userProfile)
	if err != nil {
		return nil, fmt.Errorf("failed to save user profile : %w", err)
	}

	return userProfile, nil
}

func (o *Operation) handleBootstrapDataRequest(w http.ResponseWriter, r *http.Request) {
	handle := r.URL.Query().Get(userProfileQueryParam)
	if handle == "" {
		o.writeErrorResponse(w, http.StatusBadRequest, "missing handle")

		return
	}

	profile, err := user.NewStore(o.transientStore).Get(handle)
	if errors.Is(err, storage.ErrValueNotFound) {
		o.writeErrorResponse(w, http.StatusBadRequest, "invalid handle")

		return
	}

	if err != nil {
		o.writeErrorResponse(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to query transient store for handle: %s", err))

		return
	}

	response, err := json.Marshal(&bootstrapData{
		SDSURL:            o.bootstrapConfig.SDSURL,
		SDSPrimaryVaultID: profile.SDSPrimaryVaultID,
		KeyServerURL:      o.bootstrapConfig.KeyServerURL,
		KeyStoreIDs:       profile.KeyStoreIDs,
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
	if errors.Is(err, storage.ErrValueNotFound) {
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

func (o *Operation) oauth2Config(scopes ...string) oauth2Config {
	return o.oauth2ConfigFunc(scopes...)
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

func initOIDCProvider(config *Config) (*oidc.Provider, error) {
	var idp *oidc.Provider

	err := backoff.RetryNotify(
		func() error {
			var idpErr error

			idp, idpErr = oidc.NewProvider(
				oidc.ClientContext(
					context.Background(),
					&http.Client{
						Transport: &http.Transport{TLSClientConfig: config.TLSConfig},
					},
				),
				config.OIDCProviderURL,
			)

			return idpErr
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), config.StartupTimeout),
		func(retryErr error, t time.Duration) {
			logger.Warnf(
				"failed to connect to the OIDC provider, will sleep for %s before trying again : %s",
				t, retryErr)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to init oidc provider with url [%s]: %w", config.OIDCProviderURL, err)
	}

	return idp, nil
}
