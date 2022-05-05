/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gnap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"golang.org/x/oauth2"

	"github.com/trustbloc/auth/pkg/gnap/accesspolicy"
	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/pkg/gnap/authhandler"
	"github.com/trustbloc/auth/pkg/internal/common/support"
	"github.com/trustbloc/auth/pkg/restapi/common"
	oidcmodel "github.com/trustbloc/auth/pkg/restapi/common/oidc"
	"github.com/trustbloc/auth/pkg/restapi/common/store/cookie"
	"github.com/trustbloc/auth/spi/gnap"
	"github.com/trustbloc/auth/spi/gnap/clientverifier/httpsig"
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
	InteractPath      = gnapBasePath + "/interact"
	authProvidersPath = "/oidc/providers"

	// GNAP error response codes.
	errInvalidRequest = "invalid_request"
	errRequestDenied  = "request_denied"

	// api path params.
	providerQueryParam = "provider"
	stateCookie        = "oauth2_state"
	providerCookie     = "oauth2_provider"
)

// TODO: figure out what logic should go in the access policy vs operation handlers.

// Operation defines Auth Server GNAP handlers.
type Operation struct {
	authHandler         *authhandler.AuthHandler
	uiEndpoint          string
	authProviders       []authProvider
	cookies             cookie.Store
	oidcProvidersConfig map[string]*oidcmodel.ProviderConfig
	cachedOIDCProviders map[string]oidcProvider
	cachedOIDCProvLock  sync.RWMutex
	tlsConfig           *tls.Config
	callbackURL         string
	timeout             uint64
}

// Config defines configuration for GNAP operations.
type Config struct {
	StoreProvider      storage.Provider
	AccessPolicy       *accesspolicy.AccessPolicy
	BaseURL            string
	InteractionHandler api.InteractionHandler
	UIEndpoint         string
	OIDC               *oidcmodel.Config
	StartupTimeout     uint64
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
		AccessPolicy:       config.AccessPolicy,
		ContinuePath:       config.BaseURL + AuthContinuePath,
		InteractionHandler: config.InteractionHandler,
	})
	if err != nil {
		return nil, err
	}

	return &Operation{
		authHandler:         auth,
		uiEndpoint:          config.UIEndpoint,
		authProviders:       authProviders,
		oidcProvidersConfig: config.OIDC.Providers,
		cachedOIDCProviders: make(map[string]oidcProvider),
		timeout:             config.StartupTimeout,
	}, nil
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []common.Handler {
	return []common.Handler{
		support.NewHTTPHandler(AuthRequestPath, http.MethodPost, o.authRequestHandler),
		// TODO add txn_id to url path
		support.NewHTTPHandler(InteractPath, http.MethodGet, o.interactHandler),
		support.NewHTTPHandler(AuthContinuePath, http.MethodPost, o.authContinueHandler),
		support.NewHTTPHandler(AuthIntrospectPath, http.MethodPost, o.introspectHandler),
		support.NewHTTPHandler(authProvidersPath, http.MethodGet, o.authProvidersHandler),
	}
}

func (o *Operation) authRequestHandler(w http.ResponseWriter, req *http.Request) {
	authRequest := &gnap.AuthRequest{}

	if err := json.NewDecoder(req.Body).Decode(authRequest); err != nil {
		logger.Errorf("failed to parse gnap auth request: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		o.writeResponse(w, &gnap.ErrorResponse{
			Error: errInvalidRequest,
		})

		return
	}

	v := httpsig.NewVerifier(req)

	resp, err := o.authHandler.HandleAccessRequest(authRequest, v)
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
	// TODO validate txn_id
	// redirect to UI
	http.Redirect(w, req, o.uiEndpoint+"/sign-up", http.StatusFound)
}

func (o *Operation) authProvidersHandler(w http.ResponseWriter, _ *http.Request) {
	o.writeResponse(w, &authProviders{Providers: o.authProviders})
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

	authOption := oauth2.SetAuthURLParam(providerQueryParam, providerID)
	redirectURL := provider.OAuth2Config(
		scopes...,
	).AuthCodeURL(state, oauth2.AccessTypeOnline, authOption)

	http.Redirect(w, r, redirectURL, http.StatusFound)

	logger.Debugf("redirected to: %s", redirectURL)
}

func (o *Operation) authContinueHandler(w http.ResponseWriter, req *http.Request) {
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

	if err := json.NewDecoder(req.Body).Decode(continueRequest); err != nil {
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

func (o *Operation) introspectHandler(w http.ResponseWriter, req *http.Request) {
	o.writeResponse(w, nil)
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
