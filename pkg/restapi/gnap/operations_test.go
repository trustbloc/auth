/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gnap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/trustbloc/auth/pkg/gnap/accesspolicy"
	"github.com/trustbloc/auth/pkg/gnap/interact/redirect"
	"github.com/trustbloc/auth/pkg/internal/common/mockoidc"
	"github.com/trustbloc/auth/pkg/internal/common/mockstorage"
	oidcmodel "github.com/trustbloc/auth/pkg/restapi/common/oidc"
	"github.com/trustbloc/auth/spi/gnap"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		o, err := New(config(t))
		require.NoError(t, err)
		require.NotNil(t, o)
	})

	t.Run("failure", func(t *testing.T) {
		conf := config(t)

		expectErr := errors.New("expected error")

		conf.StoreProvider = &mockstorage.Provider{ErrOpenStoreHandle: expectErr}

		o, err := New(conf)
		require.Error(t, err)
		require.ErrorIs(t, err, expectErr)
		require.Nil(t, o)
	})

	t.Run("error if unable to open transient store", func(t *testing.T) {
		config := config(t)
		config.TransientStoreProvider = &mockstore.MockStoreProvider{
			ErrOpenStoreHandle: errors.New("test"),
		}
		_, err := New(config)
		require.Error(t, err)
	})
}

func TestOperation_GetRESTHandlers(t *testing.T) {
	o := &Operation{}

	h := o.GetRESTHandlers()
	require.Len(t, h, 7)
}

func TestOperation_AuthProvidersHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		config := config(t)
		o, err := New(config)
		require.NoError(t, err)

		w := httptest.NewRecorder()
		o.authProvidersHandler(w, nil)

		require.Equal(t, http.StatusOK, w.Code)
		var resp *authProviders
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)

		require.Equal(t, 2, len(resp.Providers))
	})
}

func TestOperation_authRequestHandler(t *testing.T) {
	t.Run("fail to parse empty request body", func(t *testing.T) {
		o := &Operation{}

		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, AuthRequestPath, nil)

		o.authRequestHandler(rw, req)

		require.Equal(t, http.StatusBadRequest, rw.Code)
	})

	t.Run("access policy error", func(t *testing.T) {
		o := &Operation{}

		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, AuthRequestPath, bytes.NewReader([]byte("{}")))

		o.authRequestHandler(rw, req)

		require.Equal(t, http.StatusUnauthorized, rw.Code)
	})
}

func TestOperation_interactHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		o := &Operation{}

		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodGet, InteractPath, nil)

		o.interactHandler(rw, req)

		require.Equal(t, http.StatusFound, rw.Code)
	})
}

func TestOperation_authContinueHandler(t *testing.T) {
	t.Run("missing Auth token", func(t *testing.T) {
		o := &Operation{}

		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, AuthContinuePath, nil)

		o.authContinueHandler(rw, req)

		require.Equal(t, http.StatusUnauthorized, rw.Code)

		resp := &gnap.ErrorResponse{}
		require.NoError(t, json.Unmarshal(rw.Body.Bytes(), resp))
		require.Equal(t, errRequestDenied, resp.Error)
	})

	t.Run("Auth token not GNAP token", func(t *testing.T) {
		o := &Operation{}

		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, AuthContinuePath, nil)
		req.Header.Add("Authorization", "Bearer mock-token")

		o.authContinueHandler(rw, req)

		require.Equal(t, http.StatusUnauthorized, rw.Code)

		resp := &gnap.ErrorResponse{}
		require.NoError(t, json.Unmarshal(rw.Body.Bytes(), resp))
		require.Equal(t, errRequestDenied, resp.Error)
	})

	t.Run("fail to parse empty request body", func(t *testing.T) {
		o := &Operation{}

		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, AuthContinuePath, nil)
		req.Header.Add("Authorization", "GNAP mock-token")

		o.authContinueHandler(rw, req)

		require.Equal(t, http.StatusBadRequest, rw.Code)

		resp := &gnap.ErrorResponse{}
		require.NoError(t, json.Unmarshal(rw.Body.Bytes(), resp))
		require.Equal(t, errInvalidRequest, resp.Error)
	})

	t.Run("access policy error", func(t *testing.T) {
		o, err := New(config(t))
		require.NoError(t, err)

		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, AuthContinuePath, bytes.NewReader([]byte("{}")))
		req.Header.Add("Authorization", "GNAP mock-token")

		o.authContinueHandler(rw, req)

		require.Equal(t, http.StatusUnauthorized, rw.Code)

		resp := &gnap.ErrorResponse{}
		require.NoError(t, json.Unmarshal(rw.Body.Bytes(), resp))
		require.Equal(t, errRequestDenied, resp.Error)
	})
}

func TestOperation_introspectHandler(t *testing.T) {
	o := &Operation{}

	rw := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodPost, AuthContinuePath, bytes.NewReader([]byte("{}")))

	o.introspectHandler(rw, req)

	require.Equal(t, http.StatusOK, rw.Code)
}

func TestOIDCLoginHandler(t *testing.T) {
	t.Run("returns oidc request", func(t *testing.T) {
		provider := uuid.New().String()
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		svc.cachedOIDCProviders = map[string]oidcProvider{
			provider: &mockOIDCProvider{},
		}
		svc.oidcProvidersConfig = map[string]*oidcmodel.ProviderConfig{provider: {}}
		w := httptest.NewRecorder()
		svc.oidcLoginHandler(w, newOIDCLoginRequest(provider))
		require.Equal(t, http.StatusFound, w.Code)
		require.NotEmpty(t, w.Header().Get("location"))
	})

	t.Run("provider not supported", func(t *testing.T) {
		provider := uuid.New().String()
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		svc.cachedOIDCProviders = map[string]oidcProvider{
			provider: &mockOIDCProvider{},
		}
		w := httptest.NewRecorder()
		svc.oidcLoginHandler(w, newOIDCLoginRequest(provider))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("bad request if provider is missing", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		svc.oidcLoginHandler(w, newOIDCLoginRequest(""))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bad request if provider is not supported", func(t *testing.T) {
		svc, err := New(config(t))
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.oidcLoginHandler(result, newOIDCLoginRequest("unsupported"))
		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "provider not supported")
	})

	t.Run("store error", func(t *testing.T) {
		provider := uuid.New().String()
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		svc.cachedOIDCProviders = map[string]oidcProvider{
			provider: &mockOIDCProvider{},
		}
		svc.oidcProvidersConfig = map[string]*oidcmodel.ProviderConfig{provider: {}}
		svc.transientStore = &mockstore.MockStore{
			ErrPut: errors.New("generic"),
		}

		result := httptest.NewRecorder()
		svc.oidcLoginHandler(result, newOIDCLoginRequest(provider))

		require.Contains(t, result.Body.String(), "failed to write state data to transient store")
		require.Equal(t, http.StatusInternalServerError, result.Code)
	})

	t.Run("error if oidc provider is invalid", func(t *testing.T) {
		config := config(t)
		config.OIDC.Providers = map[string]*oidcmodel.ProviderConfig{
			"test": {
				URL: "INVALID",
			},
		}

		svc, err := New(config)
		require.NoError(t, err)

		w := httptest.NewRecorder()
		svc.oidcLoginHandler(w, newOIDCLoginRequest("test"))
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "failed to init oidc provider")
	})
}

func TestOIDCCallbackHandler(t *testing.T) {
	t.Run("setup user", func(t *testing.T) {
		provider := uuid.New().String()
		state := uuid.New().String()
		code := uuid.New().String()
		config := config(t)

		o, err := New(config)
		require.NoError(t, err)

		o.cachedOIDCProviders = map[string]oidcProvider{
			provider: &mockOIDCProvider{
				name: provider,
				oauth2Config: &mockOAuth2Config{
					exchangeVal: &mockToken{
						oauth2Claim: uuid.New().String(),
					},
				},
				verifyVal: &mockToken{
					oidcClaimsFunc: func(v interface{}) error {
						c, ok := v.(*oidcClaims)
						require.True(t, ok)
						c.Sub = uuid.New().String()

						return nil
					},
				},
			},
		}

		err = o.transientStore.Put(state, []byte(provider))
		require.NoError(t, err)

		result := httptest.NewRecorder()
		o.oidcCallbackHandler(result, newOIDCCallback(state, code))
		require.Equal(t, http.StatusFound, result.Code)
		// TODO validate redirect url
	})

	t.Run("error missing state", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback("", "code"))
		require.Equal(t, http.StatusBadRequest, result.Code)
	})

	t.Run("invalid state", func(t *testing.T) {
		state := uuid.New().String()
		mismatch := "mismatch"
		require.NotEqual(t, state, mismatch)
		svc, err := New(config(t))
		require.NoError(t, err)

		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback(state, "code"))
		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "failed to get state data to transient store")
	})

	t.Run("error missing code", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback("state", ""))
		require.Equal(t, http.StatusBadRequest, result.Code)
	})

	t.Run("bad request if oidc provider is not supported (should not happen)", func(t *testing.T) {
		svc, err := New(config(t))
		require.NoError(t, err)

		err = svc.transientStore.Put("state", []byte("invalid"))
		require.NoError(t, err)

		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback("state", "code"))

		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "provider not supported")
	})

	t.Run("error exchanging auth code", func(t *testing.T) {
		provider := uuid.New().String()
		state := uuid.New().String()
		config := config(t)
		config.TransientStoreProvider = &mockstore.MockStoreProvider{Store: &mockstore.MockStore{
			Store: map[string]mockstore.DBEntry{
				state: {Value: []byte(state)},
			},
		}}
		svc, err := New(config)
		require.NoError(t, err)

		err = svc.transientStore.Put(state, []byte(provider))
		require.NoError(t, err)

		svc.cachedOIDCProviders = map[string]oidcProvider{
			provider: &mockOIDCProvider{
				oauth2Config: &mockOAuth2Config{
					exchangeErr: errors.New("test"),
				},
			},
		}
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback(state, "code"))
		require.Equal(t, http.StatusBadGateway, result.Code)
		require.Contains(t, result.Body.String(), "failed to exchange oauth2 code for token")
	})

	t.Run("error missing id_token", func(t *testing.T) {
		provider := uuid.New().String()
		state := uuid.New().String()
		config := config(t)
		config.TransientStoreProvider = &mockstore.MockStoreProvider{Store: &mockstore.MockStore{
			Store: map[string]mockstore.DBEntry{
				state: {Value: []byte(state)},
			},
		}}
		svc, err := New(config)
		require.NoError(t, err)

		err = svc.transientStore.Put(state, []byte(provider))
		require.NoError(t, err)

		svc.cachedOIDCProviders = map[string]oidcProvider{
			provider: &mockOIDCProvider{
				name: provider,
				oauth2Config: &mockOAuth2Config{
					exchangeVal: &mockToken{},
				},
				verifyVal: &mockToken{},
			},
		}
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback(state, "code"))
		require.Equal(t, http.StatusBadGateway, result.Code)
	})

	t.Run("error id_token verification", func(t *testing.T) {
		provider := uuid.New().String()
		state := uuid.New().String()
		config := config(t)
		config.TransientStoreProvider = &mockstore.MockStoreProvider{Store: &mockstore.MockStore{
			Store: map[string]mockstore.DBEntry{
				state: {Value: []byte(state)},
			},
		}}
		svc, err := New(config)
		require.NoError(t, err)

		err = svc.transientStore.Put(state, []byte(provider))
		require.NoError(t, err)

		svc.cachedOIDCProviders = map[string]oidcProvider{
			provider: &mockOIDCProvider{
				name: provider,
				oauth2Config: &mockOAuth2Config{
					exchangeVal: &mockToken{oauth2Claim: "id_token"},
				},
				verifyErr: errors.New("test"),
			},
		}
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback(state, "code"))
		require.Equal(t, http.StatusForbidden, result.Code)
	})

	t.Run("error scanning id_token claims", func(t *testing.T) {
		provider := uuid.New().String()
		state := uuid.New().String()
		config := config(t)
		config.TransientStoreProvider = &mockstore.MockStoreProvider{Store: &mockstore.MockStore{
			Store: map[string]mockstore.DBEntry{
				state: {Value: []byte(state)},
			},
		}}
		svc, err := New(config)
		require.NoError(t, err)

		err = svc.transientStore.Put(state, []byte(provider))
		require.NoError(t, err)

		svc.cachedOIDCProviders = map[string]oidcProvider{
			provider: &mockOIDCProvider{
				name: provider,
				oauth2Config: &mockOAuth2Config{
					exchangeVal: &mockToken{oauth2Claim: "id_token"},
				},
				verifyVal: &mockToken{oidcClaimsErr: errors.New("test")},
			},
		}
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback(state, "code"))
		require.Equal(t, http.StatusInternalServerError, result.Code)
	})
}

type mockOIDCProvider struct {
	name         string
	baseURL      string
	oauth2Config oauth2Config
	verifyVal    idToken
	verifyErr    error
}

func (m *mockOIDCProvider) Name() string {
	return m.name
}

func (m *mockOIDCProvider) OAuth2Config(...string) oauth2Config {
	if m.oauth2Config != nil {
		return m.oauth2Config
	}

	return &mockOAuth2Config{}
}

func (m *mockOIDCProvider) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  fmt.Sprintf("%s/oauth2/auth", m.baseURL),
		TokenURL: fmt.Sprintf("%s/oauth2/token", m.baseURL),
	}
}

func (m *mockOIDCProvider) Verify(_ context.Context, _ string) (idToken, error) {
	return m.verifyVal, m.verifyErr
}

type mockOAuth2Config struct {
	authCodeVal  string
	authCodeFunc func(string, ...oauth2.AuthCodeOption) string
	exchangeVal  oauth2Token
	exchangeErr  error
}

func (m *mockOAuth2Config) AuthCodeURL(state string, options ...oauth2.AuthCodeOption) string {
	if m.authCodeFunc != nil {
		return m.authCodeFunc(state, options...)
	}

	return m.authCodeVal
}

func (m *mockOAuth2Config) Exchange(
	ctx context.Context, code string, options ...oauth2.AuthCodeOption) (oauth2Token, error) {
	return m.exchangeVal, m.exchangeErr
}

func newOIDCLoginRequest(provider string) *http.Request {
	return httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://example.com/oauth2/login?provider=%s", provider), nil)
}

func newOIDCCallback(state, code string) *http.Request {
	return httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("http://example.com/oauth2/callback?state=%s&code=%s", state, code), nil)
}

type mockToken struct {
	oauth2Claim    interface{}
	oidcClaimsFunc func(v interface{}) error
	oidcClaimsErr  error
}

func (m *mockToken) Extra(_ string) interface{} {
	if m.oauth2Claim != nil {
		return m.oauth2Claim
	}

	return nil
}

func (m *mockToken) Claims(v interface{}) error {
	if m.oidcClaimsFunc != nil {
		return m.oidcClaimsFunc(v)
	}

	return m.oidcClaimsErr
}

func config(t *testing.T) *Config {
	t.Helper()

	interact, err := redirect.New(InteractPath)
	require.NoError(t, err)

	return &Config{
		StoreProvider:      mem.NewProvider(),
		AccessPolicyConfig: &accesspolicy.Config{},
		BaseURL:            "example.com",
		InteractionHandler: interact,
		OIDC: &oidcmodel.Config{
			CallbackURL: "http://test.com",
			Providers: map[string]*oidcmodel.ProviderConfig{
				"mock1": {
					URL:          mockoidc.StartProvider(t),
					ClientID:     uuid.New().String(),
					ClientSecret: uuid.New().String(),
				},
				"mock2": {
					URL:          mockoidc.StartProvider(t),
					ClientID:     uuid.New().String(),
					ClientSecret: uuid.New().String(),
				},
			},
		},
		TransientStoreProvider: mem.NewProvider(),
		StartupTimeout:         1,
	}
}
