/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/trustbloc/auth/pkg/bootstrap/user"
	"github.com/trustbloc/auth/pkg/gnap/accesspolicy"
	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/pkg/gnap/interact/redirect"
	"github.com/trustbloc/auth/pkg/internal/common/mockinteract"
	"github.com/trustbloc/auth/pkg/internal/common/mockoidc"
	"github.com/trustbloc/auth/pkg/internal/common/mockstorage"
	oidcmodel "github.com/trustbloc/auth/pkg/restapi/common/oidc"
	"github.com/trustbloc/auth/spi/gnap"
	"github.com/trustbloc/auth/spi/gnap/proof/httpsig"
)

const (
	baseURL = "http://test.auth"
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
	require.Len(t, h, 9)
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
	t.Run("fail to read body", func(t *testing.T) {
		o := &Operation{}

		rw := httptest.NewRecorder()

		expectErr := errors.New("expected error")

		req := httptest.NewRequest(http.MethodPost, AuthRequestPath, &errorReader{err: expectErr})

		o.authRequestHandler(rw, req)

		require.Equal(t, http.StatusInternalServerError, rw.Code)
	})

	t.Run("fail to parse empty request body", func(t *testing.T) {
		o := &Operation{}

		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, AuthRequestPath, nil)

		o.authRequestHandler(rw, req)

		require.Equal(t, http.StatusBadRequest, rw.Code)
	})

	t.Run("auth handler error", func(t *testing.T) {
		o := &Operation{}

		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, AuthRequestPath, bytes.NewReader([]byte("{}")))

		o.authRequestHandler(rw, req)

		require.Equal(t, http.StatusUnauthorized, rw.Code)
	})

	t.Run("success", func(t *testing.T) {
		o, err := New(config(t))
		require.NoError(t, err)

		priv, client := clientKey(t)

		authReq := &gnap.AuthRequest{
			Client: &gnap.RequestClient{
				IsReference: false,
				Key:         client,
			},
		}

		authReqBytes, err := json.Marshal(authReq)
		require.NoError(t, err)

		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, baseURL+AuthRequestPath, bytes.NewReader(authReqBytes))

		req, err = httpsig.Sign(req, authReqBytes, priv, "sha-256")
		require.NoError(t, err)

		o.authRequestHandler(rw, req)

		require.Equal(t, http.StatusOK, rw.Code)
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

	t.Run("fail to read request body", func(t *testing.T) {
		o := &Operation{}

		rw := httptest.NewRecorder()

		expectErr := errors.New("expected error")

		req := httptest.NewRequest(http.MethodPost, AuthContinuePath, &errorReader{err: expectErr})
		req.Header.Add("Authorization", "GNAP mock-token")

		o.authContinueHandler(rw, req)

		require.Equal(t, http.StatusInternalServerError, rw.Code)

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

	t.Run("auth handler error", func(t *testing.T) {
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

func TestOperation_authIntrospectHandler(t *testing.T) {
	t.Run("fail to read request body", func(t *testing.T) {
		o := &Operation{}

		rw := httptest.NewRecorder()

		expectErr := errors.New("expected error")

		req := httptest.NewRequest(http.MethodPost, AuthRequestPath, &errorReader{err: expectErr})

		o.authIntrospectHandler(rw, req)

		require.Equal(t, http.StatusInternalServerError, rw.Code)
	})

	t.Run("fail to parse empty request body", func(t *testing.T) {
		o := &Operation{}

		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, AuthRequestPath, nil)

		o.authIntrospectHandler(rw, req)

		require.Equal(t, http.StatusBadRequest, rw.Code)
	})

	t.Run("auth handler error", func(t *testing.T) {
		o := &Operation{}

		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, AuthRequestPath, bytes.NewReader([]byte("{}")))

		o.authIntrospectHandler(rw, req)

		require.Equal(t, http.StatusUnauthorized, rw.Code)
	})

	t.Run("requested token does not exist", func(t *testing.T) {
		o, err := New(config(t))
		require.NoError(t, err)

		priv, client := clientKey(t)

		intReq := &gnap.IntrospectRequest{
			AccessToken: "invalid token",
			Proof:       "httpsig",
			ResourceServer: &gnap.RequestClient{
				Key: client,
			},
		}

		intReqBytes, err := json.Marshal(intReq)
		require.NoError(t, err)

		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, baseURL+AuthIntrospectPath, bytes.NewReader(intReqBytes))

		req, err = httpsig.Sign(req, intReqBytes, priv, "sha-256")
		require.NoError(t, err)

		o.authIntrospectHandler(rw, req)

		require.Equal(t, http.StatusOK, rw.Code)

		resp := &gnap.IntrospectResponse{}

		err = json.Unmarshal(rw.Body.Bytes(), resp)
		require.NoError(t, err)

		require.False(t, resp.Active)
	})
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
		svc.oidcLoginHandler(w, newOIDCLoginRequest(provider, "foo"))
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
		svc.oidcLoginHandler(w, newOIDCLoginRequest(provider, "foo"))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("bad request if provider is missing", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		svc.oidcLoginHandler(w, newOIDCLoginRequest("", ""))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bad request if txn ID is missing", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		svc.oidcLoginHandler(w, newOIDCLoginRequest("foo", ""))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bad request if provider is not supported", func(t *testing.T) {
		svc, err := New(config(t))
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.oidcLoginHandler(result, newOIDCLoginRequest("unsupported", "foo"))
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
		svc.oidcLoginHandler(result, newOIDCLoginRequest(provider, "foo"))

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
		svc.oidcLoginHandler(w, newOIDCLoginRequest("test", "foo"))
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

		templatePath, deleteTmp := tmpStaticHTML(t)
		defer deleteTmp()

		config.ClosePopupHTML = templatePath

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

		respInteract, err := o.interactionHandler.PrepareInteraction(&gnap.RequestInteract{
			Start: []string{"redirect"},
			Finish: gnap.RequestFinish{
				Method: "redirect",
				URI:    "example.foo/client-redirect",
			},
		}, "", []*api.ExpiringTokenRequest{
			{
				TokenRequest: gnap.TokenRequest{
					Access: []gnap.TokenAccess{
						{
							IsReference: true,
							Ref:         "client-id",
						},
					},
				},
			},
		})
		require.NoError(t, err)

		redirURL, err := url.Parse(respInteract.Redirect)
		require.NoError(t, err)

		txnID := redirURL.Query().Get("txnID")

		data := &oidcTransientData{
			Provider: provider,
			TxnID:    txnID,
		}

		dataBytes, err := json.Marshal(data)
		require.NoError(t, err)

		err = o.transientStore.Put(state, dataBytes)
		require.NoError(t, err)

		result := httptest.NewRecorder()
		o.oidcCallbackHandler(result, newOIDCCallback(state, code))
		require.Equal(t, http.StatusOK, result.Code)
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

	t.Run("internal server error if transient data is invalid", func(t *testing.T) {
		svc, err := New(config(t))
		require.NoError(t, err)

		dataBytes := []byte("foo bar baz")

		err = svc.transientStore.Put("state", dataBytes)
		require.NoError(t, err)

		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback("state", "code"))

		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to parse")
	})

	t.Run("bad request if oidc provider is not supported (should not happen)", func(t *testing.T) {
		svc, err := New(config(t))
		require.NoError(t, err)

		data := &oidcTransientData{
			Provider: "invalid",
		}

		dataBytes, err := json.Marshal(data)
		require.NoError(t, err)

		err = svc.transientStore.Put("state", dataBytes)
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

		data := &oidcTransientData{
			Provider: provider,
		}

		dataBytes, err := json.Marshal(data)
		require.NoError(t, err)

		err = svc.transientStore.Put(state, dataBytes)
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

		data := &oidcTransientData{
			Provider: provider,
		}

		dataBytes, err := json.Marshal(data)
		require.NoError(t, err)

		err = svc.transientStore.Put(state, dataBytes)
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

		data := &oidcTransientData{
			Provider: provider,
		}

		dataBytes, err := json.Marshal(data)
		require.NoError(t, err)

		err = svc.transientStore.Put(state, dataBytes)
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

		data := &oidcTransientData{
			Provider: provider,
		}

		dataBytes, err := json.Marshal(data)
		require.NoError(t, err)

		err = svc.transientStore.Put(state, dataBytes)
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

	t.Run("generic bootstrap store PUT error while onboarding user", func(t *testing.T) {
		provider := uuid.New().String()
		id := uuid.New().String()
		state := uuid.New().String()
		code := uuid.New().String()
		config := config(t)

		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					id: {},
				},
				ErrGet: storage.ErrDataNotFound,
				ErrPut: errors.New("generic"),
			},
		}

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

		data := &oidcTransientData{
			Provider: provider,
			TxnID:    "foo",
		}

		dataBytes, err := json.Marshal(data)
		require.NoError(t, err)

		err = o.transientStore.Put(state, dataBytes)
		require.NoError(t, err)

		result := httptest.NewRecorder()
		o.oidcCallbackHandler(result, newOIDCCallback(state, code))
		require.Equal(t, http.StatusInternalServerError, result.Code)

		require.Contains(t, result.Body.String(), "failed to onboard new user")
	})

	t.Run("fail to complete interaction", func(t *testing.T) {
		provider := uuid.New().String()
		state := uuid.New().String()
		code := uuid.New().String()
		config := config(t)

		expectErr := errors.New("expected error")

		config.InteractionHandler = &mockinteract.InteractHandler{
			CompleteErr: expectErr,
		}

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

		data := &oidcTransientData{
			Provider: provider,
			TxnID:    "foo",
		}

		dataBytes, err := json.Marshal(data)
		require.NoError(t, err)

		err = o.transientStore.Put(state, dataBytes)
		require.NoError(t, err)

		result := httptest.NewRecorder()
		o.oidcCallbackHandler(result, newOIDCCallback(state, code))
		require.Equal(t, http.StatusInternalServerError, result.Code)

		require.Contains(t, result.Body.String(), "failed to complete GNAP interaction")
	})

	t.Run("bad client redirect URI", func(t *testing.T) {
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

		respInteract, err := o.interactionHandler.PrepareInteraction(&gnap.RequestInteract{
			Start: []string{"redirect"},
			Finish: gnap.RequestFinish{
				Method: "redirect",
				URI:    "^$#^*#%$^&#$%#T^ UTTER GIBBERISH",
			},
		}, "", []*api.ExpiringTokenRequest{
			{
				TokenRequest: gnap.TokenRequest{
					Access: []gnap.TokenAccess{
						{
							IsReference: true,
							Ref:         "client-id",
						},
					},
				},
			},
		})
		require.NoError(t, err)

		redirURL, err := url.Parse(respInteract.Redirect)
		require.NoError(t, err)

		txnID := redirURL.Query().Get("txnID")

		data := &oidcTransientData{
			Provider: provider,
			TxnID:    txnID,
		}

		dataBytes, err := json.Marshal(data)
		require.NoError(t, err)

		err = o.transientStore.Put(state, dataBytes)
		require.NoError(t, err)

		result := httptest.NewRecorder()
		o.oidcCallbackHandler(result, newOIDCCallback(state, code))
		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "client provided invalid redirect URI")
	})

	t.Run("generic bootstrap store PUT error while onboarding user", func(t *testing.T) {
		provider := uuid.New().String()
		id := uuid.New().String()
		state := uuid.New().String()
		config := config(t)

		config.TransientStoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					state: {Value: []byte(state)},
				},
			},
		}

		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					id: {},
				},
				ErrGet: storage.ErrDataNotFound,
				ErrPut: errors.New("generic"),
			},
		}

		svc, err := New(config)
		require.NoError(t, err)

		svc.cachedOIDCProviders = map[string]oidcProvider{
			provider: &mockOIDCProvider{
				name: provider,
				oauth2Config: &mockOAuth2Config{exchangeVal: &mockToken{
					oauth2Claim: uuid.New().String(),
				}},
				verifyVal: &mockToken{
					oidcClaimsFunc: func(v interface{}) error {
						c, ok := v.(*oidcClaims)
						require.True(t, ok)
						c.Sub = id

						return nil
					},
				},
			},
		}

		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback(state, "code"))
		require.Equal(t, http.StatusInternalServerError, result.Code)
	})
}

func TestGetBootstrapDataHandler(t *testing.T) {
	t.Run("returns bootstrap data when using GNAP token", func(t *testing.T) {
		userSub := uuid.New().String()
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		svc.SetIntrospectHandler(func(req *gnap.IntrospectRequest) (*gnap.IntrospectResponse, error) {
			return &gnap.IntrospectResponse{
				SubjectData: map[string]string{"sub": userSub},
			}, nil
		})
		expected := &user.Profile{
			ID:     uuid.New().String(),
			AAGUID: uuid.New().String(),
			Data: map[string]string{
				"primary vault": uuid.New().String(),
				"backup vault":  uuid.New().String(),
			},
		}

		err = svc.bootstrapStore.Put(userSub, marshal(t, expected))
		require.NoError(t, err)

		w := httptest.NewRecorder()

		request := newGetBootstrapDataRequest()
		request.Header.Set("authorization", "GNAP 123")

		svc.getBootstrapDataHandler(w, request)
		require.Equal(t, http.StatusOK, w.Code)
		result := &BootstrapData{}
		err = json.NewDecoder(w.Body).Decode(result)
		require.NoError(t, err)
		require.Equal(t, config.BootstrapConfig.DocumentSDSVaultURL, result.DocumentSDSVaultURL)
		require.Equal(t, config.BootstrapConfig.KeySDSVaultURL, result.KeySDSVaultURL)
		require.Equal(t, config.BootstrapConfig.OpsKeyServerURL, result.OpsKeyServerURL)
		require.Equal(t, expected.Data, result.Data)
	})

	t.Run("forbidden if auth header is missing", func(t *testing.T) {
		svc, err := New(config(t))
		require.NoError(t, err)
		w := httptest.NewRecorder()
		svc.getBootstrapDataHandler(w, httptest.NewRequest(http.MethodGet, "http://examepl.com/bootstrap", nil))
		require.Equal(t, http.StatusForbidden, w.Code)
		require.Contains(t, w.Body.String(), "no credentials")
	})

	t.Run("bad request if auth scheme is invalid", func(t *testing.T) {
		request := newGetBootstrapDataRequest()
		request.Header.Set("authorization", "invalid 123")
		svc, err := New(config(t))
		require.NoError(t, err)
		w := httptest.NewRecorder()
		svc.getBootstrapDataHandler(w, request)
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "invalid authorization scheme")
	})

	t.Run("unauthorized if invalid gnap token", func(t *testing.T) {
		request := newGetBootstrapDataRequest()
		request.Header.Set("authorization", "GNAP 123")
		svc, err := New(config(t))
		svc.SetIntrospectHandler(func(req *gnap.IntrospectRequest) (*gnap.IntrospectResponse, error) {
			return nil, fmt.Errorf("gnap introspect error")
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		svc.getBootstrapDataHandler(w, request)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.Contains(t, w.Body.String(), "gnap introspect error")
	})

	t.Run("unauthorized if gnap token does not grant access to subject id", func(t *testing.T) {
		request := newGetBootstrapDataRequest()
		request.Header.Set("authorization", "GNAP 123")
		svc, err := New(config(t))
		svc.SetIntrospectHandler(func(req *gnap.IntrospectRequest) (*gnap.IntrospectResponse, error) {
			return &gnap.IntrospectResponse{
				SubjectData: map[string]string{},
			}, nil
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		svc.getBootstrapDataHandler(w, request)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.Contains(t, w.Body.String(), "does not grant access")
	})

	t.Run("bad request if user does not have bootstrap data", func(t *testing.T) {
		userSub := uuid.New().String()
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		svc.SetIntrospectHandler(func(req *gnap.IntrospectRequest) (*gnap.IntrospectResponse, error) {
			return &gnap.IntrospectResponse{
				SubjectData: map[string]string{"sub": userSub},
			}, nil
		})
		w := httptest.NewRecorder()
		svc.getBootstrapDataHandler(w, newGetBootstrapDataRequest())
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "invalid handle")
	})

	t.Run("internal server error if bootstrap store FETCH fails generically", func(t *testing.T) {
		userSub := uuid.New().String()
		config := config(t)
		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					userSub: {Value: marshal(t, &user.Profile{})},
				},
				ErrGet: errors.New("generic"),
			},
		}
		svc, err := New(config)
		require.NoError(t, err)
		svc.SetIntrospectHandler(func(req *gnap.IntrospectRequest) (*gnap.IntrospectResponse, error) {
			return &gnap.IntrospectResponse{
				SubjectData: map[string]string{"sub": userSub},
			}, nil
		})
		w := httptest.NewRecorder()
		svc.getBootstrapDataHandler(w, newGetBootstrapDataRequest())
		require.Equal(t, http.StatusInternalServerError, w.Code)
		require.Contains(t, w.Body.String(), "failed to query bootstrap store for handle")
	})
}

func TestPostBootstrapDataHandler(t *testing.T) {
	t.Run("updates bootstrap data when using GNAP token", func(t *testing.T) {
		expected := &user.Profile{
			ID:     uuid.New().String(),
			AAGUID: uuid.New().String(),
			Data: map[string]string{
				"docsSDS": "https://example.org/edvs/123",
				"keysSDS": "https://example.org/edvs/456",
				"opskeys": "https://example.org/kms/456",
			},
		}
		config := config(t)
		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					expected.ID: {Value: marshal(t, &user.Profile{
						ID:     expected.ID,
						AAGUID: expected.AAGUID,
					})},
				},
			},
		}
		svc, err := New(config)
		require.NoError(t, err)

		svc.SetIntrospectHandler(func(req *gnap.IntrospectRequest) (*gnap.IntrospectResponse, error) {
			return &gnap.IntrospectResponse{
				SubjectData: map[string]string{"sub": expected.ID},
			}, nil
		})

		result := httptest.NewRecorder()

		request := newPostBootstrapDataRequest(t, &UpdateBootstrapDataRequest{
			Data: expected.Data,
		})

		svc.postBootstrapDataHandler(result, request)
		require.Equal(t, http.StatusOK, result.Code)
		raw, err := svc.bootstrapStore.Get(expected.ID)
		require.NoError(t, err)
		update := &user.Profile{}
		err = json.NewDecoder(bytes.NewReader(raw)).Decode(update)
		require.NoError(t, err)
		require.Equal(t, expected, update)
	})

	t.Run("error badrequest if payload is not json", func(t *testing.T) {
		userSub := uuid.New().String()
		config := config(t)
		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					userSub: {Value: nil},
				},
			},
		}
		svc, err := New(config)
		require.NoError(t, err)
		svc.SetIntrospectHandler(func(req *gnap.IntrospectRequest) (*gnap.IntrospectResponse, error) {
			return &gnap.IntrospectResponse{
				SubjectData: map[string]string{"sub": userSub},
			}, nil
		})
		request := httptest.NewRequest(http.MethodPost, "https://example.org/bootstrap", bytes.NewReader([]byte("}")))
		request.Header.Set("authorization", "GNAP 123")
		result := httptest.NewRecorder()
		svc.postBootstrapDataHandler(result, request)
		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "failed to decode request")
	})

	t.Run("error conflict if user does not exist", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		svc.SetIntrospectHandler(func(req *gnap.IntrospectRequest) (*gnap.IntrospectResponse, error) {
			return &gnap.IntrospectResponse{
				SubjectData: map[string]string{"sub": uuid.New().String()},
			}, nil
		})
		result := httptest.NewRecorder()
		svc.postBootstrapDataHandler(result, newPostBootstrapDataRequest(t, &UpdateBootstrapDataRequest{}))
		require.Equal(t, http.StatusConflict, result.Code)
		require.Contains(t, result.Body.String(), "associated bootstrap data not found")
	})

	t.Run("internal server error on generic FETCH bootstrap store error", func(t *testing.T) {
		userSub := uuid.New().String()
		config := config(t)
		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					userSub: {Value: nil},
				},
				ErrGet: errors.New("generic"),
			},
		}
		svc, err := New(config)
		require.NoError(t, err)
		svc.SetIntrospectHandler(func(req *gnap.IntrospectRequest) (*gnap.IntrospectResponse, error) {
			return &gnap.IntrospectResponse{
				SubjectData: map[string]string{"sub": userSub},
			}, nil
		})
		result := httptest.NewRecorder()
		svc.postBootstrapDataHandler(result, newPostBootstrapDataRequest(t, &UpdateBootstrapDataRequest{}))
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to query storage")
	})

	t.Run("internal server error if cannot persist update to bootstrap store", func(t *testing.T) {
		userSub := uuid.New().String()
		config := config(t)
		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					userSub: {Value: marshal(t, &user.Profile{})},
				},
				ErrPut: errors.New("generic"),
			},
		}
		svc, err := New(config)
		require.NoError(t, err)
		svc.SetIntrospectHandler(func(req *gnap.IntrospectRequest) (*gnap.IntrospectResponse, error) {
			return &gnap.IntrospectResponse{
				SubjectData: map[string]string{"sub": userSub},
			}, nil
		})
		result := httptest.NewRecorder()
		svc.postBootstrapDataHandler(result, newPostBootstrapDataRequest(t, &UpdateBootstrapDataRequest{}))
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to update storage")
	})
}

func Test_Full_Flow(t *testing.T) {
	conf := config(t)

	templatePath, deleteTmp := tmpStaticHTML(t)
	defer deleteTmp()

	conf.ClosePopupHTML = templatePath

	o, err := New(conf)
	require.NoError(t, err)

	authResp := &gnap.AuthResponse{}

	var (
		txnID       string
		interactRef string
		state       string
	)

	userPriv, userClient := clientKey(t)

	{
		authReq := &gnap.AuthRequest{
			Client: &gnap.RequestClient{
				IsReference: false,
				Key:         userClient,
			},
			AccessToken: []*gnap.TokenRequest{
				{
					Access: []gnap.TokenAccess{
						{
							IsReference: true,
							Ref:         "client-id",
						},
					},
				},
			},
			Interact: &gnap.RequestInteract{
				Start: []string{"redirect"},
				Finish: gnap.RequestFinish{
					Method: "redirect",
					URI:    "example.com/client-ui",
				},
			},
		}

		authReqBytes, err := json.Marshal(authReq)
		require.NoError(t, err)

		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, baseURL+AuthRequestPath, bytes.NewReader(authReqBytes))

		req, err = httpsig.Sign(req, authReqBytes, userPriv, "sha-256")
		require.NoError(t, err)

		o.authRequestHandler(rw, req)

		require.Equal(t, http.StatusOK, rw.Code)

		require.NoError(t, json.Unmarshal(rw.Body.Bytes(), authResp))

		redirectURL, err := url.Parse(authResp.Interact.Redirect)
		require.NoError(t, err)

		txnID = redirectURL.Query().Get("txnID")
	}

	provider := uuid.New().String()

	subjectID := "mock-subject-id"

	o.cachedOIDCProviders = map[string]oidcProvider{provider: &mockOIDCProvider{
		oauth2Config: &mockOAuth2Config{
			authCodeFunc: func(state string, opts ...oauth2.AuthCodeOption) string {
				return "example.com/oauth2?state=" + state
			},
			exchangeVal: &mockToken{
				oauth2Claim: "mock-id-token",
			},
		},
		verifyVal: &mockToken{
			oidcClaimsFunc: func(v interface{}) error {
				claims, ok := v.(*oidcClaims)
				if !ok {
					return nil
				}

				claims.Sub = subjectID

				return nil
			},
		},
	}}
	o.oidcProvidersConfig = map[string]*oidcmodel.ProviderConfig{provider: {}}

	{
		rw := httptest.NewRecorder()

		o.oidcLoginHandler(rw, newOIDCLoginRequest(provider, txnID))
		require.Equal(t, http.StatusFound, rw.Code)
		redirectURL, err := url.Parse(rw.Header().Get("location"))
		require.NoError(t, err)

		state = redirectURL.Query().Get("state")
	}

	{
		code := uuid.New().String()

		rw := httptest.NewRecorder()

		o.oidcCallbackHandler(rw, newOIDCCallback(state, code))

		require.Equal(t, http.StatusOK, rw.Code)

		body := rw.Body.Bytes()

		rx := regexp.MustCompile("window.opener.location.href = '(.*)';")
		res := rx.FindStringSubmatch(string(body))

		u := res[1]

		u = strings.ReplaceAll(u, "\\u0026", "\u0026")
		u = strings.ReplaceAll(u, "\\/", "/")

		redirectURL, err := url.Parse(u)
		require.NoError(t, err)

		require.Contains(t, redirectURL.String(), "interact_ref")

		interactRef = redirectURL.Query().Get("interact_ref")
		require.NotEqual(t, "", interactRef)
	}

	contResp := &gnap.AuthResponse{}

	{
		contReq := &gnap.ContinueRequest{
			InteractRef: interactRef,
		}

		contReqBytes, err := json.Marshal(contReq)
		require.NoError(t, err)

		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, baseURL+AuthRequestPath, bytes.NewReader(contReqBytes))
		req.Header.Add("Authorization", "GNAP "+authResp.Continue.AccessToken.Value)

		req, err = httpsig.Sign(req, contReqBytes, userPriv, "sha-256")
		require.NoError(t, err)

		o.authContinueHandler(rw, req)

		require.Equal(t, http.StatusOK, rw.Code)

		require.NoError(t, json.Unmarshal(rw.Body.Bytes(), contResp))
	}

	require.Len(t, contResp.AccessToken, 1)

	rsPriv, rsClient := clientKey(t)

	{
		intReq := &gnap.IntrospectRequest{
			AccessToken: contResp.AccessToken[0].Value,
			Proof:       "httpsig",
			ResourceServer: &gnap.RequestClient{
				Key: rsClient,
			},
		}

		intReqBytes, err := json.Marshal(intReq)
		require.NoError(t, err)

		rw := httptest.NewRecorder()

		req := httptest.NewRequest(http.MethodPost, baseURL+AuthIntrospectPath, bytes.NewReader(intReqBytes))

		req, err = httpsig.Sign(req, intReqBytes, rsPriv, "sha-256")
		require.NoError(t, err)

		o.authIntrospectHandler(rw, req)

		require.Equal(t, http.StatusOK, rw.Code)

		resp := &gnap.IntrospectResponse{}

		err = json.Unmarshal(rw.Body.Bytes(), resp)
		require.NoError(t, err)

		require.True(t, resp.Active)

		resultID := resp.SubjectData["sub"]

		// introspection returns the user's OIDC 'sub' ID value
		require.Equal(t, subjectID, resultID)
	}
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

func newOIDCLoginRequest(provider, txnID string) *http.Request {
	return httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("http://example.com/oauth2/login?provider=%s&txnID=%s", provider, txnID),
		nil)
}

func newOIDCCallback(state, code string) *http.Request {
	return httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("http://example.com/oauth2/callback?state=%s&code=%s", state, code), nil)
}

func newGetBootstrapDataRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://example.com/bootstrap", nil)
	r.Header.Set("Authorization", "GNAP 123")

	return r
}

func newPostBootstrapDataRequest(t *testing.T, params *UpdateBootstrapDataRequest) *http.Request {
	t.Helper()

	bits, err := json.Marshal(params)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "http://example.com/bootstrap", bytes.NewReader(bits))
	r.Header.Set("Authorization", "GNAP 123")

	return r
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

	storeProv := mem.NewProvider()

	interact, err := redirect.New(&redirect.Config{
		StoreProvider:    storeProv,
		InteractBasePath: InteractPath,
	})
	require.NoError(t, err)

	apConfig := &accesspolicy.Config{}

	err = json.Unmarshal([]byte(accessPolicyConf), apConfig)
	require.NoError(t, err)

	return &Config{
		StoreProvider:      storeProv,
		AccessPolicyConfig: apConfig,
		BaseURL:            baseURL,
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
		BootstrapConfig: &BootstrapConfig{
			DocumentSDSVaultURL: "http://docs.sds.example.org/sds/vaults",
			KeySDSVaultURL:      "http://keys.sds.example.org/sds/vaults/",
			OpsKeyServerURL:     "http://ops.kms.example.org/kms/keystores/",
		},
		TransientStoreProvider: mem.NewProvider(),
		StartupTimeout:         1,
	}
}

func marshal(t *testing.T, v interface{}) []byte {
	t.Helper()

	bits, err := json.Marshal(v)
	require.NoError(t, err)

	return bits
}

type errorReader struct {
	err error
}

func (e *errorReader) Read([]byte) (int, error) {
	return 0, e.err
}

func clientKey(t *testing.T) (*jwk.JWK, *gnap.ClientKey) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privJWK := jwk.JWK{
		JSONWebKey: jose.JSONWebKey{
			Key:       priv,
			KeyID:     "key1",
			Algorithm: "ES256",
		},
		Kty: "EC",
		Crv: "P-256",
	}

	pubJWK := jwk.JWK{
		JSONWebKey: privJWK.Public(),
		Kty:        "EC",
		Crv:        "P-256",
	}

	ck := gnap.ClientKey{
		Proof: "httpsig",
		JWK:   pubJWK,
	}

	return &privJWK, &ck
}

func tmpStaticHTML(t *testing.T) (string, func()) {
	t.Helper()

	f, err := os.CreateTemp("", "tmpfile-*.html")
	require.NoError(t, err)

	defer func() {
		e := f.Close()
		if e != nil {
			fmt.Printf("failed to close tmpfile: %s", e.Error())
		}
	}()

	_, err = f.Write([]byte(staticHTML))
	require.NoError(t, err)

	return f.Name(), func() {
		e := os.Remove(f.Name())
		if e != nil {
			fmt.Printf("failed to delete tmpfile: %s", e.Error())
		}
	}
}

const (
	accessPolicyConf = `{
	"access-types": [{
			"reference": "client-id",
			"permission": "NeedsConsent",
			"expires-in": 600,
			"access": {
				"type": "trustbloc.xyz/auth/type/client-id",
				"subject-keys": ["sub"],
				"userid-key": "sub"
			}
		}, {
			"reference": "other-access",
			"permission": "NeedsConsent",
			"expires-in": 300,
			"access": {
				"type": "trustbloc.xyz/auth/type/other-access",
				"actions": ["write"],
				"datasets": ["foobase"]
			}
		} 
	]
}`
	staticHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Redirecting...</title>
</head>

<script>
window.opener.location.href = '{{.RedirectURI}}';
window.top.close();
</script>

<body>

</body>
</html>`
)
