/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"
	"golang.org/x/oauth2"

	"github.com/trustbloc/hub-auth/pkg/bootstrap/user"
	"github.com/trustbloc/hub-auth/pkg/internal/common/mockoidc"
	"github.com/trustbloc/hub-auth/pkg/internal/common/mockstorage"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Equal(t, 3, len(svc.GetRESTHandlers()))
	})

	t.Run("success, bootstrap store already exists", func(t *testing.T) {
		config := config(t)

		config.TransientStoreProvider = memstore.NewProvider()

		err := config.TransientStoreProvider.CreateStore(bootstrapStoreName)
		require.NoError(t, err)

		svc, err := New(config)
		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Equal(t, 3, len(svc.GetRESTHandlers()))
	})

	t.Run("error if oidc provider is invalid", func(t *testing.T) {
		config := config(t)
		config.OIDCProviderURL = "INVALID"
		_, err := New(config)
		require.Error(t, err)
	})

	t.Run("error if unable to open transient store", func(t *testing.T) {
		config := config(t)
		config.TransientStoreProvider = &mockstore.Provider{
			ErrOpenStoreHandle: errors.New("test"),
		}
		_, err := New(config)
		require.Error(t, err)
	})

	t.Run("error if unable to create transient store", func(t *testing.T) {
		config := config(t)
		config.TransientStoreProvider = &mockstore.Provider{
			ErrCreateStore: errors.New("generic"),
		}
		_, err := New(config)
		require.Error(t, err)
	})
}
func TestCreateOIDCRequest(t *testing.T) {
	t.Run("returns oidc request", func(t *testing.T) {
		const scope = "CreditCardStatement"
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		svc.oidcProvider = &mockOIDCProvider{baseURL: "http://test.com"}
		w := httptest.NewRecorder()
		svc.createOIDCRequest(w, newCreateOIDCHTTPRequest(scope))
		require.Equal(t, http.StatusOK, w.Code)
		result := &createOIDCRequestResponse{}
		err = json.NewDecoder(w.Body).Decode(result)
		require.NoError(t, err)
		u, err := url.Parse(result.Request)
		require.NoError(t, err)
		scopes := strings.Split(u.Query().Get("scope"), " ")
		require.Contains(t, scopes, oidc.ScopeOpenID)
		require.Contains(t, scopes, scope)
		require.NotEmpty(t, u.Query().Get("state"))
		require.Equal(t, config.OIDCClientID, u.Query().Get("client_id"))
		require.Equal(t,
			fmt.Sprintf("%s%s", config.OIDCCallbackURL, oauth2CallbackPath), u.Query().Get("redirect_uri"))
	})

	t.Run("bad request if scope is missing", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		svc.oidcProvider = &mockOIDCProvider{baseURL: "http://test.com"}
		w := httptest.NewRecorder()
		svc.createOIDCRequest(w, newCreateOIDCHTTPRequest(""))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("internal server error if transient store fails", func(t *testing.T) {
		config := config(t)
		config.TransientStoreProvider = &mockstore.Provider{
			Store: &mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrPut: errors.New("test"),
			},
		}

		svc, err := New(config)
		require.NoError(t, err)
		svc.oidcProvider = &mockOIDCProvider{baseURL: "http://test.com"}
		w := httptest.NewRecorder()
		svc.createOIDCRequest(w, newCreateOIDCHTTPRequest("CreditCardStatement"))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestHandleOIDCCallback(t *testing.T) {
	t.Run("onboard user", func(t *testing.T) {
		state := uuid.New().String()
		code := uuid.New().String()

		config := config(t)

		config.TransientStoreProvider = &mockstore.Provider{
			Store: &mockstore.MockStore{
				Store: map[string][]byte{
					state: []byte(state),
				},
			},
		}

		o, err := New(config)
		require.NoError(t, err)

		o.oauth2ConfigFunc = func(...string) oauth2Config {
			return &mockOAuth2Config{exchangeVal: &mockToken{
				oauth2Claim: uuid.New().String(),
			}}
		}

		o.oidcProvider = &mockOIDCProvider{
			verifier: &mockVerifier{
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

		result := httptest.NewRecorder()
		o.handleOIDCCallback(result, newOIDCCallback(state, code))
		require.Equal(t, http.StatusFound, result.Code)
	})

	t.Run("error missing state", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.handleOIDCCallback(result, newOIDCCallback("", "code"))
		require.Equal(t, http.StatusBadRequest, result.Code)
	})

	t.Run("error missing code", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.handleOIDCCallback(result, newOIDCCallback("state", ""))
		require.Equal(t, http.StatusBadRequest, result.Code)
	})

	t.Run("error invalid state parameter", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.handleOIDCCallback(result, newOIDCCallback("state", "code"))
		require.Equal(t, http.StatusBadRequest, result.Code)
	})

	t.Run("generic transient store error", func(t *testing.T) {
		state := uuid.New().String()
		config := config(t)

		config.TransientStoreProvider = &mockstore.Provider{
			Store: &mockstore.MockStore{
				Store: map[string][]byte{
					state: []byte(state),
				},
				ErrGet: errors.New("generic"),
			},
		}

		svc, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.handleOIDCCallback(result, newOIDCCallback(state, "code"))
		require.Equal(t, http.StatusInternalServerError, result.Code)
	})

	t.Run("generic bootstrap store FETCH error", func(t *testing.T) {
		id := uuid.New().String()
		state := uuid.New().String()
		config := config(t)

		config.TransientStoreProvider = &mockstorage.Provider{
			Stores: map[string]storage.Store{
				transientStoreName: &mockstore.MockStore{
					Store: map[string][]byte{
						state: []byte(state),
					},
				},
			},
		}

		config.StoreProvider = &mockstorage.Provider{
			Stores: map[string]storage.Store{
				bootstrapStoreName: &mockstore.MockStore{
					Store: map[string][]byte{
						id: {},
					},
					ErrGet: errors.New("generic"),
				},
			},
		}

		svc, err := New(config)
		require.NoError(t, err)

		svc.oauth2ConfigFunc = func(...string) oauth2Config {
			return &mockOAuth2Config{exchangeVal: &mockToken{
				oauth2Claim: uuid.New().String(),
			}}
		}

		svc.oidcProvider = &mockOIDCProvider{
			verifier: &mockVerifier{
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
		svc.handleOIDCCallback(result, newOIDCCallback(state, "code"))
		require.Equal(t, http.StatusInternalServerError, result.Code)
	})

	t.Run("generic bootstrap store PUT error while onboarding user", func(t *testing.T) {
		id := uuid.New().String()
		state := uuid.New().String()
		config := config(t)

		config.TransientStoreProvider = &mockstorage.Provider{
			Stores: map[string]storage.Store{
				transientStoreName: &mockstore.MockStore{
					Store: map[string][]byte{
						state: []byte(state),
					},
				},
			},
		}

		config.StoreProvider = &mockstorage.Provider{
			Stores: map[string]storage.Store{
				bootstrapStoreName: &mockstore.MockStore{
					Store: map[string][]byte{
						id: []byte("{}"),
					},
					ErrGet: storage.ErrValueNotFound,
					ErrPut: errors.New("generic"),
				},
			},
		}

		svc, err := New(config)
		require.NoError(t, err)

		svc.oauth2ConfigFunc = func(...string) oauth2Config {
			return &mockOAuth2Config{exchangeVal: &mockToken{
				oauth2Claim: uuid.New().String(),
			}}
		}

		svc.oidcProvider = &mockOIDCProvider{
			verifier: &mockVerifier{
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
		svc.handleOIDCCallback(result, newOIDCCallback(state, "code"))
		require.Equal(t, http.StatusInternalServerError, result.Code)
	})

	t.Run("error exchanging auth code", func(t *testing.T) {
		state := uuid.New().String()
		config := config(t)
		config.TransientStoreProvider = &mockstore.Provider{Store: &mockstore.MockStore{
			Store: map[string][]byte{
				state: []byte(state),
			},
		}}
		svc, err := New(config)
		require.NoError(t, err)
		svc.oauth2ConfigFunc = func(...string) oauth2Config {
			return &mockOAuth2Config{
				exchangeErr: errors.New("test"),
			}
		}
		result := httptest.NewRecorder()
		svc.handleOIDCCallback(result, newOIDCCallback(state, "code"))
		require.Equal(t, http.StatusBadGateway, result.Code)
	})

	t.Run("error missing id_token", func(t *testing.T) {
		state := uuid.New().String()
		config := config(t)
		config.TransientStoreProvider = &mockstore.Provider{Store: &mockstore.MockStore{
			Store: map[string][]byte{
				state: []byte(state),
			},
		}}
		svc, err := New(config)
		require.NoError(t, err)
		svc.oauth2ConfigFunc = func(...string) oauth2Config {
			return &mockOAuth2Config{exchangeVal: &mockToken{}}
		}
		svc.oidcProvider = &mockOIDCProvider{
			verifier: &mockVerifier{verifyVal: &mockToken{}},
		}
		result := httptest.NewRecorder()
		svc.handleOIDCCallback(result, newOIDCCallback(state, "code"))
		require.Equal(t, http.StatusBadGateway, result.Code)
	})

	t.Run("error id_token verification", func(t *testing.T) {
		state := uuid.New().String()
		config := config(t)
		config.TransientStoreProvider = &mockstore.Provider{Store: &mockstore.MockStore{
			Store: map[string][]byte{
				state: []byte(state),
			},
		}}
		svc, err := New(config)
		require.NoError(t, err)
		svc.oauth2ConfigFunc = func(...string) oauth2Config {
			return &mockOAuth2Config{exchangeVal: &mockToken{oauth2Claim: "id_token"}}
		}
		svc.oidcProvider = &mockOIDCProvider{
			verifier: &mockVerifier{verifyErr: errors.New("test")},
		}
		result := httptest.NewRecorder()
		svc.handleOIDCCallback(result, newOIDCCallback(state, "code"))
		require.Equal(t, http.StatusForbidden, result.Code)
	})

	t.Run("error scanning id_token claims", func(t *testing.T) {
		state := uuid.New().String()
		config := config(t)
		config.TransientStoreProvider = &mockstore.Provider{Store: &mockstore.MockStore{
			Store: map[string][]byte{
				state: []byte(state),
			},
		}}
		svc, err := New(config)
		require.NoError(t, err)
		svc.oauth2ConfigFunc = func(...string) oauth2Config {
			return &mockOAuth2Config{exchangeVal: &mockToken{oauth2Claim: "id_token"}}
		}
		svc.oidcProvider = &mockOIDCProvider{
			verifier: &mockVerifier{verifyVal: &mockToken{oidcClaimsErr: errors.New("test")}},
		}
		result := httptest.NewRecorder()
		svc.handleOIDCCallback(result, newOIDCCallback(state, "code"))
		require.Equal(t, http.StatusInternalServerError, result.Code)
	})
	t.Run("PUT error while storing user info while handling callback user", func(t *testing.T) {
		id := uuid.New().String()
		state := uuid.New().String()
		config := config(t)

		config.TransientStoreProvider = &mockstorage.Provider{
			Stores: map[string]storage.Store{
				transientStoreName: &mockstore.MockStore{
					Store: map[string][]byte{
						id: []byte("{}"),
					},
					ErrGet: storage.ErrValueNotFound,
					ErrPut: errors.New("generic"),
				},
			},
		}

		svc, err := New(config)
		require.NoError(t, err)

		result := httptest.NewRecorder()
		svc.handleAuthResult(result, newOIDCCallback(state, "code"), nil)
		require.Equal(t, http.StatusInternalServerError, result.Code)
	})
}

func TestHandleBootstrapDataRequest(t *testing.T) {
	t.Run("returns bootstrap data", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		expected := &user.Profile{
			SDSPrimaryVaultID: uuid.New().String(),
			KeyStoreIDs:       []string{uuid.New().String()},
		}

		handle := uuid.New().String()

		// put in transient store by onboardUser()
		err = svc.transientStore.Put(handle, marshal(t, expected))
		require.NoError(t, err)

		w := httptest.NewRecorder()
		svc.handleBootstrapDataRequest(w, newBootstrapDataRequest(handle))
		require.Equal(t, http.StatusOK, w.Code)
		result := &bootstrapData{}
		err = json.NewDecoder(w.Body).Decode(result)
		require.NoError(t, err)
		require.Equal(t, expected.SDSPrimaryVaultID, result.SDSPrimaryVaultID)
		require.Equal(t, expected.KeyStoreIDs, result.KeyStoreIDs)
		require.Equal(t, config.BootstrapConfig.KeyServerURL, result.KeyServerURL)
		require.Equal(t, config.BootstrapConfig.SDSURL, result.SDSURL)
	})

	t.Run("bad request if handle is missing", func(t *testing.T) {
		svc, err := New(config(t))
		require.NoError(t, err)
		w := httptest.NewRecorder()
		svc.handleBootstrapDataRequest(w, httptest.NewRequest(http.MethodGet, "http://examepl.com/bootstrap", nil))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bad request if handle is invalid", func(t *testing.T) {
		svc, err := New(config(t))
		require.NoError(t, err)
		w := httptest.NewRecorder()
		svc.handleBootstrapDataRequest(w, newBootstrapDataRequest("INVALID"))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("internal server error if transient store FETCH fails generically", func(t *testing.T) {
		config := config(t)
		handle := uuid.New().String()
		config.TransientStoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: map[string][]byte{
					handle: marshal(t, &user.Profile{}),
				},
				ErrGet: errors.New("generic"),
			},
		}
		svc, err := New(config)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		svc.handleBootstrapDataRequest(w, newBootstrapDataRequest(handle))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func newCreateOIDCHTTPRequest(scope string) *http.Request {
	return httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://example.com/oauth2/request?scope=%s", scope), nil)
}

func newOIDCCallback(state, code string) *http.Request {
	return httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("http://example.com/oauth2/callback?state=%s&code=%s", state, code), nil)
}

func newBootstrapDataRequest(handle string) *http.Request {
	return httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("http://example.com/bootstrap?%s=%s", userProfileQueryParam, handle), nil)
}

type mockOIDCProvider struct {
	baseURL  string
	verifier *mockVerifier
}

func (m *mockOIDCProvider) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  fmt.Sprintf("%s/oauth2/auth", m.baseURL),
		TokenURL: fmt.Sprintf("%s/oauth2/token", m.baseURL),
	}
}

func (m *mockOIDCProvider) Verifier(*oidc.Config) verifier {
	return m.verifier
}

type mockVerifier struct {
	verifyVal idToken
	verifyErr error
}

func (m *mockVerifier) Verify(ctx context.Context, token string) (idToken, error) {
	return m.verifyVal, m.verifyErr
}

func config(t *testing.T) *Config {
	return &Config{
		OIDCProviderURL:        mockoidc.StartProvider(t),
		OIDCClientID:           uuid.New().String(),
		OIDCClientSecret:       uuid.New().String(),
		OIDCCallbackURL:        "http://test.com",
		TransientStoreProvider: memstore.NewProvider(),
		StoreProvider:          memstore.NewProvider(),
		BootstrapConfig: &BootstrapConfig{
			SDSURL:       "http://sds.example.com",
			KeyServerURL: "http://keyserver.example.com",
		},
	}
}

func marshal(t *testing.T, v interface{}) []byte {
	bits, err := json.Marshal(v)
	require.NoError(t, err)

	return bits
}

type mockOAuth2Config struct {
	authCodeFunc func(string, ...oauth2.AuthCodeOption) string
	exchangeVal  oauth2Token
	exchangeErr  error
}

func (m *mockOAuth2Config) AuthCodeURL(state string, options ...oauth2.AuthCodeOption) string {
	return m.authCodeFunc(state, options...)
}

func (m *mockOAuth2Config) Exchange(
	ctx context.Context, code string, options ...oauth2.AuthCodeOption) (oauth2Token, error) {
	return m.exchangeVal, m.exchangeErr
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
