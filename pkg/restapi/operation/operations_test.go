/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/trustbloc/hub-auth/pkg/bootstrap/user"
	"github.com/trustbloc/hub-auth/pkg/internal/common/mockoidc"
	"github.com/trustbloc/hub-auth/pkg/internal/common/mockstorage"
	"github.com/trustbloc/hub-auth/pkg/restapi/common/store/cookie"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		require.NotNil(t, svc)
		require.NotEmpty(t, svc.GetRESTHandlers())
	})

	t.Run("success, bootstrap store already exists", func(t *testing.T) {
		config := config(t)

		config.TransientStoreProvider = mem.NewProvider()

		_, err := config.TransientStoreProvider.OpenStore(bootstrapStoreName)
		require.NoError(t, err)

		svc, err := New(config)
		require.NoError(t, err)
		require.NotNil(t, svc)
		require.NotEmpty(t, svc.GetRESTHandlers())
	})

	t.Run("error if unable to open transient store", func(t *testing.T) {
		config := config(t)
		config.TransientStoreProvider = &mockstore.MockStoreProvider{
			ErrOpenStoreHandle: errors.New("test"),
		}
		_, err := New(config)
		require.Error(t, err)
	})

	t.Run("error if device certificate root CAs are invalid", func(t *testing.T) {
		config := config(t)
		config.DeviceRootCerts = []string{"invalid"}

		_, err := New(config)
		require.Error(t, err)
	})

	t.Run("error if cannot open secrets store", func(t *testing.T) {
		config := config(t)
		config.StoreProvider = &mockstore.MockStoreProvider{
			FailNamespace: secretsStoreName,
			Store:         &mockstore.MockStore{},
		}
		_, err := New(config)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store for name space secrets")
	})
}

func TestOIDCLoginHandler(t *testing.T) {
	t.Run("returns oidc request", func(t *testing.T) {
		provider := uuid.New().String()
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		svc.cookies = mockCookies()
		svc.cachedOIDCProviders = map[string]oidcProvider{
			provider: &mockOIDCProvider{},
		}
		w := httptest.NewRecorder()
		svc.oidcLoginHandler(w, newOIDCLoginRequest(provider))
		require.Equal(t, http.StatusFound, w.Code)
		require.NotEmpty(t, w.Header().Get("location"))
	})

	t.Run("internal server error if cannot open cookie store", func(t *testing.T) {
		svc, err := New(config(t))
		require.NoError(t, err)
		svc.cookies = &cookie.MockStore{
			OpenErr: errors.New("test"),
		}
		w := httptest.NewRecorder()
		svc.oidcLoginHandler(w, newOIDCLoginRequest("mock1"))
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

	t.Run("internal server error if cannot save cookies", func(t *testing.T) {
		provider := uuid.New().String()
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		svc.cookies = &cookie.MockStore{
			Jar: &cookie.MockJar{
				SaveErr: errors.New("test"),
			},
		}
		svc.cachedOIDCProviders = map[string]oidcProvider{
			provider: &mockOIDCProvider{},
		}
		w := httptest.NewRecorder()
		svc.oidcLoginHandler(w, newOIDCLoginRequest(provider))
		require.Equal(t, http.StatusInternalServerError, w.Code)
		require.Contains(t, w.Body.String(), "failed to persist session cookies")
	})

	t.Run("error if oidc provider is invalid", func(t *testing.T) {
		config := config(t)
		config.OIDC.Providers = map[string]OIDCProviderConfig{
			"test": {
				URL: "INVALID",
			},
		}

		svc, err := New(config)
		require.NoError(t, err)
		svc.cookies = mockCookies()

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
		hydraChallenge := uuid.New().String()
		hydraRedirectURL := fmt.Sprintf("http://example.org/foo/%s", uuid.New().String())

		config := config(t)

		config.Hydra = &mockHydra{
			acceptLoginRequestValue: &admin.AcceptLoginRequestOK{Payload: &models.CompletedRequest{
				RedirectTo: &hydraRedirectURL,
			}},
		}

		o, err := New(config)
		require.NoError(t, err)

		o.cookies = mockCookies(withState(state), withHydraLoginChallenge(hydraChallenge), withProvider(provider))
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

		result := httptest.NewRecorder()
		o.oidcCallbackHandler(result, newOIDCCallback(state, code))
		require.Equal(t, http.StatusFound, result.Code)
		require.Equal(t, hydraRedirectURL, result.Header().Get("location"))
	})

	t.Run("error missing state", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback("", "code"))
		require.Equal(t, http.StatusBadRequest, result.Code)
	})

	t.Run("error mismatching state", func(t *testing.T) {
		state := uuid.New().String()
		mismatch := "mismatch"
		require.NotEqual(t, state, mismatch)
		svc, err := New(config(t))
		require.NoError(t, err)
		svc.cookies = mockCookies(withState("MISMATCH"), withHydraLoginChallenge("challenge"))
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback(state, "code"))
		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "invalid state parameter")
	})

	t.Run("error missing code", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback("state", ""))
		require.Equal(t, http.StatusBadRequest, result.Code)
	})

	t.Run("bad request if missing state cookie", func(t *testing.T) {
		svc, err := New(config(t))
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback("state", "code"))
		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "missing state cookie")
	})

	t.Run("bad request if missing hydra login challenge cookie", func(t *testing.T) {
		svc, err := New(config(t))
		require.NoError(t, err)
		svc.cookies = mockCookies(withState("state"), withProvider("provider"))
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback("state", "code"))
		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "missing hydra login challenge cookie")
	})

	t.Run("bad request if missing provider cookie", func(t *testing.T) {
		svc, err := New(config(t))
		require.NoError(t, err)
		svc.cookies = mockCookies(withState("state"))
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback("state", "code"))
		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "missing provider cookie")
	})

	t.Run("bad request if oidc provider is not supported (should not happen)", func(t *testing.T) {
		svc, err := New(config(t))
		require.NoError(t, err)
		svc.cookies = mockCookies(withState("state"), withHydraLoginChallenge("challenge"), withProvider("INVALID"))
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback("state", "code"))
		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "provider not supported")
	})

	t.Run("internal server error if cannot open cookies", func(t *testing.T) {
		svc, err := New(config(t))
		require.NoError(t, err)
		svc.cookies = &cookie.MockStore{
			OpenErr: errors.New("test"),
		}
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback("state", "code"))
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to get cookies")
	})

	t.Run("generic bootstrap store FETCH error", func(t *testing.T) {
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
				ErrGet: errors.New("generic"),
			},
		}

		svc, err := New(config)
		require.NoError(t, err)

		svc.cookies = mockCookies(withState(state), withHydraLoginChallenge("challenge"), withProvider(provider))
		svc.cachedOIDCProviders = map[string]oidcProvider{
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

		svc.cookies = mockCookies(withState(state), withHydraLoginChallenge("challenge"), withProvider(provider))
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
		svc.cookies = mockCookies(withState(state), withHydraLoginChallenge("challenge"), withProvider(provider))
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
		svc.cookies = mockCookies(withState(state), withHydraLoginChallenge("challenge"), withProvider(provider))
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
		svc.cookies = mockCookies(withState(state), withHydraLoginChallenge("challenge"), withProvider(provider))
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
		svc.cookies = mockCookies(withState(state), withHydraLoginChallenge("challenge"), withProvider(provider))
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
	t.Run("PUT error while storing user info while handling callback user", func(t *testing.T) {
		id := uuid.New().String()
		state := uuid.New().String()
		config := config(t)

		config.TransientStoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					id: {Value: []byte("{}")},
				},
				ErrGet: storage.ErrDataNotFound,
				ErrPut: errors.New("generic"),
			},
		}

		svc, err := New(config)
		require.NoError(t, err)

		result := httptest.NewRecorder()
		svc.handleAuthResult(result, newOIDCCallback(state, "code"), nil)
		require.Equal(t, http.StatusInternalServerError, result.Code)
	})

	t.Run("error bad gateway if hydra fails to accept login request", func(t *testing.T) {
		provider := uuid.New().String()
		state := uuid.New().String()
		code := uuid.New().String()
		hydraChallenge := uuid.New().String()

		config := config(t)

		config.Hydra = &mockHydra{
			acceptLoginRequestErr: errors.New("test"),
		}

		o, err := New(config)
		require.NoError(t, err)

		o.cookies = mockCookies(withState(state), withHydraLoginChallenge(hydraChallenge), withProvider(provider))
		o.cachedOIDCProviders = map[string]oidcProvider{
			provider: &mockOIDCProvider{
				name: provider,
				oauth2Config: &mockOAuth2Config{
					exchangeVal: &mockToken{
						oauth2Claim: uuid.New().String()},
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

		result := httptest.NewRecorder()
		o.oidcCallbackHandler(result, newOIDCCallback(state, code))
		require.Equal(t, http.StatusBadGateway, result.Code)
		require.Contains(t, result.Body.String(), "hydra failed to accept login request")
	})

	t.Run("internal server error if cannot delete cookies", func(t *testing.T) {
		provider := uuid.New().String()
		svc, err := New(config(t))
		require.NoError(t, err)
		svc.cookies = &cookie.MockStore{
			Jar: &cookie.MockJar{
				Cookies: map[interface{}]interface{}{
					stateCookie:               "state",
					hydraLoginChallengeCookie: "challenge",
					providerCookie:            provider,
				},
				SaveErr: errors.New("test"),
			},
		}
		svc.cachedOIDCProviders = map[string]oidcProvider{
			provider: &mockOIDCProvider{
				oauth2Config: &mockOAuth2Config{
					exchangeVal: &mockToken{oauth2Claim: uuid.New().String()},
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
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback("state", "code"))
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to delete cookies")
	})
}

func TestOperations_HydraConsentHandler(t *testing.T) {
	t.Run("redirects back to hydra", func(t *testing.T) {
		redirectURL := fmt.Sprintf("https://example.org/foo/%s", uuid.New().String())
		sub := uuid.New().String()
		challenge := uuid.New().String()

		config := config(t)
		config.Hydra = &mockHydra{
			getConsentRequestValue: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Subject:   sub,
				Challenge: &challenge,
			}},
			acceptConsentRequestValue: &admin.AcceptConsentRequestOK{Payload: &models.CompletedRequest{
				RedirectTo: &redirectURL,
			}},
		}
		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					sub: {Value: marshal(t, &user.Profile{})},
				},
			},
		}

		o, err := New(config)
		require.NoError(t, err)

		result := httptest.NewRecorder()
		o.hydraConsentHandler(result, newHydraConsentHTTPRequest(uuid.New().String()))
		require.Equal(t, http.StatusFound, result.Code)
		require.Equal(t, redirectURL, result.Header().Get("location"))
	})

	t.Run("err bad request if consent challenge is missing", func(t *testing.T) {
		o, err := New(config(t))
		require.NoError(t, err)

		result := httptest.NewRecorder()
		o.hydraConsentHandler(result, newHydraConsentHTTPRequest(""))
		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "missing consent_challenge")
	})

	t.Run("err badgateway if cannot fetch hydra consent request", func(t *testing.T) {
		config := config(t)
		config.Hydra = &mockHydra{
			getConsentRequestErr: errors.New("test"),
		}

		o, err := New(config)
		require.NoError(t, err)

		result := httptest.NewRecorder()
		o.hydraConsentHandler(result, newHydraConsentHTTPRequest("challenge"))
		require.Equal(t, http.StatusBadGateway, result.Code)
		require.Contains(t, result.Body.String(), "failed to fetch consent request from hydra")
	})

	t.Run("err internalservererror if cannot fetch user from store", func(t *testing.T) {
		config := config(t)
		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				ErrGet: errors.New("test"),
			},
		}
		config.Hydra = &mockHydra{
			getConsentRequestValue: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Subject: uuid.New().String(),
			}},
		}

		o, err := New(config)
		require.NoError(t, err)

		result := httptest.NewRecorder()
		o.hydraConsentHandler(result, newHydraConsentHTTPRequest("challenge"))
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to query for user profile")
	})

	t.Run("error badgateway if hydra fails to accept consent request", func(t *testing.T) {
		sub := uuid.New().String()
		challenge := uuid.New().String()

		config := config(t)
		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					sub: {Value: marshal(t, &user.Profile{})},
				},
			},
		}
		config.Hydra = &mockHydra{
			getConsentRequestValue: &admin.GetConsentRequestOK{Payload: &models.ConsentRequest{
				Challenge: &challenge,
				Subject:   sub,
			}},
			acceptConsentRequestErr: errors.New("test"),
		}

		o, err := New(config)
		require.NoError(t, err)

		result := httptest.NewRecorder()
		o.hydraConsentHandler(result, newHydraConsentHTTPRequest(challenge))
		require.Equal(t, http.StatusBadGateway, result.Code)
		require.Contains(t, result.Body.String(), "hydra failed to accept consent request")
	})
}

func TestGetBootstrapDataHandler(t *testing.T) {
	t.Run("returns bootstrap data", func(t *testing.T) {
		userSub := uuid.New().String()
		config := config(t)
		config.Hydra = &mockHydra{
			introspectValue: &admin.IntrospectOAuth2TokenOK{Payload: &models.OAuth2TokenIntrospection{
				Sub: userSub,
			}},
		}
		svc, err := New(config)
		require.NoError(t, err)
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
		svc.getBootstrapDataHandler(w, newGetBootstrapDataRequest())
		require.Equal(t, http.StatusOK, w.Code)
		result := &BootstrapData{}
		err = json.NewDecoder(w.Body).Decode(result)
		require.NoError(t, err)
		require.Equal(t, config.BootstrapConfig.DocumentSDSVaultURL, result.DocumentSDSVaultURL)
		require.Equal(t, config.BootstrapConfig.KeySDSVaultURL, result.KeySDSVaultURL)
		require.Equal(t, config.BootstrapConfig.AuthZKeyServerURL, result.AuthZKeyServerURL)
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

	t.Run("badrequest if token is not base64 encoded", func(t *testing.T) {
		request := newGetBootstrapDataRequest()
		request.Header.Set("authorization", "Bearer 123")
		svc, err := New(config(t))
		require.NoError(t, err)
		w := httptest.NewRecorder()
		svc.getBootstrapDataHandler(w, request)
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "failed to decode token")
	})

	t.Run("bad request if user does not have bootstrap data", func(t *testing.T) {
		userSub := uuid.New().String()
		config := config(t)
		config.Hydra = &mockHydra{
			introspectValue: &admin.IntrospectOAuth2TokenOK{Payload: &models.OAuth2TokenIntrospection{
				Sub: userSub,
			}},
		}
		svc, err := New(config)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		svc.getBootstrapDataHandler(w, newGetBootstrapDataRequest())
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "invalid handle")
	})

	t.Run("internal server error if bootstrap store FETCH fails generically", func(t *testing.T) {
		userSub := uuid.New().String()
		config := config(t)
		config.Hydra = &mockHydra{
			introspectValue: &admin.IntrospectOAuth2TokenOK{Payload: &models.OAuth2TokenIntrospection{
				Sub: userSub,
			}},
		}
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
		w := httptest.NewRecorder()
		svc.getBootstrapDataHandler(w, newGetBootstrapDataRequest())
		require.Equal(t, http.StatusInternalServerError, w.Code)
		require.Contains(t, w.Body.String(), "failed to query bootstrap store for handle")
	})
}

func TestPostBootstrapDataHandler(t *testing.T) {
	t.Run("updates bootstrap data", func(t *testing.T) {
		expected := &user.Profile{
			ID:     uuid.New().String(),
			AAGUID: uuid.New().String(),
			Data: map[string]string{
				"docsSDS":  "https://example.org/edvs/123",
				"keysSDS":  "https://example.org/edvs/456",
				"authkeys": "https://example.org/kms/123",
				"opskeys":  "https://example.org/kms/456",
			},
		}
		config := config(t)
		config.Hydra = &mockHydra{
			introspectValue: &admin.IntrospectOAuth2TokenOK{Payload: &models.OAuth2TokenIntrospection{
				Sub: expected.ID,
			}},
		}
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
		result := httptest.NewRecorder()
		svc.postBootstrapDataHandler(result, newPostBootstrapDataRequest(t, &UpdateBootstrapDataRequest{
			Data: expected.Data,
		}))
		require.Equal(t, http.StatusOK, result.Code)
		raw, err := svc.bootstrapStore.Get(expected.ID)
		require.NoError(t, err)
		update := &user.Profile{}
		err = json.NewDecoder(bytes.NewReader(raw)).Decode(update)
		require.NoError(t, err)
		require.Equal(t, expected, update)
	})

	t.Run("error badrequest if payload is not json", func(t *testing.T) {
		config := config(t)
		config.Hydra = &mockHydra{
			introspectValue: &admin.IntrospectOAuth2TokenOK{Payload: &models.OAuth2TokenIntrospection{
				Sub: uuid.New().String(),
			}},
		}
		svc, err := New(config)
		require.NoError(t, err)
		request := httptest.NewRequest(http.MethodPost, "https://example.org/bootstrap", bytes.NewReader([]byte("}")))
		request.Header.Set("authorization", "Bearer "+base64.StdEncoding.EncodeToString([]byte("test")))
		result := httptest.NewRecorder()
		svc.postBootstrapDataHandler(result, request)
		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "failed to decode request")
	})

	t.Run("error conflict if user does not exist", func(t *testing.T) {
		config := config(t)
		config.Hydra = &mockHydra{
			introspectValue: &admin.IntrospectOAuth2TokenOK{Payload: &models.OAuth2TokenIntrospection{
				Sub: uuid.New().String(),
			}},
		}
		svc, err := New(config)
		require.NoError(t, err)
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
		config.Hydra = &mockHydra{
			introspectValue: &admin.IntrospectOAuth2TokenOK{Payload: &models.OAuth2TokenIntrospection{
				Sub: userSub,
			}},
		}
		svc, err := New(config)
		require.NoError(t, err)
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
		config.Hydra = &mockHydra{
			introspectValue: &admin.IntrospectOAuth2TokenOK{Payload: &models.OAuth2TokenIntrospection{
				Sub: userSub,
			}},
		}
		svc, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.postBootstrapDataHandler(result, newPostBootstrapDataRequest(t, &UpdateBootstrapDataRequest{}))
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to update storage")
	})

	t.Run("err badgateway if cannot introspect token at hydra", func(t *testing.T) {
		config := config(t)
		config.Hydra = &mockHydra{
			introspectErr: errors.New("test"),
		}
		o, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		o.postBootstrapDataHandler(result, newPostBootstrapDataRequest(t, &UpdateBootstrapDataRequest{}))
		require.Equal(t, http.StatusBadGateway, result.Code)
		require.Contains(t, result.Body.String(), "failed to introspect token")
	})
}

func TestOperation_DeviceCertHandler(t *testing.T) {
	t.Run("invalid request json", func(t *testing.T) {
		config := config(t)

		svc, err := New(config)
		require.NoError(t, err)

		w := httptest.NewRecorder()

		svc.deviceCertHandler(w, httptest.NewRequest(http.MethodPost, "http://example.com/device",
			bytes.NewReader([]byte("not json"))))

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "invalid json")
	})

	t.Run("missing device certificate", func(t *testing.T) {
		config := config(t)

		handle := uuid.New().String()
		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					handle: {Value: marshal(t, &user.Profile{})},
				},
			},
		}

		svc, err := New(config)
		require.NoError(t, err)

		w := httptest.NewRecorder()

		data := certHolder{
			X5C:    nil,
			Sub:    handle,
			AAGUID: "AAGUID",
		}

		svc.deviceCertHandler(w, newDeviceCertRequest(t, &data))

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, "missing device certificate", w.Body.String())
	})

	t.Run("invalid user profile id", func(t *testing.T) {
		config := config(t)

		svc, err := New(config)
		require.NoError(t, err)

		w := httptest.NewRecorder()

		data := certHolder{
			X5C:    []string{"abc", "abcd"},
			Sub:    "bad handle",
			AAGUID: "AAGUID",
		}

		svc.deviceCertHandler(w, newDeviceCertRequest(t, &data))

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, "invalid user profile id", w.Body.String())
	})

	t.Run("can't load profile from store", func(t *testing.T) {
		config := config(t)
		handle := uuid.New().String()
		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					handle: {Value: marshal(t, &user.Profile{})},
				},
				ErrGet: errors.New("get error"),
			},
		}

		svc, err := New(config)
		require.NoError(t, err)

		w := httptest.NewRecorder()

		data := certHolder{
			X5C:    []string{"abc", "abcd"},
			Sub:    handle,
			AAGUID: "AAGUID",
		}

		svc.deviceCertHandler(w, newDeviceCertRequest(t, &data))

		require.Equal(t, http.StatusInternalServerError, w.Code)
		require.Equal(t, "failed to load user profile", w.Body.String())
	})

	t.Run("invalid cert PEM", func(t *testing.T) {
		config := config(t)
		handle := uuid.New().String()
		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					handle: {Value: marshal(t, &user.Profile{})},
				},
			},
		}

		svc, err := New(config)
		require.NoError(t, err)

		w := httptest.NewRecorder()

		data := certHolder{
			X5C:    []string{"abc", "abcd"},
			Sub:    handle,
			AAGUID: "AAGUID",
		}

		svc.deviceCertHandler(w, newDeviceCertRequest(t, &data))

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, "can't parse certificate PEM", w.Body.String())
	})

	t.Run("PEM does not encode a certificate", func(t *testing.T) {
		config := config(t)
		handle := uuid.New().String()
		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					handle: {Value: marshal(t, &user.Profile{})},
				},
			},
		}

		svc, err := New(config)
		require.NoError(t, err)

		w := httptest.NewRecorder()

		data := certHolder{
			X5C: []string{
				string(pem.EncodeToMemory(&pem.Block{
					Type:  "NOT A CERT",
					Bytes: []byte("definitely not a cert"),
				})),
			},
			Sub:    handle,
			AAGUID: "AAGUID",
		}

		svc.deviceCertHandler(w, newDeviceCertRequest(t, &data))

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, "can't parse certificate", w.Body.String())
	})

	t.Run("cert is not signed by chain from root CAs", func(t *testing.T) {
		config := config(t)
		handle := uuid.New().String()
		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					handle: {Value: marshal(t, &user.Profile{})},
				},
			},
		}

		svc, err := New(config)
		require.NoError(t, err)

		w := httptest.NewRecorder()

		data := certHolder{
			X5C: []string{
				makeSelfSignedCert(t),
			},
			Sub:    handle,
			AAGUID: "AAGUID",
		}

		svc.deviceCertHandler(w, newDeviceCertRequest(t, &data))

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, "cert chain fails to authenticate", w.Body.String())
	})

	t.Run("success - device cert is a root cert", func(t *testing.T) {
		config := config(t)
		handle := uuid.New().String()
		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					handle: {Value: marshal(t, &user.Profile{})},
				},
			},
		}

		svc, err := New(config)
		require.NoError(t, err)

		w := httptest.NewRecorder()

		_, devicePEM, _ := makeCACert(t)

		// device PEM is added to roots
		ok := svc.deviceRootCerts.AppendCertsFromPEM([]byte(devicePEM))
		require.True(t, ok)

		data := certHolder{
			X5C: []string{
				devicePEM,
			},
			Sub:    handle,
			AAGUID: "AAGUID",
		}

		svc.deviceCertHandler(w, newDeviceCertRequest(t, &data))

		require.Equal(t, http.StatusFound, w.Code)
	})

	t.Run("success - device cert is signed by root cert", func(t *testing.T) {
		config := config(t)
		handle := uuid.New().String()
		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					handle: {Value: marshal(t, &user.Profile{})},
				},
			},
		}

		svc, err := New(config)
		require.NoError(t, err)

		w := httptest.NewRecorder()

		rootCert, rootPEM, rootKey := makeCACert(t)

		_, devicePEM, _ := makeChildCert(t, rootCert, rootKey, false)

		// CA cert PEM is added to roots
		ok := svc.deviceRootCerts.AppendCertsFromPEM([]byte(rootPEM))
		require.True(t, ok)

		data := certHolder{
			X5C: []string{
				devicePEM,
			},
			Sub:    handle,
			AAGUID: "AAGUID",
		}

		svc.deviceCertHandler(w, newDeviceCertRequest(t, &data))

		require.Equal(t, http.StatusFound, w.Code)
	})

	t.Run("success - device cert is signed by a rooted certificate chain", func(t *testing.T) {
		config := config(t)
		handle := uuid.New().String()
		config.StoreProvider = &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{
				Store: map[string]mockstore.DBEntry{
					handle: {Value: marshal(t, &user.Profile{})},
				},
			},
		}

		svc, err := New(config)
		require.NoError(t, err)

		w := httptest.NewRecorder()

		rootCert, rootPEM, rootKey := makeCACert(t)

		i1Cert, i1PEM, i1Key := makeChildCert(t, rootCert, rootKey, true)
		i2Cert, i2PEM, i2Key := makeChildCert(t, i1Cert, i1Key, true)

		_, devicePEM, _ := makeChildCert(t, i2Cert, i2Key, false)

		// CA cert PEM is added to roots
		ok := svc.deviceRootCerts.AppendCertsFromPEM([]byte(rootPEM))
		require.True(t, ok)

		data := certHolder{
			X5C: []string{
				devicePEM,
				i2PEM,
				i1PEM,
			},
			Sub:    handle,
			AAGUID: "AAGUID",
		}

		svc.deviceCertHandler(w, newDeviceCertRequest(t, &data))

		require.Equal(t, "", w.Body.String())
		require.Equal(t, http.StatusFound, w.Code)
	})
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

func TestOperation_HydraLoginHandler(t *testing.T) {
	t.Run("redirects to login UI", func(t *testing.T) {
		uiEndpoint := "/ui"
		hydraLoginRequest := &admin.GetLoginRequestOK{Payload: &models.LoginRequest{
			Client: &models.OAuth2Client{
				ClientID: uuid.New().String(),
				Scope:    "registered scopes",
			},
			RequestedScope: []string{"requested", "scope"},
		}}

		config := config(t)
		config.UIEndpoint = uiEndpoint
		config.Hydra = &mockHydra{
			getLoginRequestValue: hydraLoginRequest,
		}

		o, err := New(config)
		require.NoError(t, err)

		o.cookies = mockCookies()

		w := httptest.NewRecorder()
		o.hydraLoginHandler(w, newHydraLoginHTTPRequest(uuid.New().String()))

		require.Equal(t, http.StatusFound, w.Code)
		require.True(t, strings.HasPrefix(w.Header().Get("Location"), uiEndpoint))
		require.Equal(t, uiEndpoint, w.Header().Get("location"))
	})

	t.Run("error bad request if login_challenge is missing", func(t *testing.T) {
		o, err := New(config(t))
		require.NoError(t, err)

		w := httptest.NewRecorder()
		o.hydraLoginHandler(w, httptest.NewRequest(http.MethodGet, "/login", nil))

		require.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("error bad gateway if cannot fetch login request from hydra", func(t *testing.T) {
		config := config(t)
		config.Hydra = &mockHydra{
			getLoginRequestErr: errors.New("test"),
		}

		o, err := New(config)
		require.NoError(t, err)

		w := httptest.NewRecorder()
		o.hydraLoginHandler(w, newHydraLoginHTTPRequest(uuid.New().String()))

		require.Equal(t, http.StatusBadGateway, w.Code)
	})

	t.Run("error internal server error if cannot open cookie store", func(t *testing.T) {
		o, err := New(config(t))
		require.NoError(t, err)

		o.cookies = &cookie.MockStore{
			OpenErr: errors.New("test"),
		}

		w := httptest.NewRecorder()
		o.hydraLoginHandler(w, newHydraLoginHTTPRequest(uuid.New().String()))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestPostSecretHandler(t *testing.T) {
	t.Run("saves secret", func(t *testing.T) {
		secret := secret(t)
		secrets := make(map[string][]byte)
		userSub := uuid.New().String()
		config := config(t)
		config.StoreProvider = &mockstorage.Provider{
			Stores: map[string]storage.Store{
				bootstrapStoreName: &mockstorage.MockStore{
					Store: map[string][]byte{
						userSub: marshal(t, &user.Profile{}),
					},
				},
				secretsStoreName: &mockstorage.MockStore{Store: secrets},
			},
		}
		config.Hydra = &mockHydra{
			introspectValue: &admin.IntrospectOAuth2TokenOK{Payload: &models.OAuth2TokenIntrospection{
				Sub: userSub,
			}},
		}
		o, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		o.postSecretHandler(result, newPostSecretRequest(t, secret))
		require.Equal(t, http.StatusOK, result.Code)
		require.Contains(t, secrets, userSub)
		require.Equal(t, secret, secrets[userSub])
	})

	t.Run("error forbidden if request is not authenticated", func(t *testing.T) {
		o, err := New(config(t))
		require.NoError(t, err)
		result := httptest.NewRecorder()
		o.postSecretHandler(result, httptest.NewRequest(http.MethodPost, "http://example.org/", nil))
		require.Equal(t, http.StatusForbidden, result.Code)
		require.Contains(t, result.Body.String(), "no credentials")
	})

	t.Run("error statusconflict if user does not exist", func(t *testing.T) {
		config := config(t)
		config.Hydra = &mockHydra{
			introspectValue: &admin.IntrospectOAuth2TokenOK{Payload: &models.OAuth2TokenIntrospection{
				Sub: uuid.New().String(),
			}},
		}
		o, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		o.postSecretHandler(result, newPostSecretRequest(t, nil))
		require.Equal(t, http.StatusConflict, result.Code)
		require.Contains(t, result.Body.String(), "no such user")
	})

	t.Run("internal server error on generic bootstrap store FETCH error", func(t *testing.T) {
		userSub := uuid.New().String()
		config := config(t)
		config.Hydra = &mockHydra{
			introspectValue: &admin.IntrospectOAuth2TokenOK{Payload: &models.OAuth2TokenIntrospection{
				Sub: userSub,
			}},
		}
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store:  map[string][]byte{userSub: marshal(t, &user.Profile{})},
				ErrGet: errors.New("test"),
			},
		}
		o, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		o.postSecretHandler(result, newPostSecretRequest(t, nil))
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to query bootstrap store")
	})

	t.Run("error statusconflict if secret is already set for the user", func(t *testing.T) {
		userSub := uuid.New().String()
		config := config(t)
		config.Hydra = &mockHydra{
			introspectValue: &admin.IntrospectOAuth2TokenOK{Payload: &models.OAuth2TokenIntrospection{
				Sub: userSub,
			}},
		}
		config.StoreProvider = &mockstorage.Provider{
			Stores: map[string]storage.Store{
				bootstrapStoreName: &mockstorage.MockStore{Store: map[string][]byte{
					userSub: marshal(t, &user.Profile{}),
				}},
				secretsStoreName: &mockstorage.MockStore{Store: map[string][]byte{
					userSub: []byte("existing"),
				}},
			},
		}
		o, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		o.postSecretHandler(result, newPostSecretRequest(t, nil))
		require.Equal(t, http.StatusConflict, result.Code)
		require.Contains(t, result.Body.String(), "secret already set")
	})

	t.Run("error internalservererror if cannot query secrets store", func(t *testing.T) {
		userSub := uuid.New().String()
		config := config(t)
		config.Hydra = &mockHydra{
			introspectValue: &admin.IntrospectOAuth2TokenOK{Payload: &models.OAuth2TokenIntrospection{
				Sub: userSub,
			}},
		}
		config.StoreProvider = &mockstorage.Provider{
			Stores: map[string]storage.Store{
				bootstrapStoreName: &mockstorage.MockStore{Store: map[string][]byte{
					userSub: marshal(t, &user.Profile{}),
				}},
				secretsStoreName: &mockstorage.MockStore{
					Store:  map[string][]byte{userSub: marshal(t, &user.Profile{})},
					ErrGet: errors.New("test"),
				},
			},
		}
		o, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		o.postSecretHandler(result, newPostSecretRequest(t, nil))
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to query secrets store")
	})

	t.Run("error internalservererror if cannot save to secrets store", func(t *testing.T) {
		userSub := uuid.New().String()
		config := config(t)
		config.Hydra = &mockHydra{
			introspectValue: &admin.IntrospectOAuth2TokenOK{Payload: &models.OAuth2TokenIntrospection{
				Sub: userSub,
			}},
		}
		config.StoreProvider = &mockstorage.Provider{
			Stores: map[string]storage.Store{
				bootstrapStoreName: &mockstorage.MockStore{Store: map[string][]byte{
					userSub: marshal(t, &user.Profile{}),
				}},
				secretsStoreName: &mockstorage.MockStore{
					Store:  make(map[string][]byte),
					ErrPut: errors.New("test"),
				},
			},
		}
		o, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		o.postSecretHandler(result, newPostSecretRequest(t, nil))
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to save to secrets store")
	})
}

func TestGetSecretHandler(t *testing.T) {
	t.Run("returns secret", func(t *testing.T) {
		expected := uuid.New().String()
		userSub := uuid.New().String()
		config := config(t)
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: map[string][]byte{
					userSub: []byte(expected),
				},
			},
		}
		o, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		o.getSecretHandler(result, newGetSecretRequest(t, userSub, config.SecretsToken))
		require.Equal(t, http.StatusOK, result.Code)
		payload := &GetSecretResponse{}
		err = json.NewDecoder(result.Body).Decode(payload)
		require.NoError(t, err)
		decoded, err := base64.StdEncoding.DecodeString(payload.Secret)
		require.NoError(t, err)
		require.Equal(t, expected, string(decoded))
	})

	t.Run("status forbidden if missing bearer token", func(t *testing.T) {
		o, err := New(config(t))
		require.NoError(t, err)
		result := httptest.NewRecorder()
		o.getSecretHandler(result, httptest.NewRequest(http.MethodGet, "http://example.org/secrets/123", nil))
		require.Equal(t, http.StatusForbidden, result.Code)
		require.Contains(t, result.Body.String(), "no credentials")
	})

	t.Run("status unauthorized if token is invalid", func(t *testing.T) {
		o, err := New(config(t))
		require.NoError(t, err)
		request := httptest.NewRequest(http.MethodGet, "http://example.org/secrets/123", nil)
		request.Header.Set("authorization", "Bearer "+base64.StdEncoding.EncodeToString([]byte("INVALID")))
		result := httptest.NewRecorder()
		o.getSecretHandler(result, request)
		require.Equal(t, http.StatusForbidden, result.Code)
		require.Contains(t, result.Body.String(), "unauthorized")
	})

	t.Run("status badrequest if query parameter is missing", func(t *testing.T) {
		config := config(t)
		o, err := New(config)
		require.NoError(t, err)
		request := httptest.NewRequest(http.MethodGet, "http://example.org/secrets?sub=", nil)
		request.Header.Set("authorization", "Bearer "+base64.StdEncoding.EncodeToString([]byte(config.SecretsToken)))
		result := httptest.NewRecorder()
		o.getSecretHandler(result, request)
		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "missing parameter")
	})

	t.Run("error badrequest if user does not exist", func(t *testing.T) {
		userSub := uuid.New().String()
		config := config(t)
		o, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		o.getSecretHandler(result, newGetSecretRequest(t, userSub, config.SecretsToken))
		require.Equal(t, http.StatusBadRequest, result.Code)
		require.Contains(t, result.Body.String(), "non-existent user")
	})

	t.Run("internal server error on generic secrets store FETCH error", func(t *testing.T) {
		userSub := uuid.New().String()
		config := config(t)
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store:  map[string][]byte{userSub: marshal(t, &user.Profile{})},
				ErrGet: errors.New("generic"),
			},
		}
		o, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		o.getSecretHandler(result, newGetSecretRequest(t, userSub, config.SecretsToken))
		require.Equal(t, http.StatusInternalServerError, result.Code)
		require.Contains(t, result.Body.String(), "failed to query secrets store")
	})
}

func newHydraLoginHTTPRequest(challenge string) *http.Request {
	return httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("http://hub-auth.com/hydra/login?login_challenge=%s", challenge), nil)
}

func newHydraConsentHTTPRequest(challenge string) *http.Request {
	return httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("http://hub-auth.com/hydra/consent?consent_challenge=%s", challenge), nil)
}

func newOIDCLoginRequest(provider string) *http.Request {
	return httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://example.com/oauth2/login?provider=%s", provider), nil)
}

func newOIDCCallback(state, code string) *http.Request {
	return httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("http://example.com/oauth2/callback?state=%s&code=%s", state, code), nil)
}

func newGetBootstrapDataRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://example.com/bootstrap", nil)
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", base64.StdEncoding.EncodeToString([]byte("1234567random"))))

	return r
}

func newPostBootstrapDataRequest(t *testing.T, params *UpdateBootstrapDataRequest) *http.Request {
	t.Helper()

	bits, err := json.Marshal(params)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "http://example.com/bootstrap", bytes.NewReader(bits))
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", base64.StdEncoding.EncodeToString([]byte("1234567random"))))

	return r
}

func newPostSecretRequest(t *testing.T, secret []byte) *http.Request {
	t.Helper()

	payload, err := json.Marshal(&SetSecretRequest{Secret: secret})
	require.NoError(t, err)

	request := httptest.NewRequest(http.MethodPost, "http://example.com/secret", bytes.NewReader(payload))
	request.Header.Set(
		"Authorization",
		fmt.Sprintf("Bearer %s", base64.StdEncoding.EncodeToString([]byte("1234567random"))),
	)

	return request
}

func newGetSecretRequest(t *testing.T, sub, token string) *http.Request {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://www.example.org/secrets?sub=%s", sub), nil)

	r.Header.Set(
		"authorization",
		fmt.Sprintf("Bearer %s", base64.StdEncoding.EncodeToString([]byte(token))),
	)

	return r
}

func newDeviceCertRequest(t *testing.T, data *certHolder) *http.Request {
	dataBytes, err := json.Marshal(data)
	require.NoError(t, err)

	dataReader := bytes.NewReader(dataBytes)

	return httptest.NewRequest(http.MethodPost, "http://example.com/device", dataReader)
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

func config(t *testing.T) *Config {
	return &Config{
		OIDC: &OIDCConfig{
			CallbackURL: "http://test.com",
			Providers: map[string]OIDCProviderConfig{
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
		StoreProvider:          mem.NewProvider(),
		BootstrapConfig: &BootstrapConfig{
			DocumentSDSVaultURL: "http://docs.sds.example.org/sds/vaults",
			KeySDSVaultURL:      "http://keys.sds.example.org/sds/vaults/",
			AuthZKeyServerURL:   "http://auth.kms.example.org/kms/keystores/",
			OpsKeyServerURL:     "http://ops.kms.example.org/kms/keystores/",
		},
		Hydra: &mockHydra{},
		Cookies: &CookieConfig{
			AuthKey: cookieKey(t),
			EncKey:  cookieKey(t),
		},
		StartupTimeout: 1,
		SecretsToken:   uuid.New().String(),
	}
}

func cookieKey(t *testing.T) []byte {
	key := make([]byte, aes.BlockSize)

	_, err := rand.Read(key)
	require.NoError(t, err)

	return key
}

func marshal(t *testing.T, v interface{}) []byte {
	bits, err := json.Marshal(v)
	require.NoError(t, err)

	return bits
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

type mockHydra struct {
	getLoginRequestValue      *admin.GetLoginRequestOK
	getLoginRequestErr        error
	acceptLoginRequestValue   *admin.AcceptLoginRequestOK
	acceptLoginRequestErr     error
	getConsentRequestValue    *admin.GetConsentRequestOK
	getConsentRequestErr      error
	acceptConsentRequestValue *admin.AcceptConsentRequestOK
	acceptConsentRequestErr   error
	introspectValue           *admin.IntrospectOAuth2TokenOK
	introspectErr             error
}

func (m *mockHydra) GetLoginRequest(_ *admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error) {
	return m.getLoginRequestValue, m.getLoginRequestErr
}

func (m *mockHydra) AcceptLoginRequest(_ *admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error) {
	return m.acceptLoginRequestValue, m.acceptLoginRequestErr
}

func (m *mockHydra) GetConsentRequest(_ *admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error) {
	return m.getConsentRequestValue, m.getConsentRequestErr
}

func (m *mockHydra) AcceptConsentRequest(_ *admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error) {
	return m.acceptConsentRequestValue, m.acceptConsentRequestErr
}

func (m *mockHydra) IntrospectOAuth2Token(
	params *admin.IntrospectOAuth2TokenParams) (*admin.IntrospectOAuth2TokenOK, error) {
	return m.introspectValue, m.introspectErr
}

// makeSelfSignedCert returns a PEM-encoded self-signed certificate.
func makeSelfSignedCert(t *testing.T) string {
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1234),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	require.NoError(t, err)

	pemBytes := &bytes.Buffer{}
	err = pem.Encode(pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	require.NoError(t, err)

	return pemBytes.String()
}

// makeCACert returns a CA certificate, self-signed, with its PEM encoding and private key.
func makeCACert(t *testing.T) (*x509.Certificate, string, interface{}) {
	certSerialNumber, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: certSerialNumber,
		Subject: pkix.Name{
			CommonName:   "Testing CA",
			SerialNumber: fmt.Sprint(*certSerialNumber),
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	require.NoError(t, err)

	pemBytes := &bytes.Buffer{}
	err = pem.Encode(pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	require.NoError(t, err)

	return &template, pemBytes.String(), priv
}

// makeChildCert returns a certificate signed by parent, with its PEM encoding and private key.
func makeChildCert(t *testing.T, parent *x509.Certificate, parentPriv interface{},
	isIntermediate bool) (*x509.Certificate, string, interface{}) {
	certSerialNumber, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	require.NoError(t, err)

	keyID := make([]byte, 16)
	_, err = rand.Read(keyID)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: certSerialNumber,
		Subject: pkix.Name{
			CommonName:   "Testing child cert",
			SerialNumber: fmt.Sprint(*certSerialNumber),
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SubjectKeyId:          keyID,
		IsCA:                  isIntermediate,
	}

	if isIntermediate {
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, pub, parentPriv)
	require.NoError(t, err)

	pemBytes := &bytes.Buffer{}
	err = pem.Encode(pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	require.NoError(t, err)

	return &template, pemBytes.String(), priv
}

type cookieOpt func(map[string]string)

func withState(state string) cookieOpt {
	return func(c map[string]string) {
		c[stateCookie] = state
	}
}

func withHydraLoginChallenge(challenge string) cookieOpt {
	return func(c map[string]string) {
		c[hydraLoginChallengeCookie] = challenge
	}
}

func withProvider(provider string) cookieOpt {
	return func(c map[string]string) {
		c[providerCookie] = provider
	}
}

func mockCookies(c ...cookieOpt) *cookie.MockStore {
	t := make(map[string]string)

	for i := range c {
		c[i](t)
	}

	cookies := make(map[interface{}]interface{}, len(c))

	for k, v := range t {
		cookies[k] = v
	}

	return &cookie.MockStore{
		Jar: &cookie.MockJar{
			Cookies: cookies,
		},
	}
}

func secret(t *testing.T) []byte {
	t.Helper()

	s := make([]byte, 256)

	_, err := rand.Reader.Read(s)
	require.NoError(t, err)

	return s
}
