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

	"github.com/trustbloc/hub-auth/pkg/restapi/common/store/cookie"

	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
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
		require.NotEmpty(t, svc.GetRESTHandlers())
	})

	t.Run("success, bootstrap store already exists", func(t *testing.T) {
		config := config(t)

		config.TransientStoreProvider = memstore.NewProvider()

		err := config.TransientStoreProvider.CreateStore(bootstrapStoreName)
		require.NoError(t, err)

		svc, err := New(config)
		require.NoError(t, err)
		require.NotNil(t, svc)
		require.NotEmpty(t, svc.GetRESTHandlers())
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

	t.Run("error if device certificate root CAs are invalid", func(t *testing.T) {
		config := config(t)
		config.DeviceRootCerts = []string{"invalid"}

		_, err := New(config)
		require.Error(t, err)
	})
}

func TestOIDCLoginHandler(t *testing.T) {
	t.Run("returns oidc request", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		svc.cookies = mockCookies()
		svc.oidcProvider = &mockOIDCProvider{baseURL: "http://test.com"}
		w := httptest.NewRecorder()
		svc.oidcLoginHandler(w, newOIDCLoginRequest("google"))
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
		svc.oidcLoginHandler(w, newOIDCLoginRequest("google"))
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("bad request if scope is missing", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		svc.oidcProvider = &mockOIDCProvider{baseURL: "http://test.com"}
		w := httptest.NewRecorder()
		svc.oidcLoginHandler(w, newOIDCLoginRequest(""))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestOIDCCallbackHandler(t *testing.T) {
	t.Run("onboard user", func(t *testing.T) {
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

		o.cookies = mockCookies(withState(state), withHydraLoginChallenge(hydraChallenge))

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

	t.Run("error invalid state parameter", func(t *testing.T) {
		config := config(t)
		svc, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback("state", "code"))
		require.Equal(t, http.StatusBadRequest, result.Code)
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

		svc.cookies = mockCookies(withState(state), withHydraLoginChallenge("challenge"))

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
		svc.oidcCallbackHandler(result, newOIDCCallback(state, "code"))
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

		svc.cookies = mockCookies(withState(state), withHydraLoginChallenge("challenge"))

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
		svc.oidcCallbackHandler(result, newOIDCCallback(state, "code"))
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
		svc.cookies = mockCookies(withState(state), withHydraLoginChallenge("challenge"))
		svc.oauth2ConfigFunc = func(...string) oauth2Config {
			return &mockOAuth2Config{
				exchangeErr: errors.New("test"),
			}
		}
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback(state, "code"))
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
		svc.cookies = mockCookies(withState(state), withHydraLoginChallenge("challenge"))
		svc.oauth2ConfigFunc = func(...string) oauth2Config {
			return &mockOAuth2Config{exchangeVal: &mockToken{}}
		}
		svc.oidcProvider = &mockOIDCProvider{
			verifier: &mockVerifier{verifyVal: &mockToken{}},
		}
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback(state, "code"))
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
		svc.cookies = mockCookies(withState(state), withHydraLoginChallenge("challenge"))
		svc.oauth2ConfigFunc = func(...string) oauth2Config {
			return &mockOAuth2Config{exchangeVal: &mockToken{oauth2Claim: "id_token"}}
		}
		svc.oidcProvider = &mockOIDCProvider{
			verifier: &mockVerifier{verifyErr: errors.New("test")},
		}
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback(state, "code"))
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
		svc.cookies = mockCookies(withState(state), withHydraLoginChallenge("challenge"))
		svc.oauth2ConfigFunc = func(...string) oauth2Config {
			return &mockOAuth2Config{exchangeVal: &mockToken{oauth2Claim: "id_token"}}
		}
		svc.oidcProvider = &mockOIDCProvider{
			verifier: &mockVerifier{verifyVal: &mockToken{oidcClaimsErr: errors.New("test")}},
		}
		result := httptest.NewRecorder()
		svc.oidcCallbackHandler(result, newOIDCCallback(state, "code"))
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

	t.Run("error bad gateway if hydra fails to accept login request", func(t *testing.T) {
		state := uuid.New().String()
		code := uuid.New().String()
		hydraChallenge := uuid.New().String()

		config := config(t)

		config.Hydra = &mockHydra{
			acceptLoginRequestErr: errors.New("test"),
		}

		o, err := New(config)
		require.NoError(t, err)

		o.cookies = mockCookies(withState(state), withHydraLoginChallenge(hydraChallenge))

		o.oauth2ConfigFunc = func(...string) oauth2Config {
			return &mockOAuth2Config{exchangeVal: &mockToken{
				oauth2Claim: uuid.New().String(),
			}}
		}

		o.oidcProvider = &mockOIDCProvider{
			verifier: &mockVerifier{
				verifyVal: &mockToken{},
			},
		}

		result := httptest.NewRecorder()
		o.oidcCallbackHandler(result, newOIDCCallback(state, code))
		require.Equal(t, http.StatusBadGateway, result.Code)
		require.Contains(t, result.Body.String(), "hydra failed to accept login request")
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
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: map[string][]byte{
					sub: marshal(t, &user.Profile{}),
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
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
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
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: map[string][]byte{
					sub: marshal(t, &user.Profile{}),
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
			SDSPrimaryVaultID: uuid.New().String(),
			KeyStoreIDs:       []string{uuid.New().String()},
		}

		err = svc.bootstrapStore.Put(userSub, marshal(t, expected))
		require.NoError(t, err)

		w := httptest.NewRecorder()
		svc.getBootstrapDataHandler(w, newGetBootstrapDataRequest())
		require.Equal(t, http.StatusOK, w.Code)
		result := &BootstrapData{}
		err = json.NewDecoder(w.Body).Decode(result)
		require.NoError(t, err)
		require.Equal(t, expected.SDSPrimaryVaultID, result.SDSPrimaryVaultID)
		require.Equal(t, expected.KeyStoreIDs, result.KeyStoreIDs)
		require.Equal(t, config.BootstrapConfig.KeyServerURL, result.KeyServerURL)
		require.Equal(t, config.BootstrapConfig.SDSURL, result.SDSURL)
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
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: map[string][]byte{
					userSub: marshal(t, &user.Profile{}),
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
			ID:                uuid.New().String(),
			AAGUID:            uuid.New().String(),
			SDSPrimaryVaultID: "https://example.org/edvs/123",
			KeyStoreIDs:       []string{"https://example.org/kms/123", "https://example.org/kms/456"},
		}
		config := config(t)
		config.Hydra = &mockHydra{
			introspectValue: &admin.IntrospectOAuth2TokenOK{Payload: &models.OAuth2TokenIntrospection{
				Sub: expected.ID,
			}},
		}
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: map[string][]byte{
					expected.ID: marshal(t, &user.Profile{
						ID:     expected.ID,
						AAGUID: expected.AAGUID,
					}),
				},
			},
		}
		svc, err := New(config)
		require.NoError(t, err)
		result := httptest.NewRecorder()
		svc.postBootstrapDataHandler(result, newPostBootstrapDataRequest(t, &UpdateBootstrapDataRequest{
			SDSPrimaryVaultID: expected.SDSPrimaryVaultID,
			KeyStoreIDs:       expected.KeyStoreIDs,
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
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: map[string][]byte{
					userSub: nil,
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
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: map[string][]byte{
					userSub: marshal(t, &user.Profile{}),
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
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: map[string][]byte{
					handle: marshal(t, &user.Profile{}),
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
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: map[string][]byte{
					handle: marshal(t, &user.Profile{}),
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
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: map[string][]byte{
					handle: marshal(t, &user.Profile{}),
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
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: map[string][]byte{
					handle: marshal(t, &user.Profile{}),
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
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: map[string][]byte{
					handle: marshal(t, &user.Profile{}),
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
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: map[string][]byte{
					handle: marshal(t, &user.Profile{}),
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
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: map[string][]byte{
					handle: marshal(t, &user.Profile{}),
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
		config.StoreProvider = &mockstorage.Provider{
			Store: &mockstorage.MockStore{
				Store: map[string][]byte{
					handle: marshal(t, &user.Profile{}),
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

func newDeviceCertRequest(t *testing.T, data *certHolder) *http.Request {
	dataBytes, err := json.Marshal(data)
	require.NoError(t, err)

	dataReader := bytes.NewReader(dataBytes)

	return httptest.NewRequest(http.MethodPost, "http://example.com/device", dataReader)
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
		Hydra: &mockHydra{},
		Cookies: &CookieConfig{
			AuthKey: cookieKey(t),
			EncKey:  cookieKey(t),
		},
		StartupTimeout: 1,
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
