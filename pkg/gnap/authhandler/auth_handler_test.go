/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authhandler

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/auth/pkg/gnap/accesspolicy"
	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/pkg/internal/common/mockinteract"
	"github.com/trustbloc/auth/pkg/internal/common/mockstorage"
	"github.com/trustbloc/auth/pkg/internal/common/mockverifier"
	"github.com/trustbloc/auth/spi/gnap"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		h, err := New(config(t))
		require.NoError(t, err)
		require.NotNil(t, h)
	})

	t.Run("fail to initialize access policy", func(t *testing.T) {
		conf := config(t)

		conf.AccessPolicyConfig = &accesspolicy.Config{
			AccessTypes: []accesspolicy.TokenAccessConfig{{
				Access: gnap.TokenAccess{
					Type: "foo",
					Raw:  []byte("foo bar baz"),
				},
			}},
		}

		h, err := New(conf)
		require.Error(t, err)
		require.Nil(t, h)
	})

	t.Run("fail to initialize session manager", func(t *testing.T) {
		conf := config(t)

		expectErr := errors.New("expected error")

		conf.StoreProvider = &mockstorage.Provider{ErrOpenStoreHandle: expectErr}

		h, err := New(conf)
		require.Error(t, err)
		require.ErrorIs(t, err, expectErr)
		require.Nil(t, h)
	})
}

func TestAuthHandler_HandleAccessRequest(t *testing.T) {
	t.Run("missing client", func(t *testing.T) {
		h, err := New(config(t))
		require.NoError(t, err)

		req := &gnap.AuthRequest{}
		v := &mockverifier.MockVerifier{}

		_, err = h.HandleAccessRequest(req, v)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing client")
	})

	t.Run("missing client reference", func(t *testing.T) {
		h, err := New(config(t))
		require.NoError(t, err)

		req := &gnap.AuthRequest{
			Client: &gnap.RequestClient{
				IsReference: true,
				Ref:         "foo",
			},
		}
		v := &mockverifier.MockVerifier{}

		_, err = h.HandleAccessRequest(req, v)
		require.Error(t, err)
		require.Contains(t, err.Error(), "getting client session by client ID")
	})

	t.Run("getting session by client key", func(t *testing.T) {
		h, err := New(config(t))
		require.NoError(t, err)

		req := &gnap.AuthRequest{
			Client: &gnap.RequestClient{
				IsReference: false,
				Key:         &gnap.ClientKey{},
			},
		}
		v := &mockverifier.MockVerifier{}

		_, err = h.HandleAccessRequest(req, v)
		require.Error(t, err)
		require.Contains(t, err.Error(), "getting client session by key")
	})

	t.Run("request verification failure", func(t *testing.T) {
		h, err := New(config(t))
		require.NoError(t, err)

		expectedErr := errors.New("expected error")

		req := &gnap.AuthRequest{
			Client: &gnap.RequestClient{
				IsReference: false,
				Key:         clientKey(t),
			},
		}
		v := &mockverifier.MockVerifier{
			ErrVerify: expectedErr,
		}

		_, err = h.HandleAccessRequest(req, v)
		require.Error(t, err)
		require.ErrorIs(t, err, expectedErr)
		require.Contains(t, err.Error(), "verification failure")
	})

	t.Run("fail to save", func(t *testing.T) {
		conf := config(t)

		expectErr := errors.New("expected error")

		conf.StoreProvider = &mockstorage.Provider{Store: &mockstorage.MockStore{
			Store:    map[string][]byte{},
			ErrQuery: storage.ErrDataNotFound,
			ErrPut:   expectErr,
		}}

		h, err := New(conf)
		require.NoError(t, err)

		h.loginConsent = &mockinteract.InteractHandler{
			PrepareVal: &gnap.ResponseInteract{
				Redirect: "foo.com",
				Finish:   "barbazqux",
			},
		}

		req := &gnap.AuthRequest{
			Client: &gnap.RequestClient{
				IsReference: false,
				Key:         clientKey(t),
			},
		}
		v := &mockverifier.MockVerifier{}

		resp, err := h.HandleAccessRequest(req, v)
		require.Error(t, err)
		require.ErrorIs(t, err, expectErr)

		require.Nil(t, resp)
	})

	t.Run("success", func(t *testing.T) {
		h, err := New(config(t))
		require.NoError(t, err)

		h.loginConsent = &mockinteract.InteractHandler{
			PrepareVal: &gnap.ResponseInteract{
				Redirect: "foo.com",
				Finish:   "barbazqux",
			},
		}

		req := &gnap.AuthRequest{
			Client: &gnap.RequestClient{
				IsReference: false,
				Key:         clientKey(t),
			},
		}
		v := &mockverifier.MockVerifier{}

		resp, err := h.HandleAccessRequest(req, v)
		require.NoError(t, err)

		require.Equal(t, "foo.com", resp.Interact.Redirect)
	})
}

func TestAuthHandler_HandleContinueRequest(t *testing.T) {
	t.Run("missing session", func(t *testing.T) {
		h, err := New(config(t))
		require.NoError(t, err)

		_, err = h.HandleContinueRequest(nil, "", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "getting session for continue token")
	})

	t.Run("failed request verify", func(t *testing.T) {
		h, err := New(config(t))
		require.NoError(t, err)

		s, err := h.sessionStore.GetOrCreateByKey(clientKey(t))
		require.NoError(t, err)

		s.ContinueToken = &api.ExpiringToken{AccessToken: gnap.AccessToken{
			Value: "foo",
		}}

		require.NoError(t, h.sessionStore.Save(s))

		expectErr := errors.New("expected error")

		_, err = h.HandleContinueRequest(nil, "foo", &mockverifier.MockVerifier{
			ErrVerify: expectErr,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "client request verification failure")
		require.ErrorIs(t, err, expectErr)
	})

	t.Run("failed interaction query", func(t *testing.T) {
		h, err := New(config(t))
		require.NoError(t, err)

		expectErr := errors.New("expected error")

		h.loginConsent = &mockinteract.InteractHandler{
			QueryErr: expectErr,
		}

		s, err := h.sessionStore.GetOrCreateByKey(clientKey(t))
		require.NoError(t, err)

		s.ContinueToken = &api.ExpiringToken{AccessToken: gnap.AccessToken{
			Value: "foo",
		}}

		require.NoError(t, h.sessionStore.Save(s))

		_, err = h.HandleContinueRequest(&gnap.ContinueRequest{}, "foo", &mockverifier.MockVerifier{})
		require.Error(t, err)
		require.ErrorIs(t, err, expectErr)
	})

	t.Run("success", func(t *testing.T) {
		h, err := New(config(t))
		require.NoError(t, err)

		h.loginConsent = &mockinteract.InteractHandler{
			QueryVal: &api.ConsentResult{
				Tokens: []*gnap.TokenRequest{
					{
						Access: []gnap.TokenAccess{
							{
								IsReference: true,
								Ref:         "foo",
							},
						},
						Label: "foo",
					},
				},
			},
		}

		s, err := h.sessionStore.GetOrCreateByKey(clientKey(t))
		require.NoError(t, err)

		s.ContinueToken = &api.ExpiringToken{AccessToken: gnap.AccessToken{
			Value: "foo",
		}}
		require.NoError(t, h.sessionStore.Save(s))

		resp, err := h.HandleContinueRequest(&gnap.ContinueRequest{}, "foo", &mockverifier.MockVerifier{})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Len(t, resp.AccessToken, 1)
		require.Equal(t, "foo", resp.AccessToken[0].Label)
	})
}

func TestAuthHandler_HandleIntrospection(t *testing.T) {
	t.Run("missing rs", func(t *testing.T) {
		h, err := New(config(t))
		require.NoError(t, err)

		req := &gnap.IntrospectRequest{}
		v := &mockverifier.MockVerifier{}

		_, err = h.HandleIntrospection(req, v)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing rs")
	})

	t.Run("missing rs reference", func(t *testing.T) {
		h, err := New(config(t))
		require.NoError(t, err)

		req := &gnap.IntrospectRequest{
			ResourceServer: &gnap.RequestClient{
				IsReference: true,
				Ref:         "foo",
			},
		}
		v := &mockverifier.MockVerifier{}

		_, err = h.HandleIntrospection(req, v)
		require.Error(t, err)
		require.Contains(t, err.Error(), "getting rs session by rs ID")
	})

	t.Run("getting session by rs key", func(t *testing.T) {
		h, err := New(config(t))
		require.NoError(t, err)

		req := &gnap.IntrospectRequest{
			ResourceServer: &gnap.RequestClient{
				IsReference: false,
				Key:         &gnap.ClientKey{},
			},
		}
		v := &mockverifier.MockVerifier{}

		_, err = h.HandleIntrospection(req, v)
		require.Error(t, err)
		require.Contains(t, err.Error(), "getting rs session by key")
	})

	t.Run("request verification failure", func(t *testing.T) {
		h, err := New(config(t))
		require.NoError(t, err)

		expectedErr := errors.New("expected error")

		req := &gnap.IntrospectRequest{
			ResourceServer: &gnap.RequestClient{
				IsReference: false,
				Key:         clientKey(t),
			},
		}
		v := &mockverifier.MockVerifier{
			ErrVerify: expectedErr,
		}

		_, err = h.HandleIntrospection(req, v)
		require.Error(t, err)
		require.ErrorIs(t, err, expectedErr)
		require.Contains(t, err.Error(), "verification failure")
	})

	t.Run("access token does not exist", func(t *testing.T) {
		h, err := New(config(t))
		require.NoError(t, err)

		req := &gnap.IntrospectRequest{
			ResourceServer: &gnap.RequestClient{
				IsReference: false,
				Key:         clientKey(t),
			},
		}
		v := &mockverifier.MockVerifier{}

		resp, err := h.HandleIntrospection(req, v)
		require.NoError(t, err)
		require.Equal(t, &gnap.IntrospectResponse{}, resp)
	})

	t.Run("client used wrong request signing method", func(t *testing.T) {
		h, err := New(config(t))
		require.NoError(t, err)

		clientSession, err := h.sessionStore.GetOrCreateByKey(clientKey(t))
		require.NoError(t, err)

		token := CreateToken(&gnap.TokenRequest{
			Label: "foo",
			Access: []gnap.TokenAccess{
				{
					IsReference: true,
					Ref:         "foo",
				},
			},
		})

		clientSession.Tokens = append(clientSession.Tokens, &api.ExpiringToken{AccessToken: *token})

		require.NoError(t, h.sessionStore.Save(clientSession))

		req := &gnap.IntrospectRequest{
			ResourceServer: &gnap.RequestClient{
				IsReference: false,
				Key:         clientKey(t),
			},
			Proof:       "wrong-proof-method",
			AccessToken: token.Value,
		}
		v := &mockverifier.MockVerifier{}

		resp, err := h.HandleIntrospection(req, v)
		require.NoError(t, err)
		require.Equal(t, &gnap.IntrospectResponse{}, resp)
	})

	t.Run("success", func(t *testing.T) {
		h, err := New(config(t))
		require.NoError(t, err)

		clientVerKey := clientKey(t)

		clientSession, err := h.sessionStore.GetOrCreateByKey(clientVerKey)
		require.NoError(t, err)

		clientIDKey := "client-id"
		clientIDVal := "123abc123"

		token := CreateToken(&gnap.TokenRequest{
			Label: "foo",
			Access: []gnap.TokenAccess{
				{
					IsReference: true,
					Ref:         clientIDKey,
				},
				{
					IsReference: true,
					Ref:         "other-access",
				},
			},
		})

		clientSession.Tokens = append(clientSession.Tokens, &api.ExpiringToken{AccessToken: *token})
		clientSession.AddSubjectData(map[string]string{
			clientIDKey: clientIDVal,
			"secret":    "blah blah",
		})

		require.NoError(t, h.sessionStore.Save(clientSession))

		req := &gnap.IntrospectRequest{
			ResourceServer: &gnap.RequestClient{
				IsReference: false,
				Key:         clientKey(t),
			},
			AccessToken: token.Value,
		}
		v := &mockverifier.MockVerifier{}

		resp, err := h.HandleIntrospection(req, v)
		require.NoError(t, err)

		expectedResp := &gnap.IntrospectResponse{
			Active: true,
			Access: token.Access,
			Key:    clientVerKey,
			SubjectData: map[string]string{
				clientIDKey: clientIDVal,
			},
		}
		require.Equal(t, expectedResp, resp)
	})
}

func config(t *testing.T) *Config {
	t.Helper()

	apConfig := &accesspolicy.Config{}

	err := json.Unmarshal([]byte(accessPolicyConf), apConfig)
	require.NoError(t, err)

	return &Config{
		StoreProvider:      mem.NewProvider(),
		AccessPolicyConfig: apConfig,
		ContinuePath:       "example.com",
		InteractionHandler: &mockinteract.InteractHandler{},
	}
}

func clientKey(t *testing.T) *gnap.ClientKey {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	k, err := jwksupport.JWKFromKey(pub)
	require.NoError(t, err)

	ck := gnap.ClientKey{
		Proof: "httpsig",
		JWK:   *k,
	}

	return &ck
}

const (
	accessPolicyConf = `{
	"access-types": [{
			"reference": "client-id",
			"permission": "NeedsConsent",
			"access": {
				"type": "trustbloc.xyz/auth/type/client-id",
				"subject-keys": ["client-id"],
				"userid-key": "client-id"
			}
		}, {
			"reference": "other-access",
			"permission": "NeedsConsent",
			"access": {
				"type": "trustbloc.xyz/auth/type/other-access",
				"actions": ["write"],
				"datasets": ["foobase"]
			}
		} 
	]
}`
)
