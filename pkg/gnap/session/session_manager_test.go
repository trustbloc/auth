/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/pkg/internal/common/mockstorage"
	"github.com/trustbloc/auth/spi/gnap"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		sm, err := New(config(t))
		require.NoError(t, err)
		require.NotNil(t, sm)
	})

	t.Run("failure", func(t *testing.T) {
		conf := config(t)

		expectErr := errors.New("expected error")

		conf.StoreProvider = &mockstorage.Provider{ErrOpenStoreHandle: expectErr}

		sm, err := New(conf)
		require.Error(t, err)
		require.ErrorIs(t, err, expectErr)
		require.Nil(t, sm)
	})
}

func TestManager(t *testing.T) {
	t.Run("create / get by key", func(t *testing.T) {
		sm, err := New(config(t))
		require.NoError(t, err)

		invalid := &gnap.ClientKey{
			JWK: jwk.JWK{},
		}

		_, err = sm.GetOrCreateByKey(invalid)
		require.Error(t, err)
		require.Contains(t, err.Error(), "creating jwk thumbprint")

		ck := clientKey(t)

		s, err := sm.GetOrCreateByKey(ck)
		require.NoError(t, err)

		require.Equal(t, ck, s.ClientKey)

		s2, err := sm.GetOrCreateByKey(ck)
		require.NoError(t, err)

		require.Equal(t, s.ClientID, s2.ClientID)
	})

	t.Run("get by ID", func(t *testing.T) {
		sm, err := New(config(t))
		require.NoError(t, err)

		_, err = sm.GetByID("foo")
		require.ErrorIs(t, err, errNotFound)

		s, err := sm.GetOrCreateByKey(clientKey(t))
		require.NoError(t, err)

		s2, err := sm.GetByID(s.ClientID)
		require.NoError(t, err)

		require.Equal(t, s, s2)
	})

	t.Run("add&get token", func(t *testing.T) {
		sm, err := New(config(t))
		require.NoError(t, err)

		s, err := sm.GetOrCreateByKey(clientKey(t))
		require.NoError(t, err)

		tok := &api.ExpiringToken{AccessToken: gnap.AccessToken{
			Value: "foo",
		}}

		s.Tokens = append(s.Tokens, tok)

		require.NoError(t, sm.Save(s))

		s2, tok2, err := sm.GetByAccessToken(tok.Value)
		require.NoError(t, err)

		require.Equal(t, s.ClientID, s2.ClientID)
		require.Equal(t, tok, tok2)
		require.Len(t, s2.Tokens, 1)
		require.Equal(t, tok.Value, s2.Tokens[0].Value)
	})

	t.Run("set&get continuation token", func(t *testing.T) {
		sm, err := New(config(t))
		require.NoError(t, err)

		s, err := sm.GetOrCreateByKey(clientKey(t))
		require.NoError(t, err)

		tok := &api.ExpiringToken{
			AccessToken: gnap.AccessToken{
				Value: "foo",
			},
		}

		s.ContinueToken = tok

		require.NoError(t, sm.Save(s))

		s2, err := sm.GetByContinueToken(tok.Value)
		require.NoError(t, err)

		require.Equal(t, s.ClientID, s2.ClientID)
		require.Equal(t, tok, s2.ContinueToken)
	})

	t.Run("set&get access request", func(t *testing.T) {
		sm, err := New(config(t))
		require.NoError(t, err)

		s, err := sm.GetOrCreateByKey(clientKey(t))
		require.NoError(t, err)

		req := &api.AccessMetadata{
			Tokens: []*api.ExpiringTokenRequest{
				{
					TokenRequest: gnap.TokenRequest{
						Access: []gnap.TokenAccess{
							{
								IsReference: true,
								Ref:         "foo",
							},
						},
					},
				},
			},
			SubjectKeys: []string{"foo"},
		}

		s.Requested = req

		require.NoError(t, sm.Save(s))

		s, err = sm.GetByID(s.ClientID)
		require.NoError(t, err)
		require.Equal(t, req, s.Requested)
	})

	t.Run("set&get subject data", func(t *testing.T) {
		sm, err := New(config(t))
		require.NoError(t, err)

		s, err := sm.GetOrCreateByKey(clientKey(t))
		require.NoError(t, err)

		sub := map[string]string{
			"foo": "bar",
			"baz": "baz 1",
		}

		s.AddSubjectData(sub)

		require.NoError(t, sm.Save(s))

		s, err = sm.GetByID(s.ClientID)
		require.NoError(t, err)
		require.Equal(t, sub, s.SubjectData)

		sub2 := map[string]string{
			"baz": "baz 2",
			"qux": "wak",
		}

		s.AddSubjectData(sub2)

		require.NoError(t, sm.Save(s))

		s, err = sm.GetByID(s.ClientID)
		require.NoError(t, err)

		expected := map[string]string{
			"foo": "bar",
			"baz": "baz 2",
			"qux": "wak",
		}

		require.Equal(t, expected, s.SubjectData)
	})

	t.Run("create&delete session", func(t *testing.T) {
		sm, err := New(config(t))
		require.NoError(t, err)

		s, err := sm.GetOrCreateByKey(clientKey(t))
		require.NoError(t, err)

		err = sm.DeleteSession(s.ClientID)
		require.NoError(t, err)

		_, err = sm.GetByID(s.ClientID)
		require.ErrorIs(t, err, errNotFound)
	})

	t.Run("err not found", func(t *testing.T) {
		sm, err := New(config(t))
		require.NoError(t, err)

		_, err = sm.GetByID("foo")
		require.ErrorIs(t, err, errNotFound)

		_, _, err = sm.GetByAccessToken("foo")
		require.ErrorIs(t, err, errNotFound)

		err = sm.DeleteSession("foo")
		require.NoError(t, err)

		_, err = sm.GetByID("foo")
		require.ErrorIs(t, err, errNotFound)

		_, err = sm.GetByInteractRef("foo")
		require.ErrorIs(t, err, errNotFound)

		_, err = sm.GetByInteractFlowID("foo")
		require.ErrorIs(t, err, errNotFound)
	})
}

func TestManager_Expiry(t *testing.T) {
	// TODO tests for session expiry
	t.Run("not expired", func(t *testing.T) {
		sm, err := New(config(t))
		require.NoError(t, err)

		sm.sessionLifetime = time.Hour

		foo := "foo"

		s := &Session{
			ClientID:       uuid.New().String(),
			InteractRef:    foo,
			InteractFlowID: foo,
		}

		err = sm.Save(s)
		require.NoError(t, err)

		s2, err := sm.GetByID(s.ClientID)
		require.NoError(t, err)
		require.Equal(t, s.ClientID, s2.ClientID)

		s2, err = sm.GetByInteractRef(foo)
		require.NoError(t, err)
		require.Equal(t, s.ClientID, s2.ClientID)

		s2, err = sm.GetByInteractFlowID(foo)
		require.NoError(t, err)
		require.Equal(t, s.ClientID, s2.ClientID)
	})

	t.Run("expiry test", func(t *testing.T) {
		sm, err := New(config(t))
		require.NoError(t, err)

		sm.sessionLifetime = time.Millisecond * 5

		s := &Session{
			ClientID: uuid.New().String(),
		}

		err = sm.Save(s)
		require.NoError(t, err)

		timer := time.NewTimer(time.Millisecond * 10)

		<-timer.C

		_, err = sm.GetByID(s.ClientID)
		require.Error(t, err)
		require.ErrorIs(t, err, errSessionExpired)
	})
}

func config(t *testing.T) *Config {
	t.Helper()

	return &Config{
		StoreProvider: mem.NewProvider(),
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
