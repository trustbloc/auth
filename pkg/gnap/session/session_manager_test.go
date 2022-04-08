/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/spi/gnap"
)

func TestManager(t *testing.T) {
	t.Run("create / get by key", func(t *testing.T) {
		sm := New()

		invalid := &gnap.ClientKey{
			JWK: jwk.JWK{},
		}

		_, err := sm.GetOrCreateByKey(invalid)
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
		sm := New()

		_, err := sm.GetByID("foo")
		require.ErrorIs(t, err, errNotFound)

		s, err := sm.GetOrCreateByKey(clientKey(t))
		require.NoError(t, err)

		s2, err := sm.GetByID(s.ClientID)
		require.NoError(t, err)

		require.Equal(t, s, s2)
	})

	t.Run("add&get token", func(t *testing.T) {
		sm := New()

		s, err := sm.GetOrCreateByKey(clientKey(t))
		require.NoError(t, err)

		tok := &gnap.AccessToken{
			Value: "foo",
		}

		err = sm.AddToken(tok, s.ClientID)
		require.NoError(t, err)

		s2, tok2, err := sm.GetByAccessToken(tok.Value)
		require.NoError(t, err)

		require.Equal(t, s.ClientID, s2.ClientID)
		require.Equal(t, tok, tok2)
		require.Len(t, s2.Tokens, 1)
		require.Equal(t, tok.Value, s2.Tokens[0].Value)
	})

	t.Run("set&get continuation token", func(t *testing.T) {
		sm := New()

		s, err := sm.GetOrCreateByKey(clientKey(t))
		require.NoError(t, err)

		tok := &gnap.AccessToken{
			Value: "foo",
		}

		err = sm.ContinueToken(tok, s.ClientID)
		require.NoError(t, err)

		s2, err := sm.GetByContinueToken(tok.Value)
		require.NoError(t, err)

		require.Equal(t, s.ClientID, s2.ClientID)
		require.Equal(t, tok, s2.ContinueToken)
	})

	t.Run("set&get access request", func(t *testing.T) {
		sm := New()

		s, err := sm.GetOrCreateByKey(clientKey(t))
		require.NoError(t, err)

		req := &api.AccessMetadata{
			Tokens: []*gnap.TokenRequest{
				{
					Access: []gnap.TokenAccess{
						{
							IsReference: true,
							Ref:         "foo",
						},
					},
				},
			},
			SubjectKeys: []string{"foo"},
		}

		err = sm.SaveRequests(req, s.ClientID)
		require.NoError(t, err)

		s, err = sm.GetByID(s.ClientID)
		require.NoError(t, err)
		require.Equal(t, req, s.Requested)
	})

	t.Run("set&get subject data", func(t *testing.T) {
		sm := New()

		s, err := sm.GetOrCreateByKey(clientKey(t))
		require.NoError(t, err)

		sub := map[string]string{
			"foo": "bar",
			"baz": "baz 1",
		}

		err = sm.SaveSubjectData(sub, s.ClientID)
		require.NoError(t, err)

		s, err = sm.GetByID(s.ClientID)
		require.NoError(t, err)
		require.Equal(t, sub, s.SubjectData)

		sub2 := map[string]string{
			"baz": "baz 2",
			"qux": "wak",
		}

		err = sm.SaveSubjectData(sub2, s.ClientID)
		require.NoError(t, err)

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
		sm := New()

		s, err := sm.GetOrCreateByKey(clientKey(t))
		require.NoError(t, err)

		err = sm.DeleteSession(s.ClientID)
		require.NoError(t, err)

		require.Empty(t, sm.store)
		require.Empty(t, sm.keyFP2ID)
		require.Empty(t, sm.token2ID)
	})

	t.Run("err not found", func(t *testing.T) {
		sm := New()

		_, err := sm.GetByID("foo")
		require.ErrorIs(t, err, errNotFound)

		_, _, err = sm.GetByAccessToken("foo")
		require.ErrorIs(t, err, errNotFound)

		sm.token2ID["foo"] = "foo"

		_, _, err = sm.GetByAccessToken("foo")
		require.ErrorIs(t, err, errNotFound)

		err = sm.DeleteSession("foo")
		require.NoError(t, err)

		_, err = sm.GetByID("foo")
		require.ErrorIs(t, err, errNotFound)

		err = sm.AddToken(nil, "foo")
		require.ErrorIs(t, err, errNotFound)

		err = sm.SaveRequests(nil, "foo")
		require.ErrorIs(t, err, errNotFound)

		err = sm.SaveSubjectData(nil, "foo")
		require.ErrorIs(t, err, errNotFound)

		err = sm.ContinueToken(nil, "foo")
		require.ErrorIs(t, err, errNotFound)
	})
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
