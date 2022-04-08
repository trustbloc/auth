/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package session

import (
	"crypto"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "golang.org/x/crypto/sha3" // nolint:gci

	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/spi/gnap"
)

/*
Manager handles GNAP client sessions.

A session is created when the Auth Server receives an auth request from a
client, and the request is signed by and contains a new client key. The session
manager creates a client instance ID and saves the client's public key, with
configurable expiry.

When the Auth Server grants access tokens to a client, the Manager binds
the granted tokens to the client session.

When a Resource Server introspects an access token, the Manager fetches
the session bound to the token, checks expiry, and returns the token's access
descriptor, the client key, and stored subject information to the AccessPolicy.
*/
type Manager struct {
	store    map[string]*Session
	keyFP2ID map[string]string
	token2ID map[string]string
	ctok2ID  map[string]string
}

// New creates a new client session Manager.
func New() *Manager {
	return &Manager{
		store:    map[string]*Session{},
		keyFP2ID: map[string]string{},
		token2ID: map[string]string{},
		ctok2ID:  map[string]string{},
	}
}

// TODO: how to handle retrieving a session by key if it expired and was deleted?

/*
Session holds a GNAP session.

TODO: session contents
 - client ID
 - client key
 - bound tokens
 - access descriptors for bound tokens
 - bound subject data
 - expiry metadata

TODO: session lookup keys
 - client ID
 - client key
 - bound tokens.
*/
type Session struct {
	ClientID      string
	ClientKey     *gnap.ClientKey
	Tokens        []*gnap.AccessToken
	ContinueToken *gnap.AccessToken
	Requested     *api.AccessMetadata
	SubjectData   map[string]string
	Expires       time.Time
}

var errNotFound = errors.New("session not found")

// GetOrCreateByKey gets the client session with the given key, or creates a
// fresh session with the given key if one doesn't exist.
func (s *Manager) GetOrCreateByKey(clientKey *gnap.ClientKey) (*Session, error) {
	keyFingerprint, err := clientKey.JWK.Thumbprint(crypto.SHA3_512)
	if err != nil {
		return nil, fmt.Errorf("creating jwk thumbprint: %w", err)
	}

	keyFP := string(keyFingerprint)

	id, exists := s.keyFP2ID[keyFP]
	if exists {
		return s.store[id], nil
	}

	id = uuid.New().String()

	session := &Session{
		ClientKey: clientKey,
		ClientID:  id,
	}

	s.store[id] = session
	s.keyFP2ID[keyFP] = id

	return session, nil
}

// GetByID gets the Session under the given client ID.
func (s *Manager) GetByID(clientID string) (*Session, error) {
	session, ok := s.store[clientID]
	if !ok {
		return nil, errNotFound
	}

	return session, nil
}

// GetByAccessToken gets the Session that has the given token.
func (s *Manager) GetByAccessToken(token string) (*Session, *gnap.AccessToken, error) {
	id, ok := s.token2ID[token]
	if !ok {
		return nil, nil, errNotFound
	}

	session, ok := s.store[id]
	if !ok {
		return nil, nil, errNotFound
	}

	var t *gnap.AccessToken

	if session.ContinueToken != nil && session.ContinueToken.Value == token {
		t = session.ContinueToken
	} else {
		for _, tok := range session.Tokens {
			if tok.Value == token {
				t = tok

				break
			}
		}
	}

	return session, t, nil
}

// GetByContinueToken gets the Session that has the given continuation token.
func (s *Manager) GetByContinueToken(token string) (*Session, error) {
	id, ok := s.ctok2ID[token]
	if !ok {
		return nil, errNotFound
	}

	session, ok := s.store[id]
	if !ok {
		return nil, errNotFound
	}

	if session.ContinueToken == nil || session.ContinueToken.Value != token {
		return nil, errNotFound
	}

	return session, nil
}

// DeleteSession deletes the session under the given client ID, if it exists.
func (s *Manager) DeleteSession(clientID string) error {
	session, ok := s.store[clientID]
	if !ok {
		return nil
	}

	if session.ClientKey != nil {
		keyFingerprint, err := session.ClientKey.JWK.Thumbprint(crypto.SHA3_512)
		if err != nil {
			return fmt.Errorf("creating jwk thumbprint: %w", err)
		}

		keyFP := string(keyFingerprint)

		delete(s.keyFP2ID, keyFP)
	}

	if session.ContinueToken != nil {
		delete(s.ctok2ID, session.ContinueToken.Value)
	}

	for _, token := range session.Tokens {
		if token == nil {
			continue
		}

		delete(s.token2ID, token.Value)
	}

	delete(s.store, clientID)

	return nil
}

// AddToken adds a token to a client session.
func (s *Manager) AddToken(token *gnap.AccessToken, clientID string) error {
	session, ok := s.store[clientID]
	if !ok {
		return errNotFound
	}

	session.Tokens = append(session.Tokens, token)

	s.store[clientID] = session
	s.token2ID[token.Value] = clientID

	return nil
}

// SaveRequests saves the given token requests to a session.
func (s *Manager) SaveRequests(req *api.AccessMetadata, clientID string) error {
	session, ok := s.store[clientID]
	if !ok {
		return errNotFound
	}

	session.Requested = req

	s.store[clientID] = session

	return nil
}

// SaveSubjectData saves the given token requests to a session.
func (s *Manager) SaveSubjectData(data map[string]string, clientID string) error {
	session, ok := s.store[clientID]
	if !ok {
		return errNotFound
	}

	if session.SubjectData == nil {
		session.SubjectData = map[string]string{}
	}

	for k, v := range data {
		session.SubjectData[k] = v
	}

	s.store[clientID] = session

	return nil
}

// ContinueToken sets the given token as the continuation token of a client session.
func (s *Manager) ContinueToken(token *gnap.AccessToken, clientID string) error {
	session, ok := s.store[clientID]
	if !ok {
		return errNotFound
	}

	session.ContinueToken = token

	s.store[clientID] = session
	s.ctok2ID[token.Value] = clientID

	return nil
}
