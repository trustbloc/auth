/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package session

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
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
	store           storage.Store
	sessionLifetime time.Duration
}

// Config startup config for SessionManager.
type Config struct {
	StoreProvider   storage.Provider
	SessionLifetime time.Duration
}

// New creates a new client session Manager.
func New(config *Config) (*Manager, error) {
	store, err := config.StoreProvider.OpenStore("gnap_session_store")
	if err != nil {
		return nil, err
	}

	return &Manager{
		store:           store,
		sessionLifetime: config.SessionLifetime,
	}, nil
}

// TODO: how to handle retrieving a session by key if it expired and was deleted?

/*
TODO: session contents
 - client ID
 - client key
 - bound tokens
 - access descriptors for bound tokens
 - bound subject data
 - expiry metadata
 - interact_ref
 - interaction flow ID

TODO: session lookup keys
 - client ID
 - client key
 - bound tokens
 - interact_ref
 - interaction flow ID
*/

// Session holds a GNAP session.
type Session struct {
	ClientID       string
	ClientKey      *gnap.ClientKey
	Tokens         []*api.ExpiringToken
	ContinueToken  *api.ExpiringToken
	NeedsConsent   *api.AccessMetadata
	AllowedRequest *api.AccessMetadata
	SubjectData    map[string]string
	Expires        time.Time
	InteractRef    string
	InteractFlowID string
}

var errNotFound = errors.New("session not found")

var errSessionExpired = errors.New("session expired")

const (
	keyFingerprintTag = "k"
	tokenTagPrefix    = "t|"
	interactRefTag    = "i"
	interactFlowTag   = "f"
	continueTokenTag  = "c"
)

// Save saves the given Session in the Manager's store.
func (s *Manager) Save(session *Session) error { // nolint:funlen,gocyclo
	// add expiry time
	if s.sessionLifetime != 0 {
		if session.Expires.IsZero() {
			session.Expires = time.Now().Add(s.sessionLifetime)
		} else if session.Expires.Before(time.Now()) {
			if session.ClientID != "" {
				_ = s.DeleteSession(session.ClientID) // nolint:errcheck
			}

			return errSessionExpired
		}
	}

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshaling session: %w", err)
	}

	tags := []storage.Tag{}

	if session.ClientKey != nil {
		keyFingerprint, e := session.ClientKey.JWK.Thumbprint(crypto.SHA3_512)
		if e != nil {
			return fmt.Errorf("creating jwk thumbprint: %w", e)
		}

		tags = append(tags, storage.Tag{
			Name:  keyFingerprintTag,
			Value: base64.RawURLEncoding.EncodeToString(keyFingerprint),
		})
	}

	if session.InteractRef != "" {
		tags = append(tags, storage.Tag{
			Name:  interactRefTag,
			Value: session.InteractRef,
		})
	}

	if session.InteractFlowID != "" {
		tags = append(tags, storage.Tag{
			Name:  interactFlowTag,
			Value: session.InteractFlowID,
		})
	}

	for _, token := range session.Tokens {
		tags = append(tags, storage.Tag{
			Name: tokenTagPrefix + token.Value,
		})
	}

	if session.ContinueToken != nil {
		tags = append(tags, storage.Tag{
			Name:  continueTokenTag,
			Value: session.ContinueToken.Value,
		})
	}

	err = s.store.Put(session.ClientID, data, tags...)
	if err != nil {
		return fmt.Errorf("storing session: %w", err)
	}

	return nil
}

func (s *Manager) checkExpired(session *Session) error {
	if s.sessionLifetime == 0 || session.Expires.IsZero() {
		return nil
	}

	if session.Expires.Before(time.Now()) {
		if session.ClientID != "" {
			_ = s.DeleteSession(session.ClientID) // nolint:errcheck
		}

		return errSessionExpired
	}

	return nil
}

func (s *Manager) getByTag(tag storage.Tag) (*Session, error) {
	tagString := tag.Name + ":" + tag.Value

	it, err := s.store.Query(tagString)
	if errors.Is(err, storage.ErrDataNotFound) {
		return nil, errNotFound
	} else if err != nil {
		return nil, fmt.Errorf("querying session by tag: %w", err)
	}

	has, err := it.Next()
	if err != nil {
		return nil, fmt.Errorf("session query iterator: %w", err)
	}

	if !has {
		return nil, errNotFound
	}

	data, err := it.Value()
	if err != nil {
		return nil, fmt.Errorf("session query value: %w", err)
	}

	err = it.Close()
	if err != nil {
		return nil, fmt.Errorf("closing session iterator: %w", err)
	}

	session := &Session{}

	err = json.Unmarshal(data, session)
	if err != nil {
		return nil, fmt.Errorf("parsing session: %w", err)
	}

	err = s.checkExpired(session)
	if err != nil {
		return nil, err
	}

	return session, nil
}

// GetOrCreateByKey gets the client session with the given key, or creates a
// fresh session with the given key if one doesn't exist.
func (s *Manager) GetOrCreateByKey(clientKey *gnap.ClientKey) (*Session, error) {
	keyFingerprint, err := clientKey.JWK.Thumbprint(crypto.SHA3_512)
	if err != nil {
		return nil, fmt.Errorf("creating jwk thumbprint: %w", err)
	}

	keyFP := base64.RawURLEncoding.EncodeToString(keyFingerprint)

	session, err := s.getByTag(storage.Tag{
		Name:  keyFingerprintTag,
		Value: keyFP,
	})
	if err == nil {
		return session, nil
	} else if !errors.Is(err, errNotFound) {
		return nil, err
	}

	id := uuid.New().String()

	session = &Session{
		ClientKey: clientKey,
		ClientID:  id,
	}

	err = s.Save(session)
	if err != nil {
		return nil, err
	}

	return session, nil
}

// GetByID gets the Session under the given client ID.
func (s *Manager) GetByID(clientID string) (*Session, error) {
	data, err := s.store.Get(clientID)
	if errors.Is(err, storage.ErrDataNotFound) {
		return nil, errNotFound
	} else if err != nil {
		return nil, fmt.Errorf("loading session: %w", err)
	}

	session := &Session{}

	err = json.Unmarshal(data, session)
	if err != nil {
		return nil, fmt.Errorf("parsing session: %w", err)
	}

	err = s.checkExpired(session)
	if err != nil {
		return nil, err
	}

	return session, nil
}

// GetByAccessToken gets the Session that has the given token.
func (s *Manager) GetByAccessToken(token string) (*Session, *api.ExpiringToken, error) {
	session, err := s.getByTag(storage.Tag{
		Name: tokenTagPrefix + token,
	})
	if err != nil {
		return nil, nil, err
	}

	var t *api.ExpiringToken

	for _, tok := range session.Tokens {
		if tok.Value == token {
			t = tok

			break
		}
	}

	return session, t, nil
}

// GetByContinueToken gets the Session that has the given continuation token.
func (s *Manager) GetByContinueToken(token string) (*Session, error) {
	session, err := s.getByTag(storage.Tag{
		Name:  continueTokenTag,
		Value: token,
	})
	if err != nil {
		return nil, err
	}

	if session.ContinueToken == nil || session.ContinueToken.Value != token {
		return nil, errNotFound
	}

	return session, nil
}

// GetByInteractRef gets the Session under the given interact_ref.
func (s *Manager) GetByInteractRef(interactRef string) (*Session, error) {
	return s.getByTag(storage.Tag{
		Name:  interactRefTag,
		Value: interactRef,
	})
}

// GetByInteractFlowID gets the Session under the given interaction flow ID.
func (s *Manager) GetByInteractFlowID(interactFlowID string) (*Session, error) {
	return s.getByTag(storage.Tag{
		Name:  interactFlowTag,
		Value: interactFlowID,
	})
}

// DeleteSession deletes the session under the given client ID, if it exists.
func (s *Manager) DeleteSession(clientID string) error {
	return s.store.Delete(clientID)
}

// AddSubjectData adds the given subject data to a session.
func (s *Session) AddSubjectData(data map[string]string) {
	if s.SubjectData == nil {
		s.SubjectData = map[string]string{}
	}

	for k, v := range data {
		s.SubjectData[k] = v
	}
}
