/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package session

import (
	"errors"

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
type Manager struct{}

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
type Session struct{}

// GetOrCreateByKey gets the client session with the given key, or creates a
// fresh session with the given key if one doesn't exist.
func (s *Manager) GetOrCreateByKey(clientKey *gnap.ClientKey) (*Session, error) {
	return nil, errors.New("not implemented")
}

// GetByID gets the Session under the given client ID.
func (s *Manager) GetByID(clientID string) (*Session, error) {
	return nil, errors.New("not implemented")
}

// GetByToken gets the Session that has the given token.
func (s *Manager) GetByToken(token string) (*Session, error) {
	return nil, errors.New("not implemented")
}
