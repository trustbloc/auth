/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"time"

	"github.com/trustbloc/auth/spi/gnap"
)

// Verifier verifies that a client request is signed by the client's key.
//
// A Verifier is initialized on the client request, and Verifier.Verify is
// called when the key is dereferenced or extracted from the message.
type Verifier interface {
	// Verify verifies that the client request is signed by the given key.
	Verify(key *gnap.ClientKey) error
}

/*
InteractionHandler handles user login & consent for a given set of access requests.

TODO code interface:
 - Given a set of token access descriptors and subject info requests, prepare a login & consent flow, and return
   anything necessary to trigger the login & consent flow
 - When a login & consent flow is triggered, execute the flow, and cache the result under an interact_ref
 - When an interact_ref is queried, return the cached login & consent result.
 - Allow caller to delete the interact_ref
 - Delete expired interact_refs automatically.
*/
type InteractionHandler interface {
	// PrepareLoginConsentFlow takes a set of requested access tokens and subject
	// data, prepares a login & consent flow, and returns parameters for the user
	// client to initiate the login & consent flow.
	PrepareInteraction(clientInteract *gnap.RequestInteract, requestURI string, requestedTokens []*ExpiringTokenRequest,
	) (*gnap.ResponseInteract, error)

	// CompleteLoginConsentFlow takes a set of access requests that the user
	// consented to, and the ID of the flow where this was performed, creates an
	// interact_ref, saves the consent set under the interact_ref, and returns the
	// interact_ref.
	//
	// Returns: interact_ref, response hash, client's RequestInteract, error
	CompleteInteraction(flowID string, consentSet *ConsentResult) (string, string, *gnap.RequestInteract, error)
	// QueryInteraction returns the consent metadata and subject info saved under the interaction.
	QueryInteraction(interactRef string) (*ConsentResult, error)
	// DeleteInteraction deletes the interaction under interactRef if it exists.
	DeleteInteraction(interactRef string) error
}

// AccessMetadata holds a set of token access descriptors and subject data keys.
type AccessMetadata struct {
	Tokens      []*ExpiringTokenRequest
	SubjectKeys []string
}

// ExpiringTokenRequest holds a request for a token with a custom expiration
// time. If this token is granted, the token's expiration time must be the
// earliest of this value and the expiry determined by the token's lifetime.
type ExpiringTokenRequest struct {
	gnap.TokenRequest
	Expires time.Time
}

// ExpiringToken holds a gnap.AccessToken annotated with the expiry time.
type ExpiringToken struct {
	gnap.AccessToken
	Expires time.Time `json:"expiry"`
}

// ConsentResult holds access token descriptors and subject data that were granted by a user consent interaction.
type ConsentResult struct {
	Tokens      []*ExpiringTokenRequest `json:"tok,omitempty"`
	SubjectData map[string]string       `json:"sub,omitempty"`
}
