/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
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
	PrepareInteraction(accessRequest interface{}) (interface{}, error)
	// CompleteLoginConsentFlow takes a set of access requests that the user
	// consented to, and the ID of the flow where this was performed, creates an
	// interact_ref, saves the consent set under the interact_ref, and returns the
	// interact_ref.
	CompleteInteraction(flowID string, consentSet interface{}) (string, error)
	// QueryInteraction returns the consent metadata and subject info saved under the interaction.
	QueryInteraction(interactRef string) (interface{}, error)
	// DeleteInteraction deletes the interaction under interactRef if it exists.
	DeleteInteraction(interactRef string) error
}
