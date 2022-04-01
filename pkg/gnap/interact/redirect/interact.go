/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redirect

import (
	"errors"
)

// InteractHandler handles GNAP redirect-based user login and consent.
type InteractHandler struct{}

// New creates a GNAP redirect-based user login&consent interaction handler.
func New() (*InteractHandler, error) {
	return nil, errors.New("not implemented")
}

// PrepareInteraction initializes a redirect-based login&consent interaction,
// returning the redirect parameters to be sent to the client.
func (l InteractHandler) PrepareInteraction(accessRequest interface{}) (interface{}, error) {
	// TODO implement me
	panic("implement me")
}

// CompleteInteraction saves an interaction with the given consent data for
// the given login&consent interaction, returning the interact_ref.
func (l InteractHandler) CompleteInteraction(flowID string, consentSet interface{}) (string, error) {
	// TODO implement me
	panic("implement me")
}

// QueryInteraction fetches the interaction under the given interact_ref.
func (l InteractHandler) QueryInteraction(interactRef string) (interface{}, error) {
	// TODO implement me
	panic("implement me")
}

// DeleteInteraction deletes the interaction under the given interact_ref.
func (l InteractHandler) DeleteInteraction(interactRef string) error {
	// TODO implement me
	panic("implement me")
}
