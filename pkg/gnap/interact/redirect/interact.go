/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redirect

import (
	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/spi/gnap"
)

// InteractHandler handles GNAP redirect-based user login and consent.
type InteractHandler struct {
	interactBasePath string
}

// New creates a GNAP redirect-based user login&consent interaction handler.
func New(interactBasePath string) (*InteractHandler, error) {
	return &InteractHandler{
		interactBasePath: interactBasePath,
	}, nil
}

// PrepareInteraction initializes a redirect-based login&consent interaction,
// returning the redirect parameters to be sent to the client.
func (l InteractHandler) PrepareInteraction(clientInteract *gnap.RequestInteract) (*gnap.ResponseInteract, error) {
	// TODO integrate session
	return &gnap.ResponseInteract{
		Redirect: l.interactBasePath,
	}, nil
}

// CompleteInteraction saves an interaction with the given consent data for
// the given login&consent interaction, returning the interact_ref.
func (l InteractHandler) CompleteInteraction(flowID string, consentSet *api.ConsentResult) (string, error) {
	// TODO implement me
	panic("implement me")
}

// QueryInteraction fetches the interaction under the given interact_ref.
func (l InteractHandler) QueryInteraction(interactRef string) (*api.ConsentResult, error) {
	// TODO implement query interaction
	return &api.ConsentResult{}, nil
}

// DeleteInteraction deletes the interaction under the given interact_ref.
func (l InteractHandler) DeleteInteraction(interactRef string) error {
	// TODO implement me
	panic("implement me")
}
