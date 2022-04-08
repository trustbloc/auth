/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mockinteract

import (
	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/spi/gnap"
)

// InteractHandler mock.
type InteractHandler struct {
	PrepareVal  *gnap.ResponseInteract
	PrepareErr  error
	CompleteVal string
	CompleteErr error
	QueryVal    *api.ConsentResult
	QueryErr    error
	DeleteErr   error
}

// PrepareInteraction mock.
func (l *InteractHandler) PrepareInteraction(clientInteract *gnap.RequestInteract) (*gnap.ResponseInteract, error) {
	return l.PrepareVal, l.PrepareErr
}

// CompleteInteraction mock.
func (l *InteractHandler) CompleteInteraction(flowID string, consentSet *api.ConsentResult) (string, error) {
	return l.CompleteVal, l.CompleteErr
}

// QueryInteraction mock.
func (l *InteractHandler) QueryInteraction(interactRef string) (*api.ConsentResult, error) {
	return l.QueryVal, l.QueryErr
}

// DeleteInteraction mock.
func (l *InteractHandler) DeleteInteraction(interactRef string) error {
	return l.DeleteErr
}
