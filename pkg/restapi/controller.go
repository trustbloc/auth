/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"fmt"

	"github.com/trustbloc/auth/pkg/restapi/common"
	"github.com/trustbloc/auth/pkg/restapi/gnap"
	"github.com/trustbloc/auth/pkg/restapi/operation"
)

// New returns new controller instance.
func New(config *operation.Config, gnapConfig *gnap.Config) (*Controller, error) {
	var allHandlers []common.Handler

	rpService, err := operation.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize auth-rest operations: %w", err)
	}

	allHandlers = append(allHandlers, rpService.GetRESTHandlers()...)

	gnapService, err := gnap.New(gnapConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize auth-rest gnap operations: %w", err)
	}

	allHandlers = append(allHandlers, gnapService.GetRESTHandlers()...)

	return &Controller{handlers: allHandlers}, nil
}

// Controller contains handlers for controller.
type Controller struct {
	handlers []common.Handler
}

// GetOperations returns all controller endpoints.
func (c *Controller) GetOperations() []common.Handler {
	return c.handlers
}
