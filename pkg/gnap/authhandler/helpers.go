/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authhandler

import (
	"github.com/google/uuid"

	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/spi/gnap"
)

// CreateToken creates a token object matching the given token request.
func CreateToken(req *api.ExpiringTokenRequest) *gnap.AccessToken {
	return &gnap.AccessToken{
		Value:   uuid.New().String(),
		Label:   req.Label,
		Access:  req.Access,
		Expires: 0,
		Flags:   req.Flags,
	}
}
