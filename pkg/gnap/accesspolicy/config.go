/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package accesspolicy

import (
	"github.com/trustbloc/auth/spi/gnap"
)

// Config holds the configuration details for the access policy.
type Config struct {
	AccessTypes []TokenAccessConfig `json:"access-types"`
}

const (
	// PermissionAlwaysAllowed value for TokenAccessConfig.Permission
	// indicating that said gnap.TokenAccess is always allowed.
	PermissionAlwaysAllowed = "AlwaysAllowed"
	// PermissionNeedsConsent value for TokenAccessConfig.Permission
	// indicating that said gnap.TokenAccess requires user consent.
	PermissionNeedsConsent = "NeedsConsent"
)

// TokenAccessConfig holds the parameters for a gnap.TokenAccess definition in an AccessPolicy Config.
type TokenAccessConfig struct {
	Access     gnap.TokenAccess `json:"access"`
	Ref        string           `json:"reference"`
	Permission string           `json:"permission"`
	Expiry     int              `json:"expires-in"`
}
