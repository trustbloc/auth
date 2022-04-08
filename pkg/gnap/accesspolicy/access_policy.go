/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package accesspolicy

import (
	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/pkg/gnap/session"
	"github.com/trustbloc/auth/spi/gnap"
)

// AccessPolicy processes access requests and decides what access can be
// granted, what requires user consent, and what is forbidden.
type AccessPolicy struct{}

// TODO: make access policy configurable

// Permissions holds the result of an AccessPolicy decision.
type Permissions struct {
	Allowed      *api.AccessMetadata
	NeedsConsent *api.AccessMetadata
}

// DeterminePermissions processes a list of token requests for a given client
// session, and returns a Permissions listing the permissions allowed, and those
// that need user consent.
func (ap *AccessPolicy) DeterminePermissions(requested []*gnap.TokenRequest, clientSession *session.Session,
) (*Permissions, error) {
	// FIXME: for now, forbid nothing, pass everything through to login&consent
	return &Permissions{
		NeedsConsent: &api.AccessMetadata{Tokens: requested},
	}, nil
}

// AllowedSubjectKeys returns the subject data keys allowed by the given token access descriptors.
func (ap *AccessPolicy) AllowedSubjectKeys(tokAccess []gnap.TokenAccess) map[string]struct{} {
	// FIXME: currently hardcoded.
	allowedKeys := map[string]struct{}{}

	for _, t := range tokAccess {
		var access, key string

		if t.IsReference {
			access = t.Ref
		} else {
			access = t.Type
		}

		switch access {
		case "client-id":
			key = "client-id"
		default:
			continue
		}

		allowedKeys[key] = struct{}{}
	}

	return allowedKeys
}
