/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package accesspolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/pkg/gnap/session"
	"github.com/trustbloc/auth/spi/gnap"
)

// AccessPolicy processes access requests and decides what access can be
// granted, what requires user consent, and what is forbidden.
type AccessPolicy struct {
	refToType map[string]string
	// accessDescriptors maps each supported TokenAccess.Type to the tokenAccessMap form of the TokenAccess.
	accessDescriptors map[string]tokenAccessMap
	// basePermissions holds the base permission of given TokenAccess.Type values, if no other permission is granted.
	basePermissions map[string]permissionLevel
	// lifetime number of seconds that a given token access should be valid for.
	lifetime map[string]int
}

// New initializes an AccessPolicy.
func New(config *Config) (*AccessPolicy, error) {
	ap := &AccessPolicy{
		refToType:         map[string]string{},
		accessDescriptors: map[string]tokenAccessMap{},
		basePermissions:   map[string]permissionLevel{},
		lifetime:          map[string]int{},
	}

	for _, accessType := range config.AccessTypes {
		typeStr := accessType.Access.Type

		accessMap := tokenAccessMap{}

		err := json.Unmarshal(accessType.Access.Raw, &accessMap)
		if err != nil {
			return nil, err
		}

		ap.accessDescriptors[typeStr] = accessMap

		if accessType.Ref != "" {
			ap.refToType[accessType.Ref] = typeStr
		}

		ap.lifetime[typeStr] = accessType.Expiry

		switch accessType.Permission {
		case PermissionAlwaysAllowed:
			ap.basePermissions[typeStr] = permissionAllowed
		case PermissionNeedsConsent:
			ap.basePermissions[typeStr] = permissionNeedsConsent
		}
	}

	return ap, nil
}

type tokenAccessMap map[string]interface{}

type permissionLevel int

const (
	permissionDenied permissionLevel = iota
	permissionNeedsConsent
	permissionAllowed
)

const (
	subjectKeyFieldName = "subject-keys"
	typeFieldName       = "type"
)

var (
	errReferenceNotFound     = errors.New("reference to TokenAccess type missing from AccessPolicy configuration")
	errInternal              = errors.New("internal AccessPolicy error")
	errUnsupportedAccessType = errors.New("unsupported access descriptor format")
)

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
	perms := []*Permissions{}

	for _, req := range requested {
		perm, err := ap.tokenPermission(req, clientSession)
		if err != nil {
			return nil, err
		}

		perms = append(perms, perm)
	}

	return mergePermissions(perms), nil
}

type expirableTokenAccess struct {
	TokenAccess gnap.TokenAccess
	expiry      time.Time
}

// tokenPermission returns the permission of the given token for the given client Session.
func (ap *AccessPolicy) tokenPermission( // nolint: gocyclo,funlen
	tok *gnap.TokenRequest,
	clientSession *session.Session,
) (*Permissions, error) {
	var (
		allowedTokenAccesses []*expirableTokenAccess
		needsConsent         bool
	)

	for _, v := range tok.Access {
		perm, expAccess, err := ap.getTokenAccessPermission(v, clientSession)
		if err != nil {
			return nil, err
		}

		if perm == permissionDenied {
			return &Permissions{}, nil
		}

		if perm == permissionNeedsConsent {
			needsConsent = true
		}

		allowedTokenAccesses = append(allowedTokenAccesses, expAccess)
	}

	expiry := time.Time{}

	for _, access := range allowedTokenAccesses {
		if expiry.IsZero() || expiry.After(access.expiry) {
			expiry = access.expiry
		}
	}

	accessMetaData := &api.AccessMetadata{
		Tokens: []*api.ExpiringTokenRequest{
			{
				TokenRequest: *tok,
				Expires:      expiry,
			},
		},
	}

	subKeys, err := ap.AllowedSubjectKeys(tok.Access)
	if err != nil {
		return nil, err
	}

	for s := range subKeys {
		accessMetaData.SubjectKeys = append(accessMetaData.SubjectKeys, s)
	}

	// if permission is denied, we already returned before this
	if needsConsent {
		return &Permissions{
			NeedsConsent: accessMetaData,
		}, nil
	}

	return &Permissions{
		Allowed: accessMetaData,
	}, nil
}

func (ap *AccessPolicy) getTokenAccessPermission(access gnap.TokenAccess, clientSession *session.Session,
) (permissionLevel, *expirableTokenAccess, error) {
	var (
		latestExpiry time.Time
		granted      bool
	)

	accessMap, err := ap.parse(access)
	if err != nil {
		return permissionDenied, nil, err
	}

	for _, grantedToken := range clientSession.Tokens {
		for _, grantedAccess := range grantedToken.Access {
			grantedMap, err := ap.parse(grantedAccess)
			if err != nil {
				continue
			}

			ok := isTokenAccessSuperset(grantedMap, accessMap)
			if ok {
				granted = true

				if latestExpiry.Before(grantedToken.Expires) {
					latestExpiry = grantedToken.Expires
				}

				break
			}
		}
	}

	if granted {
		return permissionAllowed, &expirableTokenAccess{
			TokenAccess: access,
			expiry:      latestExpiry,
		}, nil
	}

	return ap.defaultTokenAccessPermission(access, accessMap)
}

func (ap *AccessPolicy) defaultTokenAccessPermission(access gnap.TokenAccess, accessMap tokenAccessMap,
) (permissionLevel, *expirableTokenAccess, error) {
	// if the given TokenAccess wasn't a subset of a granted token's access,
	// we use the AccessPolicy's default permissions
	defaultPermission := permissionDenied
	defaultLifetime := 0

	for defaultType, defaultAccess := range ap.accessDescriptors {
		ok := isTokenAccessSuperset(defaultAccess, accessMap)
		if ok {
			perm := ap.basePermissions[defaultType]
			lifetime := ap.lifetime[defaultType]

			if perm > defaultPermission {
				defaultPermission = perm
				defaultLifetime = lifetime
			} else if perm == defaultPermission && defaultLifetime < lifetime {
				defaultLifetime = lifetime
			}
		}
	}

	if defaultPermission == permissionDenied {
		return permissionDenied, nil, nil
	}

	return defaultPermission, &expirableTokenAccess{
		TokenAccess: access,
		expiry:      time.Now().Add(time.Second * time.Duration(defaultLifetime)),
	}, nil
}

// mergePermissions merges a set of Permissions into one.
// All TokenRequests are treated as unique, and subject key sets are merged.
func mergePermissions(perms []*Permissions) *Permissions {
	out := &Permissions{
		NeedsConsent: &api.AccessMetadata{},
		Allowed:      &api.AccessMetadata{},
	}

	ncMap := map[string]struct{}{}
	alMap := map[string]struct{}{}

	for _, perm := range perms {
		if perm.NeedsConsent != nil {
			out.NeedsConsent.Tokens = append(out.NeedsConsent.Tokens, perm.NeedsConsent.Tokens...)

			for _, sk := range perm.NeedsConsent.SubjectKeys {
				ncMap[sk] = struct{}{}
			}
		}

		if perm.Allowed != nil {
			out.Allowed.Tokens = append(out.Allowed.Tokens, perm.Allowed.Tokens...)

			for _, sk := range perm.Allowed.SubjectKeys {
				alMap[sk] = struct{}{}
			}
		}
	}

	for nc := range ncMap {
		out.NeedsConsent.SubjectKeys = append(out.NeedsConsent.SubjectKeys, nc)
	}

	for al := range alMap {
		out.Allowed.SubjectKeys = append(out.Allowed.SubjectKeys, al)
	}

	return out
}

// AllowedSubjectKeys returns the subject data keys allowed by the given token access descriptors.
func (ap *AccessPolicy) AllowedSubjectKeys(tokAccess []gnap.TokenAccess) (map[string]struct{}, error) {
	allowedKeys := map[string]struct{}{}

	for _, t := range tokAccess {
		keys, err := ap.subKeys(t)
		if err != nil {
			return nil, err
		}

		for _, key := range keys {
			allowedKeys[key] = struct{}{}
		}
	}

	return allowedKeys, nil
}

func (ap *AccessPolicy) subKeys(tok gnap.TokenAccess) ([]string, error) {
	tokMap, err := ap.parse(tok)
	if err != nil {
		return nil, err
	}

	subKeysInterface, ok := tokMap[subjectKeyFieldName]
	if !ok {
		return nil, nil
	}

	subKeys, ok := subKeysInterface.([]interface{})
	if !ok {
		return nil, errUnsupportedAccessType
	}

	out, extra := toStringSlice(subKeys)
	if len(extra) > 0 {
		return nil, errUnsupportedAccessType
	}

	return out, nil
}

func (ap *AccessPolicy) parse(tok gnap.TokenAccess) (tokenAccessMap, error) {
	var err error

	if tok.IsReference {
		tokType, ok := ap.refToType[tok.Ref]
		if !ok {
			return nil, errReferenceNotFound
		}

		out, ok := ap.accessDescriptors[tokType]
		if !ok {
			return nil, errInternal
		}

		return out, nil
	}

	tokMap := tokenAccessMap{}

	err = json.Unmarshal(tok.Raw, &tokMap)
	if err != nil {
		return nil, fmt.Errorf("parsing TokenAccess data: %w", err)
	}

	return tokMap, nil
}

// isTokenAccessSuperset returns true iff TokenAccess super is a superset of sub.
//
// Note: only supports maps with values that are string and/or []string.
func isTokenAccessSuperset(super, sub tokenAccessMap) bool { // nolint:gocyclo
	for k, subV := range sub {
		if k == typeFieldName {
			continue
		}

		superV, ok := super[k]
		if !ok {
			return false
		}

		switch subValue := subV.(type) {
		case string:
			superValue, ok := superV.(string)
			if !ok || superValue != subValue {
				return false
			}
		case []interface{}:
			// assume order unimportant
			superValue, ok := superV.([]interface{})
			if !ok {
				return false
			}

			subVStrings, extraSub := toStringSlice(subValue)
			superVStrings, extraSuper := toStringSlice(superValue)

			if len(extraSub) > 0 || len(extraSuper) > 0 {
				return false
			}

			if !isSubset(superVStrings, subVStrings) {
				return false
			}
		default:
			return false
		}
	}

	return true
}

func toStringSlice(a []interface{}) ([]string, []interface{}) {
	out := []string{}
	skip := []interface{}{}

	for _, v := range a {
		s, ok := v.(string)
		if ok {
			out = append(out, s)
		} else {
			skip = append(skip, v)
		}
	}

	return out, skip
}

func isSubset(super, sub []string) bool {
	superSet := map[string]struct{}{}

	for _, s := range super {
		superSet[s] = struct{}{}
	}

	for _, s := range sub {
		if _, ok := superSet[s]; !ok {
			return false
		}
	}

	return true
}
