/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package accesspolicy

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/pkg/gnap/session"
	"github.com/trustbloc/auth/spi/gnap"
)

const (
	validConf = `{
	"access-types": [{
			"reference": "foo",
			"permission": "NeedsConsent",
			"expires-in": 360,
			"access": {
				"type": "trustbloc.xyz/auth/type/foo",
				"subject-keys": ["client-id", "preferred-name"],
				"actions": ["read", "update"],
				"datasets": ["foobase"],
				"userid-key": "client-id"
			}
		}, {
			"reference": "bar-comm",
			"permission": "NeedsConsent",
			"access": {
				"type": "trustbloc.xyz/auth/type/kms/decrypt",
				"subject-keys": ["client-id"],
				"actions": ["decrypt", "unseal"],
				"provider": ["kms"],
				"userid-key": "client-id"
			}
		}, {
			"reference": "audit-writer",
			"permission": "NeedsConsent",
			"expires-in": 600,
			"access": {
				"type": "trustbloc.xyz/auth/type/audit-write",
				"subject-keys": ["client-id"],
				"actions": ["append"],
				"datasets": ["audit-log"],
				"userid-key": "client-id"
			}
		}, {
			"reference": "example-allowed",
			"permission": "AlwaysAllowed",
			"access": {
				"type": "trustbloc.xyz/auth/type/client-update-config",
				"actions": ["read"],
				"datasets": ["client-update-config"]
			}
		}, {
			"reference": "example-forbidden",
			"permission": "",
			"access": {
				"type": "example.net/deprecated-definition",
				"powers": ["unlimited"]
			}
		}
	]
}`
)

func TestNew(t *testing.T) {
	t.Run("empty config", func(t *testing.T) {
		ap, err := New(&Config{})
		require.NoError(t, err)

		require.Len(t, ap.basePermissions, 0)
		require.Len(t, ap.refToType, 0)
		require.Len(t, ap.accessDescriptors, 0)
	})

	t.Run("invalid config", func(t *testing.T) {
		conf := &Config{
			AccessTypes: []TokenAccessConfig{
				{
					Access: gnap.TokenAccess{
						Type: "foo",
						Raw:  []byte("foo bar baz"),
					},
				},
			},
		}

		ap, err := New(conf)
		require.Error(t, err)
		require.Nil(t, ap)
	})

	t.Run("valid config", func(t *testing.T) {
		conf := &Config{}

		err := json.Unmarshal([]byte(validConf), conf)
		require.NoError(t, err)

		ap, err := New(conf)
		require.NoError(t, err)
		require.NotNil(t, ap)
	})
}

func TestAccessPolicy_DeterminePermissions(t *testing.T) {
	t.Run("needs consent", func(t *testing.T) {
		ap := makeAccessPolicy(t)

		req := []*gnap.TokenRequest{
			{
				Label: "foo",
				Access: []gnap.TokenAccess{
					{
						IsReference: true,
						Ref:         "foo",
					},
				},
			},
		}

		p, err := ap.DeterminePermissions(req, &session.Session{})
		require.NoError(t, err)

		require.Len(t, p.NeedsConsent.Tokens, 1)

		require.Equal(t, *req[0], p.NeedsConsent.Tokens[0].TokenRequest)
	})

	t.Run("allowed by default", func(t *testing.T) {
		ap := makeAccessPolicy(t)

		req := []*gnap.TokenRequest{
			{
				Access: []gnap.TokenAccess{
					{
						IsReference: true,
						Ref:         "example-allowed",
					},
				},
			},
		}

		p, err := ap.DeterminePermissions(req, &session.Session{})
		require.NoError(t, err)

		require.Len(t, p.Allowed.Tokens, 1)

		require.Equal(t, *req[0], p.Allowed.Tokens[0].TokenRequest)
	})

	t.Run("allowed by session", func(t *testing.T) {
		ap := makeAccessPolicy(t)

		customAccessBytes := []byte(`{
			"type": "custom-type",
			"subject-keys": ["client-id"],
			"actions": ["read"],
			"datasets": ["foobase"]
		}`)

		customAccess := gnap.TokenAccess{}

		err := json.Unmarshal(customAccessBytes, &customAccess)
		require.NoError(t, err)

		s := &session.Session{
			Tokens: []*api.ExpiringToken{
				{
					Expires: time.Now().Add(time.Hour),
					AccessToken: gnap.AccessToken{
						Access: []gnap.TokenAccess{
							{
								IsReference: true,
								Ref:         "foo",
							},
						},
					},
				},
			},
		}

		req := []*gnap.TokenRequest{
			{
				Access: []gnap.TokenAccess{
					customAccess,
				},
			},
		}

		p, err := ap.DeterminePermissions(req, s)
		require.NoError(t, err)

		require.Len(t, p.Allowed.Tokens, 1)

		require.Equal(t, *req[0], p.Allowed.Tokens[0].TokenRequest)
	})

	t.Run("forbidden", func(t *testing.T) {
		ap := makeAccessPolicy(t)

		req := []*gnap.TokenRequest{
			{
				Access: []gnap.TokenAccess{
					{
						IsReference: true,
						Ref:         "example-forbidden",
					},
				},
			},
		}

		p, err := ap.DeterminePermissions(req, &session.Session{})
		require.NoError(t, err)

		require.Len(t, p.Allowed.Tokens, 0)
	})

	t.Run("reference to nonexistent access type", func(t *testing.T) {
		ap := makeAccessPolicy(t)

		req := []*gnap.TokenRequest{
			{
				Access: []gnap.TokenAccess{
					{
						IsReference: true,
						Ref:         "blah blah not found",
					},
				},
			},
		}

		_, err := ap.DeterminePermissions(req, &session.Session{})
		require.Error(t, err)
		require.ErrorIs(t, err, errReferenceNotFound)
	})

	t.Run("session contains garbled data", func(t *testing.T) {
		ap := makeAccessPolicy(t)

		s := &session.Session{
			Tokens: []*api.ExpiringToken{
				{
					Expires: time.Now().Add(time.Hour),
					AccessToken: gnap.AccessToken{
						Access: []gnap.TokenAccess{
							{
								Raw: []byte("garble garble"),
							},
						},
					},
				},
			},
		}

		req := []*gnap.TokenRequest{
			{
				Access: []gnap.TokenAccess{
					{
						IsReference: true,
						Ref:         "foo",
					},
				},
			},
		}

		p, err := ap.DeterminePermissions(req, s)
		require.NoError(t, err)
		require.Len(t, p.Allowed.Tokens, 0)
		require.Len(t, p.NeedsConsent.Tokens, 1)
	})
}

func TestAccessPolicy_AllowedSubjectKeys(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ap := makeAccessPolicy(t)

		keys, err := ap.AllowedSubjectKeys([]gnap.TokenAccess{
			{
				IsReference: true,
				Ref:         "bar-comm",
			},
		})
		require.NoError(t, err)
		require.Len(t, keys, 1)
		require.Contains(t, keys, "client-id")
	})

	t.Run("error parsing", func(t *testing.T) {
		ap := makeAccessPolicy(t)

		keys, err := ap.AllowedSubjectKeys([]gnap.TokenAccess{
			{
				IsReference: false,
				Raw:         []byte("garble garble"),
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing TokenAccess data")
		require.Nil(t, keys)
	})

	t.Run("unsupported access descriptor format", func(t *testing.T) {
		ap := makeAccessPolicy(t)

		// should be an array
		keys, err := ap.AllowedSubjectKeys([]gnap.TokenAccess{
			{
				IsReference: false,
				Raw:         []byte(`{"subject-keys": 12345}`),
			},
		})
		require.ErrorIs(t, err, errUnsupportedAccessType)
		require.Nil(t, keys)

		// should be an array of strings
		keys, err = ap.AllowedSubjectKeys([]gnap.TokenAccess{
			{
				IsReference: false,
				Raw:         []byte(`{"subject-keys": [12345]}`),
			},
		})
		require.ErrorIs(t, err, errUnsupportedAccessType)
		require.Nil(t, keys)
	})
}

func TestAccessPolicy_parse(t *testing.T) {
	t.Run("error with AP config", func(t *testing.T) {
		ap := makeAccessPolicy(t)

		// empty this map, to break the AccessPolicy
		ap.accessDescriptors = map[string]tokenAccessMap{}

		_, err := ap.parse(gnap.TokenAccess{
			IsReference: true,
			Ref:         "foo", // reference exists, but access descriptor data deleted
		})
		require.ErrorIs(t, err, errInternal)
	})

	t.Run("error parsing invalid TokenAccess data", func(t *testing.T) {
		ap := makeAccessPolicy(t)

		_, err := ap.parse(gnap.TokenAccess{
			IsReference: false,
			Raw:         []byte("foo abc not json"),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing TokenAccess data")
	})
}

func Test_isTokenAccessSubset(t *testing.T) {
	testcases := []struct {
		name   string
		super  tokenAccessMap
		sub    tokenAccessMap
		result bool
	}{
		{
			name: "empty set is subset of empty set",
			super: tokenAccessMap{
				"type": "foo",
			},
			sub: tokenAccessMap{
				"type": "bar",
			},
			result: true,
		},
		{
			name: "subset field missing from superset",
			super: tokenAccessMap{
				"type": "foo",
			},
			sub: tokenAccessMap{
				"type": "bar",
				"foo":  "foo",
			},
			result: false,
		},
		{
			name: "field has unsupported type",
			super: tokenAccessMap{
				"type": "foo",
				"foo":  5,
			},
			sub: tokenAccessMap{
				"type": "bar",
				"foo":  5,
			},
			result: false,
		},
		{
			name: "superset field is not string",
			super: tokenAccessMap{
				"type": "foo",
				"foo":  []interface{}{"foo"},
			},
			sub: tokenAccessMap{
				"type": "bar",
				"foo":  "foo",
			},
			result: false,
		},
		{
			name: "superset string has different value",
			super: tokenAccessMap{
				"type": "foo",
				"foo":  "foo",
			},
			sub: tokenAccessMap{
				"type": "bar",
				"foo":  "bar",
			},
			result: false,
		},
		{
			name: "superset field is not []interface{}",
			super: tokenAccessMap{
				"type": "foo",
				"foo":  "foo",
			},
			sub: tokenAccessMap{
				"type": "bar",
				"foo":  []interface{}{"bar"},
			},
			result: false,
		},
		{
			name: "subset array contains non-strings",
			super: tokenAccessMap{
				"type": "foo",
				"foo":  []interface{}{"foo"},
			},
			sub: tokenAccessMap{
				"type": "bar",
				"foo":  []interface{}{123},
			},
			result: false,
		},
		{
			name: "superset array contains non-strings",
			super: tokenAccessMap{
				"type": "foo",
				"foo":  []interface{}{123},
			},
			sub: tokenAccessMap{
				"type": "bar",
				"foo":  []interface{}{"bar"},
			},
			result: false,
		},
		{
			name: "subset array not subset of superset's",
			super: tokenAccessMap{
				"type": "foo",
				"foo":  []interface{}{"foo", "blah"},
			},
			sub: tokenAccessMap{
				"type": "bar",
				"foo":  []interface{}{"foo", "bar"},
			},
			result: false,
		},
		{
			name: "subset array ignores order",
			super: tokenAccessMap{
				"type": "foo",
				"foo":  []interface{}{"bar", "foo"},
			},
			sub: tokenAccessMap{
				"type": "bar",
				"foo":  []interface{}{"foo", "bar"},
			},
			result: true,
		},
		{
			name: "example pass",
			super: tokenAccessMap{
				"type":      "rw-all-dbs",
				"actions":   []interface{}{"read", "write", "delete"},
				"databases": []interface{}{"secret-store", "userdata", "localdb"},
				"userkey":   "foo123",
			},
			sub: tokenAccessMap{
				"type":      "read-localdb",
				"actions":   []interface{}{"read"},
				"databases": []interface{}{"localdb"},
				"userkey":   "foo123",
			},
			result: true,
		},
		{
			name: "example fail",
			super: tokenAccessMap{
				"type":      "read-localdb",
				"actions":   []interface{}{"read"},
				"databases": []interface{}{"localdb"},
				"userkey":   "foo123",
			},
			sub: tokenAccessMap{
				"type":      "rw-all-dbs",
				"actions":   []interface{}{"read", "write", "delete"},
				"databases": []interface{}{"secret-store", "userdata", "localdb"},
				"userkey":   "foo123",
			},
			result: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			res := isTokenAccessSubset(tc.super, tc.sub)
			require.Equal(t, tc.result, res)
		})
	}
}

func makeAccessPolicy(t *testing.T) *AccessPolicy {
	t.Helper()

	conf := &Config{}

	err := json.Unmarshal([]byte(validConf), conf)
	require.NoError(t, err)

	ap, err := New(conf)
	require.NoError(t, err)

	return ap
}
