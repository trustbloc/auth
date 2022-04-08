/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gnap

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthRequest_MarshalUnmarshal(t *testing.T) {
	testcases := []struct {
		name string
		src  string
	}{
		{
			name: "empty",
			src:  `{}`,
		},
		{
			name: "single access token",
			src: `
{
	"access_token": {
		"access": ["foo", "bar"]
	}
}`,
		},
		{
			name: "access token with both embedded and referenced access descriptors",
			src: `
{
	"access_token": {
		"access": [
			{
				"type":"foo",
				"foo":"bar"
			},
			"bar"
		]
	}
}`,
		},
		{
			name: "multiple access tokens and client reference",
			src: `
{
	"access_token": [
		{
			"access": ["foo"],
			"label": "foo",
			"flags": ["foo"]
		},
		{
			"access": ["bar"],
			"label": "bar",
			"flags": ["bar"]
		}
	],
	"client": "foo-reference"
}`,
		},
		{
			name: "single access token with client and interact",
			src: `
{
	"access_token": {
		"access": ["foo", "bar"],
		"flags": ["foo"]
	},
	"client": {
		"key": {
			"proof": "foo",
			"jwk": {
				"kty": "EC",
				"crv": "P-256",
				"x": "IAY6G0xR4kcVkc_KrIyPb1a50qMCMjHPjVfUunrVGvs",
				"y": "qzOw6AnovPqnYn2l6MdEBYfVMPNEQTpMxrlcKRDenCk"
			}
		}
	},
	"interact": {
		"start": ["foo"],
		"finish": {
			"method": "foo",
			"uri": "bar",
			"nonce": "baz"
		}
	}
}`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			src := []byte(tc.src)

			req := &AuthRequest{}

			err := json.Unmarshal(src, req)
			require.NoError(t, err)

			out, err := json.Marshal(req)
			require.NoError(t, err)

			expected := map[string]interface{}{}
			actual := map[string]interface{}{}

			require.NoError(t, json.Unmarshal(src, &expected))
			require.NoError(t, json.Unmarshal(out, &actual))

			require.Equal(t, expected, actual)
		})
	}
}

func Test_ParseErrors(t *testing.T) {
	t.Run("fail to parse request", func(t *testing.T) {
		src := []byte(`"foo"`)

		req := &AuthRequest{}

		err := json.Unmarshal(src, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing request")
	})

	t.Run("access_token field can't be string", func(t *testing.T) {
		src := []byte(`{"access_token":"foo"}`)

		req := &AuthRequest{}

		err := json.Unmarshal(src, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected to be either an object or array")
	})

	t.Run("failed to parse access_token object", func(t *testing.T) {
		src := []byte(`{"access_token":{"label": {}}}`)

		req := &AuthRequest{}

		err := json.Unmarshal(src, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing as object")
	})

	t.Run("failed to parse access_token array", func(t *testing.T) {
		src := []byte(`{"access_token":["foo", "bar"]}`)

		req := &AuthRequest{}

		err := json.Unmarshal(src, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing as array")
	})

	t.Run("client type must be string or object", func(t *testing.T) {
		src := []byte(`{"client":123}`)

		req := &AuthRequest{}

		err := json.Unmarshal(src, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "request.client expected either string or object")

		src = []byte(`{"client":["foo"]}`)

		err = json.Unmarshal(src, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "request.client expected either string or object")
	})

	t.Run("client object has incorrect key type", func(t *testing.T) {
		src := []byte(`{"client":{"key":"foo"}}`)

		req := &AuthRequest{}

		err := json.Unmarshal(src, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing request.client as object")
	})

	t.Run("token access descriptor must be string or object", func(t *testing.T) {
		src := []byte(`{"access_token":{"access":[123]}}`)

		req := &AuthRequest{}

		err := json.Unmarshal(src, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "token access descriptor expected either string or object")

		src = []byte(`{"access_token":{"access":[["foo"]]}}`)

		err = json.Unmarshal(src, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "token access descriptor expected either string or object")
	})

	t.Run("fail to parse token access descriptor object", func(t *testing.T) {
		src := []byte(`{"access_token":{"access":[{"type":{}}]}}`)

		req := &AuthRequest{}

		err := json.Unmarshal(src, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing token access descriptor as object")
	})
}
