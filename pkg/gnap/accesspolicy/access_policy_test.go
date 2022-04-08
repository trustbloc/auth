/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package accesspolicy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/auth/spi/gnap"
)

func TestAccessPolicy_DeterminePermissions(t *testing.T) {
	ap := &AccessPolicy{}

	req := []*gnap.TokenRequest{
		{
			Label: "foo",
		},
	}

	p, err := ap.DeterminePermissions(req, nil)
	require.NoError(t, err)

	require.Equal(t, req, p.NeedsConsent.Tokens)
}

func TestAccessPolicy_AllowedSubjectKeys(t *testing.T) {
	ap := &AccessPolicy{}

	keys := ap.AllowedSubjectKeys([]gnap.TokenAccess{
		{
			IsReference: true,
			Ref:         "foo",
		},
		{
			IsReference: false,
			Type:        "client-id",
		},
	})

	require.Len(t, keys, 1)
	require.Contains(t, keys, "client-id")
}
