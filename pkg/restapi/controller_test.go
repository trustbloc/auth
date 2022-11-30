/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/auth/pkg/gnap/accesspolicy"
	"github.com/trustbloc/auth/pkg/internal/common/mockinteract"
	"github.com/trustbloc/auth/pkg/internal/common/mockoidc"
	"github.com/trustbloc/auth/pkg/internal/common/mockstorage"
	oidcmodel "github.com/trustbloc/auth/pkg/restapi/common/oidc"
	"github.com/trustbloc/auth/pkg/restapi/operation"
)

func TestController_New(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller, err := New(gnapConfig(t))
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("error if gnap operations cannot start", func(t *testing.T) {
		gconf := gnapConfig(t)

		expectErr := errors.New("expected error")

		gconf.StoreProvider = &mockstorage.Provider{ErrOpenStoreHandle: expectErr}

		_, err := New(gconf)
		require.Error(t, err)
		require.ErrorIs(t, err, expectErr)
	})
}

func TestController_GetOperations(t *testing.T) {
	controller, err := New(gnapConfig(t))
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()
	require.NotEmpty(t, ops)
}

func gnapConfig(t *testing.T) *operation.Config {
	t.Helper()

	path := mockoidc.StartProvider(t)

	return &operation.Config{
		StoreProvider:      mem.NewProvider(),
		AccessPolicyConfig: &accesspolicy.Config{},
		BaseURL:            "example.com",
		InteractionHandler: &mockinteract.InteractHandler{},
		OIDC: &oidcmodel.Config{
			CallbackURL: "https://example.com/callback",
			Providers: map[string]*oidcmodel.ProviderConfig{
				"test": {
					URL:          path,
					ClientID:     uuid.New().String(),
					ClientSecret: uuid.New().String(),
				},
			},
		},
		StartupTimeout:         1,
		TransientStoreProvider: mem.NewProvider(),
	}
}
