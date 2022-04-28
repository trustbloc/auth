/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/auth/pkg/gnap/accesspolicy"
	"github.com/trustbloc/auth/pkg/internal/common/mockinteract"
	"github.com/trustbloc/auth/pkg/internal/common/mockoidc"
	"github.com/trustbloc/auth/pkg/internal/common/mockstorage"
	"github.com/trustbloc/auth/pkg/restapi/gnap"
	"github.com/trustbloc/auth/pkg/restapi/operation"
)

func TestController_New(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		config := config(t)

		controller, err := New(config, gnapConfig(t))
		require.NoError(t, err)
		require.NotNil(t, controller)
	})

	t.Run("error if operations cannot start", func(t *testing.T) {
		conf := config(t)
		conf.TransientStoreProvider = &mockstore.MockStoreProvider{
			ErrOpenStoreHandle: errors.New("test"),
		}

		_, err := New(conf, gnapConfig(t))
		require.Error(t, err)
	})

	t.Run("error if gnap operations cannot start", func(t *testing.T) {
		conf := config(t)
		gconf := gnapConfig(t)

		expectErr := errors.New("expected error")

		gconf.StoreProvider = &mockstorage.Provider{ErrOpenStoreHandle: expectErr}

		_, err := New(conf, gconf)
		require.Error(t, err)
		require.ErrorIs(t, err, expectErr)
	})
}

func TestController_GetOperations(t *testing.T) {
	config := config(t)

	controller, err := New(config, gnapConfig(t))
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()
	require.NotEmpty(t, ops)
}

func config(t *testing.T) *operation.Config {
	t.Helper()

	path := mockoidc.StartProvider(t)

	return &operation.Config{
		OIDC: &operation.OIDCConfig{
			CallbackURL: "https://example.com/callback",
			Providers: map[string]*operation.OIDCProviderConfig{
				"test": {
					URL:          path,
					ClientID:     uuid.New().String(),
					ClientSecret: uuid.New().String(),
				},
			},
		},
		TransientStoreProvider: mem.NewProvider(),
		StoreProvider:          mem.NewProvider(),
		Cookies: &operation.CookieConfig{
			AuthKey: cookieKey(t),
			EncKey:  cookieKey(t),
		},
		StartupTimeout: 1,
	}
}

func gnapConfig(t *testing.T) *gnap.Config {
	t.Helper()

	return &gnap.Config{
		StoreProvider:      mem.NewProvider(),
		AccessPolicy:       &accesspolicy.AccessPolicy{},
		BaseURL:            "example.com",
		InteractionHandler: &mockinteract.InteractHandler{},
	}
}

func cookieKey(t *testing.T) []byte {
	t.Helper()

	key := make([]byte, aes.BlockSize)

	_, err := rand.Read(key)
	require.NoError(t, err)

	return key
}
