/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package redirect

import (
	"errors"
	"strings"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/auth/pkg/gnap/api"
	"github.com/trustbloc/auth/pkg/internal/common/mockstorage"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		h, err := New(config())
		require.NoError(t, err)
		require.NotNil(t, h)
	})

	t.Run("error", func(t *testing.T) {
		expectErr := errors.New("expected error")

		h, err := New(&Config{
			StoreProvider: &mockstorage.Provider{ErrOpenStoreHandle: expectErr},
		})
		require.ErrorIs(t, err, expectErr)
		require.Nil(t, h)
	})
}

func TestInteractHandler_PrepareInteraction(t *testing.T) {
	t.Run("fail to save txn data", func(t *testing.T) {
		h, err := New(config())
		require.NoError(t, err)

		expectErr := errors.New("expected error")

		h.txnStore = &mockstorage.MockStore{
			Store:  map[string][]byte{},
			ErrPut: expectErr,
		}

		res, err := h.PrepareInteraction(nil, "foo", nil)
		require.ErrorIs(t, err, expectErr)
		require.Nil(t, res)
	})

	t.Run("success", func(t *testing.T) {
		h, err := New(config())
		require.NoError(t, err)

		res, err := h.PrepareInteraction(nil, "foo", nil)
		require.NoError(t, err)

		require.True(t, strings.HasPrefix(res.Redirect, h.interactBasePath))
		require.NotEmpty(t, res.Finish)
	})
}

func TestInteractHandler_CompleteInteraction(t *testing.T) {
	t.Run("fail to load txn data", func(t *testing.T) {
		h, err := New(config())
		require.NoError(t, err)

		expectErr := errors.New("expected error")

		h.txnStore = &mockstorage.MockStore{
			Store: map[string][]byte{
				txnIDPrefix: nil,
			},
			ErrGet: expectErr,
		}

		_, _, _, err = h.CompleteInteraction("", nil)
		require.ErrorIs(t, err, expectErr)
	})

	t.Run("fail to parse txn data", func(t *testing.T) {
		h, err := New(config())
		require.NoError(t, err)

		h.txnStore = &mockstorage.MockStore{
			Store: map[string][]byte{
				txnIDPrefix: nil,
			},
		}

		_, _, _, err = h.CompleteInteraction("", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing txn data")
	})

	t.Run("fail to save txn data", func(t *testing.T) {
		h, err := New(config())
		require.NoError(t, err)

		expectErr := errors.New("expected error")

		h.txnStore = &mockstorage.MockStore{
			Store: map[string][]byte{
				txnIDPrefix: []byte(`{"interact":{"finish":{}},"tok":[],"sub":{}}`),
			},
			ErrPut: expectErr,
		}

		_, _, _, err = h.CompleteInteraction("", &api.ConsentResult{})
		require.ErrorIs(t, err, expectErr)
	})

	t.Run("fail to delete old txn data", func(t *testing.T) {
		h, err := New(config())
		require.NoError(t, err)

		expectErr := errors.New("expected error")

		h.txnStore = &mockstorage.MockStore{
			Store: map[string][]byte{
				txnIDPrefix: []byte(`{"interact":{"finish":{}},"tok":[],"sub":{}}`),
			},
			ErrDelete: expectErr,
		}

		_, _, _, err = h.CompleteInteraction("", &api.ConsentResult{})
		require.ErrorIs(t, err, expectErr)
	})

	t.Run("success", func(t *testing.T) {
		h, err := New(config())
		require.NoError(t, err)

		h.txnStore = &mockstorage.MockStore{
			Store: map[string][]byte{
				txnIDPrefix: []byte(`{"interact":{"finish":{}},"tok":[],"sub":{}}`),
			},
		}

		_, _, _, err = h.CompleteInteraction("", &api.ConsentResult{})
		require.NoError(t, err)
	})
}

func TestInteractHandler_QueryInteraction(t *testing.T) {
	t.Run("fail to load txn data", func(t *testing.T) {
		h, err := New(config())
		require.NoError(t, err)

		expectErr := errors.New("expected error")

		h.txnStore = &mockstorage.MockStore{
			Store: map[string][]byte{
				interactRefPrefix: nil,
			},
			ErrGet: expectErr,
		}

		_, err = h.QueryInteraction("")
		require.ErrorIs(t, err, expectErr)
	})

	t.Run("fail to parse txn data", func(t *testing.T) {
		h, err := New(config())
		require.NoError(t, err)

		h.txnStore = &mockstorage.MockStore{
			Store: map[string][]byte{
				interactRefPrefix: nil,
			},
		}

		_, err = h.QueryInteraction("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing interaction data")
	})

	t.Run("success", func(t *testing.T) {
		h, err := New(config())
		require.NoError(t, err)

		h.txnStore = &mockstorage.MockStore{
			Store: map[string][]byte{
				interactRefPrefix: []byte(`{"tok":[],"sub":{}}`),
			},
		}

		res, err := h.QueryInteraction("")
		require.NoError(t, err)
		require.NotNil(t, res)
	})
}

func TestInteractHandler_DeleteInteraction(t *testing.T) {
	t.Run("fail to delete interaction", func(t *testing.T) {
		h, err := New(config())
		require.NoError(t, err)

		expectErr := errors.New("expected error")

		h.txnStore = &mockstorage.MockStore{
			Store: map[string][]byte{
				interactRefPrefix: []byte(`{"interact":{"finish":{}},"tok":[],"sub":{}}`),
			},
			ErrDelete: expectErr,
		}

		err = h.DeleteInteraction("")
		require.ErrorIs(t, err, expectErr)
	})

	t.Run("success", func(t *testing.T) {
		h, err := New(config())
		require.NoError(t, err)

		h.txnStore = &mockstorage.MockStore{
			Store: map[string][]byte{
				interactRefPrefix: []byte(`{"interact":{"finish":{}},"tok":[],"sub":{}}`),
			},
		}

		err = h.DeleteInteraction("")
		require.NoError(t, err)
	})
}

func config() *Config {
	return &Config{
		InteractBasePath: "https://example.com/interact-base-path",
		StoreProvider:    mem.NewProvider(),
	}
}
