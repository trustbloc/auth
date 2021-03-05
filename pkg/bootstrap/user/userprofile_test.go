/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package user

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
)

func TestNewStore(t *testing.T) {
	p := NewStore(&mockstore.MockStore{})
	require.NotNil(t, p)
}

func TestSave(t *testing.T) {
	t.Run("saves profile", func(t *testing.T) {
		expected := &Profile{
			ID:     uuid.New().String(),
			AAGUID: uuid.New().String(),
			Data: map[string]string{
				"my vault": uuid.New().String(),
				"keystore": uuid.New().String(),
			},
		}

		store := &mockstore.MockStore{
			Store: make(map[string]mockstore.DBEntry),
		}

		err := NewStore(store).Save(expected)
		require.NoError(t, err)
		result := &Profile{}
		err = json.Unmarshal(store.Store[expected.ID].Value, result)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("wraps store error", func(t *testing.T) {
		expected := errors.New("test")
		store := &mockstore.MockStore{
			Store:  make(map[string]mockstore.DBEntry),
			ErrPut: expected,
		}
		err := NewStore(store).Save(&Profile{ID: "test"})
		require.True(t, errors.Is(err, expected))
	})
}

func TestGet(t *testing.T) {
	t.Run("fetches profile", func(t *testing.T) {
		expected := &Profile{
			ID:     uuid.New().String(),
			AAGUID: uuid.New().String(),
			Data: map[string]string{
				"my vault": uuid.New().String(),
				"keystore": uuid.New().String(),
			},
		}
		store := &mockstore.MockStore{
			Store: map[string]mockstore.DBEntry{
				expected.ID: {Value: toBytes(t, expected)},
			},
		}
		result, err := NewStore(store).Get(expected.ID)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})

	t.Run("wraps store error", func(t *testing.T) {
		expected := errors.New("test")
		store := &mockstore.MockStore{
			Store: map[string]mockstore.DBEntry{
				"test": {},
			},
			ErrGet: expected,
		}
		_, err := NewStore(store).Get("test")
		require.True(t, errors.Is(err, expected))
	})
}

func toBytes(t *testing.T, v interface{}) []byte {
	t.Helper()

	bits, err := json.Marshal(v)
	require.NoError(t, err)

	return bits
}
