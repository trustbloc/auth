/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package user

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// Profile is the user's bootstrap profile.
type Profile struct {
	ID     string
	AAGUID string // TODO: create user device store https://github.com/trustbloc/hub-auth/issues/58
	Data   map[string]string
}

// ProfileStore is the user Profile CRUD API.
type ProfileStore struct {
	s storage.Store
}

// NewStore returns a new ProfileStore.
func NewStore(s storage.Store) *ProfileStore {
	return &ProfileStore{s: s}
}

// Save saves the user Profile.
func (ps *ProfileStore) Save(p *Profile) error {
	bits, err := json.Marshal(p)

	if err != nil {
		return fmt.Errorf("failed to marshal user profile : %w", err)
	}

	err = ps.s.Put(p.ID, bits)
	if err != nil {
		return fmt.Errorf("failed to save user profile : %w", err)
	}

	return nil
}

// Get fetches the user Profile.
func (ps *ProfileStore) Get(id string) (*Profile, error) {
	bits, err := ps.s.Get(id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user profile : %w", err)
	}

	p := &Profile{}

	return p, json.Unmarshal(bits, p)
}
