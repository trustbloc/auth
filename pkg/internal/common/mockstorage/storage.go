/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mockstorage

import (
	"fmt"
	"sync"

	"github.com/trustbloc/edge-core/pkg/storage"
)

// Provider mock store provider.
type Provider struct {
	Stores             map[string]storage.Store
	Store              *MockStore
	ErrCreateStore     error
	ErrOpenStoreHandle error
	FailNameSpace      string
}

// NewMockStoreProvider new store provider instance.
func NewMockStoreProvider() *Provider {
	return &Provider{
		Stores: make(map[string]storage.Store),
		Store: &MockStore{
			Store: make(map[string][]byte),
		},
	}
}

// CreateStore creates a new store with the given name.
func (p *Provider) CreateStore(name string) error {
	return p.ErrCreateStore
}

// OpenStore opens and returns a store for given name space.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	if name == p.FailNameSpace {
		return nil, fmt.Errorf("failed to open store for name space %s", name)
	}

	if s, ok := p.Stores[name]; ok {
		return s, nil
	}

	return p.Store, p.ErrOpenStoreHandle
}

// Close closes all stores created under this store provider.
func (p *Provider) Close() error {
	return nil
}

// CloseStore closes store for given name space.
func (p *Provider) CloseStore(name string) error {
	return nil
}

// MockStore represents a mock store.
type MockStore struct {
	Store                   map[string][]byte
	lock                    sync.RWMutex
	ErrPut                  error
	ErrGet                  error
	ErrCreateIndex          error
	ErrQuery                error
	ResultsIteratorToReturn storage.ResultsIterator
}

// Put stores the key-value pair.
func (s *MockStore) Put(k string, v []byte) error {
	if k == "" {
		return storage.ErrKeyRequired
	}

	s.lock.Lock()
	s.Store[k] = v
	s.lock.Unlock()

	return s.ErrPut
}

// Get fetches the value associated with the given key.
func (s *MockStore) Get(k string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	val, ok := s.Store[k]
	if !ok {
		return nil, storage.ErrValueNotFound
	}

	return val, s.ErrGet
}

// CreateIndex returns a mocked error.
func (s *MockStore) CreateIndex(createIndexRequest storage.CreateIndexRequest) error {
	return s.ErrCreateIndex
}

// Query returns a mocked error.
func (s *MockStore) Query(query string) (storage.ResultsIterator, error) {
	return s.ResultsIteratorToReturn, s.ErrQuery
}

// Delete is currently unimplemented.
func (s *MockStore) Delete(k string) error {
	panic("implement me")
}
