/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mockstorage

import (
	"fmt"
	"sync"

	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// Provider mock store provider.
type Provider struct {
	Stores             map[string]storage.Store
	Store              *MockStore
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

// SetStoreConfig sets the configuration on a store.
func (p *Provider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	panic("implement me")
}

// GetStoreConfig gets the current store configuration.
func (p *Provider) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	panic("implement me")
}

// GetOpenStores returns all currently open stores.
func (p *Provider) GetOpenStores() []storage.Store {
	panic("implement me")
}

// MockStore represents a mock store.
type MockStore struct {
	Store    map[string][]byte
	lock     sync.RWMutex
	ErrPut   error
	ErrGet   error
	ErrQuery error
}

// GetTags fetches all tags associated with the given key.
func (s *MockStore) GetTags(key string) ([]storage.Tag, error) {
	panic("implement me")
}

// Query returns all data that satisfies the expression. Expression format: TagName:TagValue.
func (s *MockStore) Query(expression string, options ...storage.QueryOption) (storage.Iterator, error) {
	return nil, s.ErrQuery
}

// Batch performs multiple Put and/or Delete operations in order.
func (s *MockStore) Batch(operations []storage.Operation) error {
	panic("implement me")
}

// Flush forces any queued up Put and/or Delete operations to execute.
func (s *MockStore) Flush() error {
	panic("implement me")
}

// Close closes this store object, freeing resources.
func (s *MockStore) Close() error {
	panic("implement me")
}

// PutBulk mock not implemented.
func (s *MockStore) PutBulk(keys []string, values [][]byte) error {
	panic("implement me")
}

// GetBulk mock is not implemented.
func (s *MockStore) GetBulk(k ...string) ([][]byte, error) {
	panic("implement me")
}

// Put stores the key-value pair.
func (s *MockStore) Put(k string, v []byte, _ ...storage.Tag) error {
	if k == "" {
		return fmt.Errorf("key is required")
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
		return nil, storage.ErrDataNotFound
	}

	return val, s.ErrGet
}

// Delete is currently unimplemented.
func (s *MockStore) Delete(k string) error {
	panic("implement me")
}
