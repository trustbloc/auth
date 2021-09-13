/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"fmt"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

func supportedProviders() map[string]func(url, prefix string) (storage.Provider, error) {
	return map[string]func(url, prefix string) (storage.Provider, error){
		databaseTypeMemOption: func(_, _ string) (storage.Provider, error) { // nolint:unparam // memstore no error
			return mem.NewProvider(), nil
		},
		databaseTypeCouchDBOption: func(url, prefix string) (storage.Provider, error) {
			return couchdb.NewProvider(url, couchdb.WithDBPrefix(prefix))
		},
		databaseTypeMySQLOption: func(url, prefix string) (storage.Provider, error) {
			return mysql.NewProvider(url, mysql.WithDBPrefix(prefix))
		},
		databaseTypeMongoDBOption: func(url, prefix string) (storage.Provider, error) {
			return mongodb.NewProvider(url, mongodb.WithDBPrefix(prefix))
		},
	}
}

func createProvider(parameters *authRestParameters) (storage.Provider, error) {
	provider, supported := supportedProviders()[parameters.databaseType]
	if !supported {
		return nil, fmt.Errorf(invalidDatabaseTypeErrMsg, parameters.databaseType)
	}

	var store storage.Provider

	err := backoff.RetryNotify(
		func() error {
			var openErr error

			store, openErr = provider(parameters.databaseURL, parameters.databasePrefix)

			return openErr
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), parameters.startupTimeout),
		func(retryErr error, t time.Duration) {
			logger.Warnf(
				"failed to connect to storage, will sleep for %s before trying again : %s",
				t, retryErr)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to storage at %s : %w", parameters.databaseURL, err)
	}

	return store, nil
}
