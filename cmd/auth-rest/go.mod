// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/hub-auth/cmd/auth-rest

go 1.16

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/go-kivik/couchdb/v3 v3.2.8 // indirect
	github.com/go-sql-driver/mysql v1.6.0 // indirect
	github.com/google/uuid v1.2.0
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210816155437-90525d054756
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210816155437-90525d054756
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210807121559-b41545a4f1e8
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210816113201-26c0665ef2b9
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210816120552-ed93662ac716
	github.com/trustbloc/hub-auth v0.0.0-00010101000000-000000000000
	golang.org/x/net v0.0.0-20210813160813-60bc85c4be6d // indirect
	gopkg.in/yaml.v2 v2.3.0
)

replace github.com/trustbloc/hub-auth => ../..
