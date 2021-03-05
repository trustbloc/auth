// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/hub-auth/cmd/auth-rest

go 1.14

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/google/uuid v1.2.0
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210303194824-a55a12f8d063
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210303194824-a55a12f8d063
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210305161732-29081cf55c77
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210305165454-c65334e35380
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.6-0.20210305000733-14a89fe44ae8
	github.com/trustbloc/hub-auth v0.0.0-00010101000000-000000000000
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110 // indirect
	gopkg.in/yaml.v2 v2.3.0
)

replace github.com/trustbloc/hub-auth => ../..
