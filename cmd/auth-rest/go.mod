// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/hub-auth/cmd/auth-rest

go 1.14

require (
	github.com/gorilla/mux v1.7.4
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.5.1
	github.com/trustbloc/edge-core v0.1.4-0.20200709143857-e104bb29f6c6
	github.com/trustbloc/hub-auth v0.0.0-00010101000000-000000000000
)

replace github.com/trustbloc/hub-auth => ../..
