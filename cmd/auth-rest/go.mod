// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/hub-auth/cmd/auth-rest

go 1.14

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.7.4
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.6-0.20210212172534-81ab3a5abf5b
	github.com/trustbloc/hub-auth v0.0.0-00010101000000-000000000000
	gopkg.in/yaml.v2 v2.3.0
)

replace github.com/trustbloc/hub-auth => ../..
