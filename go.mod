// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/auth

go 1.17

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/coreos/go-oidc/v3 v3.1.0
	github.com/google/uuid v1.3.0
	github.com/gorilla/sessions v1.2.1
	github.com/hyperledger/aries-framework-go v0.1.8
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20220330140627-07042d78580c
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20220330140627-07042d78580c
	github.com/ory/hydra-client-go v1.10.6
	github.com/stretchr/testify v1.7.1
	github.com/trustbloc/auth/spi/gnap v0.0.0-00010101000000-000000000000
	github.com/trustbloc/edge-core v0.1.8
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5
	golang.org/x/oauth2 v0.0.0-20211104180415-d3ed0bb246c8
)

require (
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/asaskevich/govalidator v0.0.0-20200907205600-7a23bdc65eef // indirect
	github.com/btcsuite/btcd v0.22.0-beta // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-openapi/analysis v0.20.0 // indirect
	github.com/go-openapi/errors v0.20.1 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.5 // indirect
	github.com/go-openapi/loads v0.20.2 // indirect
	github.com/go-openapi/runtime v0.19.31 // indirect
	github.com/go-openapi/spec v0.20.3 // indirect
	github.com/go-openapi/strfmt v0.20.2 // indirect
	github.com/go-openapi/swag v0.19.15 // indirect
	github.com/go-openapi/validate v0.20.2 // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.6 // indirect
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/igor-pavlenko/httpsignatures-go v0.0.23 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/kilic/bls12-381 v0.1.1-0.20210503002446-7b7597926c69 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693 // indirect
	github.com/teserakt-io/golang-ed25519 v0.0.0-20210104091850-3888c087a4c8 // indirect
	go.mongodb.org/mongo-driver v1.5.1 // indirect
	golang.org/x/net v0.0.0-20210813160813-60bc85c4be6d // indirect
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/square/go-jose.v2 v2.5.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)

replace github.com/trustbloc/auth/spi/gnap => ./spi/gnap
