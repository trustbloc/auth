// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/hub-auth/test/bdd

go 1.14

require (
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.6.5
	github.com/google/uuid v1.1.1
	github.com/ory/hydra-client-go v1.8.5
	github.com/pkg/errors v0.9.1
	github.com/pquerna/cachecontrol v0.0.0-20200921180117-858c6e7e6b7e // indirect
	github.com/tidwall/gjson v1.6.0
	github.com/trustbloc/edge-core v0.1.5-0.20200916124536-c32454a16108
	github.com/trustbloc/hub-auth v0.0.0-20201116135852-764f60b8417b
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
)

replace (
	github.com/trustbloc/hub-auth => ../..
)
