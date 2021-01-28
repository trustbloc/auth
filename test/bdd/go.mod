// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/hub-auth/test/bdd

go 1.14

require (
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.6.5
	github.com/google/uuid v1.1.2
	github.com/ory/hydra-client-go v1.8.5
	github.com/pkg/errors v0.9.1
	github.com/pquerna/cachecontrol v0.0.0-20200921180117-858c6e7e6b7e // indirect
	github.com/tidwall/gjson v1.6.7
	github.com/trustbloc/edge-core v0.1.6-0.20210127161542-9e174750f523
	github.com/trustbloc/hub-auth v0.0.0-20201116135852-764f60b8417b
	golang.org/x/oauth2 v0.0.0-20200902213428-5d25da1a8d43
	gotest.tools/v3 v3.0.3 // indirect
)

replace github.com/trustbloc/hub-auth => ../..
