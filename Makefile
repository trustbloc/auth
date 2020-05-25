# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

AUTH_REST_PATH=cmd/auth-rest

# Namespace for the agent images
DOCKER_OUTPUT_NS   ?= docker.pkg.github.com
AUTH_REST_IMAGE_NAME   ?= trustbloc/hub-auth/auth-rest

# Tool commands (overridable)
ALPINE_VER ?= 3.11
GO_VER ?= 1.14

.PHONY: all
all: checks unit-test bdd-test

.PHONY: checks
checks: license lint

.PHONY: lint
lint:
	@scripts/check_lint.sh

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: unit-test
unit-test:
	@scripts/check_unit.sh

.PHONY: auth-rest
auth-rest:
	@echo "Building auth-rest"
	@mkdir -p ./.build/bin
	@cd ${AUTH_REST_PATH} && go build -o ../../.build/bin/auth-rest main.go

.PHONY: auth-rest-docker
auth-rest-docker:
	@echo "Building auth rest docker image"
	@docker build -f ./images/auth-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(AUTH_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: bdd-test
bdd-test: clean auth-rest-docker generate-test-keys
	@scripts/check_integration.sh


.PHONY: generate-test-keys
generate-test-keys: clean
	@mkdir -p -p test/bdd/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/hub-auth \
		--entrypoint "/opt/workspace/hub-auth/scripts/generate_test_keys.sh" \
		frapsoft/openssl

.PHONY: clean
clean: clean-build

.PHONY: clean-build
clean-build:
	@rm -Rf ./.build
	@rm -Rf ./test/bdd/fixtures/keys/tls
	@rm -Rf ./test/bdd/docker-compose.log
