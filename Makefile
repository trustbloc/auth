# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

AUTH_REST_PATH=cmd/auth-rest

# Namespace for the agent images
DOCKER_OUTPUT_NS   ?= ghcr.io
AUTH_REST_IMAGE_NAME   ?= trustbloc/hub-auth

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

.PHONY: auth-vue
auth-vue:
	@echo "building auth vue frontend"
	@mkdir -p ./.build/bin/auth-vue
	@npm --prefix cmd/auth-vue install
	@npm --prefix cmd/auth-vue run build
	@cp -rp cmd/auth-vue/dist/* ./.build/bin/auth-vue

.PHONY: hub-auth-docker
hub-auth-docker: auth-vue
	@echo "Building auth rest docker image"
	@docker build -f ./images/auth-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(AUTH_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: mock-login-consent-docker
mock-login-consent-docker:
	@echo "Building mock login consent server for BDD tests..."
	@cd test/bdd/mock/loginconsent && docker build -f image/Dockerfile --build-arg GO_VER=$(GO_VER) --build-arg ALPINE_VER=$(ALPINE_VER) -t hubauth/mockloginconsent:latest .

.PHONY: bdd-test
bdd-test: clean hub-auth-docker generate-test-keys mock-login-consent-docker
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
