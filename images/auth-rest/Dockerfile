#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG GO_VER
ARG ALPINE_VER

FROM golang:${GO_VER}-alpine${ALPINE_VER} as golang
RUN apk add --no-cache \
	gcc \
	musl-dev \
	git \
	libtool \
	bash \
	make;
ADD . src/github.com/trustbloc/auth
WORKDIR src/github.com/trustbloc/auth
ENV EXECUTABLES go git

FROM golang as auth
LABEL org.opencontainers.image.source https://github.com/trustbloc/auth

RUN make auth-rest


FROM alpine:${ALPINE_VER} as base
COPY --from=auth /go/src/github.com/trustbloc/auth/.build/bin/auth-rest /usr/local/bin
COPY --from=auth /go/src/github.com/trustbloc/auth/.build/bin/static /usr/local/static
COPY ./.build/bin/auth-vue /usr/local/static/auth-vue
ENV AUTH_REST_STATIC_FILES=/usr/local/static

# set up nsswitch.conf for Go's "netgo" implementation
# - https://github.com/golang/go/blob/go1.9.1/src/net/conf.go#L194-L275
RUN [ ! -e /etc/nsswitch.conf ] && echo 'hosts: files dns' > /etc/nsswitch.conf

ENTRYPOINT ["auth-rest"]
