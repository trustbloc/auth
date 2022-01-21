# Building and Testing

## Prerequisites
- Go 1.17
- Docker
- Docker-Compose
- Make
- bash
- [modify your `hosts` file](#hosts-file-entries) if you want to run BDD tests

## Targets

```
# run everything
make all

# linters
make checks

# unit tests
make unit-test

# BDD tests
make bdd-test
```

## hosts file entries

The following entries are required on your local `/etc/hosts` to enable BDD tests:

```
127.0.0.1 third.party.oidc.provider.example.com
```
