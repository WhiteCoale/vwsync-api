.PHONY: test e2e build linux

# Set from git when available, e.g. v1.2.3 or 3f2a1bc-dirty. "make linux VERSION=v1.2.3" overrides it.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

test:
	go vet ./...
	go test -race ./...

# Needs a throwaway Vaultwarden, see the comment at the top of e2e/e2e_test.go.
e2e:
	VW_E2E_URL=$${VW_E2E_URL:-http://127.0.0.1:18082} go test -tags e2e -count=1 -v ./e2e

build:
	go build -ldflags="-X main.version=$(VERSION)" -o vwsync-api ./cmd/vwsync-api

# Static Linux binary for the server, built from any OS.
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/vwsync-api ./cmd/vwsync-api
