GO ?= /usr/local/go/bin/go

.PHONY: test build generate

test:
	$(GO) test ./...

build:
	$(GO) build ./cmd/fcktls

generate:
	$(GO) generate ./pkg/ebpf
