.PHONY: build test test-short test-race cover fuzz clean run-encrypt run-decrypt help fmt lint

LDFLAGS := -X main.Build=$(shell git rev-parse --short HEAD 2>/dev/null || echo dev)

help:
	@echo "Bitseal - File Encryption CLI Tool"
	@echo ""
	@echo "Available targets:"
	@echo "  build         - Build the bitseal binary (embeds the git revision)"
	@echo "  test          - Run all tests"
	@echo "  test-short    - Run tests, skipping large-file cases"
	@echo "  test-race     - Run all tests with the race detector"
	@echo "  cover         - Run tests and print per-function coverage"
	@echo "  fuzz          - Fuzz each target for FUZZTIME (default 20s)"
	@echo "  clean         - Remove build artifacts"
	@echo "  run-encrypt   - Build and run encrypt demo"
	@echo "  run-decrypt   - Build and run decrypt demo"
	@echo "  fmt           - Format code"
	@echo "  lint          - Run go vet"

build:
	go build -ldflags "$(LDFLAGS)" -o bitseal

test:
	go test -v ./...

test-short:
	go test -short ./...

test-race:
	go test -race ./...

cover:
	go test -coverprofile=cover.out ./...
	go tool cover -func=cover.out
	@rm -f cover.out

FUZZTIME ?= 20s
FUZZ_TARGETS := FuzzDecryptV2 FuzzDecryptV1 FuzzParseHeaderV2 FuzzInspect FuzzRoundTripV2

fuzz:
	@for t in $(FUZZ_TARGETS); do \
		echo "== $$t"; \
		go test -run='^$$' -fuzz="^$$t$$" -fuzztime=$(FUZZTIME) . || exit 1; \
	done

clean:
	go clean
	rm -f bitseal bitseal.exe cover.out
	rm -rf dist

run-encrypt: build
	./bitseal encrypt -file README.md

run-decrypt: build
	./bitseal decrypt -file README.md.enc

fmt:
	go fmt ./...

lint:
	go vet ./...
