.PHONY: build test clean run-encrypt run-decrypt help

help:
	@echo "Bitseal - File Encryption CLI Tool"
	@echo ""
	@echo "Available targets:"
	@echo "  build         - Build the bitseal binary"
	@echo "  test          - Run tests"
	@echo "  clean         - Remove build artifacts"
	@echo "  run-encrypt   - Build and run encrypt demo"
	@echo "  run-decrypt   - Build and run decrypt demo"
	@echo "  fmt           - Format code"
	@echo "  lint          - Run linter"

build:
	go build -o bitseal

test:
	go test -v -race ./...

clean:
	go clean
	rm -f bitseal bitseal.exe

run-encrypt: build
	./bitseal encrypt -file README.md

run-decrypt: build
	./bitseal decrypt -file README.md.enc

fmt:
	go fmt ./...

lint:
	go vet ./...
