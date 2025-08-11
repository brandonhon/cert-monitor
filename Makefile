# Makefile for cert-monitor

# Build variables
BINARY_NAME=cert-monitor
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# Go variables
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOVET=$(GOCMD) vet
GOFMT=gofmt

# Build targets
.PHONY: all build clean test coverage vet fmt deps help

all: deps vet fmt test build

build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) .

build-race:
	@echo "Building $(BINARY_NAME) with race detector..."
	$(GOBUILD) $(LDFLAGS) -race -o $(BINARY_NAME)-race .

build-static:
	@echo "Building static $(BINARY_NAME)..."
	CGO_ENABLED=0 GOOS=linux $(GOBUILD) $(LDFLAGS) -a -installsuffix cgo -o $(BINARY_NAME)-static .

# Multi-platform builds
build-all: build-linux build-darwin #build-windows

build-linux:
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o build/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o build/$(BINARY_NAME)-linux-arm64 .

# build-windows:
# 	@echo "Building for Windows..."
# 	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o build/$(BINARY_NAME)-windows-amd64.exe .

build-darwin:
	@echo "Building for macOS..."
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o build/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o build/$(BINARY_NAME)-darwin-arm64 .

clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-race
	rm -f $(BINARY_NAME)-static
	rm -rf build/
	rm -f coverage.out coverage.html

test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

test-race:
	@echo "Running tests with race detector..."
	$(GOTEST) -race -v ./...

test-short:
	@echo "Running short tests..."
	$(GOTEST) -short -v ./...

coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

benchmark:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

vet:
	@echo "Running go vet..."
	$(GOVET) ./...

fmt:
	@echo "Formatting code..."
	gofmt -s -w .
	go fmt ./...

fmt-check:
	@echo "Checking code formatting..."
	@if [ -n "$(gofmt -l .)" ]; then \
		echo "Code is not formatted. Run 'make fmt' to fix."; \
		gofmt -l .; \
		exit 1; \
	fi

deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

deps-update:
	@echo "Updating dependencies..."
	$(GOMOD) tidy
	$(GOGET) -u ./...

# Development helpers
run:
	@echo "Running $(BINARY_NAME) in development mode..."
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) . && \
	./$(BINARY_NAME) -cert-dir ./test-certs -dry-run -log-file ""

run-config:
	@echo "Running $(BINARY_NAME) with config file..."
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) . && \
	./$(BINARY_NAME) -config config.yaml

validate-config:
	@echo "Validating configuration..."
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) . && \
	./$(BINARY_NAME) -config config.yaml -check-config

# Installation
install:
	@echo "Installing $(BINARY_NAME)..."
	$(GOCMD) install $(LDFLAGS) .

install-tools:
	@echo "Installing development tools..."
	$(GOGET) github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Linting
lint:
	@echo "Running golangci-lint..."
	golangci-lint run --config .golangci.yml

lint-fix:
	@echo "Running golangci-lint with auto-fix..."
	golangci-lint run --config .golangci.yml --fix

# Docker
docker-build:
	@echo "Building Docker image..."
	docker build -t $(BINARY_NAME):$(VERSION) .
	docker build -t $(BINARY_NAME):latest .

docker-run:
	@echo "Running Docker container..."
	docker run -p 3000:3000 -v $(PWD)/test-certs:/certs $(BINARY_NAME):latest -cert-dir /certs

# Release preparation
prepare-release:
	@echo "Preparing release $(VERSION)..."
	@if [ -z "$(VERSION)" ]; then echo "VERSION must be set"; exit 1; fi
	mkdir -p build
	$(MAKE) build-all
	@echo "Release artifacts created in build/"

# Documentation
docs:
	@echo "Generating documentation..."
	@echo "Documentation available in README.md"

# Security
security:
	@echo "Running security checks..."
	$(GOMOD) tidy
	$(GOCMD) list -json -deps | nancy sleuth

# Database/Cache management
clean-cache:
	@echo "Cleaning cache files..."
	rm -f cache.json
	rm -f /tmp/cert-monitor-cache.json

# Help
help:
	@echo "Available targets:"
	@echo "  build          - Build the binary"
	@echo "  build-all      - Build for all platforms"
	@echo "  build-race     - Build with race detector"
	@echo "  build-static   - Build static binary"
	@echo "  clean          - Clean build artifacts"
	@echo "  test           - Run tests"
	@echo "  test-race      - Run tests with race detector"
	@echo "  coverage       - Generate coverage report"
	@echo "  benchmark      - Run benchmarks"
	@echo "  vet            - Run go vet"
	@echo "  fmt            - Format code"
	@echo "  fmt-check      - Check code formatting"
	@echo "  deps           - Download dependencies"
	@echo "  deps-update    - Update dependencies"
	@echo "  run            - Run in development mode"
	@echo "  install        - Install binary"
	@echo "  lint           - Run linter"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Run Docker container"
	@echo "  security       - Run security checks"
	@echo "  help           - Show this help"