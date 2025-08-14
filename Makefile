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

# Test app configuration
TEST_PORT=3000
TEST_CONFIG=test-config.yaml
TEST_CERT_DIR=./test-certs
TEST_PID_FILE=/tmp/cert-monitor-test.pid
TEST_LOG_FILE=/tmp/cert-monitor-test.log

# Build targets
.PHONY: all build clean test coverage vet fmt deps help test-setup test-cleanup

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
	@$(MAKE) test-cleanup

# Test setup and cleanup functions
test-setup: build
	@echo "Setting up test environment..."
	@mkdir -p $(TEST_CERT_DIR)
	@$(MAKE) generate-test-certs || true
	@$(MAKE) create-test-config
	@echo "Starting $(BINARY_NAME) in background for testing..."
	@./$(BINARY_NAME) -config $(TEST_CONFIG) > $(TEST_LOG_FILE) 2>&1 & echo $$! > $(TEST_PID_FILE)
	@echo "Waiting for application to start..."
	@for i in $$(seq 1 30); do \
		if curl -s http://localhost:$(TEST_PORT)/healthz > /dev/null 2>&1; then \
			echo "Application is ready for testing"; \
			break; \
		fi; \
		if [ $$i -eq 30 ]; then \
			echo "Application failed to start within 30 seconds"; \
			$(MAKE) test-cleanup; \
			exit 1; \
		fi; \
		echo "Waiting for application... ($$i/30)"; \
		sleep 1; \
	done

test-cleanup:
	@echo "Cleaning up test environment..."
	@if [ -f $(TEST_PID_FILE) ]; then \
		PID=$$(cat $(TEST_PID_FILE)); \
		if [ -n "$$PID" ] && kill -0 $$PID 2>/dev/null; then \
			echo "Stopping application (PID: $$PID)..."; \
			kill $$PID; \
			sleep 2; \
			if kill -0 $$PID 2>/dev/null; then \
				echo "Force killing application..."; \
				kill -9 $$PID; \
			fi; \
		fi; \
		rm -f $(TEST_PID_FILE); \
	fi
	@rm -f $(TEST_CONFIG)
	@rm -f $(TEST_LOG_FILE)
	@rm -f $(BINARY_NAME)
	@echo "Test cleanup completed"

create-test-config:
	@echo "Creating test configuration..."
	@echo "cert_dirs:" > $(TEST_CONFIG)
	@echo "  - \"$(TEST_CERT_DIR)\"" >> $(TEST_CONFIG)
	@echo "port: \"$(TEST_PORT)\"" >> $(TEST_CONFIG)
	@echo "bind_address: \"0.0.0.0\"" >> $(TEST_CONFIG)
	@echo "num_workers: 2" >> $(TEST_CONFIG)
	@echo "expiry_threshold_days: 30" >> $(TEST_CONFIG)
	@echo "cache_file: \"/tmp/cert-monitor-test-cache.json\"" >> $(TEST_CONFIG)
	@echo "log_file: \"$(TEST_LOG_FILE)\"" >> $(TEST_CONFIG)
	@echo "enable_runtime_metrics: true" >> $(TEST_CONFIG)
	@echo "enable_weak_crypto_metrics: true" >> $(TEST_CONFIG)
	@echo "enable_pprof: false" >> $(TEST_CONFIG)
	@echo "dry_run: false" >> $(TEST_CONFIG)
	@echo "clear_cache_on_reload: false" >> $(TEST_CONFIG)

generate-test-certs:
	@echo "Generating test certificates..."
	@if [ ! -f $(TEST_CERT_DIR)/test-cert.pem ]; then \
		mkdir -p $(TEST_CERT_DIR); \
		openssl req -x509 -newkey rsa:2048 -keyout $(TEST_CERT_DIR)/test-key.pem \
			-out $(TEST_CERT_DIR)/test-cert.pem -days 365 -nodes \
			-subj "/C=US/ST=Test/L=Test/O=Test/OU=Test/CN=test.example.com" \
			2>/dev/null || echo "Warning: Could not generate test certificates (openssl not available)"; \
	fi
	@if [ -f $(TEST_CERT_DIR)/test-cert.pem ]; then \
		cp $(TEST_CERT_DIR)/test-cert.pem $(TEST_CERT_DIR)/test-cert.crt; \
		cp $(TEST_CERT_DIR)/test-cert.pem $(TEST_CERT_DIR)/test-cert.cer; \
		echo "Test certificates generated in $(TEST_CERT_DIR)"; \
	fi

# Enhanced test targets with background app management
test: test-setup
	@echo "Running tests with background application..."
	@$(GOTEST) -v ./... || ($(MAKE) test-cleanup && exit 1)
	@$(MAKE) test-cleanup

test-race: test-setup
	@echo "Running tests with race detector and background application..."
	@$(GOTEST) -race -v ./... || ($(MAKE) test-cleanup && exit 1)
	@$(MAKE) test-cleanup

test-short: test-setup
	@echo "Running short tests with background application..."
	@$(GOTEST) -short -v ./... || ($(MAKE) test-cleanup && exit 1)
	@$(MAKE) test-cleanup

coverage: test-setup
	@echo "Running tests with coverage and background application..."
	@$(GOTEST) -coverprofile=coverage.out ./... || ($(MAKE) test-cleanup && exit 1)
	@$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"
	@$(MAKE) test-cleanup

benchmark: test-setup
	@echo "Running benchmarks with background application..."
	@$(GOTEST) -bench=. -benchmem ./... || ($(MAKE) test-cleanup && exit 1)
	@$(MAKE) test-cleanup

# Comprehensive package testing
test-packages: test-certificate test-metrics test-cache test-config test-server
	@echo "All package tests completed"

test-packages-race:
	@echo "Running all package tests with race detector..."
	$(GOTEST) -race -v ./internal/certificate/... ./internal/metrics/... ./internal/cache/... ./internal/config/... ./internal/server/...

test-packages-coverage:
	@echo "Running all package tests with coverage..."
	$(GOTEST) -coverprofile=coverage-packages.out ./internal/certificate/... ./internal/metrics/... ./internal/cache/... ./internal/config/... ./internal/server/...
	$(GOCMD) tool cover -html=coverage-packages.out -o coverage-packages.html
	@echo "Package test coverage report generated: coverage-packages.html"

# Unit tests without background app (for pure unit tests)
test-unit:
	@echo "Running unit tests only (no background app)..."
	$(GOTEST) -v ./internal/... ./pkg/...

test-unit-race:
	@echo "Running unit tests with race detector (no background app)..."
	$(GOTEST) -race -v ./internal/... ./pkg/...

test-unit-coverage:
	@echo "Running unit tests with coverage (no background app)..."
	$(GOTEST) -coverprofile=coverage-unit.out ./internal/... ./pkg/...
	$(GOCMD) tool cover -html=coverage-unit.out -o coverage-unit.html
	@echo "Unit test coverage report generated: coverage-unit.html"

# Server package specific tests
test-server:
	@echo "Running server package tests..."
	$(GOTEST) -v ./internal/server/...

test-server-race:
	@echo "Running server package tests with race detector..."
	$(GOTEST) -race -v ./internal/server/...

test-server-coverage:
	@echo "Running server package tests with coverage..."
	$(GOTEST) -coverprofile=coverage-server.out ./internal/server/...
	$(GOCMD) tool cover -html=coverage-server.out -o coverage-server.html
	@echo "Server test coverage report generated: coverage-server.html"

# Cache package specific test targets
test-cache:
	@echo "Running cache package tests..."
	$(GOTEST) -v ./internal/cache/...

test-cache-race:
	@echo "Running cache package tests with race detector..."
	$(GOTEST) -race -v ./internal/cache/...

test-cache-coverage:
	@echo "Running cache package tests with coverage..."
	$(GOTEST) -coverprofile=coverage-cache.out ./internal/cache/...
	$(GOCMD) tool cover -html=coverage-cache.out -o coverage-cache.html
	@echo "Cache test coverage report generated: coverage-cache.html"

test-cache-short:
	@echo "Running cache package short tests..."
	$(GOTEST) -short -v ./internal/cache/...

test-cache-benchmark:
	@echo "Running cache package benchmarks..."
	$(GOTEST) -bench=. -benchmem -v ./internal/cache/...

# Server integration tests
test-server-integration:
	@echo "Running server integration tests..."
	@chmod +x ./scripts/test-server-integration.sh
	@./scripts/test-server-integration.sh

# Package-specific test targets
test-certificate:
	@echo "Running certificate package tests..."
	$(GOTEST) -v ./internal/certificate/...

test-metrics:
	@echo "Running metrics package tests..."
	$(GOTEST) -v ./internal/metrics/...

test-config:
	@echo "Running config package tests..."
	$(GOTEST) -v ./internal/config/...

# Test debugging helpers
test-logs:
	@echo "Showing test application logs..."
	@if [ -f $(TEST_LOG_FILE) ]; then \
		tail -f $(TEST_LOG_FILE); \
	else \
		echo "No test log file found at $(TEST_LOG_FILE)"; \
	fi

test-status:
	@echo "Checking test application status..."
	@if [ -f $(TEST_PID_FILE) ]; then \
		PID=$$(cat $(TEST_PID_FILE)); \
		if [ -n "$$PID" ] && kill -0 $$PID 2>/dev/null; then \
			echo "Application is running (PID: $$PID)"; \
			echo "Health check:"; \
			curl -s http://localhost:$(TEST_PORT)/healthz | jq . 2>/dev/null || curl -s http://localhost:$(TEST_PORT)/healthz; \
		else \
			echo "Application is not running"; \
		fi; \
	else \
		echo "No PID file found"; \
	fi

# Manual test app management
test-start: test-setup
	@echo "Test application started. Use 'make test-stop' to stop it."
	@echo "Logs: $(TEST_LOG_FILE)"
	@echo "PID file: $(TEST_PID_FILE)"
	@echo "Health: http://localhost:$(TEST_PORT)/healthz"
	@echo "Metrics: http://localhost:$(TEST_PORT)/metrics"

test-stop: test-cleanup
	@echo "Test application stopped."

test-restart: test-stop test-start

vet:
	@echo "Running go vet..."
	$(GOVET) ./...

fmt:
	@echo "Formatting code..."
	gofmt -s -w .
	go fmt ./...

fmt-check:
	@echo "Checking code formatting..."
	@if [ -n "$$(gofmt -l .)" ]; then \
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
	@if [ -f .golangci.yml ]; then \
		golangci-lint run --config .golangci.yml; \
	else \
		golangci-lint run; \
	fi

lint-fix:
	@echo "Running golangci-lint with auto-fix..."
	@if [ -f .golangci.yml ]; then \
		golangci-lint run --config .golangci.yml --fix; \
	else \
		golangci-lint run --fix; \
	fi

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
	rm -f /tmp/cert-monitor-test-cache.json

# CI/CD helpers
ci-test: deps vet fmt-check test-unit coverage
	@echo "CI pipeline completed successfully"

pre-commit: deps vet fmt lint test-unit
	@echo "Pre-commit checks completed successfully"

# Help
help:
	@echo "Available targets:"
	@echo ""
	@echo "Build targets:"
	@echo "  build          - Build the binary"
	@echo "  build-all      - Build for all platforms"
	@echo "  build-race     - Build with race detector"
	@echo "  build-static   - Build static binary"
	@echo ""
	@echo "Test targets (with background app):"
	@echo "  test           - Run all tests with background app"
	@echo "  test-race      - Run tests with race detector and background app"
	@echo "  test-short     - Run short tests with background app"
	@echo "  coverage       - Generate coverage report with background app"
	@echo "  benchmark      - Run benchmarks with background app"
	@echo ""
	@echo "Unit test targets (no background app):"
	@echo "  test-unit      - Run unit tests only"
	@echo "  test-unit-race - Run unit tests with race detector"
	@echo "  test-unit-coverage - Generate unit test coverage"
	@echo ""
	@echo "Package-specific tests:"
	@echo "  test-server    - Run server package tests"
	@echo "  test-server-race - Run server tests with race detector"
	@echo "  test-server-coverage - Generate server test coverage"
	@echo "  test-server-integration - Run server integration tests"
	@echo "  test-certificate - Run certificate package tests"
	@echo "  test-metrics   - Run metrics package tests"
	@echo "  test-cache     - Run cache package tests"
	@echo "  test-cache-race - Run cache tests with race detector"
	@echo "  test-cache-coverage - Generate cache test coverage"
	@echo "  test-cache-short - Run cache short tests"
	@echo "  test-cache-benchmark - Run cache benchmarks"
	@echo "  test-config    - Run config package tests"
	@echo "  test-packages  - Run all package tests"
	@echo "  test-packages-race - Run all package tests with race detector"
	@echo "  test-packages-coverage - Generate all package coverage"
	@echo ""
	@echo "Test management:"
	@echo "  test-start     - Start test app in background"
	@echo "  test-stop      - Stop test app"
	@echo "  test-restart   - Restart test app"
	@echo "  test-status    - Check test app status"
	@echo "  test-logs      - Show test app logs"
	@echo "  test-metrics   - Show test app metrics"
	@echo ""
	@echo "Code quality:"
	@echo "  vet            - Run go vet"
	@echo "  fmt            - Format code"
	@echo "  fmt-check      - Check code formatting"
	@echo "  lint           - Run linter"
	@echo "  lint-fix       - Run linter with auto-fix"
	@echo ""
	@echo "Dependencies:"
	@echo "  deps           - Download dependencies"
	@echo "  deps-update    - Update dependencies"
	@echo ""
	@echo "Development:"
	@echo "  run            - Run in development mode"
	@echo "  install        - Install binary"
	@echo "  clean          - Clean build artifacts"
	@echo "  clean-cache    - Clean cache files"
	@echo ""
	@echo "CI/CD:"
	@echo "  ci-test        - Run CI pipeline"
	@echo "  pre-commit     - Run pre-commit checks"
	@echo ""
	@echo "Other:"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Run Docker container"
	@echo "  security       - Run security checks"
	@echo "  help           - Show this help"
