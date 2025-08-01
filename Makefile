# Makefile for cert-monitor

# Variables
BINARY_NAME := cert-monitor
GO := go
GOFLAGS := -v
BUILD_DIR := build
DIST_DIR := dist
CMD_DIR := cmd/cert-monitor
DOCKER_IMAGE := cert-monitor
DOCKER_TAG := latest

# Version information
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GO_VERSION := $(shell go version | cut -d' ' -f3)

# Build flags
LDFLAGS := -ldflags "\
	-X main.Version=$(VERSION) \
	-X main.Commit=$(COMMIT) \
	-X main.BuildTime=$(BUILD_TIME) \
	-s -w"

# Platforms for cross-compilation
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# Default module name (can be overridden)
MODULE_NAME ?= github.com/yourusername/cert-monitor

# Default target
.PHONY: all
all: clean test build

# Initialize the project
.PHONY: init
init:
	@echo "Initializing project..."
	@# Check and set GO111MODULE
	@if [ -z "$GO111MODULE" ] || [ "$GO111MODULE" != "on" ]; then \
		echo "Setting GO111MODULE=on"; \
		export GO111MODULE=on; \
	fi
	@if [ ! -f go.mod ]; then \
		echo "Creating go.mod with module name: $(MODULE_NAME)"; \
		GO111MODULE=on $(GO) mod init $(MODULE_NAME); \
		echo "Installing dependencies..."; \
		GO111MODULE=on $(GO) get github.com/fsnotify/fsnotify@latest; \
		GO111MODULE=on $(GO) get github.com/prometheus/client_golang/prometheus@latest; \
		GO111MODULE=on $(GO) get github.com/prometheus/client_golang/prometheus/promhttp@latest; \
		GO111MODULE=on $(GO) get github.com/prometheus/client_model/go@latest; \
		GO111MODULE=on $(GO) get github.com/sirupsen/logrus@latest; \
		GO111MODULE=on $(GO) get golang.org/x/sys/unix@latest; \
		GO111MODULE=on $(GO) get gopkg.in/natefinch/lumberjack.v2@latest; \
		GO111MODULE=on $(GO) get gopkg.in/yaml.v3@latest; \
		GO111MODULE=on $(GO) mod tidy; \
		echo "Project initialized successfully!"; \
		echo ""; \
		echo "Next steps:"; \
		echo "  1. Update import paths in source files to: $(MODULE_NAME)"; \
		echo "  2. Create a config.yaml file (see config.example.yaml)"; \
		echo "  3. Run 'make build' to build the project"; \
	else \
		echo "go.mod already exists. Run 'make deps' to update dependencies."; \
	fi

# Setup project structure
.PHONY: setup
setup: init
	@echo "Setting up project structure..."
	@mkdir -p cmd/cert-monitor
	@mkdir -p internal/cache
	@mkdir -p internal/cert
	@mkdir -p internal/config
	@mkdir -p internal/metrics
	@mkdir -p internal/scanner
	@mkdir -p internal/server
	@mkdir -p internal/watcher
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(DIST_DIR)
	@if [ ! -f config.example.yaml ]; then \
		echo "Creating example configuration file..."; \
		echo "# Example configuration for cert-monitor" > config.example.yaml; \
		echo "cert_dirs:" >> config.example.yaml; \
		echo "  - ./certs" >> config.example.yaml; \
		echo "  - /etc/ssl/certs" >> config.example.yaml; \
		echo "log_file: /var/log/cert-monitor.log" >> config.example.yaml; \
		echo "port: \"3000\"" >> config.example.yaml; \
		echo "bind_address: \"0.0.0.0\"" >> config.example.yaml; \
		echo "num_workers: 4" >> config.example.yaml; \
		echo "expiry_threshold_days: 45" >> config.example.yaml; \
		echo "cache_file: /var/lib/cert-monitor/cache.json" >> config.example.yaml; \
		echo "enable_runtime_metrics: true" >> config.example.yaml; \
		echo "enable_weak_crypto_metrics: true" >> config.example.yaml; \
	fi
	@if [ ! -f .gitignore ]; then \
		echo "Creating .gitignore..."; \
		echo "# Binaries" > .gitignore; \
		echo "$(BINARY_NAME)" >> .gitignore; \
		echo "$(BUILD_DIR)/" >> .gitignore; \
		echo "$(DIST_DIR)/" >> .gitignore; \
		echo "" >> .gitignore; \
		echo "# Test and coverage" >> .gitignore; \
		echo "*.test" >> .gitignore; \
		echo "*.out" >> .gitignore; \
		echo "coverage.html" >> .gitignore; \
		echo "" >> .gitignore; \
		echo "# IDE" >> .gitignore; \
		echo ".vscode/" >> .gitignore; \
		echo ".idea/" >> .gitignore; \
		echo "*.swp" >> .gitignore; \
		echo "*.swo" >> .gitignore; \
		echo "" >> .gitignore; \
		echo "# Config files with secrets" >> .gitignore; \
		echo "config.yaml" >> .gitignore; \
		echo "*.key" >> .gitignore; \
		echo "*.pem" >> .gitignore; \
		echo "*.crt" >> .gitignore; \
		echo "" >> .gitignore; \
		echo "# OS files" >> .gitignore; \
		echo ".DS_Store" >> .gitignore; \
		echo "Thumbs.db" >> .gitignore; \
	fi
	@echo "Project structure setup complete!"

# Build the binary
.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Build with race detector (for development)
.PHONY: build-race
build-race:
	@echo "Building $(BINARY_NAME) with race detector..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -race $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-race ./$(CMD_DIR)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)-race"

# Cross-compile for multiple platforms
.PHONY: build-all
build-all:
	@echo "Building for all platforms..."
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		GOOS=$$(echo $$platform | cut -d/ -f1) \
		GOARCH=$$(echo $$platform | cut -d/ -f2) \
		output=$(DIST_DIR)/$(BINARY_NAME)-$$GOOS-$$GOARCH; \
		if [ "$$GOOS" = "windows" ]; then output="$$output.exe"; fi; \
		echo "Building for $$platform..."; \
		GOOS=$$GOOS GOARCH=$$GOARCH $(GO) build $(GOFLAGS) $(LDFLAGS) \
			-o $$output ./$(CMD_DIR) || exit 1; \
	done
	@echo "Cross-platform builds complete"

# Run the application
.PHONY: run
run: build
	@echo "Running $(BINARY_NAME)..."
	./$(BUILD_DIR)/$(BINARY_NAME) -config config.yaml

# Run with dry-run mode
.PHONY: dry-run
dry-run: build
	@echo "Running $(BINARY_NAME) in dry-run mode..."
	./$(BUILD_DIR)/$(BINARY_NAME) -config config.yaml -dry-run

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	$(GO) test -v -race -cover ./...

# Run tests with coverage report
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p $(BUILD_DIR)/coverage
	$(GO) test -v -race -coverprofile=$(BUILD_DIR)/coverage/coverage.out ./...
	$(GO) tool cover -html=$(BUILD_DIR)/coverage/coverage.out -o $(BUILD_DIR)/coverage/coverage.html
	@echo "Coverage report: $(BUILD_DIR)/coverage/coverage.html"

# Run benchmarks
.PHONY: bench
bench:
	@echo "Running benchmarks..."
	$(GO) test -bench=. -benchmem ./...

# Check code quality
.PHONY: lint
lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Install it with:"; \
		echo "  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin"; \
		exit 1; \
	fi

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...

# Tidy dependencies
.PHONY: tidy
tidy:
	@echo "Tidying dependencies..."
	$(GO) mod tidy
	$(GO) mod verify

# Download dependencies
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	$(GO) mod download

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@echo "Clean complete"

# Generate mocks (if using mockgen)
.PHONY: mocks
mocks:
	@echo "Generating mocks..."
	@if command -v mockgen >/dev/null 2>&1; then \
		go generate ./...; \
	else \
		echo "mockgen not installed. Install it with:"; \
		echo "  go install github.com/golang/mock/mockgen@latest"; \
	fi

# Validate configuration
.PHONY: check-config
check-config: build
	@echo "Validating configuration..."
	./$(BUILD_DIR)/$(BINARY_NAME) -check-config -config config.yaml

# Docker targets
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		.

.PHONY: docker-push
docker-push: docker-build
	@echo "Pushing Docker image..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)

# Create a release tarball
.PHONY: release
release: clean test build-all
	@echo "Creating release packages..."
	@mkdir -p $(DIST_DIR)/release
	@for platform in $(PLATFORMS); do \
		GOOS=$$(echo $$platform | cut -d/ -f1); \
		GOARCH=$$(echo $$platform | cut -d/ -f2); \
		binary=$(BINARY_NAME)-$$GOOS-$$GOARCH; \
		if [ "$$GOOS" = "windows" ]; then binary="$$binary.exe"; fi; \
		tar -czf $(DIST_DIR)/release/$(BINARY_NAME)-$(VERSION)-$$GOOS-$$GOARCH.tar.gz \
			-C $(DIST_DIR) $$binary \
			-C ../.. README.md LICENSE config.example.yaml || exit 1; \
	done
	@echo "Release packages created in $(DIST_DIR)/release"

# Install the binary
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME)..."
	@install -d $${DESTDIR}$${PREFIX}/bin
	@install -m 755 $(BUILD_DIR)/$(BINARY_NAME) $${DESTDIR}$${PREFIX}/bin/
	@echo "Installed to $${DESTDIR}$${PREFIX}/bin/$(BINARY_NAME)"

# Uninstall the binary
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@rm -f $${DESTDIR}$${PREFIX}/bin/$(BINARY_NAME)
	@echo "Uninstalled"

# Development helpers
.PHONY: dev
dev: fmt lint test build
	@echo "Development build complete"

# Watch for changes and rebuild (requires entr)
.PHONY: watch
watch:
	@if command -v entr >/dev/null 2>&1; then \
		find . -name "*.go" | entr -r make run; \
	else \
		echo "entr not installed. Install it with your package manager."; \
		exit 1; \
	fi

# Generate documentation
.PHONY: docs
docs:
	@echo "Generating documentation..."
	@if command -v godoc >/dev/null 2>&1; then \
		echo "Documentation server starting at http://localhost:6060"; \
		godoc -http=:6060; \
	else \
		echo "godoc not installed. Install it with:"; \
		echo "  go install golang.org/x/tools/cmd/godoc@latest"; \
		exit 1; \
	fi

# Security scan
.PHONY: security
security:
	@echo "Running security scan..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not installed. Install it with:"; \
		echo "  go install github.com/securego/gosec/v2/cmd/gosec@latest"; \
		exit 1; \
	fi

# Check for outdated dependencies
.PHONY: outdated
outdated:
	@echo "Checking for outdated dependencies..."
	$(GO) list -u -m all

# Print version
.PHONY: version
version:
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Go Version: $(GO_VERSION)"

# Help target
.PHONY: help
help:
	@echo "Certificate Monitor Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build targets:"
	@echo "  build         - Build the binary for current platform"
	@echo "  build-race    - Build with race detector enabled"
	@echo "  build-all     - Build for all supported platforms"
	@echo "  install       - Install the binary to PREFIX/bin (default: /usr/local)"
	@echo "  uninstall     - Remove the installed binary"
	@echo ""
	@echo "Setup targets:"
	@echo "  init          - Initialize Go module and dependencies"
	@echo "  setup         - Initialize project and create directory structure"
	@echo ""
	@echo "Run targets:"
	@echo "  run           - Build and run the application"
	@echo "  dry-run       - Run in dry-run mode"
	@echo "  check-config  - Validate configuration file"
	@echo ""
	@echo "Test targets:"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  bench         - Run benchmarks"
	@echo "  security      - Run security scan"
	@echo ""
	@echo "Development targets:"
	@echo "  dev           - Run fmt, lint, test, and build"
	@echo "  fmt           - Format code"
	@echo "  lint          - Run linters"
	@echo "  tidy          - Tidy and verify dependencies"
	@echo "  deps          - Download dependencies"
	@echo "  mocks         - Generate mock files"
	@echo "  watch         - Watch for changes and rebuild"
	@echo "  docs          - Start documentation server"
	@echo ""
	@echo "Docker targets:"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-push   - Push Docker image to registry"
	@echo ""
	@echo "Release targets:"
	@echo "  release       - Create release packages for all platforms"
	@echo "  version       - Print version information"
	@echo ""
	@echo "Maintenance targets:"
	@echo "  clean         - Remove build artifacts"
	@echo "  outdated      - Check for outdated dependencies"
	@echo ""
	@echo "Variables:"
	@echo "  PREFIX        - Installation prefix (default: /usr/local)"
	@echo "  DESTDIR       - Installation destination directory"
	@echo "  GOFLAGS       - Additional Go build flags"

.DEFAULT_GOAL := help
