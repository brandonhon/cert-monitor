# Testing Strategy for cert-monitor

## Overview

The cert-monitor project follows a comprehensive testing strategy that includes unit tests, integration tests, package-specific tests, and performance testing. This document outlines the testing approach and how to run the various test suites.

## Testing Hierarchy

### 1. Unit Tests
- **Location**: `*_test.go` files alongside source code
- **Purpose**: Test individual functions and methods in isolation
- **Scope**: Internal packages (`internal/`) and utility packages (`pkg/`)
- **Mock**: Uses mock implementations for dependencies

### 2. Package Tests
- **Location**: Each package in `internal/` has its own test suite
- **Purpose**: Test package-level functionality and interfaces
- **Scope**: 
  - `internal/server` - HTTP server and handlers
  - `internal/certificate` - Certificate processing and analysis
  - `internal/metrics` - Prometheus metrics collection
  - `internal/cache` - Caching functionality
  - `internal/config` - Configuration management

### 3. Integration Tests
- **Location**: `test/` directory and `scripts/` directory
- **Purpose**: Test full application functionality with real services
- **Scope**: End-to-end API testing, server behavior, real certificate processing

### 4. Performance Tests
- **Location**: Benchmark functions in `*_test.go` files
- **Purpose**: Measure and track performance characteristics
- **Scope**: Critical paths like certificate processing and HTTP handlers

## Test Commands

### Quick Test Commands

```bash
# Run all unit tests
make test-unit

# Run all unit tests with race detection
make test-unit-race

# Generate unit test coverage
make test-unit-coverage
```

### Package-Specific Tests

```bash
# Test individual packages
make test-server           # Server package tests
make test-certificate      # Certificate package tests
make test-metrics          # Metrics package tests
make test-cache            # Cache package tests
make test-config           # Config package tests

# Test all packages with race detection
make test-packages-race

# Generate package coverage reports
make test-packages-coverage
```

### Integration Tests

```bash
# Run server integration tests
make test-server-integration

# Run full application tests (with background app)
make test

# Run full application tests with race detection
make test-race
```

### Advanced Testing

```bash
# Run package tests with detailed reporting
COVERAGE_ENABLED=true RACE_ENABLED=true VERBOSE=true ./scripts/test-packages.sh

# Run benchmarks
RUN_BENCHMARKS=true ./scripts/test-packages.sh

# Run server integration tests manually
./scripts/test-server-integration.sh
```

## Server Package Testing

The server package has comprehensive test coverage including:

### Unit Tests (`internal/server/server_test.go`)

- **Configuration Validation**: Tests server config validation logic
- **HTTP Handlers**: Tests all HTTP endpoints (`/healthz`, `/certs`, `/config`, `/reload`)
- **Server Lifecycle**: Tests server start/stop functionality
- **Request Handling**: Tests HTTP method restrictions, 404 handling
- **Concurrent Access**: Tests thread safety of handlers
- **TLS Configuration**: Tests TLS setup validation
- **Performance**: Benchmark tests for critical handlers

### Integration Tests (`scripts/test-server-integration.sh`)

- **Real Server Testing**: Starts actual server instance for testing
- **Endpoint Verification**: Tests all endpoints with real HTTP requests
- **Performance Testing**: 50-request performance test
- **Concurrent Testing**: Tests concurrent request handling
- **Error Handling**: Tests 404 responses and method restrictions
- **Graceful Shutdown**: Tests server cleanup

## Test Structure

### Mock Implementations

The server tests use mock implementations for dependencies:

```go
type mockCacheManager struct {
    stats cache.Statistics
}

func (m *mockCacheManager) Get(path string) (*cache.Entry, *cache.FileInfo, bool, error) {
    return nil, nil, false, nil
}
// ... other mock methods
```

### Test Helpers

Common test setup functions:

```go
func createTestDependencies() *Dependencies {
    // Creates test configuration and dependencies
}

func createTestServer() *HTTPServer {
    // Creates server instance for testing
}
```

### Test Categories

1. **Configuration Tests**: Validate server configuration
2. **Handler Tests**: Test HTTP endpoint functionality
3. **Lifecycle Tests**: Test server start/stop
4. **Integration Tests**: Test with real HTTP requests
5. **Performance Tests**: Benchmark critical paths
6. **Concurrency Tests**: Test thread safety

## Coverage Goals

- **Unit Tests**: 80%+ coverage for all packages
- **Integration Tests**: All major user flows covered
- **Critical Paths**: 95%+ coverage for security-sensitive code

### Current Coverage by Package

```bash
# Generate coverage reports
make test-packages-coverage

# View individual package coverage
open coverage-server.html
open coverage-certificate.html
open coverage-metrics.html
open coverage-cache.html
open coverage-config.html
```

## Continuous Integration

### GitHub Actions Workflow

The CI pipeline runs multiple test phases:

1. **Unit Tests**: All packages tested with race detection
2. **Package Tests**: Individual package validation
3. **Integration Tests**: Server integration testing
4. **Linting**: Code quality checks
5. **Security**: Security vulnerability scanning

### Test Matrix

Tests run on multiple Go versions:
- Go 1.21 (minimum supported)
- Go 1.22 (latest stable)

## Test Data and Fixtures

### Test Certificates

Generated by `scripts/generate-test-certs.sh`:

- **Valid Certificates**: Standard RSA and ECDSA certificates
- **Expired Certificates**: For expiration testing
- **Weak Keys**: RSA 1024-bit for security testing
- **Self-signed**: For issuer classification testing
- **Multiple Formats**: PEM, DER, CRT, CER formats

### Test Configuration

Example test configuration in `test-server-config.yaml`:

```yaml
cert_dirs:
  - "./test-certs"
port: "3001"
bind_address: "127.0.0.1"
num_workers: 2
expiry_threshold_days: 30
enable_runtime_metrics: true
enable_weak_crypto_metrics: true
```

## Running Tests in Development

### Pre-commit Testing

```bash
# Run before committing
make pre-commit

# This runs:
# - make deps (dependency check)
# - make vet (go vet)
# - make fmt (formatting)
# - make lint (linting)
# - make test-unit (unit tests)
```

### Development Workflow

1. **Write Tests First**: Follow TDD when possible
2. **Run Package Tests**: Test specific package during development
3. **Run Integration Tests**: Verify end-to-end functionality
4. **Check Coverage**: Ensure adequate test coverage
5. **Run Full Suite**: Before pushing changes

### Test Debugging

```bash
# Run tests with verbose output
go test -v ./internal/server/

# Run specific test
go test -v ./internal/server/ -run TestHealthHandler

# Run with race detection
go test -race ./internal/server/

# Generate coverage for specific test
go test -coverprofile=debug.out ./internal/server/
go tool cover -html=debug.out
```

## Performance Testing

### Benchmarks

Run benchmarks to track performance:

```bash
# Run all benchmarks
go test -bench=. ./...

# Run server benchmarks specifically
go test -bench=. ./internal/server/

# Run with memory profiling
go test -bench=. -benchmem ./internal/server/
```

### Performance Targets

- **Health Handler**: < 1ms per request
- **Metrics Handler**: < 5ms per request
- **Certificate Processing**: < 10ms per certificate
- **Concurrent Requests**: 100+ req/s with no errors

## Troubleshooting Tests

### Common Issues

1. **Port Conflicts**: Integration tests use port 3001
2. **Test Certificates**: Generate with `./scripts/generate-test-certs.sh`
3. **Race Conditions**: Use race detector to identify issues
4. **Mock Failures**: Ensure mocks match interface signatures

### Test Environment

Required tools:
- Go 1.21+
- OpenSSL (for certificate generation)
- curl (for integration tests)
- Make

### Clean Test Environment

```bash
# Clean test artifacts
make clean

# Remove test certificates
rm -rf test-certs/

# Remove coverage files
rm -f coverage-*.out coverage-*.html

# Regenerate test certificates
./scripts/generate-test-certs.sh
```

## Test Maintenance

### Adding New Tests

1. **Unit Tests**: Add to appropriate `*_test.go` file
2. **Integration Tests**: Extend `scripts/test-server-integration.sh`
3. **Package Tests**: Update `scripts/test-packages.sh` if needed
4. **Update Documentation**: Update this file with new test categories

### Test Quality Guidelines

- **Descriptive Names**: Test names should describe the scenario
- **Single Assertion**: One assertion per test when possible
- **Clean Setup/Teardown**: Use table-driven tests for multiple scenarios
- **Error Testing**: Test both success and failure cases
- **Mock Appropriately**: Use mocks for external dependencies

### Test Review Checklist

- [ ] Tests cover happy path and error cases
- [ ] Tests use appropriate mocks
- [ ] Tests are deterministic (no flaky tests)
- [ ] Tests follow naming conventions
- [ ] Integration tests verify real behavior
- [ ] Performance tests set appropriate baselines

## Future Enhancements

### Planned Test Improvements

1. **Property-Based Testing**: Use fuzzing for certificate parsing
2. **Load Testing**: Add proper load testing with tools like k6
3. **End-to-End Testing**: Browser-based testing for web interfaces
4. **Chaos Testing**: Test resilience under failure conditions
5. **Security Testing**: Automated security testing integration

### Metrics and Monitoring

- **Test Duration Tracking**: Monitor test execution time
- **Coverage Trending**: Track coverage changes over time
- **Flaky Test Detection**: Identify and fix unreliable tests
- **Performance Regression**: Alert on performance degradation
