# Development Guide

This guide covers setting up the development environment, testing, and contributing to cert-monitor.

## Prerequisites

- Go 1.21 or later
- OpenSSL (for generating test certificates)
- Make
- Git

## Quick Start

1. **Clone and Setup**
   ```bash
   git clone https://github.com/brandonhon/cert-monitor.git
   cd cert-monitor
   ./setup.sh
   ```

2. **Generate Test Certificates**
   ```bash
   chmod +x scripts/generate-test-certs.sh
   ./scripts/generate-test-certs.sh
   ```

3. **Run Development Server**
   ```bash
   make run
   ```

## Development Workflow

### Building

```bash
# Standard build
make build

# Build with race detection
make build-race

# Build for all platforms
make build-all

# Static build (for containers)
make build-static
```

### Testing

```bash
# Run all tests
make test

# Run tests with race detection
make test-race

# Run short tests only
make test-short

# Generate coverage report
make coverage

# Run benchmarks
make benchmark
```

### Code Quality

```bash
# Format code
make fmt

# Check formatting
make fmt-check

# Run linting
make lint

# Run go vet
make vet

# Run security scan
make security
```

### Development Server

```bash
# Run with test certificates
make run

# Run with custom config
make run-config

# Validate configuration
make validate-config

# Clean cache
make clean-cache
```

## Project Structure

```
cert-monitor/
├── main.go                 # Main application code
├── go.mod                  # Go module definition
├── go.sum                  # Go module checksums
├── Makefile               # Build automation
├── config.example.yaml    # Example configuration
├── README.md              # Project documentation
├── DEVELOPMENT.md         # This file
├── IMPLEMENTATION_PLAN.md # Development roadmap
├── LICENSE                # MIT License
├── .gitignore            # Git ignore rules
│
├── .github/
│   └── workflows/
│       ├── ci.yml         # Continuous integration
│       └── release.yml    # Release automation
│
├── deploy/
│   ├── cert-monitor.service # Systemd service file
│   └── docker-compose.yml   # Docker Compose setup
│
├── scripts/
│   ├── generate-test-certs.sh # Test certificate generator
│   └── install.sh            # Installation script
│
├── test/
│   └── basic_test.go      # Basic functionality tests
│
├── test-certs/           # Generated test certificates
│   ├── README.md         # Test certificate documentation
│   └── *.pem, *.crt, etc # Various certificate formats
│
├── prometheus.yml        # Prometheus configuration
└── alert_rules.yml      # Prometheus alerting rules
```

## Configuration

### Development Configuration

Create `config.yaml` from the example:

```bash
cp config.example.yaml config.yaml
```

Example development configuration:

```yaml
cert_dirs:
  - "./test-certs"
port: "3000"
bind_address: "127.0.0.1"
num_workers: 2
dry_run: false
expiry_threshold_days: 30
log_file: ""  # Log to stdout in development
cache_file: "./dev-cache.json"
enable_runtime_metrics: true
enable_weak_crypto_metrics: true
enable_pprof: true  # Enable pprof in development
```

### Environment Variables

All configuration can be overridden with environment variables:

```bash
export CERT_DIRS="./test-certs"
export PORT="3000"
export LOG_FILE=""
export ENABLE_PPROF="true"
```

## Testing Strategy

### Unit Tests

Add unit tests in `*_test.go` files alongside the main code:

```go
// Example test structure
func TestCertificateProcessing(t *testing.T) {
    // Test certificate processing logic
}

func BenchmarkCertificateProcessing(b *testing.B) {
    // Benchmark performance
}
```

### Integration Tests

Integration tests require the application to be running:

```bash
# Terminal 1: Start the application
make run

# Terminal 2: Run integration tests
go test ./test/ -v
```

### Test Certificates

The test certificate generator creates various scenarios:

- **Standard certificates**: Valid certificates with multiple SANs
- **Expired certificates**: For testing expiration alerts
- **Weak keys**: RSA 1024-bit for security testing
- **Self-signed**: For issuer classification testing
- **Multiple formats**: PEM, DER, CRT, CER formats
- **Duplicates**: For duplicate detection testing

## Development Features

### Hot Reload

The application supports hot configuration reload:

```bash
# Modify config.yaml, then trigger reload
curl -X POST http://localhost:3000/reload
```

### Debug Endpoints

When `enable_pprof: true`:

- `http://localhost:3000/debug/pprof/` - CPU profiling
- `http://localhost:3000/debug/pprof/heap` - Memory profiling
- `http://localhost:3000/debug/pprof/goroutine` - Goroutine analysis

### API Endpoints

- `GET /metrics` - Prometheus metrics
- `GET /healthz` - Health check
- `GET /certs` - Certificate information (JSON)
- `GET /config` - Configuration status
- `POST /reload` - Trigger configuration reload

## Debugging

### Memory Profiling

```bash
# Enable pprof in config
echo "enable_pprof: true" >> config.yaml

# Start application
make run

# Analyze memory usage
go tool pprof http://localhost:3000/debug/pprof/heap
```

### CPU Profiling

```bash
# Profile CPU usage for 30 seconds
go tool pprof http://localhost:3000/debug/pprof/profile?seconds=30
```

### Trace Analysis

```bash
# Generate trace
curl http://localhost:3000/debug/pprof/trace?seconds=5 -o trace.out

# Analyze trace
go tool trace trace.out
```

## Docker Development

### Build Docker Image

```bash
# Build development image
docker build -t cert-monitor:dev .

# Run with test certificates
docker run -p 3000:3000 -v $(pwd)/test-certs:/certs cert-monitor:dev -cert-dir /certs
```

### Docker Compose

```bash
# Start full stack (cert-monitor + Prometheus + Grafana)
docker-compose up -d

# View logs
docker-compose logs -f cert-monitor

# Stop stack
docker-compose down
```

## Contributing

### Code Style

- Follow standard Go formatting (`gofmt`)
- Use meaningful variable names
- Add comments for exported functions
- Keep functions focused and small
- Handle errors explicitly

### Commit Messages

Use conventional commit format:

```
type(scope): description

feat(metrics): add certificate issuer classification
fix(cache): resolve race condition in cache pruning
docs(readme): update installation instructions
test(integration): add API endpoint tests
```

### Pull Request Process

1. **Fork the repository**
2. **Create feature branch** (`git checkout -b feature/amazing-feature`)
3. **Write tests** for new functionality
4. **Ensure all tests pass** (`make test`)
5. **Update documentation** if needed
6. **Submit pull request** with clear description

### Development Guidelines

Follow the project's development guidelines:

- **Incremental progress** over big changes
- **Learn from existing code** patterns
- **Test-driven development** when possible
- **Clear intent** over clever code
- **Document design decisions**

## Release Process

### Creating a Release

1. **Update version** in appropriate files
2. **Create git tag** (`git tag -a v1.0.0 -m "Release v1.0.0"`)
3. **Push tag** (`git push origin v1.0.0`)
4. **GitHub Actions** will automatically build and release

### Release Artifacts

Automated releases include:

- Linux AMD64/ARM64 binaries
- Windows AMD64 binary
- macOS AMD64/ARM64 binaries
- Checksums file
- Release notes

## Troubleshooting

### Common Issues

**Build Failures**
```bash
# Clean and rebuild
make clean
go mod tidy
make build
```

**Test Certificate Issues**
```bash
# Regenerate test certificates
rm -rf test-certs/
./scripts/generate-test-certs.sh
```

**Permission Errors**
```bash
# Fix test certificate permissions
chmod 644 test-certs/*.pem
```

**Port Already in Use**
```bash
# Find process using port 3000
lsof -i :3000

# Use different port
export PORT="3001"
make run
```

### Getting Help

- **Check Issues**: [GitHub Issues](https://github.com/brandonhon/cert-monitor/issues)
- **Read Documentation**: Project README and code comments
- **Ask Questions**: Create an issue with the "question" label

## Performance Considerations

### Optimization Tips

- **Worker Count**: Set to number of CPU cores for CPU-bound workloads
- **Cache Size**: Monitor memory usage with large certificate inventories
- **Scan Frequency**: Balance between freshness and performance
- **Log Level**: Use appropriate log levels in production

### Monitoring Development Performance

```bash
# Monitor resource usage
make run &
top -p $!

# Profile memory allocations
go tool pprof http://localhost:3000/debug/pprof/allocs

# Monitor goroutines
go tool pprof http://localhost:3000/debug/pprof/goroutine
```

This guide should evolve as the project grows. Keep it updated with new development practices and tooling.
