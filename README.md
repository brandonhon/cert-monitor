# Cert Monitor

A robust, production-ready SSL/TLS certificate monitoring tool that scans directories for certificates and exposes detailed Prometheus metrics about their status, expiration dates, cryptographic strength, and more.

## Features

### Core Functionality
- **Certificate Discovery**: Automatically scans specified directories for SSL/TLS certificates
- **Multi-format Support**: Handles PEM, CRT, CER, and DER certificate formats
- **Leaf Certificate Focus**: Processes only leaf certificates from certificate chains
- **Real-time Monitoring**: File system watching for automatic certificate updates and removals
- **Hot Configuration Reload**: Update settings without restarting the service
- **Multi-Platform**: Works on Linux, Windows, and macOS

### Configuration Management
- **Automatic File Watching**: Detects configuration file changes and reloads automatically
- **Manual Reload API**: Trigger configuration reloads via HTTP endpoint
- **Intelligent Change Detection**: Identifies which settings can be hot-reloaded vs require restart
- **Zero-Downtime Updates**: Certificate monitoring continues during configuration updates
- **Environment Variables**: All configuration options support environment variable overrides
- **CLI Flags**: Full command-line interface for configuration

### Metrics & Observability
- **Prometheus Integration**: Comprehensive metrics for monitoring and alerting
- **Certificate Expiration**: Tracks expiration timestamps with configurable thresholds
- **Cryptographic Analysis**: Detects weak keys and deprecated signature algorithms
- **Duplicate Detection**: Identifies certificate duplicates across directories
- **SAN Analysis**: Subject Alternative Names detection and counting
- **Performance Metrics**: Scan duration, cache hit ratios, and system resource usage
- **Health Endpoints**: Comprehensive health checks and status reporting

### Production Ready
- **High Performance**: Multi-threaded processing with configurable worker pools
- **Smart Caching**: Efficient caching system to minimize redundant certificate parsing
- **Graceful Degradation**: Continues operating despite individual certificate errors
- **Resource Management**: Memory limits, backoff strategies, and cleanup routines
- **Security**: Supports TLS endpoints, runs with minimal privileges
- **Observability**: Structured logging with rotation and comprehensive metrics

## Quick Start

### Installation

#### From Source
```bash
git clone https://github.com/yourusername/cert-monitor.git
cd cert-monitor
go build -o cert-monitor
```

#### Using Go Install
```bash
go install github.com/yourusername/cert-monitor@latest
```

### Basic Usage

```bash
# Scan certificates in /etc/ssl/certs and start metrics server
./cert-monitor -cert-dir /etc/ssl/certs -port 3000

# Multiple directories with custom configuration
./cert-monitor -config config.yaml

# Dry run to test configuration
./cert-monitor -cert-dir /path/to/certs -dry-run
```

### Configuration

#### YAML Configuration File
```yaml
# config.yaml
cert_dirs:
  - "/etc/ssl/certs"
  - "/usr/local/share/ca-certificates"
port: "3000"
bind_address: "0.0.0.0"
num_workers: 4
expiry_threshold_days: 30
log_file: "/var/log/cert-monitor.log"
cache_file: "/var/lib/cert-monitor/cache.json"
enable_runtime_metrics: true
enable_weak_crypto_metrics: true
```

#### Environment Variables
```bash
export CERT_DIRS="/etc/ssl/certs:/usr/local/certs"
export PORT="3000"
export NUM_WORKERS="4"
export EXPIRY_THRESHOLD_DAYS="30"
./cert-monitor
```

#### Command Line Flags
```bash
./cert-monitor \
  -cert-dir /etc/ssl/certs \
  -cert-dir /usr/local/certs \
  -port 3000 \
  -workers 4 \
  -expiry-threshold-days 30 \
  -log-file /var/log/cert-monitor.log
```

## API Endpoints

### Metrics
- `GET /metrics` - Prometheus metrics endpoint
- `GET /healthz` - Health check with detailed status
- `GET /certs` - JSON API for certificate information

### Management
- `POST /reload` - Trigger configuration reload
- `GET /config` - Current configuration status

## Prometheus Metrics

### Certificate Metrics
- `ssl_cert_expiration_timestamp` - Certificate expiration time (Unix timestamp)
- `ssl_cert_san_count` - Number of Subject Alternative Names
- `ssl_cert_info` - Certificate information with labels
- `ssl_cert_duplicate_count` - Number of duplicate certificates
- `ssl_cert_issuer_code` - Numeric issuer classification

### Cryptographic Security
- `ssl_cert_weak_key_total` - Certificates with weak cryptographic keys
- `ssl_cert_deprecated_sigalg_total` - Certificates using deprecated signature algorithms

### Operational Metrics
- `ssl_cert_files_total` - Total certificate files processed
- `ssl_certs_parsed_total` - Successfully parsed certificates
- `ssl_cert_parse_errors_total` - Certificate parsing errors
- `ssl_cert_scan_duration_seconds` - Directory scan duration
- `ssl_cert_last_scan_timestamp` - Last successful scan time

## Configuration Options

| Option | CLI Flag | Environment | Description |
|--------|----------|-------------|-------------|
| Certificate Directories | `-cert-dir` | `CERT_DIRS` | Directories to scan (colon-separated for env) |
| Port | `-port` | `PORT` | HTTP server port |
| Bind Address | `-bind-address` | `BIND_ADDRESS` | HTTP server bind address |
| Workers | `-workers` | `NUM_WORKERS` | Number of worker threads |
| Log File | `-log-file` | `LOG_FILE` | Log file path |
| Config File | `-config` | - | YAML configuration file |
| Dry Run | `-dry-run` | `DRY_RUN` | Test mode (no metrics) |
| Expiry Threshold | `-expiry-threshold-days` | `EXPIRY_THRESHOLD_DAYS` | Days to consider certificate expiring |
| TLS Certificate | `-tls-cert-file` | `TLS_CERT_FILE` | TLS certificate for HTTPS |
| TLS Key | `-tls-key-file` | `TLS_KEY_FILE` | TLS private key for HTTPS |

## Monitoring and Alerting

### Grafana Dashboard
Import the provided Grafana dashboard to visualize:
- Certificate expiration timeline
- Cryptographic strength distribution
- Scan performance metrics
- Error rates and health status

### Prometheus Alerting Rules
```yaml
# Example alerting rules
- alert: CertificateExpiringSoon
  expr: ssl_cert_expiration_timestamp - time() < 7 * 24 * 3600
  for: 1h
  labels:
    severity: warning
  annotations:
    summary: "Certificate {{ $labels.common_name }} expires in less than 7 days"

- alert: WeakCryptographicKeys
  expr: increase(ssl_cert_weak_key_total[1h]) > 0
  for: 0m
  labels:
    severity: critical
  annotations:
    summary: "Weak cryptographic keys detected"
```

## Development

### Building from Source
```bash
go mod download
go build -ldflags "-X main.Version=$(git describe --tags) -X main.Commit=$(git rev-parse HEAD)" -o cert-monitor
```

### Running Tests
```bash
go test ./...
go test -race ./...
go test -cover ./...
```

### Development Mode
```bash
# Run with debug logging and dry-run mode
./cert-monitor -cert-dir ./test-certs -dry-run -log-file ""
```

## Deployment

### Docker
```dockerfile
# Example Dockerfile usage
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY cert-monitor .
EXPOSE 3000
CMD ["./cert-monitor"]
```

### Systemd Service
```ini
# /etc/systemd/system/cert-monitor.service
[Unit]
Description=SSL Certificate Monitor
After=network.target

[Service]
Type=simple
User=cert-monitor
ExecStart=/usr/local/bin/cert-monitor -config /etc/cert-monitor/config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Security Considerations

- Run with dedicated non-root user
- Restrict file system permissions
- Use TLS for metrics endpoint in production
- Monitor log files for security events
- Regular security updates and dependency scanning

## Performance Tuning

- Adjust worker count based on CPU cores and I/O characteristics
- Configure cache settings for large certificate inventories
- Monitor memory usage and adjust limits accordingly
- Use SSD storage for cache files in high-throughput environments

## Troubleshooting

### Common Issues

**Permission Errors**
```bash
# Ensure proper permissions for certificate directories
sudo chown -R cert-monitor:cert-monitor /path/to/certs
chmod -R 755 /path/to/certs
```

**High Memory Usage**
```bash
# Monitor memory usage
./cert-monitor -enable-pprof
# Visit http://localhost:3000/debug/pprof/heap
```

**Configuration Validation**
```bash
# Validate configuration before deployment
./cert-monitor -config config.yaml -check-config
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following the development guidelines
4. Add tests for new functionality
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: Report bugs and request features via [GitHub Issues](https://github.com/yourusername/cert-monitor/issues)
- **Documentation**: Additional documentation available in the [docs](docs/) directory
- **Community**: Join discussions in [GitHub Discussions](https://github.com/yourusername/cert-monitor/discussions)
