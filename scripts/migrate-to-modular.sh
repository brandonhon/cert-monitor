#!/bin/bash
# Migration script to convert monolithic main.go to modular architecture

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🏗️  Starting migration to modular architecture...${NC}"

# Ensure we're in the right directory
if [ ! -f "main.go" ]; then
    echo -e "${RED}❌ main.go not found. Please run from project root.${NC}"
    exit 1
fi

# Create backup
echo -e "${BLUE}📋 Creating backup of current main.go...${NC}"
cp main.go main.go.backup
echo -e "${GREEN}✅ Backup created: main.go.backup${NC}"

# Create modular directory structure from MODULAR_ARCHITECTURE.md
echo -e "${BLUE}📁 Creating modular package structure...${NC}"

directories=(
    "cmd/cert-monitor"
    "internal/config"
    "internal/certificate"
    "internal/metrics"
    "internal/cache"
    "internal/watcher"
    "internal/server"
    "internal/worker"
    "internal/state"
    "pkg/logger"
    "pkg/utils"
    "test/integration"
    "test/fixtures"
    "test/mocks"
)

for dir in "${directories[@]}"; do
    mkdir -p "$dir"
    echo -e "${GREEN}✅${NC} Created: $dir"
done

for dir in "${directories[@]}"; do
    mkdir -p "$dir"
    echo -e "${GREEN}✅${NC} Created: $dir"
done

# Create package files with basic structure
echo -e "${BLUE}📝 Creating package template files...${NC}"

# cmd/cert-monitor/main.go
cat > cmd/cert-monitor/main.go << 'EOF'
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/brandonhon/cert-monitor/internal/config"
	"github.com/brandonhon/cert-monitor/internal/server"
	"github.com/brandonhon/cert-monitor/pkg/logger"
)

var (
	Version = "dev"
	Commit  = "none"
)

func main() {
	var (
		configFile = flag.String("config", "", "Configuration file path")
		showVersion = flag.Bool("version", false, "Show version information")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("cert-monitor %s (commit: %s)\n", Version, Commit)
		os.Exit(0)
	}

	// Initialize logger
	logger.Init()

	// Load configuration
	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Setup context for graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Initialize and start services
	// TODO: Replace with actual service initialization
	srv := server.New(cfg.Server)
	
	if err := srv.Start(ctx); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	log.Println("cert-monitor started successfully")

	// Wait for shutdown signal
	<-ctx.Done()
	log.Println("Shutting down...")

	// Graceful shutdown
	if err := srv.Stop(context.Background()); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	log.Println("cert-monitor stopped")
}
EOF

# internal/config/config.go
cat > internal/config/config.go << 'EOF'
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	CertDirs                []string      `yaml:"cert_dirs"`
	LogFile                 string        `yaml:"log_file"`
	Port                    string        `yaml:"port"`
	BindAddress             string        `yaml:"bind_address"`
	NumWorkers              int           `yaml:"num_workers"`
	DryRun                  bool          `yaml:"dry_run"`
	ExpiryThresholdDays     int           `yaml:"expiry_threshold_days"`
	ClearCacheOnReload      bool          `yaml:"clear_cache_on_reload"`
	TLSCertFile             string        `yaml:"tls_cert_file"`
	TLSKeyFile              string        `yaml:"tls_key_file"`
	EnablePprof             bool          `yaml:"enable_pprof"`
	EnableRuntimeMetrics    bool          `yaml:"enable_runtime_metrics"`
	EnableWeakCryptoMetrics bool          `yaml:"enable_weak_crypto_metrics"`
	CacheFile               string        `yaml:"cache_file"`
	Server                  ServerConfig  `yaml:"server"`
	Certificate             CertConfig    `yaml:"certificate"`
	Cache                   CacheConfig   `yaml:"cache"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Port        string `yaml:"port"`
	BindAddress string `yaml:"bind_address"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	EnablePprof bool   `yaml:"enable_pprof"`
}

// CertConfig holds certificate processing configuration
type CertConfig struct {
	Dirs                []string `yaml:"dirs"`
	ExpiryThresholdDays int      `yaml:"expiry_threshold_days"`
	NumWorkers          int      `yaml:"num_workers"`
	EnableWeakCrypto    bool     `yaml:"enable_weak_crypto_metrics"`
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	File               string `yaml:"file"`
	ClearOnReload      bool   `yaml:"clear_on_reload"`
}

// Load loads configuration from file
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()
	
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		CertDirs:            []string{"./certs"},
		Port:                "3000",
		BindAddress:         "0.0.0.0",
		NumWorkers:          4,
		ExpiryThresholdDays: 45,
		CacheFile:           "/var/lib/cert-monitor/cache.json",
		Server: ServerConfig{
			Port:        "3000",
			BindAddress: "0.0.0.0",
		},
		Certificate: CertConfig{
			Dirs:                []string{"./certs"},
			ExpiryThresholdDays: 45,
			NumWorkers:          4,
		},
		Cache: CacheConfig{
			File: "/var/lib/cert-monitor/cache.json",
		},
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// TODO: Implement validation logic
	return nil
}
EOF

# internal/config/validation.go
cat > internal/config/validation.go << 'EOF'
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field  string
	Value  interface{}
	Reason string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation failed for field %s: %s", e.Field, e.Reason)
}

// ValidateConfig performs comprehensive configuration validation
func ValidateConfig(cfg *Config) error {
	if err := validateCertDirs(cfg.CertDirs); err != nil {
		return err
	}

	if err := validateServer(cfg.Server); err != nil {
		return err
	}

	if err := validateWorkers(cfg.NumWorkers); err != nil {
		return err
	}

	return nil
}

func validateCertDirs(dirs []string) error {
	if len(dirs) == 0 {
		return ValidationError{
			Field:  "cert_dirs",
			Value:  dirs,
			Reason: "at least one certificate directory must be specified",
		}
	}

	for i, dir := range dirs {
		if dir == "" {
			return ValidationError{
				Field:  fmt.Sprintf("cert_dirs[%d]", i),
				Value:  dir,
				Reason: "directory path cannot be empty",
			}
		}

		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return ValidationError{
				Field:  fmt.Sprintf("cert_dirs[%d]", i),
				Value:  dir,
				Reason: "directory does not exist",
			}
		}
	}

	return nil
}

func validateServer(cfg ServerConfig) error {
	// Validate port
	port, err := strconv.Atoi(cfg.Port)
	if err != nil {
		return ValidationError{
			Field:  "server.port",
			Value:  cfg.Port,
			Reason: "invalid port number",
		}
	}

	if port < 1 || port > 65535 {
		return ValidationError{
			Field:  "server.port",
			Value:  port,
			Reason: "port must be between 1 and 65535",
		}
	}

	// Validate bind address
	if cfg.BindAddress != "" {
		if ip := net.ParseIP(cfg.BindAddress); ip == nil {
			return ValidationError{
				Field:  "server.bind_address",
				Value:  cfg.BindAddress,
				Reason: "invalid IP address",
			}
		}
	}

	return nil
}

func validateWorkers(workers int) error {
	if workers < 1 {
		return ValidationError{
			Field:  "num_workers",
			Value:  workers,
			Reason: "must be at least 1",
		}
	}

	if workers > 100 {
		return ValidationError{
			Field:  "num_workers",
			Value:  workers,
			Reason: "excessive number of workers (max recommended: 100)",
		}
	}

	return nil
}
EOF

# pkg/logger/logger.go
cat > pkg/logger/logger.go << 'EOF'
package logger

import (
	"io"
	"os"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Config holds logger configuration
type Config struct {
	File     string
	Level    string
	DryRun   bool
}

// Init initializes the logger with default settings
func Init() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	log.SetLevel(log.InfoLevel)
}

// InitWithConfig initializes the logger with specific configuration
func InitWithConfig(cfg Config) error {
	// Set log level
	level, err := log.ParseLevel(cfg.Level)
	if err != nil {
		level = log.InfoLevel
	}
	log.SetLevel(level)

	// Configure output
	if cfg.File != "" {
		logWriter := &lumberjack.Logger{
			Filename:   cfg.File,
			MaxSize:    25, // megabytes
			MaxBackups: 3,
			MaxAge:     28, // days
			Compress:   true,
		}

		if cfg.DryRun {
			log.SetOutput(io.MultiWriter(os.Stdout, logWriter))
		} else {
			log.SetOutput(logWriter)
		}
	}

	// Configure formatter
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		DisableColors: !cfg.DryRun,
	})

	return nil
}
EOF

# Update go.mod to include cmd directory
echo -e "${BLUE}📝 Updating go.mod...${NC}"
if ! grep -q "cmd/cert-monitor" go.mod 2>/dev/null; then
    echo -e "${YELLOW}⚠️  Note: You may need to update your go.mod after migration${NC}"
fi

# Create migration status file
cat > MIGRATION_STATUS.md << 'EOF'
# Migration Status

## Phase 1: Package Structure ✅
- [x] Created modular directory structure
- [x] Basic package templates created
- [x] Backup of original main.go created

## Next Steps

### Phase 2: Extract Core Logic
1. Move configuration logic to `internal/config/`
2. Extract certificate processing to `internal/certificate/`
3. Separate metrics logic to `internal/metrics/`

### Phase 3: Advanced Components
1. Extract cache management to `internal/cache/`
2. Move HTTP server logic to `internal/server/`
3. Separate file watching to `internal/watcher/`

### Phase 4: Testing and Documentation
1. Add unit tests for each package
2. Create integration tests
3. Update documentation

## Files to Migrate

- [ ] Configuration management (GlobalState, Config functions)
- [ ] Certificate processing (processCertificateDirectory, etc.)
- [ ] Metrics collection (MetricsCollector, updateCertificateMetrics)
- [ ] Cache management (getCacheEntryAtomic, etc.)
- [ ] HTTP server (healthHandler, certsHandler, etc.)
- [ ] File watching (setupFileSystemWatcher, etc.)
- [ ] Worker pool (runMainProcessingLoop, etc.)

## Testing Strategy

After each phase:
1. Ensure code compiles
2. Run existing tests
3. Verify functionality works
4. Add new unit tests for extracted packages
EOF

echo -e "${GREEN}✅ Modular package structure created successfully!${NC}"
echo ""
echo -e "${BLUE}📋 Migration Status:${NC}"
echo "- ✅ Phase 1: Package structure created"
echo "- 📋 Backup: main.go.backup"
echo "- 📄 Status: MIGRATION_STATUS.md"
echo ""
echo -e "${YELLOW}⚠️  Next Steps:${NC}"
echo "1. Review the created package structure"
echo "2. Begin Phase 2: Extract core logic from main.go"
echo "3. Follow the migration plan in MODULAR_ARCHITECTURE.md"
echo "4. Test after each phase to ensure functionality is preserved"
echo ""
echo -e "${BLUE}💡 Tip:${NC} Start with small, incremental changes and test frequently!"