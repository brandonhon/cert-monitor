// # internal/config/config.go
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// Config holds runtime settings
type Config struct {
	CertDirs                []string `yaml:"cert_dirs"`
	LogFile                 string   `yaml:"log_file"`
	Port                    string   `yaml:"port"`
	BindAddress             string   `yaml:"bind_address"`
	NumWorkers              int      `yaml:"num_workers"`
	DryRun                  bool     `yaml:"dry_run"`
	ExpiryThresholdDays     int      `yaml:"expiry_threshold_days"`
	ClearCacheOnReload      bool     `yaml:"clear_cache_on_reload"`
	TLSCertFile             string   `yaml:"tls_cert_file"`
	TLSKeyFile              string   `yaml:"tls_key_file"`
	EnablePprof             bool     `yaml:"enable_pprof"`
	EnableRuntimeMetrics    bool     `yaml:"enable_runtime_metrics"`
	EnableWeakCryptoMetrics bool     `yaml:"enable_weak_crypto_metrics"`
	CacheFile               string   `yaml:"cache_file"`
	ConfigFile              string   // Not from YAML, set via flag
}

var (
	config      *Config
	configMutex sync.RWMutex
)

// Default returns a config with default values
func Default() *Config {
	return &Config{
		CertDirs:            []string{"./certs"},
		LogFile:             defaultLogPath(),
		Port:                "3000",
		BindAddress:         "0.0.0.0",
		NumWorkers:          4,
		DryRun:              false,
		ExpiryThresholdDays: 45,
		ClearCacheOnReload:  false,
		TLSCertFile:         "",
		TLSKeyFile:          "",
		CacheFile:           "/var/lib/cert-monitor/cache.json",
	}
}

// Load loads configuration from a YAML file
func Load(path string) error {
	if path == "" {
		log.Debug("No config path provided, using defaults")
		Set(Default())
		return nil
	}
	
	// Validate file exists and is readable
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("config file does not exist: %q", path)
		}
		return fmt.Errorf("cannot access config file %q: %w", path, err)
	}
	
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file %q: %w", path, err)
	}
	
	// Parse into a temporary config first
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("failed to parse config file %q: %w", path, err)
	}
	
	// Validate the parsed configuration
	if err := Validate(cfg); err != nil {
		return fmt.Errorf("invalid configuration in %q: %w", path, err)
	}
	
	// Store the config
	Set(cfg)
	
	log.WithFields(log.Fields{
		"config_file": path,
		"cert_dirs":   len(cfg.CertDirs),
		"port":        cfg.Port,
		"workers":     cfg.NumWorkers,
	}).Info("Configuration loaded successfully")
	
	return nil
}

// Validate performs comprehensive validation of configuration values
func Validate(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}
	
	if len(cfg.CertDirs) == 0 {
		return fmt.Errorf("no certificate directories specified")
	}
	
	// Validate certificate directories
	for i, dir := range cfg.CertDirs {
		if dir == "" {
			return fmt.Errorf("certificate directory %d is empty", i)
		}
		
		info, err := os.Stat(dir)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("certificate directory does not exist: %q", dir)
			}
			return fmt.Errorf("cannot access certificate directory %q: %w", dir, err)
		}
		
		if !info.IsDir() {
			return fmt.Errorf("certificate path is not a directory: %q", dir)
		}
		
		// Check if directory is readable
		if _, err := os.ReadDir(dir); err != nil {
			return fmt.Errorf("cannot read certificate directory %q: %w", dir, err)
		}
	}
	
	if cfg.Port == "" {
		return fmt.Errorf("metrics port is not set")
	}
	
	// Validate port
	if port, err := strconv.Atoi(cfg.Port); err != nil {
		return fmt.Errorf("invalid port number %q: %w", cfg.Port, err)
	} else if port < 1 || port > 65535 {
		return fmt.Errorf("port number %d is out of valid range (1-65535)", port)
	}
	
	// Validate worker count
	if cfg.NumWorkers < 1 {
		return fmt.Errorf("number of workers must be at least 1, got %d", cfg.NumWorkers)
	}
	if cfg.NumWorkers > 100 {
		return fmt.Errorf("number of workers %d seems excessive (max recommended: 100)", cfg.NumWorkers)
	}
	
	// Validate expiry threshold
	if cfg.ExpiryThresholdDays < 1 {
		return fmt.Errorf("expiry threshold days must be at least 1, got %d", cfg.ExpiryThresholdDays)
	}
	if cfg.ExpiryThresholdDays > 365 {
		return fmt.Errorf("expiry threshold days %d seems excessive (max recommended: 365)", cfg.ExpiryThresholdDays)
	}
	
	// Validate TLS configuration
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		if cfg.TLSCertFile == "" {
			return fmt.Errorf("TLS certificate file must be specified when TLS key file is provided")
		}
		if cfg.TLSKeyFile == "" {
			return fmt.Errorf("TLS key file must be specified when TLS certificate file is provided")
		}
		
		if _, err := os.Stat(cfg.TLSCertFile); err != nil {
			return fmt.Errorf("cannot access TLS certificate file %q: %w", cfg.TLSCertFile, err)
		}
		if _, err := os.Stat(cfg.TLSKeyFile); err != nil {
			return fmt.Errorf("cannot access TLS key file %q: %w", cfg.TLSKeyFile, err)
		}
	}
	
	// Validate log file directory
	if cfg.LogFile != "" {
		logDir := filepath.Dir(cfg.LogFile)
		if logDir != "" && logDir != "." {
			if err := os.MkdirAll(logDir, 0o755); err != nil {
				return fmt.Errorf("cannot create log directory %q: %w", logDir, err)
			}
		}
	}
	
	// Validate cache file directory
	if cfg.CacheFile != "" {
		cacheDir := filepath.Dir(cfg.CacheFile)
		if cacheDir != "" && cacheDir != "." {
			if err := os.MkdirAll(cacheDir, 0o755); err != nil {
				return fmt.Errorf("cannot create cache directory %q: %w", cacheDir, err)
			}
		}
	}
	
	return nil
}

// Get safely returns a copy of the global config
func Get() *Config {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return config
}

// Set safely updates the global config
func Set(cfg *Config) {
	configMutex.Lock()
	defer configMutex.Unlock()
	config = cfg
}

func defaultLogPath() string {
	if isWindows() {
		return "C:\\Logs\\cert-monitor.log"
	}
	return "/var/log/cert-monitor.log"
}

func isWindows() bool {
	return strings.Contains(strings.ToLower(os.Getenv("OS")), "windows") || os.PathSeparator == '\\'
}
