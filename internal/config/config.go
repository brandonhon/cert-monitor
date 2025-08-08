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
