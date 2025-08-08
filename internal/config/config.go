package config

import (
	"fmt"
	"os"

	"github.com/brandonhon/cert-monitor/pkg/utils"
	yaml "gopkg.in/yaml.v3"
)

// Load loads configuration from a YAML file with comprehensive validation
func Load(path string) (*Config, error) {
	cfg := Default()

	if path == "" {
		return cfg, nil
	}

	// Validate file accessibility
	if err := utils.ValidateFileAccess(path); err != nil {
		return nil, fmt.Errorf("config file validation failed: %w", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %q: %w", path, err)
	}

	if err := Validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration in %q: %w", path, err)
	}

	return cfg, nil
}

// Default returns a configuration with sensible defaults
func Default() *Config {
	return &Config{
		CertDirs:            []string{"./certs"},
		LogFile:             defaultLogPath(),
		Port:                DefaultPort,
		BindAddress:         DefaultBindAddress,
		NumWorkers:          DefaultWorkers,
		DryRun:              false,
		ExpiryThresholdDays: DefaultExpiryDays,
		ClearCacheOnReload:  false,
		TLSCertFile:         "",
		TLSKeyFile:          "",
		CacheFile:           DefaultCacheFile,
	}
}

// Compare compares two configurations and returns differences
func Compare(old, new *Config) Diff {
	return Diff{
		CertDirsChanged:          !equalStringSlices(old.CertDirs, new.CertDirs),
		LogFileChanged:           old.LogFile != new.LogFile,
		PortChanged:              old.Port != new.Port,
		BindAddressChanged:       old.BindAddress != new.BindAddress,
		NumWorkersChanged:        old.NumWorkers != new.NumWorkers,
		TLSConfigChanged:         old.TLSCertFile != new.TLSCertFile || old.TLSKeyFile != new.TLSKeyFile,
		RuntimeMetricsChanged:    old.EnableRuntimeMetrics != new.EnableRuntimeMetrics,
		WeakCryptoMetricsChanged: old.EnableWeakCryptoMetrics != new.EnableWeakCryptoMetrics,
		PprofChanged:             old.EnablePprof != new.EnablePprof,
		CacheFileChanged:         old.CacheFile != new.CacheFile,
		ExpiryThresholdChanged:   old.ExpiryThresholdDays != new.ExpiryThresholdDays,
		ClearCacheChanged:        old.ClearCacheOnReload != new.ClearCacheOnReload,
	}
}

// Helper functions

func defaultLogPath() string {
	if utils.IsWindows() {
		return "C:\\Logs\\cert-monitor.log"
	}
	return "/var/log/cert-monitor.log"
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	mapA := make(map[string]bool)
	mapB := make(map[string]bool)

	for _, str := range a {
		mapA[str] = true
	}

	for _, str := range b {
		mapB[str] = true
	}

	for str := range mapA {
		if !mapB[str] {
			return false
		}
	}

	return true
}
