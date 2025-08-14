package config

import (
	"fmt"
	"os"

	"github.com/brandonhon/cert-monitor/pkg/utils"
	// customerrors "github.com/brandonhon/cert-monitor/pkg/errors"
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
func Compare(old, newCfg *Config) Diff {
	return Diff{
		CertDirsChanged:          !equalStringSlices(old.CertDirs, newCfg.CertDirs),
		LogFileChanged:           old.LogFile != newCfg.LogFile,
		PortChanged:              old.Port != newCfg.Port,
		BindAddressChanged:       old.BindAddress != newCfg.BindAddress,
		NumWorkersChanged:        old.NumWorkers != newCfg.NumWorkers,
		TLSConfigChanged:         old.TLSCertFile != newCfg.TLSCertFile || old.TLSKeyFile != newCfg.TLSKeyFile,
		RuntimeMetricsChanged:    old.EnableRuntimeMetrics != newCfg.EnableRuntimeMetrics,
		WeakCryptoMetricsChanged: old.EnableWeakCryptoMetrics != newCfg.EnableWeakCryptoMetrics,
		PprofChanged:             old.EnablePprof != newCfg.EnablePprof,
		CacheFileChanged:         old.CacheFile != newCfg.CacheFile,
		ExpiryThresholdChanged:   old.ExpiryThresholdDays != newCfg.ExpiryThresholdDays,
		ClearCacheChanged:        old.ClearCacheOnReload != newCfg.ClearCacheOnReload,
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
