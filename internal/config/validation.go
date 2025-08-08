package config

import (
	"fmt"
	"net"
	"path/filepath"
	"strconv"

	"github.com/brandonhon/cert-monitor/pkg/utils"
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

// Validate performs comprehensive configuration validation
func Validate(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}

	if err := validateCertDirectories(cfg.CertDirs); err != nil {
		return err
	}

	if err := validateNetworkConfig(cfg.Port, cfg.BindAddress); err != nil {
		return err
	}

	if err := validateWorkerConfig(cfg.NumWorkers, cfg.ExpiryThresholdDays); err != nil {
		return err
	}

	if err := validateTLSConfig(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
		return err
	}

	if err := validateFileConfig(cfg.LogFile, cfg.CacheFile); err != nil {
		return err
	}

	return nil
}

// validateCertDirectories validates certificate directory configuration
func validateCertDirectories(certDirs []string) error {
	if len(certDirs) == 0 {
		return ValidationError{
			Field:  "cert_dirs",
			Value:  certDirs,
			Reason: "no certificate directories specified",
		}
	}

	for i, dir := range certDirs {
		if dir == "" {
			return ValidationError{
				Field:  fmt.Sprintf("cert_dirs[%d]", i),
				Value:  dir,
				Reason: "certificate directory is empty",
			}
		}

		if err := utils.ValidateDirectoryAccess(dir); err != nil {
			return ValidationError{
				Field:  fmt.Sprintf("cert_dirs[%d]", i),
				Value:  dir,
				Reason: fmt.Sprintf("directory validation failed: %v", err),
			}
		}
	}

	return nil
}

// validateNetworkConfig validates network-related configuration
func validateNetworkConfig(port, bindAddress string) error {
	if port == "" {
		return ValidationError{
			Field:  "port",
			Value:  port,
			Reason: "metrics port is not set",
		}
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		return ValidationError{
			Field:  "port",
			Value:  port,
			Reason: fmt.Sprintf("invalid port number: %v", err),
		}
	}

	if portNum < 1 || portNum > 65535 {
		return ValidationError{
			Field:  "port",
			Value:  portNum,
			Reason: "port number is out of valid range (1-65535)",
		}
	}

	// Validate bind address if specified
	if bindAddress != "" && bindAddress != "0.0.0.0" {
		if ip := net.ParseIP(bindAddress); ip == nil {
			return ValidationError{
				Field:  "bind_address",
				Value:  bindAddress,
				Reason: "invalid IP address",
			}
		}
	}

	return nil
}

// validateWorkerConfig validates worker and timing configuration
func validateWorkerConfig(numWorkers, expiryThresholdDays int) error {
	if numWorkers < 1 {
		return ValidationError{
			Field:  "num_workers",
			Value:  numWorkers,
			Reason: "number of workers must be at least 1",
		}
	}

	if numWorkers > 100 {
		return ValidationError{
			Field:  "num_workers",
			Value:  numWorkers,
			Reason: "number of workers seems excessive (max recommended: 100)",
		}
	}

	if expiryThresholdDays < 1 {
		return ValidationError{
			Field:  "expiry_threshold_days",
			Value:  expiryThresholdDays,
			Reason: "expiry threshold days must be at least 1",
		}
	}

	if expiryThresholdDays > 365 {
		return ValidationError{
			Field:  "expiry_threshold_days",
			Value:  expiryThresholdDays,
			Reason: "expiry threshold days seems excessive (max recommended: 365)",
		}
	}

	return nil
}

// validateTLSConfig validates TLS certificate configuration
func validateTLSConfig(tlsCertFile, tlsKeyFile string) error {
	// Both must be specified or both must be empty
	if (tlsCertFile != "") != (tlsKeyFile != "") {
		return ValidationError{
			Field:  "tls_config",
			Value:  fmt.Sprintf("cert=%s, key=%s", tlsCertFile, tlsKeyFile),
			Reason: "both TLS certificate and key files must be specified together",
		}
	}

	// If both are specified, validate they exist
	if tlsCertFile != "" && tlsKeyFile != "" {
		if err := utils.ValidateFileAccess(tlsCertFile); err != nil {
			return ValidationError{
				Field:  "tls_cert_file",
				Value:  tlsCertFile,
				Reason: fmt.Sprintf("TLS certificate file validation failed: %v", err),
			}
		}

		if err := utils.ValidateFileAccess(tlsKeyFile); err != nil {
			return ValidationError{
				Field:  "tls_key_file",
				Value:  tlsKeyFile,
				Reason: fmt.Sprintf("TLS key file validation failed: %v", err),
			}
		}
	}

	return nil
}

// validateFileConfig validates log and cache file configuration
func validateFileConfig(logFile, cacheFile string) error {
	if logFile != "" {
		logDir := filepath.Dir(logFile)
		if err := utils.ValidateDirectoryCreation(logDir); err != nil {
			return ValidationError{
				Field:  "log_file",
				Value:  logFile,
				Reason: fmt.Sprintf("log file directory validation failed: %v", err),
			}
		}
	}

	if cacheFile != "" {
		cacheDir := filepath.Dir(cacheFile)
		if err := utils.ValidateDirectoryCreation(cacheDir); err != nil {
			return ValidationError{
				Field:  "cache_file",
				Value:  cacheFile,
				Reason: fmt.Sprintf("cache file directory validation failed: %v", err),
			}
		}
	}

	return nil
}
