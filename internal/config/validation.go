package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	customerrors "github.com/brandonhon/cert-monitor/pkg/errors"
	"github.com/brandonhon/cert-monitor/pkg/utils"
)

// Validator interface for configuration validation
type Validator interface {
	Validate() error
}

// Validate performs comprehensive configuration validation
func (c *Config) Validate() error {
	if c == nil {
		return customerrors.NewValidationError("config", nil, "configuration cannot be nil")
	}

	// Collect all validation errors
	var validationErrors []error

	// Validate certificate directories
	if err := c.validateCertDirs(); err != nil {
		validationErrors = append(validationErrors, err)
	}

	// Validate server configuration
	if err := c.validateServer(); err != nil {
		validationErrors = append(validationErrors, err)
	}

	// Validate worker configuration
	if err := c.validateWorkers(); err != nil {
		validationErrors = append(validationErrors, err)
	}

	// Validate thresholds
	if err := c.validateThresholds(); err != nil {
		validationErrors = append(validationErrors, err)
	}

	// Validate file paths
	if err := c.validateFilePaths(); err != nil {
		validationErrors = append(validationErrors, err)
	}

	// Return combined errors if any
	if len(validationErrors) > 0 {
		var errorMessages []string
		for _, err := range validationErrors {
			errorMessages = append(errorMessages, err.Error())
		}
		return fmt.Errorf("configuration validation failed: %s", strings.Join(errorMessages, "; "))
	}

	return nil
}

// Validate is a standalone function for backward compatibility
func Validate(cfg *Config) error {
	return cfg.Validate()
}

// validateCertDirs validates certificate directory configuration
func (c *Config) validateCertDirs() error {
	if len(c.CertDirs) == 0 {
		return customerrors.NewValidationError("cert_dirs", c.CertDirs, "at least one directory required")
	}

	for i, dir := range c.CertDirs {
		if strings.TrimSpace(dir) == "" {
			return customerrors.NewValidationError(
				fmt.Sprintf("cert_dirs[%d]", i),
				dir,
				"directory path cannot be empty",
			)
		}

		// Check if directory exists and is accessible
		if _, err := os.Stat(dir); err != nil {
			return customerrors.NewValidationError(
				fmt.Sprintf("cert_dirs[%d]", i),
				dir,
				fmt.Sprintf("directory not accessible: %v", err),
			)
		}
	}

	return nil
}

// validateServer validates server configuration
func (c *Config) validateServer() error {
	// Validate port
	if c.Port == "" {
		return customerrors.NewValidationError("port", c.Port, "port cannot be empty")
	}

	if port, err := strconv.Atoi(c.Port); err != nil {
		return customerrors.NewValidationError("port", c.Port, fmt.Sprintf("invalid port number: %v", err))
	} else if port < 1 || port > 65535 {
		return customerrors.NewValidationError("port", c.Port, "port must be between 1 and 65535")
	}

	// Validate bind address
	if c.BindAddress != "" && c.BindAddress != "0.0.0.0" {
		if ip := net.ParseIP(c.BindAddress); ip == nil {
			return customerrors.NewValidationError("bind_address", c.BindAddress, "invalid IP address")
		}
	}

	// Validate TLS configuration if provided
	if c.TLSCertFile != "" || c.TLSKeyFile != "" {
		if c.TLSCertFile == "" {
			return customerrors.NewValidationError("tls_cert_file", c.TLSCertFile, "TLS cert file required when TLS key file is specified")
		}
		if c.TLSKeyFile == "" {
			return customerrors.NewValidationError("tls_key_file", c.TLSKeyFile, "TLS key file required when TLS cert file is specified")
		}

		// Check if TLS files exist and are accessible
		if err := utils.ValidateFileAccess(c.TLSCertFile); err != nil {
			return customerrors.NewValidationError("tls_cert_file", c.TLSCertFile, fmt.Sprintf("file not accessible: %v", err))
		}
		if err := utils.ValidateFileAccess(c.TLSKeyFile); err != nil {
			return customerrors.NewValidationError("tls_key_file", c.TLSKeyFile, fmt.Sprintf("file not accessible: %v", err))
		}
	}

	return nil
}

// validateWorkers validates worker configuration
func (c *Config) validateWorkers() error {
	if c.NumWorkers < 1 {
		return customerrors.NewValidationError("num_workers", c.NumWorkers, "must be at least 1")
	}

	if c.NumWorkers > 100 {
		return customerrors.NewValidationError("num_workers", c.NumWorkers, "excessive number of workers (max recommended: 100)")
	}

	return nil
}

// validateThresholds validates threshold configuration
func (c *Config) validateThresholds() error {
	if c.ExpiryThresholdDays < 0 {
		return customerrors.NewValidationError("expiry_threshold_days", c.ExpiryThresholdDays, "cannot be negative")
	}

	if c.ExpiryThresholdDays > 365 {
		return customerrors.NewValidationError("expiry_threshold_days", c.ExpiryThresholdDays, "excessive threshold (max recommended: 365 days)")
	}

	return nil
}

// validateFilePaths validates file path configuration
func (c *Config) validateFilePaths() error {
	// Validate log file path
	if c.LogFile != "" {
		logDir := filepath.Dir(c.LogFile)
		if _, err := os.Stat(logDir); err != nil && os.IsNotExist(err) {
			// Try to create directory if it doesn't exist
			if err := os.MkdirAll(logDir, 0o755); err != nil {
				return customerrors.NewValidationError("log_file", c.LogFile,
					fmt.Sprintf("cannot create log directory: %v", err))
			}
		}
	}

	// Validate cache file path
	if c.CacheFile != "" {
		cacheDir := filepath.Dir(c.CacheFile)
		if _, err := os.Stat(cacheDir); err != nil && os.IsNotExist(err) {
			// Try to create directory if it doesn't exist
			if err := os.MkdirAll(cacheDir, 0o755); err != nil {
				return customerrors.NewValidationError("cache_file", c.CacheFile,
					fmt.Sprintf("cannot create cache directory: %v", err))
			}
		}
	}

	return nil
}
