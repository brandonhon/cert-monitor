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
