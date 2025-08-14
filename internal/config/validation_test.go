package config

import (
	// "fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	// customerrors "github.com/brandonhon/cert-monitor/pkg/errors"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorField  string
	}{
		{
			name: "valid_config",
			config: &Config{
				CertDirs:            []string{"/tmp"},
				Port:                "3000",
				BindAddress:         "0.0.0.0",
				NumWorkers:          4,
				ExpiryThresholdDays: 30,
			},
			expectError: false,
		},
		{
			name: "nil_config",
			config:      nil,
			expectError: true,
			errorField:  "config",
		},
		{
			name: "empty_cert_dirs",
			config: &Config{
				CertDirs:            []string{},
				Port:                "3000",
				BindAddress:         "0.0.0.0",
				NumWorkers:          4,
				ExpiryThresholdDays: 30,
			},
			expectError: true,
			errorField:  "cert_dirs",
		},
		{
			name: "invalid_port",
			config: &Config{
				CertDirs:            []string{"/tmp"},
				Port:                "invalid",
				BindAddress:         "0.0.0.0",
				NumWorkers:          4,
				ExpiryThresholdDays: 30,
			},
			expectError: true,
			errorField:  "port",
		},
		{
			name: "port_out_of_range",
			config: &Config{
				CertDirs:            []string{"/tmp"},
				Port:                "99999",
				BindAddress:         "0.0.0.0",
				NumWorkers:          4,
				ExpiryThresholdDays: 30,
			},
			expectError: true,
			errorField:  "port",
		},
		{
			name: "invalid_bind_address",
			config: &Config{
				CertDirs:            []string{"/tmp"},
				Port:                "3000",
				BindAddress:         "invalid.ip",
				NumWorkers:          4,
				ExpiryThresholdDays: 30,
			},
			expectError: true,
			errorField:  "bind_address",
		},
		{
			name: "zero_workers",
			config: &Config{
				CertDirs:            []string{"/tmp"},
				Port:                "3000",
				BindAddress:         "0.0.0.0",
				NumWorkers:          0,
				ExpiryThresholdDays: 30,
			},
			expectError: true,
			errorField:  "num_workers",
		},
		{
			name: "excessive_workers",
			config: &Config{
				CertDirs:            []string{"/tmp"},
				Port:                "3000",
				BindAddress:         "0.0.0.0",
				NumWorkers:          150,
				ExpiryThresholdDays: 30,
			},
			expectError: true,
			errorField:  "num_workers",
		},
		{
			name: "negative_expiry_threshold",
			config: &Config{
				CertDirs:            []string{"/tmp"},
				Port:                "3000",
				BindAddress:         "0.0.0.0",
				NumWorkers:          4,
				ExpiryThresholdDays: -1,
			},
			expectError: true,
			errorField:  "expiry_threshold_days",
		},
		{
			name: "excessive_expiry_threshold",
			config: &Config{
				CertDirs:            []string{"/tmp"},
				Port:                "3000",
				BindAddress:         "0.0.0.0",
				NumWorkers:          4,
				ExpiryThresholdDays: 400,
			},
			expectError: true,
			errorField:  "expiry_threshold_days",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.config)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for %s, but got none", tt.name)
					return
				}

				// Check if it's a ValidationError and contains expected field
				if strings.Contains(err.Error(), tt.errorField) {
					t.Logf("Got expected error for field '%s': %v", tt.errorField, err)
				} else {
					t.Errorf("Expected error to contain field '%s', got: %v", tt.errorField, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for %s, but got: %v", tt.name, err)
				}
			}
		})
	}
}

func TestTLSConfigValidation(t *testing.T) {
	// Create temporary files for TLS testing
	tmpDir := t.TempDir()
	validCertFile := filepath.Join(tmpDir, "cert.pem")
	validKeyFile := filepath.Join(tmpDir, "key.pem")

	// Create valid cert and key files
	if err := os.WriteFile(validCertFile, []byte("dummy cert"), 0644); err != nil {
		t.Fatalf("Failed to create test cert file: %v", err)
	}
	if err := os.WriteFile(validKeyFile, []byte("dummy key"), 0644); err != nil {
		t.Fatalf("Failed to create test key file: %v", err)
	}

	tests := []struct {
		name        string
		certFile    string
		keyFile     string
		expectError bool
	}{
		{
			name:        "both_empty",
			certFile:    "",
			keyFile:     "",
			expectError: false,
		},
		{
			name:        "both_valid",
			certFile:    validCertFile,
			keyFile:     validKeyFile,
			expectError: false,
		},
		{
			name:        "cert_only",
			certFile:    validCertFile,
			keyFile:     "",
			expectError: true,
		},
		{
			name:        "key_only",
			certFile:    "",
			keyFile:     validKeyFile,
			expectError: true,
		},
		{
			name:        "cert_nonexistent",
			certFile:    "/nonexistent/cert.pem",
			keyFile:     validKeyFile,
			expectError: true,
		},
		{
			name:        "key_nonexistent",
			certFile:    validCertFile,
			keyFile:     "/nonexistent/key.pem",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				CertDirs:            []string{"/tmp"},
				Port:                "3000",
				BindAddress:         "0.0.0.0",
				NumWorkers:          4,
				ExpiryThresholdDays: 30,
				TLSCertFile:         tt.certFile,
				TLSKeyFile:          tt.keyFile,
			}

			err := config.Validate()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for %s, but got none", tt.name)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for %s, but got: %v", tt.name, err)
				}
			}
		})
	}
}

func TestFilePathValidation(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		logFile     string
		cacheFile   string
		expectError bool
	}{
		{
			name:        "both_empty",
			logFile:     "",
			cacheFile:   "",
			expectError: false,
		},
		{
			name:        "valid_paths",
			logFile:     filepath.Join(tmpDir, "test.log"),
			cacheFile:   filepath.Join(tmpDir, "cache.json"),
			expectError: false,
		},
		{
			name:        "new_directory_creation",
			logFile:     filepath.Join(tmpDir, "new_dir", "test.log"),
			cacheFile:   filepath.Join(tmpDir, "new_dir", "cache.json"),
			expectError: false, // Should create directories
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				CertDirs:            []string{"/tmp"},
				Port:                "3000",
				BindAddress:         "0.0.0.0",
				NumWorkers:          4,
				ExpiryThresholdDays: 30,
				LogFile:             tt.logFile,
				CacheFile:           tt.cacheFile,
			}

			err := config.Validate()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for %s, but got none", tt.name)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for %s, but got: %v", tt.name, err)
				}

				// Verify directories were created if files were specified
				if tt.logFile != "" {
					logDir := filepath.Dir(tt.logFile)
					if _, err := os.Stat(logDir); err != nil {
						t.Errorf("Log directory should have been created: %v", err)
					}
				}
				if tt.cacheFile != "" {
					cacheDir := filepath.Dir(tt.cacheFile)
					if _, err := os.Stat(cacheDir); err != nil {
						t.Errorf("Cache directory should have been created: %v", err)
					}
				}
			}
		})
	}
}

func TestValidationErrorTypes(t *testing.T) {
	config := &Config{
		CertDirs:            []string{},
		Port:                "invalid",
		NumWorkers:          0,
		ExpiryThresholdDays: -1,
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("Expected validation error")
	}

	// The error should contain information about multiple validation failures
	errStr := err.Error()
	expectedStrings := []string{"cert_dirs", "port", "num_workers", "expiry_threshold_days"}

	for _, expected := range expectedStrings {
		if !strings.Contains(errStr, expected) {
			t.Errorf("Error should contain '%s', but got: %s", expected, errStr)
		}
	}
}
