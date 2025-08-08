package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SanitizeLabelValue sanitizes a string for use as a Prometheus label value
func SanitizeLabelValue(val string) string {
	const maxLabelLength = 120

	val = strings.TrimSpace(val)
	if len(val) > maxLabelLength {
		return val[:maxLabelLength]
	}
	return val
}

// ValidateFileAccess validates that a file exists and is accessible
func ValidateFileAccess(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %q", path)
		}
		return fmt.Errorf("cannot access file %q: %w", path, err)
	}
	return nil
}

// ValidateDirectoryAccess validates that a directory exists and is readable
func ValidateDirectoryAccess(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("directory does not exist: %q", dir)
		}
		return fmt.Errorf("cannot access directory %q: %w", dir, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %q", dir)
	}

	if _, err := os.ReadDir(dir); err != nil {
		return fmt.Errorf("cannot read directory %q: %w", dir, err)
	}

	return nil
}

// ValidateDirectoryCreation creates a directory if it doesn't exist
func ValidateDirectoryCreation(dir string) error {
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("cannot create directory %q: %w", dir, err)
		}
	}
	return nil
}

// IsWindows detects if running on Windows
func IsWindows() bool {
	return strings.Contains(strings.ToLower(os.Getenv("OS")), "windows") ||
		os.PathSeparator == '\\'
}

// IsCertificateFile checks if a file is a certificate based on extension
func IsCertificateFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	return ext == ".pem" || ext == ".crt" || ext == ".cer" || ext == ".der"
}
