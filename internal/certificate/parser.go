package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultParser implements the Parser interface
type DefaultParser struct{}

// NewParser creates a new certificate parser
func NewParser() Parser {
	return &DefaultParser{}
}

// ParseFile parses a certificate file and returns the leaf certificate
func (p *DefaultParser) ParseFile(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %q: %w", path, err)
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".der":
		return p.ParseDER(raw)
	case ".pem", ".crt", ".cer":
		return p.ParsePEM(raw)
	default:
		// Try PEM first, then DER
		if cert, err := p.ParsePEM(raw); err == nil {
			return cert, nil
		}
		return p.ParseDER(raw)
	}
}

// ParsePEM parses PEM-encoded certificate data
func (p *DefaultParser) ParsePEM(data []byte) (*x509.Certificate, error) {
	// For PEM files, find the first (leaf) certificate
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		rest = remaining
		if block == nil {
			break
		}
		
		if block.Type != "CERTIFICATE" {
			continue
		}
		
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue // Try next block
		}
		
		return cert, nil // Return first valid certificate (leaf)
	}

	return nil, fmt.Errorf("no valid certificate found in PEM data")
}

// ParseDER parses DER-encoded certificate data
func (p *DefaultParser) ParseDER(data []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER certificate: %w", err)
	}
	return cert, nil
}

// IsCertificateFile checks if a file is a certificate based on extension
func IsCertificateFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	return ext == ".pem" || ext == ".crt" || ext == ".cer" || ext == ".der"
}

// GetCertificateFormat returns the format of a certificate file
func GetCertificateFormat(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".pem":
		return "PEM"
	case ".der":
		return "DER"
	case ".crt":
		return "CRT"
	case ".cer":
		return "CER"
	default:
		return "UNKNOWN"
	}
}
