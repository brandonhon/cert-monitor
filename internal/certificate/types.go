package certificate

import (
	"crypto/x509"
	"os"
	"time"
)

// Info represents parsed certificate data and metadata
type Info struct {
	CommonName          string            `json:"common_name"`
	FileName            string            `json:"file_name"`
	Issuer              string            `json:"issuer"`
	NotBefore           time.Time         `json:"not_before"`
	NotAfter            time.Time         `json:"not_after"`
	SANs                []string          `json:"sans,omitempty"`
	ExpiringSoon        bool              `json:"expiring_soon"`
	Type                string            `json:"type"`
	IssuerCode          int               `json:"issuer_code"`
	IsWeakKey           bool              `json:"is_weak_key"`
	HasDeprecatedSigAlg bool              `json:"has_deprecated_sig_alg"`
	Certificate         *x509.Certificate `json:"-"` // Don't marshal the full cert
}

// ScanResult represents the result of scanning a certificate file
type ScanResult struct {
	Certificate *x509.Certificate
	Info        *Info
	Path        string
	Error       error
}

// SecurityAnalysis contains security-related analysis of a certificate
type SecurityAnalysis struct {
	IsWeakKey           bool
	HasDeprecatedSigAlg bool
	KeySize             int
	SignatureAlgorithm  string
	IssuerCode          int
}

// ProcessingOptions configures certificate processing behavior
type ProcessingOptions struct {
	ExpiryThresholdDays int
	DryRun              bool
	EnableWeakCrypto    bool
}

// DirectoryStats contains statistics about certificate directory processing
type DirectoryStats struct {
	FilesProcessed  int
	CertsParsed     int
	ParseErrors     int
	DuplicatesFound int
	ProcessingTime  time.Duration
	LastScanTime    time.Time
}

// FileInfo contains information about a certificate file
type FileInfo struct {
	Path     string
	ModTime  time.Time
	Size     int64
	FileInfo os.FileInfo
}

// DuplicateMap tracks duplicate certificates by fingerprint
type DuplicateMap map[string]int

// Constants for certificate processing
const (
	TypeLeafCertificate = "leaf_certificate"
	MaxSANsExported     = 10
)

// Processor defines the interface for certificate processing
type Processor interface {
	ProcessDirectory(path string, options ProcessingOptions) (*DirectoryStats, DuplicateMap, error)
	ProcessFile(path string, options ProcessingOptions) (*ScanResult, error)
}

// Parser defines the interface for certificate parsing
type Parser interface {
	ParseFile(path string) (*x509.Certificate, error)
	ParsePEM(data []byte) (*x509.Certificate, error)
	ParseDER(data []byte) (*x509.Certificate, error)
}

// Analyzer defines the interface for certificate analysis
type Analyzer interface {
	AnalyzeSecurity(cert *x509.Certificate) SecurityAnalysis
	CreateInfo(cert *x509.Certificate, filename string, options ProcessingOptions) *Info
}

// Scanner defines the interface for directory scanning
type Scanner interface {
	ScanDirectory(path string) ([]FileInfo, error)
	IsCertificateFile(filename string) bool
}
