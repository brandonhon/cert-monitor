package certificate

import (
	"crypto/x509"
	"path/filepath"
	"strings"
	"time"

	"github.com/brandonhon/cert-monitor/pkg/utils"
)

// DefaultAnalyzer implements the Analyzer interface
type DefaultAnalyzer struct{}

// NewAnalyzer creates a new certificate analyzer
func NewAnalyzer() Analyzer {
	return &DefaultAnalyzer{}
}

// AnalyzeSecurity performs security analysis on a certificate
func (a *DefaultAnalyzer) AnalyzeSecurity(cert *x509.Certificate) SecurityAnalysis {
	analysis := SecurityAnalysis{
		IsWeakKey:           utils.IsWeakKey(cert),
		HasDeprecatedSigAlg: utils.IsDeprecatedSigAlg(cert.SignatureAlgorithm),
		SignatureAlgorithm:  cert.SignatureAlgorithm.String(),
		IssuerCode:          utils.DetermineIssuerCode(cert),
	}

	// Determine key size
	analysis.KeySize = getKeySize(cert)

	return analysis
}

// CreateInfo creates a certificate info struct from a parsed certificate
func (a *DefaultAnalyzer) CreateInfo(cert *x509.Certificate, filename string, options ProcessingOptions) *Info {
	analysis := a.AnalyzeSecurity(cert)
	
	// Check if certificate is expiring soon
	expiryThreshold := time.Duration(options.ExpiryThresholdDays) * 24 * time.Hour
	expiringSoon := time.Until(cert.NotAfter) <= expiryThreshold

	return &Info{
		CommonName:          cert.Subject.CommonName,
		FileName:            filepath.Base(filename),
		Issuer:              cert.Issuer.CommonName,
		NotBefore:           cert.NotBefore,
		NotAfter:            cert.NotAfter,
		SANs:                cert.DNSNames,
		ExpiringSoon:        expiringSoon,
		Type:                TypeLeafCertificate,
		IssuerCode:          analysis.IssuerCode,
		IsWeakKey:           analysis.IsWeakKey,
		HasDeprecatedSigAlg: analysis.HasDeprecatedSigAlg,
		Certificate:         cert, // Store reference for further processing
	}
}

// getKeySize extracts the key size from a certificate's public key
func getKeySize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case interface{ Size() int }:
		return pub.Size() * 8 // Convert bytes to bits
	default:
		return 0 // Unknown key type
	}
}

// PrepareSANsForMetrics formats SANs for Prometheus metrics
func PrepareSANsForMetrics(sans []string) string {
	if len(sans) == 0 {
		return ""
	}

	limitedSANs := sans
	if len(limitedSANs) > MaxSANsExported {
		limitedSANs = limitedSANs[:MaxSANsExported]
	}

	return utils.SanitizeLabelValue(strings.Join(limitedSANs, ","))
}

// ClassifyIssuer provides human-readable issuer classification
func ClassifyIssuer(issuerCode int) string {
	switch issuerCode {
	case utils.IssuerCodeDigiCert:
		return "DigiCert"
	case utils.IssuerCodeAmazon:
		return "Amazon"
	case utils.IssuerCodeSelfSigned:
		return "Self-Signed"
	case utils.IssuerCodeOther:
		return "Other"
	default:
		return "Unknown"
	}
}

// GetSecurityRating provides a simple security rating based on analysis
func GetSecurityRating(analysis SecurityAnalysis) string {
	if analysis.HasDeprecatedSigAlg {
		return "Poor"
	}
	if analysis.IsWeakKey {
		return "Weak"
	}
	if analysis.KeySize >= 2048 {
		return "Good"
	}
	return "Fair"
}
