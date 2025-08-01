// # internal/cert/cert.go
package cert

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"strings"
)

// DetermineIssuerCode determines the issuer code for a certificate
// Returns: 30=digicert, 31=amazon, 32=other, 33=self-signed
func DetermineIssuerCode(cert *x509.Certificate) float64 {
	if strings.EqualFold(cert.Subject.CommonName, cert.Issuer.CommonName) {
		return 33 // self-signed
	}
	
	issuerLower := strings.ToLower(cert.Issuer.CommonName)
	switch {
	case strings.Contains(issuerLower, "digicert"):
		return 30
	case strings.Contains(issuerLower, "amazon"):
		return 31
	default:
		return 32
	}
}

// IsWeakKey checks if a certificate has a weak key
func IsWeakKey(cert *x509.Certificate) bool {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen() < 2048
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize < 256
	default:
		return false
	}
}

// IsDeprecatedSigAlg checks if a signature algorithm is deprecated
func IsDeprecatedSigAlg(alg x509.SignatureAlgorithm) bool {
	return alg == x509.SHA1WithRSA ||
		alg == x509.DSAWithSHA1 ||
		alg == x509.ECDSAWithSHA1 ||
		alg == x509.MD5WithRSA
}
