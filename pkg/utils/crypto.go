package utils

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"strings"
)

// IsWeakKey determines if a certificate has a weak cryptographic key
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
	deprecatedAlgorithms := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.DSAWithSHA1,
		x509.ECDSAWithSHA1,
		x509.MD5WithRSA,
	}

	for _, deprecated := range deprecatedAlgorithms {
		if alg == deprecated {
			return true
		}
	}
	return false
}

// DetermineIssuerCode determines the issuer code for certificate classification
func DetermineIssuerCode(cert *x509.Certificate) int {
	const (
		IssuerCodeDigiCert   = 30
		IssuerCodeAmazon     = 31
		IssuerCodeOther      = 32
		IssuerCodeSelfSigned = 33
	)

	if cert.Subject.CommonName == cert.Issuer.CommonName {
		return IssuerCodeSelfSigned
	}

	issuerLower := strings.ToLower(cert.Issuer.CommonName)
	switch {
	case strings.Contains(issuerLower, "digicert"):
		return IssuerCodeDigiCert
	case strings.Contains(issuerLower, "amazon"):
		return IssuerCodeAmazon
	default:
		return IssuerCodeOther
	}
}
