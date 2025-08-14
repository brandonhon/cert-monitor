# Test Certificates

This directory contains test certificates generated for cert-monitor development and testing.

## Certificate Types

- **ca-cert.pem/crt/der**: Root CA certificate
- **server-cert.pem/crt/der**: Server certificate with multiple SANs
- **client-cert.pem/cer**: Client certificate
- **expired-cert.pem**: Certificate that has already expired
- **expiring-cert.pem**: Certificate expiring in 5 days
- **selfsigned-cert.pem**: Self-signed certificate
- **weak-cert.pem**: Certificate with weak 1024-bit RSA key
- **sha1-cert.pem**: Certificate with deprecated SHA1 signature (if supported)
- **ecdsa-cert.pem**: ECDSA certificate
- **server-chain.pem**: Certificate chain file
- **duplicate1/2-cert.pem**: Duplicate certificates for testing

## Formats

- **PEM**: .pem extension (Base64 encoded)
- **DER**: .der extension (Binary format)
- **CRT**: .crt extension (Usually PEM format)
- **CER**: .cer extension (Can be PEM or DER)

## Usage

Point cert-monitor to this directory for testing:

```bash
./cert-monitor -cert-dir ./test-certs -dry-run
```

## Security Note

These are test certificates only. Do not use in production!
All private keys are included and publicly available.
