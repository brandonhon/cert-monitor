#!/bin/bash
# Generate test certificates for development and testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_CERTS_DIR="$SCRIPT_DIR/../test-certs"

echo "🔐 Generating test certificates for cert-monitor development..."

# Create test certificates directory
mkdir -p "$TEST_CERTS_DIR"
cd "$TEST_CERTS_DIR"

# Clean up existing certificates
rm -f *.pem *.crt *.key *.der *.csr

echo "📁 Working in: $TEST_CERTS_DIR"

# Generate CA private key
echo "🔑 Generating CA private key..."
openssl genrsa -out ca-key.pem 4096

# Generate CA certificate
echo "📜 Generating CA certificate..."
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca-cert.pem -subj "/C=US/ST=CA/L=Test/O=Test CA/OU=Testing/CN=Test CA"

# Generate server private key
echo "🔑 Generating server private key..."
openssl genrsa -out server-key.pem 2048

# Generate server certificate signing request
echo "📝 Generating server CSR..."
openssl req -subj "/C=US/ST=CA/L=Test/O=Test/OU=Testing/CN=test.example.com" -new -key server-key.pem -out server.csr

# Create extensions file for server certificate
cat > server-extfile.cnf <<EOF
subjectAltName = DNS:test.example.com,DNS:www.test.example.com,DNS:api.test.example.com,IP:127.0.0.1,IP:10.0.0.1
extendedKeyUsage = serverAuth
EOF

# Generate server certificate
echo "📜 Generating server certificate..."
openssl x509 -req -days 365 -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -out server-cert.pem -extfile server-extfile.cnf -CAcreateserial

# Generate client private key
echo "🔑 Generating client private key..."
openssl genrsa -out client-key.pem 2048

# Generate client certificate signing request
echo "📝 Generating client CSR..."
openssl req -subj "/C=US/ST=CA/L=Test/O=Test/OU=Testing/CN=test-client" -new -key client-key.pem -out client.csr

# Create extensions file for client certificate
cat > client-extfile.cnf <<EOF
extendedKeyUsage = clientAuth
EOF

# Generate client certificate
echo "📜 Generating client certificate..."
openssl x509 -req -days 365 -in client.csr -CA ca-cert.pem -CAkey ca-key.pem -out client-cert.pem -extfile client-extfile.cnf -CAcreateserial

# Generate expired certificate (backdated)
echo "⏰ Generating expired certificate..."
openssl genrsa -out expired-key.pem 2048
openssl req -subj "/C=US/ST=CA/L=Test/O=Test/OU=Testing/CN=expired.example.com" -new -key expired-key.pem -out expired.csr
openssl x509 -req -days 1 -in expired.csr -CA ca-cert.pem -CAkey ca-key.pem -out expired-cert.pem -CAcreateserial
# Backdate the certificate to make it expired
touch -t 202301010000 expired-cert.pem

# Generate certificate expiring soon (5 days)
echo "⚠️  Generating soon-to-expire certificate..."
openssl genrsa -out expiring-key.pem 2048
openssl req -subj "/C=US/ST=CA/L=Test/O=Test/OU=Testing/CN=expiring.example.com" -new -key expiring-key.pem -out expiring.csr
openssl x509 -req -days 5 -in expiring.csr -CA ca-cert.pem -CAkey ca-key.pem -out expiring-cert.pem -CAcreateserial

# Generate self-signed certificate
echo "🔒 Generating self-signed certificate..."
openssl genrsa -out selfsigned-key.pem 2048
openssl req -new -x509 -days 365 -key selfsigned-key.pem -out selfsigned-cert.pem -subj "/C=US/ST=CA/L=Test/O=SelfSigned/OU=Testing/CN=selfsigned.example.com"

# Generate weak key certificate (1024 bit RSA)
echo "⚠️  Generating weak key certificate (1024 bit)..."
openssl genrsa -out weak-key.pem 1024
openssl req -subj "/C=US/ST=CA/L=Test/O=Test/OU=Testing/CN=weak.example.com" -new -key weak-key.pem -out weak.csr
openssl x509 -req -days 365 -in weak.csr -CA ca-cert.pem -CAkey ca-key.pem -out weak-cert.pem -CAcreateserial

# Generate certificate with deprecated signature algorithm (if supported)
echo "🗑️  Generating certificate with SHA1 signature..."
openssl genrsa -out sha1-key.pem 2048
openssl req -subj "/C=US/ST=CA/L=Test/O=Test/OU=Testing/CN=sha1.example.com" -new -key sha1-key.pem -out sha1.csr
# Note: Many newer OpenSSL versions don't support SHA1 for new certificates
openssl x509 -req -days 365 -in sha1.csr -CA ca-cert.pem -CAkey ca-key.pem -out sha1-cert.pem -CAcreateserial -sha1 2>/dev/null || echo "   SHA1 signing not supported, skipping..."

# Generate ECDSA certificate
echo "🔐 Generating ECDSA certificate..."
openssl ecparam -genkey -name prime256v1 -out ecdsa-key.pem
openssl req -new -x509 -days 365 -key ecdsa-key.pem -out ecdsa-cert.pem -subj "/C=US/ST=CA/L=Test/O=Test/OU=Testing/CN=ecdsa.example.com"

# Convert some certificates to different formats
echo "🔄 Converting certificates to different formats..."

# Convert to DER format
openssl x509 -outform der -in server-cert.pem -out server-cert.der
openssl x509 -outform der -in ca-cert.pem -out ca-cert.der

# Create certificate chain file
echo "🔗 Creating certificate chain..."
cat server-cert.pem ca-cert.pem > server-chain.pem

# Copy certificates with different extensions
cp server-cert.pem server-cert.crt
cp ca-cert.pem ca-cert.crt
cp client-cert.pem client-cert.cer

# Create duplicate certificates for testing duplicate detection
cp server-cert.pem duplicate1-cert.pem
cp server-cert.pem duplicate2-cert.pem

# Clean up temporary files
rm -f *.csr *.cnf *.srl

# Create README for test certificates
cat > README.md <<EOF
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

\`\`\`bash
./cert-monitor -cert-dir ./test-certs -dry-run
\`\`\`

## Security Note

These are test certificates only. Do not use in production!
All private keys are included and publicly available.
EOF

echo ""
echo "✅ Test certificates generated successfully!"
echo "📍 Location: $TEST_CERTS_DIR"
echo ""
echo "📋 Generated certificates:"
ls -la *.pem *.crt *.der *.cer 2>/dev/null || true
echo ""
echo "🧪 Test with:"
echo "   ./cert-monitor -cert-dir ./test-certs -dry-run"
echo ""
echo "⚠️  Note: These are test certificates only - do not use in production!"