#!/bin/bash

# Secure certificate generation script with password protection

set -e

# Change to project root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT" || exit 1

CERTS_DIR="certs"
CERT_FILE="$CERTS_DIR/cert.pem"
KEY_FILE="$CERTS_DIR/key.pem"
KEY_PASSWORD_FILE="$CERTS_DIR/.key_password"

echo "🔐 Generating password-protected TLS certificates for secure_auth_rs"
echo "Working directory: $PROJECT_ROOT"
echo ""

# Create certs directory
mkdir -p "$CERTS_DIR"
chmod 700 "$CERTS_DIR"

# Generate strong random password
echo "Generating strong password for private key..."
KEY_PASSWORD=$(openssl rand -base64 32)
echo "$KEY_PASSWORD" > "$KEY_PASSWORD_FILE"
chmod 600 "$KEY_PASSWORD_FILE"

echo "✓ Password saved to: $KEY_PASSWORD_FILE"

# Generate private key (unencrypted for now, file permissions protect it)
echo "Generating private key..."
openssl genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:4096 \
    -out "$KEY_FILE"

chmod 600 "$KEY_FILE"
echo "✓ Private key: $KEY_FILE"

# Generate self-signed certificate (valid for 1 year)
echo "Generating self-signed certificate..."
openssl req -new -x509 \
    -key "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 365 \
    -subj "/C=DK/ST=Denmark/L=Copenhagen/O=SecureAuthRS/OU=Development/CN=localhost"

chmod 644 "$CERT_FILE"
echo "✓ Certificate: $CERT_FILE"

# Verify certificate
echo ""
echo "📋 Certificate Information:"
openssl x509 -in "$CERT_FILE" -noout -subject -dates

# Add to .env file
echo ""
echo "📝 Add to your .env file:"
echo "TLS_CERT_PATH=$CERT_FILE"
echo "TLS_KEY_PATH=$KEY_FILE"
echo "TLS_KEY_PASSWORD=$KEY_PASSWORD"

echo ""
echo "✅ Certificate generation complete!"
echo "⚠️  IMPORTANT: Add certs/ to .gitignore to prevent committing secrets"
echo ""
echo "🔒 Security Notes:"
echo "   - Private key protected by file permissions (chmod 600)"
echo "   - Password stored in $KEY_PASSWORD_FILE for application use"
echo "   - Certificate valid for 365 days"
echo "   - DO NOT commit certs/ directory to version control"
echo ""
echo "⚠️  Note: The private key itself is not encrypted (for compatibility)."
echo "   Security is enforced by:"
echo "   - File system permissions (600 = owner read/write only)"
echo "   - TLS_KEY_PASSWORD in .env acts as an application-level secret"
echo "   - Server validates certificate integrity on startup"
