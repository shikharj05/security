#!/bin/bash

# Generate self-signed certificates for passkey e2e tests

set -e

CERTS_DIR="$(dirname "$0")/../certs"
mkdir -p "$CERTS_DIR"

echo "Generating certificates for passkey e2e tests..."

# Generate root CA
openssl genrsa -out "$CERTS_DIR/root-ca-key.pem" 2048
openssl req -new -x509 -sha256 -key "$CERTS_DIR/root-ca-key.pem" \
  -subj "/C=US/ST=Test/L=Test/O=OpenSearch/OU=Test/CN=root" \
  -out "$CERTS_DIR/root-ca.pem" -days 365

# Generate admin certificate
openssl genrsa -out "$CERTS_DIR/admin-key-temp.pem" 2048
openssl pkcs8 -inform PEM -outform PEM -in "$CERTS_DIR/admin-key-temp.pem" \
  -topk8 -nocrypt -v1 PBE-SHA1-3DES -out "$CERTS_DIR/admin-key.pem"
openssl req -new -key "$CERTS_DIR/admin-key.pem" \
  -subj "/C=US/ST=Test/L=Test/O=OpenSearch/OU=Test/CN=admin" \
  -out "$CERTS_DIR/admin.csr"
openssl x509 -req -in "$CERTS_DIR/admin.csr" -CA "$CERTS_DIR/root-ca.pem" \
  -CAkey "$CERTS_DIR/root-ca-key.pem" -CAcreateserial \
  -sha256 -out "$CERTS_DIR/admin.pem" -days 365

# Generate node certificate
openssl genrsa -out "$CERTS_DIR/node-key-temp.pem" 2048
openssl pkcs8 -inform PEM -outform PEM -in "$CERTS_DIR/node-key-temp.pem" \
  -topk8 -nocrypt -v1 PBE-SHA1-3DES -out "$CERTS_DIR/node-key.pem"
openssl req -new -key "$CERTS_DIR/node-key.pem" \
  -subj "/C=US/ST=Test/L=Test/O=OpenSearch/OU=Test/CN=node" \
  -out "$CERTS_DIR/node.csr"
openssl x509 -req -in "$CERTS_DIR/node.csr" -CA "$CERTS_DIR/root-ca.pem" \
  -CAkey "$CERTS_DIR/root-ca-key.pem" -CAcreateserial \
  -sha256 -out "$CERTS_DIR/node.pem" -days 365

# Clean up temporary files
rm -f "$CERTS_DIR/admin-key-temp.pem" "$CERTS_DIR/admin.csr"
rm -f "$CERTS_DIR/node-key-temp.pem" "$CERTS_DIR/node.csr"

echo "Certificates generated successfully in $CERTS_DIR"
