#!/bin/bash

# Script to generate test certificates for Secure IPC
# This is for development/testing purposes only

set -e

CERTS_DIR="${SECURE_IPC_CERTS_DIR:-certs}"
SERVER_CERTS_SUBDIR="agent"
CLIENT_CERTS_SUBDIR="app"
DAYS=365

echo "Generating test certificates in directory: $CERTS_DIR"

# Create certificates base directory and subdirectories
mkdir -p "$CERTS_DIR/$SERVER_CERTS_SUBDIR"
mkdir -p "$CERTS_DIR/$CLIENT_CERTS_SUBDIR"

# Generate CA private key
echo "1. Generating CA private key..."
openssl genrsa -out "$CERTS_DIR/root-ca.key" 4096

# Generate CA certificate
echo "2. Generating CA certificate..."
openssl req -new -x509 -days $DAYS -key "$CERTS_DIR/root-ca.key" -out "$CERTS_DIR/root-ca.pem" -subj "/C=IN/ST=KA/L=Bengaluru/O=Secure-IPC/OU=IPC/CN=Secure-IPC Root CA"

# --- Server Certificate Generation ---

# Generate server private key
echo "3. Generating server private key..."
openssl genrsa -out "$CERTS_DIR/$SERVER_CERTS_SUBDIR/server.key" 2048

# Convert server key to PEM format
echo "4. Converting server key to PEM format..."
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in "$CERTS_DIR/$SERVER_CERTS_SUBDIR/server.key" -out "$CERTS_DIR/$SERVER_CERTS_SUBDIR/server.key.pem"

# Create OpenSSL config with SAN for server
# Note: The config file is placed in the server subdirectory for clarity,
# but its path needs to be correctly referenced in openssl commands.
SERVER_OPENSSL_CNF="$CERTS_DIR/$SERVER_CERTS_SUBDIR/server-openssl.cnf"
cat > "$SERVER_OPENSSL_CNF" <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
C  = US
ST = CA
L  = San Francisco
O  = Secure-IPC
OU = IPC
CN = secure-ipc-server

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = secure-ipc-server
EOF

# Generate server certificate signing request with SAN
echo "5. Generating server certificate signing request with SAN..."
openssl req -new -key "$CERTS_DIR/$SERVER_CERTS_SUBDIR/server.key" -out "$CERTS_DIR/$SERVER_CERTS_SUBDIR/server.csr" \
  -config "$SERVER_OPENSSL_CNF"

# Generate server certificate signed by CA with SAN
echo "6. Generating server certificate with SAN..."
openssl x509 -req -days $DAYS -in "$CERTS_DIR/$SERVER_CERTS_SUBDIR/server.csr" \
  -CA "$CERTS_DIR/root-ca.pem" -CAkey "$CERTS_DIR/root-ca.key" \
  -CAcreateserial -out "$CERTS_DIR/$SERVER_CERTS_SUBDIR/server.pem" \
  -extensions req_ext -extfile "$SERVER_OPENSSL_CNF"

# --- Client Certificate Generation ---

# Generate client private key
echo "7. Generating client private key..."
openssl genrsa -out "$CERTS_DIR/$CLIENT_CERTS_SUBDIR/client.key" 2048

# Convert client key to PEM format
echo "8. Converting client key to PEM format..."
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in "$CERTS_DIR/$CLIENT_CERTS_SUBDIR/client.key" -out "$CERTS_DIR/$CLIENT_CERTS_SUBDIR/client.key.pem"

# Generate client certificate signing request
echo "9. Generating client certificate signing request..."
openssl req -new -key "$CERTS_DIR/$CLIENT_CERTS_SUBDIR/client.key" -out "$CERTS_DIR/$CLIENT_CERTS_SUBDIR/client.csr" -subj "/C=US/ST=CA/L=San Francisco/O=Secure-IPC/OU=IPC/CN=secure-ipc-client"

# Generate client certificate signed by CA
echo "10. Generating client certificate..."
openssl x509 -req -days $DAYS -in "$CERTS_DIR/$CLIENT_CERTS_SUBDIR/client.csr" -CA "$CERTS_DIR/root-ca.pem" -CAkey "$CERTS_DIR/root-ca.key" -CAcreateserial -out "$CERTS_DIR/$CLIENT_CERTS_SUBDIR/client.pem"

# Clean up CSR and temporary key files
rm "$CERTS_DIR/$SERVER_CERTS_SUBDIR/server.csr" \
   "$CERTS_DIR/$CLIENT_CERTS_SUBDIR/client.csr" \
   "$CERTS_DIR/$SERVER_CERTS_SUBDIR/server.key" \
   "$CERTS_DIR/$CLIENT_CERTS_SUBDIR/client.key" \
   "$SERVER_OPENSSL_CNF"

# Set permissions for keys and certificates
chmod 600 "$CERTS_DIR"/*.key "$CERTS_DIR"/*.key.pem \
          "$CERTS_DIR/$SERVER_CERTS_SUBDIR"/*.key "$CERTS_DIR/$SERVER_CERTS_SUBDIR"/*.key.pem \
          "$CERTS_DIR/$CLIENT_CERTS_SUBDIR"/*.key "$CERTS_DIR/$CLIENT_CERTS_SUBDIR"/*.key.pem
chmod 644 "$CERTS_DIR"/*.pem \
          "$CERTS_DIR/$SERVER_CERTS_SUBDIR"/*.pem \
          "$CERTS_DIR/$CLIENT_CERTS_SUBDIR"/*.pem

echo ""
echo "✓ Certificates generated successfully!"
echo ""
echo "Files created:"
echo "  - Root CA: $CERTS_DIR/root-ca.pem"
echo "  - Server cert: $CERTS_DIR/$SERVER_CERTS_SUBDIR/server.pem"
echo "  - Server key: $CERTS_DIR/$SERVER_CERTS_SUBDIR/server.key.pem"
echo "  - Client cert: $CERTS_DIR/$CLIENT_CERTS_SUBDIR/client.pem"
echo "  - Client key: $CERTS_DIR/$CLIENT_CERTS_SUBDIR/client.key.pem"
echo ""
echo "You can now test the IPC system!"
echo ""
echo "Usage:"
echo "  1. Run the secure IPC server"
echo "  2. Test with: cargo run --example cli test"
echo "  3. Interactive mode: cargo run --example cli interactive"