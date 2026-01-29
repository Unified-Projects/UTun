#!/bin/bash
# UTun Production Certificate Generator
# Generates CA, server (dest), and client (source) certificates

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Certificate parameters
CA_DAYS=3650
CERT_DAYS=365
KEY_SIZE=4096

# Get server IPs from arguments or prompt
SOURCE_IP="${1:-}"
DEST_IP="${2:-}"

if [ -z "$SOURCE_IP" ] || [ -z "$DEST_IP" ]; then
    echo -e "${YELLOW}Usage: $0 <SOURCE_SERVER_IP> <DEST_SERVER_IP>${NC}"
    echo ""
    echo "Example: $0 203.0.113.10 198.51.100.20"
    exit 1
fi

echo -e "${GREEN}Generating certificates for UTun production deployment${NC}"
echo "  Source Server IP: $SOURCE_IP"
echo "  Dest Server IP:   $DEST_IP"
echo ""

# Create certificate directories
mkdir -p "$SCRIPT_DIR/source/certs"
mkdir -p "$SCRIPT_DIR/dest/certs"

# Generate CA certificate (shared between source and dest)
echo -e "${YELLOW}[1/4] Generating CA certificate...${NC}"
openssl genrsa -out "$SCRIPT_DIR/ca.key" $KEY_SIZE 2>/dev/null
openssl req -new -x509 -days $CA_DAYS -key "$SCRIPT_DIR/ca.key" \
    -out "$SCRIPT_DIR/ca.crt" \
    -subj "/C=US/ST=State/L=City/O=UTun/OU=CA/CN=UTun Root CA"
echo -e "${GREEN}  CA certificate generated${NC}"

# Generate server certificate for dest
echo -e "${YELLOW}[2/4] Generating server certificate for dest...${NC}"
openssl genrsa -out "$SCRIPT_DIR/dest/certs/server.key" $KEY_SIZE 2>/dev/null

# Create server CSR config with SAN
cat > "$SCRIPT_DIR/dest/certs/server.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = UTun
OU = Server
CN = utun-dest

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = utun-dest
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = $DEST_IP
EOF

openssl req -new -key "$SCRIPT_DIR/dest/certs/server.key" \
    -out "$SCRIPT_DIR/dest/certs/server.csr" \
    -config "$SCRIPT_DIR/dest/certs/server.cnf"

openssl x509 -req -days $CERT_DAYS \
    -in "$SCRIPT_DIR/dest/certs/server.csr" \
    -CA "$SCRIPT_DIR/ca.crt" \
    -CAkey "$SCRIPT_DIR/ca.key" \
    -CAcreateserial \
    -out "$SCRIPT_DIR/dest/certs/server.crt" \
    -extensions v3_req \
    -extfile "$SCRIPT_DIR/dest/certs/server.cnf" 2>/dev/null
echo -e "${GREEN}  Server certificate generated${NC}"

# Generate client certificate for source
echo -e "${YELLOW}[3/4] Generating client certificate for source...${NC}"
openssl genrsa -out "$SCRIPT_DIR/source/certs/client.key" $KEY_SIZE 2>/dev/null

cat > "$SCRIPT_DIR/source/certs/client.cnf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = UTun
OU = Client
CN = utun-source

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = utun-source
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = $SOURCE_IP
EOF

openssl req -new -key "$SCRIPT_DIR/source/certs/client.key" \
    -out "$SCRIPT_DIR/source/certs/client.csr" \
    -config "$SCRIPT_DIR/source/certs/client.cnf"

openssl x509 -req -days $CERT_DAYS \
    -in "$SCRIPT_DIR/source/certs/client.csr" \
    -CA "$SCRIPT_DIR/ca.crt" \
    -CAkey "$SCRIPT_DIR/ca.key" \
    -CAcreateserial \
    -out "$SCRIPT_DIR/source/certs/client.crt" \
    -extensions v3_req \
    -extfile "$SCRIPT_DIR/source/certs/client.cnf" 2>/dev/null
echo -e "${GREEN}  Client certificate generated${NC}"

# Copy CA cert to both directories
echo -e "${YELLOW}[4/4] Distributing CA certificate...${NC}"
cp "$SCRIPT_DIR/ca.crt" "$SCRIPT_DIR/source/certs/ca.crt"
cp "$SCRIPT_DIR/ca.crt" "$SCRIPT_DIR/dest/certs/ca.crt"
echo -e "${GREEN}  CA certificate distributed${NC}"

# Set permissions
chmod 600 "$SCRIPT_DIR/ca.key"
chmod 644 "$SCRIPT_DIR/ca.crt"
chmod 600 "$SCRIPT_DIR/source/certs/client.key"
chmod 644 "$SCRIPT_DIR/source/certs/client.crt"
chmod 644 "$SCRIPT_DIR/source/certs/ca.crt"
chmod 600 "$SCRIPT_DIR/dest/certs/server.key"
chmod 644 "$SCRIPT_DIR/dest/certs/server.crt"
chmod 644 "$SCRIPT_DIR/dest/certs/ca.crt"

# Clean up temporary files
rm -f "$SCRIPT_DIR/dest/certs/server.csr" "$SCRIPT_DIR/dest/certs/server.cnf"
rm -f "$SCRIPT_DIR/source/certs/client.csr" "$SCRIPT_DIR/source/certs/client.cnf"
rm -f "$SCRIPT_DIR/ca.srl"

# Update config files with actual IPs
echo ""
echo -e "${YELLOW}Updating configuration files with server IPs...${NC}"
sed -i.bak "s/DEST_SERVER_IP/$DEST_IP/g" "$SCRIPT_DIR/source/config.toml" && rm -f "$SCRIPT_DIR/source/config.toml.bak"
sed -i.bak "s/SOURCE_SERVER_IP/$SOURCE_IP/g" "$SCRIPT_DIR/dest/config.toml" && rm -f "$SCRIPT_DIR/dest/config.toml.bak"
echo -e "${GREEN}  Configuration files updated${NC}"

echo ""
echo -e "${GREEN}Certificate generation complete!${NC}"
echo ""
echo "Generated files:"
echo "  prod/ca.crt              - Root CA certificate (keep ca.key secure!)"
echo "  prod/ca.key              - Root CA private key (DO NOT SHARE)"
echo "  prod/source/certs/       - Client certificates for source server"
echo "  prod/dest/certs/         - Server certificates for dest server"
echo ""
echo "Next steps:"
echo "  1. Copy prod/source/ to your SOURCE server ($SOURCE_IP)"
echo "  2. Copy prod/dest/ to your DEST server ($DEST_IP)"
echo "  3. Configure UFW rules (see README.md)"
echo "  4. Run 'docker compose up -d' on each server"
