#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CERT_DIR="${CERT_DIR:-$PROJECT_DIR/certs}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if utun binary exists
if ! command -v utun &> /dev/null; then
    if [ -f "$PROJECT_DIR/target/release/utun" ]; then
        UTUN="$PROJECT_DIR/target/release/utun"
    elif [ -f "$PROJECT_DIR/target/debug/utun" ]; then
        UTUN="$PROJECT_DIR/target/debug/utun"
    else
        log_error "utun binary not found. Please build first: cargo build --release"
        exit 1
    fi
else
    UTUN="utun"
fi

# Create certificate directories
mkdir -p "$CERT_DIR/source" "$CERT_DIR/dest"

log_info "Generating CA certificate..."
$UTUN cert ca \
    --common-name "UTun PQC CA" \
    --validity-days 3650 \
    --out-cert "$CERT_DIR/ca.crt" \
    --out-key "$CERT_DIR/ca.key"

log_info "Generating server certificate for destination..."
$UTUN cert server \
    --common-name "utun-dest" \
    --dns-names "utun-dest,localhost" \
    --ip-addresses "127.0.0.1,172.28.1.20" \
    --ca-cert "$CERT_DIR/ca.crt" \
    --ca-key "$CERT_DIR/ca.key" \
    --validity-days 365 \
    --out-cert "$CERT_DIR/dest/server.crt" \
    --out-key "$CERT_DIR/dest/server.key"

log_info "Generating client certificate for source..."
$UTUN cert client \
    --common-name "utun-source" \
    --ca-cert "$CERT_DIR/ca.crt" \
    --ca-key "$CERT_DIR/ca.key" \
    --validity-days 365 \
    --out-cert "$CERT_DIR/source/client.crt" \
    --out-key "$CERT_DIR/source/client.key"

# Copy CA cert to both directories
cp "$CERT_DIR/ca.crt" "$CERT_DIR/source/ca.crt"
cp "$CERT_DIR/ca.crt" "$CERT_DIR/dest/ca.crt"

# Set permissions
chmod 600 "$CERT_DIR"/*.key "$CERT_DIR"/source/*.key "$CERT_DIR"/dest/*.key
chmod 644 "$CERT_DIR"/*.crt "$CERT_DIR"/source/*.crt "$CERT_DIR"/dest/*.crt

log_info "Certificates generated successfully!"
log_info "CA certificate: $CERT_DIR/ca.crt"
log_info "Server certificate: $CERT_DIR/dest/server.crt"
log_info "Client certificate: $CERT_DIR/source/client.crt"

# Verify certificates
log_info "Verifying certificates..."
$UTUN cert verify \
    --cert "$CERT_DIR/dest/server.crt" \
    --ca-cert "$CERT_DIR/ca.crt" \
    --hostname "utun-dest"

$UTUN cert verify \
    --cert "$CERT_DIR/source/client.crt" \
    --ca-cert "$CERT_DIR/ca.crt"

log_info "All certificates verified successfully!"
