#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=== Running Clippy ==="
cargo clippy --all-targets --all-features -- -D warnings

echo ""
echo "=== Running Unit Tests ==="
cargo test --lib

echo ""
echo "=== Running Integration Tests ==="
cargo test --test '*'

echo ""
echo "=== Running Doc Tests ==="
cargo test --doc

echo ""
echo "=== All tests passed ==="
