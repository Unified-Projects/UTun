#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=== Building with optimizations ==="
cargo build --release

echo ""
echo "=== Running Benchmarks ==="
cargo bench

echo ""
echo "=== Benchmark results saved to target/criterion/ ==="
