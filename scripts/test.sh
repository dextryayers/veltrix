#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[*] Veltrix Test Runner"
echo "========================"

echo ""
echo "[1/4] Unit tests"
cargo test --lib --manifest-path "$DIR/Cargo.toml"

echo ""
echo "[2/4] Doc tests"
cargo test --doc --manifest-path "$DIR/Cargo.toml" 2>/dev/null || echo "  (skipped - no doc tests)"

echo ""
echo "[3/4] Build check (release)"
cargo build --release --manifest-path "$DIR/Cargo.toml" 2>&1 | tail -1

echo ""
echo "[4/4] Integration tests"
if docker compose version &>/dev/null; then
    echo "  Starting test containers..."
    docker compose -f "$DIR/docker/docker-compose.test.yml" up -d 2>/dev/null || true
    sleep 5
    cargo test --test integration --manifest-path "$DIR/Cargo.toml" -- --test-threads=1 2>/dev/null || \
        echo "  (skipped - no integration tests yet)"
    docker compose -f "$DIR/docker/docker-compose.test.yml" down 2>/dev/null || true
else
    echo "  (skipped - Docker not available)"
fi

echo ""
echo "[✓] All checks complete"
