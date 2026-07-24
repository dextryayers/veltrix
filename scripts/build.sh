#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MODE="${1:-release}"

echo "[*] Building veltrix ($MODE mode)..."

case "$MODE" in
    release)
        cargo build --release --manifest-path "$DIR/Cargo.toml"
        BIN="$DIR/target/release/veltrix"
        ;;
    debug)
        cargo build --manifest-path "$DIR/Cargo.toml"
        BIN="$DIR/target/debug/veltrix"
        ;;
    *)
        echo "Usage: $0 [release|debug]"
        exit 1
        ;;
esac

if [ -f "$BIN" ]; then
    SIZE=$(du -h "$BIN" | cut -f1)
    echo "[✓] Build complete: $BIN ($SIZE)"
    "$BIN" --version
else
    echo "[!] Build failed: binary not found"
    exit 1
fi
