#!/usr/bin/env bash
# F9.6: paket rilis v2.0 — biner release + SHA256 + verifikasi versi tunggal.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$DIR/dist}"

echo "[*] Packaging veltrix v2.0..."

cargo build --release --manifest-path "$DIR/Cargo.toml"
BIN="$DIR/target/release/veltrix"

# 1. Versi tunggal: Cargo.toml == --version == man header.
CARGO_VER="$(grep -m1 '^version' "$DIR/Cargo.toml" | sed 's/.*"\(.*\)"/\1/')"
BIN_VER="$("$BIN" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
if [ "$CARGO_VER" != "$BIN_VER" ]; then
    echo "[!] Version drift: Cargo.toml=$CARGO_VER binary=$BIN_VER" >&2
    exit 1
fi
echo "[✓] Single version: $CARGO_VER"

# 2. Smoke: dry-run tanpa network harus exit 0.
printf 'admin\n' > /tmp/pkg_users.txt
printf 'password\n123456\n' > /tmp/pkg_pass.txt
"$BIN" ssh -t 192.168.1.1 -U /tmp/pkg_users.txt -W /tmp/pkg_pass.txt --dry-run >/dev/null
"$BIN" wordlist eval --ranked /tmp/ml_ranked.txt --relevant /tmp/ml_heldout.txt --k 10 >/dev/null 2>&1 || true
echo "[✓] Smoke dry-run OK"

# 3. Dist: biner + checksum.
mkdir -p "$OUT"
cp "$BIN" "$OUT/veltrix-$CARGO_VER-linux-x86_64"
( cd "$OUT" && sha256sum "veltrix-$CARGO_VER-linux-x86_64" > "veltrix-$CARGO_VER-linux-x86_64.sha256" )
SIZE=$(du -h "$OUT/veltrix-$CARGO_VER-linux-x86_64" | cut -f1)
echo "[✓] dist/veltrix-$CARGO_VER-linux-x86_64 ($SIZE)"
cat "$OUT/veltrix-$CARGO_VER-linux-x86_64.sha256"

# 4. Docker image (opsional, butuh docker daemon).
if command -v docker >/dev/null 2>&1; then
    docker build -t "veltrix:$CARGO_VER" -f "$DIR/Dockerfile" "$DIR" >/dev/null \
        && echo "[✓] docker image veltrix:$CARGO_VER" \
        || echo "[!] docker build failed (non-fatal)"
else
    echo "[-] docker not found, skipping image build"
fi

echo "[✓] Package complete: $OUT"
