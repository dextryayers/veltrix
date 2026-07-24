#!/usr/bin/env bash
set -euo pipefail

VELTRIX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_NAME="veltrix"
INSTALL_DIR="/usr/local/bin"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         Veltrix Installer v1.0                ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════╝${NC}"

# Check where the binary might be
BINARY_PATH=""
for p in \
    "$VELTRIX_DIR/target/release/$BINARY_NAME" \
    "$VELTRIX_DIR/target/debug/$BINARY_NAME" \
    "/tmp/veltrix-target/release/$BINARY_NAME" \
    "/tmp/veltrix-target/debug/$BINARY_NAME"
do
    [ -f "$p" ] && { BINARY_PATH="$p"; break; }
done

if [ -z "$BINARY_PATH" ]; then
    echo -e "${YELLOW}No pre-built binary found. Compiling...${NC}"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/veltrix-target}"
    cargo build --release --manifest-path "$VELTRIX_DIR/Cargo.toml" 2>/dev/null || {
        # retry without custom target dir
        unset CARGO_TARGET_DIR
        cargo build --release --manifest-path "$VELTRIX_DIR/Cargo.toml"
    }
    BINARY_PATH="$VELTRIX_DIR/target/release/$BINARY_NAME"
    [ ! -f "$BINARY_PATH" ] && BINARY_PATH="/tmp/veltrix-target/release/$BINARY_NAME"
fi

if [ ! -f "$BINARY_PATH" ]; then
    echo -e "\033[0;31m[!] Failed to find or build binary.${NC}"
    exit 1
fi

mkdir -p "$INSTALL_DIR"
cp "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"
chmod 755 "$INSTALL_DIR/$BINARY_NAME"

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Installation Complete!               ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}$INSTALL_DIR/$BINARY_NAME${NC} is ready to use."
echo ""
echo -e "  Quick start:"
echo -e "    $BINARY_NAME -t 192.168.1.1:22 -P ssh -U users.txt -W passwords.txt"
echo -e "    $BINARY_NAME --list-protocols"
echo ""
