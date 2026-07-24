#!/usr/bin/env bash
set -euo pipefail

VELTRIX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_NAME="veltrix"
INSTALL_DIR="/usr/local/bin"
BUILD_MODE="release"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

usage() {
    cat <<EOF
Veltrix Installer v1.0

Usage: $0 [OPTIONS]

Options:
  -d, --dir <PATH>     Install binary to custom directory (default: /usr/local/bin)
  -r, --release        Build in release mode (default)
  -D, --debug          Build in debug mode (faster build, slower runtime)
  -h, --help           Show this help message

Examples:
  $0                                     # Install to /usr/local/bin
  $0 -d ~/.local/bin                     # Install to user directory
  $0 -D                                  # Build debug (dev testing)
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--dir) INSTALL_DIR="$2"; shift 2 ;;
        -r|--release) BUILD_MODE="release"; shift ;;
        -D|--debug) BUILD_MODE="debug"; shift ;;
        -h|--help) usage ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; usage ;;
    esac
done

echo -e "${CYAN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         Veltrix Installer v1.0                ║${NC}"
echo -e "${CYAN}║   Multi-Protocol Brute Force Toolkit          ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════╝${NC}"

if ! command -v cargo &>/dev/null; then
    echo -e "${RED}[!] Rust/Cargo not found. Please install Rust first:${NC}"
    echo "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

echo -e "\n${YELLOW}[1/4] Checking dependencies...${NC}"
RUST_VERSION=$(rustc --version | cut -d' ' -f2)
echo -e "  ${GREEN}✓${NC} Rust $RUST_VERSION detected"

if ! pkg-config --exists openssl 2>/dev/null && ! ldconfig -p | grep -q libssl 2>/dev/null; then
    echo -e "${YELLOW}[!] OpenSSL not detected. Attempting build anyway...${NC}"
fi

echo -e "\n${YELLOW}[2/4] Building veltrix ($BUILD_MODE mode)...${NC}"
BUILD_FLAG=""
if [ "$BUILD_MODE" = "release" ]; then
    BUILD_FLAG="--release"
fi

if ! cargo build $BUILD_FLAG --manifest-path "$VELTRIX_DIR/Cargo.toml"; then
    echo -e "${RED}[!] Build failed. Check the error output above.${NC}"
    exit 1
fi

if [ "$BUILD_MODE" = "release" ]; then
    BINARY_PATH="$VELTRIX_DIR/target/release/$BINARY_NAME"
else
    BINARY_PATH="$VELTRIX_DIR/target/debug/$BINARY_NAME"
fi

if [ ! -f "$BINARY_PATH" ]; then
    echo -e "${RED}[!] Binary not found at $BINARY_PATH${NC}"
    exit 1
fi

BINARY_SIZE=$(du -h "$BINARY_PATH" | cut -f1)
echo -e "  ${GREEN}✓${NC} Build complete ($BINARY_SIZE)"

echo -e "\n${YELLOW}[3/4] Installing binary to $INSTALL_DIR...${NC}"
mkdir -p "$INSTALL_DIR"

if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
    echo -e "  ${YELLOW}⚠${NC} Existing installation found, backing up to ${BINARY_NAME}.bak"
    cp "$INSTALL_DIR/$BINARY_NAME" "$INSTALL_DIR/${BINARY_NAME}.bak" 2>/dev/null || true
fi

cp "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"
chmod 755 "$INSTALL_DIR/$BINARY_NAME"

echo -e "  ${GREEN}✓${NC} Installed to $INSTALL_DIR/$BINARY_NAME"

echo -e "\n${YELLOW}[4/4] Verifying installation...${NC}"
if "$INSTALL_DIR/$BINARY_NAME" --help &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Installation verified"
else
    if "$INSTALL_DIR/$BINARY_NAME" --version &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Installation verified"
    else
        echo -e "  ${RED}⚠${NC} Binary installed but execution test failed"
    fi
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Installation Complete!               ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Binary:       ${CYAN}$INSTALL_DIR/$BINARY_NAME${NC}"
echo -e "  Version:      ${CYAN}$("$INSTALL_DIR/$BINARY_NAME" --version 2>/dev/null || echo "v1.0.0")${NC}"
echo -e "  Build Mode:   ${CYAN}$BUILD_MODE${NC}"
echo ""
echo -e "  ${YELLOW}Quick Start:${NC}"
echo -e "    $BINARY_NAME -t 192.168.1.1:22 -P ssh -U users.txt -W passwords.txt"
echo -e "    $BINARY_NAME -T targets.txt -P ssh,ftp -U users.txt -W passes.txt -x 20"
echo -e "    $BINARY_NAME --list-protocols"
echo ""
echo -e "  ${YELLOW}To uninstall:${NC}  sudo $VELTRIX_DIR/uninstall.sh"
echo ""
