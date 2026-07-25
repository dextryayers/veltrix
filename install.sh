#!/usr/bin/env bash
set -euo pipefail

VELTRIX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_NAME="veltrix"
INSTALL_DIR="/usr/local/bin"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

spinner() {
    local pid=$1
    local msg="$2"
    local chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${CYAN}%s${NC} %s" "${chars:$i:1}" "$msg"
        i=$(( (i+1) % ${#chars} ))
        sleep 0.08
    done
    printf "\r  ${GREEN}✓${NC} %s\n" "$msg"
}

progress_bar() {
    local current=$1
    local total=$2
    local msg="$3"
    local pct=$(( current * 100 / total ))
    local bar_len=30
    local filled=$(( pct * bar_len / 100 ))
    local empty=$(( bar_len - filled ))
    printf "\r  ${CYAN}▶${NC} %s [${CYAN}" "$msg"
    printf '█%.0s' $(seq 1 $filled)
    printf '░%.0s' $(seq 1 $empty)
    printf "${NC}] %3d%%" "$pct"
    if [ "$current" -eq "$total" ]; then echo; fi
}

echo -e "${CYAN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         Veltrix Installer v1.1                ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════╝${NC}"

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
    echo -e "\n${YELLOW}  ⚡ No pre-built binary found. Compiling from source...${NC}\n"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/veltrix-target}"
    (
        cargo build --release --manifest-path "$VELTRIX_DIR/Cargo.toml" 2>/dev/null || {
            unset CARGO_TARGET_DIR
            cargo build --release --manifest-path "$VELTRIX_DIR/Cargo.toml"
        }
    ) &
    spinner $! "Compiling veltrix (release mode)"
    BINARY_PATH="$VELTRIX_DIR/target/release/$BINARY_NAME"
    [ ! -f "$BINARY_PATH" ] && BINARY_PATH="/tmp/veltrix-target/release/$BINARY_NAME"
fi

if [ ! -f "$BINARY_PATH" ]; then
    echo -e "  ${RED}✗ Failed to find or build binary.${NC}"
    exit 1
fi

echo -e "\n${YELLOW}  📦 Installing...${NC}\n"

for i in $(seq 1 10); do
    progress_bar "$i" 10 "Copying binary to $INSTALL_DIR"
    sleep 0.05
done

mkdir -p "$INSTALL_DIR"
cp "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"
chmod 755 "$INSTALL_DIR/$BINARY_NAME"

echo -e ""
sleep 0.2

# Celebration animation
for frame in \
    "  🎉 ${GREEN}INSTALLATION COMPLETE!${NC}" \
    "  ✨ ${GREEN}INSTALLATION COMPLETE!${NC}" \
    "  🎉 ${GREEN}INSTALLATION COMPLETE!${NC}" \
    "  ✨ ${GREEN}INSTALLATION COMPLETE!${NC}"
do
    printf "\r%s" "$frame"
    sleep 0.15
done
echo -e "\n"

echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Installation Complete!               ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}$INSTALL_DIR/$BINARY_NAME${NC} is ready to use."
echo -e "  ${YELLOW}Size:${NC} $(du -h "$BINARY_PATH" | cut -f1)"
echo ""
echo -e "  Quick start:"
echo -e "    $BINARY_NAME -t 192.168.1.1 -u admin -W passwords.txt -p admin123"
echo -e "    $BINARY_NAME -t 10.0.0.0/24 -U users.txt -W passwords.txt -x 20"
echo -e "    $BINARY_NAME -t 192.168.1.5 -C combos.txt -o results.json -f json"
echo -e "    $BINARY_NAME --list-protocols"
echo -e "    $BINARY_NAME --help"
echo ""
