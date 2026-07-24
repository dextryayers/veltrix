#!/usr/bin/env bash
set -euo pipefail

BINARY_NAME="veltrix"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIRS=(
    "$HOME/.config/veltrix"
    "$HOME/.veltrix"
)

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

usage() {
    cat <<EOF
Veltrix Uninstaller v1.0

Usage: $0 [OPTIONS]

Options:
  -d, --dir <PATH>     Uninstall from custom directory (default: /usr/local/bin)
  -p, --purge          Also remove config files and cache
  -h, --help           Show this help message
EOF
    exit 0
}

PURGE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--dir) INSTALL_DIR="$2"; shift 2 ;;
        -p|--purge) PURGE=true; shift ;;
        -h|--help) usage ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; usage ;;
    esac
done

echo -e "${CYAN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         Veltrix Uninstaller v1.0             ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════╝${NC}"

BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"
BACKUP_PATH="$INSTALL_DIR/${BINARY_NAME}.bak"

echo -e "\n${YELLOW}[1/3] Removing binary...${NC}"
if [ -f "$BINARY_PATH" ]; then
    rm -f "$BINARY_PATH"
    echo -e "  ${GREEN}✓${NC} Removed $BINARY_PATH"
else
    echo -e "  ${YELLOW}⚠${NC} Binary not found at $BINARY_PATH"
fi

if [ -f "$BACKUP_PATH" ]; then
    echo -e "  ${YELLOW}⚠${NC} Backup found at $BACKUP_PATH (not removed)"
fi

echo -e "\n${YELLOW}[2/3] Checking for other installation artifacts...${NC}"
REMOVED_ANY=false
for dir in "${CONFIG_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        if [ "$PURGE" = true ]; then
            rm -rf "$dir"
            echo -e "  ${GREEN}✓${NC} Removed $dir"
            REMOVED_ANY=true
        else
            echo -e "  ${YELLOW}⚠${NC} Found $dir (use --purge to remove)"
        fi
    fi
done

CACHE_DIRS=(
    "$HOME/.cache/veltrix"
)
for dir in "${CACHE_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        if [ "$PURGE" = true ]; then
            rm -rf "$dir"
            echo -e "  ${GREEN}✓${NC} Removed cache $dir"
        else
            echo -e "  ${YELLOW}⚠${NC} Found cache $dir (use --purge to remove)"
        fi
    fi
done

if [ "$REMOVED_ANY" = false ]; then
    echo -e "  ${GREEN}✓${NC} No config files found"
fi

echo -e "\n${YELLOW}[3/3] Verifying uninstall...${NC}"
if command -v $BINARY_NAME &>/dev/null; then
    FOUND_PATH=$(which $BINARY_NAME 2>/dev/null || true)
    echo -e "  ${YELLOW}⚠${NC} Binary still found at $FOUND_PATH (different installation path)"
else
    echo -e "  ${GREEN}✓${NC} Veltrix successfully removed from PATH"
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         Uninstall Complete!                   ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${YELLOW}To reinstall:${NC}  sudo $PWD/install.sh"
echo ""

if [ "$PURGE" = false ]; then
    echo -e "  ${YELLOW}Note: Config files preserved. Use --purge to remove them.${NC}"
fi
