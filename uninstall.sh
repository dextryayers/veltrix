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
Veltrix Uninstaller v1.1

Usage: $0 [OPTIONS]

Options:
  -d, --dir <PATH>     Uninstall from custom directory (default: /usr/local/bin)
  -p, --purge          Also remove config files and cache
  -h, --help           Show this help message
EOF
    exit 0
}

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

progress_remove() {
    local msg="$1"
    local chars='▰▱▰▱▰▱▰▱'
    for i in $(seq 0 8); do
        printf "\r  ${RED}%s${NC} %s" "${chars:$i:1}" "$msg"
        sleep 0.06
    done
    printf "\r  ${GREEN}✓${NC} %s\n" "$msg"
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
echo -e "${CYAN}║         Veltrix Uninstaller v1.1              ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════╝${NC}"

BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"
BACKUP_PATH="$INSTALL_DIR/${BINARY_NAME}.bak"

echo -e "\n${YELLOW}[1/3] Removing binary...${NC}\n"

if [ -f "$BINARY_PATH" ]; then
    ( sleep 0.4 ) &
    spinner $! "Removing $BINARY_PATH"
    rm -f "$BINARY_PATH"
else
    echo -e "  ${YELLOW}⚠${NC} Binary not found at $BINARY_PATH"
fi

if [ -f "$BACKUP_PATH" ]; then
    echo -e "  ${YELLOW}⚠${NC} Backup found at $BACKUP_PATH (not removed)"
fi

echo -e "\n${YELLOW}[2/3] Checking for configuration files...${NC}\n"

REMOVED_ANY=false
for dir in "${CONFIG_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        if [ "$PURGE" = true ]; then
            progress_remove "Removing $dir"
            rm -rf "$dir"
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
            progress_remove "Removing cache $dir"
            rm -rf "$dir"
        else
            echo -e "  ${YELLOW}⚠${NC} Found cache $dir (use --purge to remove)"
        fi
    fi
done

if [ "$REMOVED_ANY" = false ]; then
    echo -e "  ${GREEN}✓${NC} No config files found"
fi

echo -e "\n${YELLOW}[3/3] Verifying uninstall...${NC}\n"

if command -v $BINARY_NAME &>/dev/null; then
    FOUND_PATH=$(which $BINARY_NAME 2>/dev/null || true)
    echo -e "  ${YELLOW}⚠${NC} Binary still found at $FOUND_PATH (different installation path)"
else
    ( sleep 0.3 ) &
    spinner $! "Verifying removal"
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
