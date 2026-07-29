#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/dextryayers/veltrix.git"
BINARY_NAME="veltrix"
REPO_DIR="${VELTRIX_REPO_DIR:-$HOME/.veltrix/repo}"
INSTALL_DIR="${VELTRIX_INSTALL_DIR:-}"
SKIP_BUILD="${VELTRIX_SKIP_BUILD:-}"
RELEASE_URL="${VELTRIX_RELEASE_URL:-https://github.com/dextryayers/veltrix/releases/latest/download}"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

info()  { printf "  ${CYAN}→${NC} %s\n" "$*"; }
ok()    { printf "  ${GREEN}✓${NC} %s\n" "$*"; }
warn()  { printf "  ${YELLOW}⚠${NC} %s\n" "$*"; }
err()   { printf "  ${RED}✗${NC} %s\n" "$*"; exit 1; }

SPIN_CHARS='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'

cleanup() { rm -rf "$TMPDIR"; }
TMPDIR=$(mktemp -d)
trap cleanup EXIT

LOG_FILE="$TMPDIR/build.log"

run_with_spinner() {
    local msg="$1"
    shift
    local i=0
    "$@" > "$LOG_FILE" 2>&1 &
    local pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${CYAN}%s${NC} %s" "${SPIN_CHARS:$i:1}" "$msg"
        i=$(( (i + 1) % 10 ))
        sleep 0.08
    done
    wait $pid
    local rc=$?
    if [[ $rc -eq 0 ]]; then
        printf "\r  ${GREEN}✓${NC} %s\n" "$msg"
    else
        printf "\r  ${RED}✗${NC} %s\n" "$msg"
        sed 's/^/    /' "$LOG_FILE"
        return 1
    fi
}

# ── Detect OS/Arch ──
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH_TRIPLE="x86_64-unknown-${OS}-gnu" ;;
    aarch64|arm64) ARCH_TRIPLE="aarch64-unknown-${OS}-gnu" ;;
    *) ARCH_TRIPLE="${ARCH}-unknown-${OS}" ;;
esac

if [[ "$OS" == "darwin" ]]; then
    ARCH_TRIPLE="${ARCH}-apple-darwin"
fi

echo -e "${CYAN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         Veltrix Installer v2.0                ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════╝${NC}"
echo ""

# ── Determine install directory ──
if [[ -z "$INSTALL_DIR" ]]; then
    if [[ -w /usr/local/bin ]]; then
        INSTALL_DIR="/usr/local/bin"
    elif [[ -w /usr/bin ]]; then
        INSTALL_DIR="/usr/bin"
    else
        INSTALL_DIR="$HOME/.local/bin"
        mkdir -p "$INSTALL_DIR"
        warn "No sudo access. Installing to ~/.local/bin (add to PATH if needed)"
    fi
fi
mkdir -p "$INSTALL_DIR"

install_local() {
    local src="$1"
    cp "$src" "$INSTALL_DIR/$BINARY_NAME"
    chmod 755 "$INSTALL_DIR/$BINARY_NAME"
    ok "Installed to $INSTALL_DIR/$BINARY_NAME ($(du -h "$src" | cut -f1))"
}

# ── Strategy 1: Running from repo directory ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd 2>/dev/null || true)"
if [[ -f "$SCRIPT_DIR/Cargo.toml" ]] && grep -q 'name = "veltrix"' "$SCRIPT_DIR/Cargo.toml" 2>/dev/null; then
    info "Repository found at $SCRIPT_DIR"
    cd "$SCRIPT_DIR"

    run_with_spinner "Fetching latest source..." git fetch origin || warn "Cannot fetch (no network?)"
    LOCAL=$(git rev-parse HEAD 2>/dev/null || true)
    REMOTE=$(git rev-parse @{upstream} 2>/dev/null || true)

    NEEDS_BUILD=false
    if [[ -n "$REMOTE" && "$LOCAL" != "$REMOTE" ]]; then
        run_with_spinner "Updating: $(git rev-parse --short HEAD) → $(git rev-parse --short "$REMOTE")..." git pull --ff-only 2>/dev/null || warn "Merge required, stashing and pulling..."
        NEEDS_BUILD=true
    elif [[ -z "$REMOTE" ]]; then
        warn "No upstream branch, using local source"
    else
        ok "Already up to date ($(git rev-parse --short HEAD))"
    fi

    # Skip build if binary exists, source unchanged, and not forced
    if [[ -z "$SKIP_BUILD" ]] && [[ -f "target/release/$BINARY_NAME" ]] && ! $NEEDS_BUILD; then
        SKIP_BUILD=1
    fi

    if [[ -z "$SKIP_BUILD" ]]; then
        run_with_spinner "Building veltrix (release)..." cargo build --release || err "Build failed"
    fi

    # Find the built binary
    for p in target/release/$BINARY_NAME target/debug/$BINARY_NAME; do
        [[ -f "$p" ]] && { install_local "$p"; break; }
    done
    exit 0
fi

# ── Strategy 2: Download pre-built binary ──
if [[ -z "$SKIP_BUILD" ]]; then
    if run_with_spinner "Downloading pre-built binary..." curl -sfL "${RELEASE_URL}/${BINARY_NAME}-${ARCH_TRIPLE}" -o "$TMPDIR/$BINARY_NAME"; then
        chmod +x "$TMPDIR/$BINARY_NAME"
        if "$TMPDIR/$BINARY_NAME" --version &>/dev/null || "$TMPDIR/$BINARY_NAME" --help &>/dev/null; then
            install_local "$TMPDIR/$BINARY_NAME"
            exit 0
        fi
        warn "Downloaded binary failed verification, falling back to build"
    else
        info "No pre-built binary available for ${OS}/${ARCH}, building from source"
    fi
fi

# ── Strategy 3: Clone & build ──
run_with_spinner "Cloning repository..." git clone --depth 1 "$REPO_URL" "$REPO_DIR" || err "Clone failed"
cd "$REPO_DIR"

if ! command -v cargo &>/dev/null; then
    err "Rust/Cargo not found. Install it first: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
fi

run_with_spinner "Building veltrix (release)..." cargo build --release || err "Build failed"
ok "Build complete"

install_local "target/release/$BINARY_NAME"

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Installation Complete!               ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}$INSTALL_DIR/$BINARY_NAME${NC}"
echo -e "  Commit: $(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")"
echo ""
echo -e "  ${YELLOW}Quick start:${NC}"
echo -e "    $BINARY_NAME -t 192.168.1.1 -u admin -W passwords.txt"
echo -e "    $BINARY_NAME -t 10.0.0.0/24 -U users.txt -W passwords.txt -x 20"
echo -e "    $BINARY_NAME -t 192.168.1.5 -C combos.txt -o results.json -f json"
echo -e "    $BINARY_NAME --list-protocols"
echo -e "    $BINARY_NAME --help"
echo ""
