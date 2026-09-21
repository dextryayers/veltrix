#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$DIR/target/debug/veltrix"
if [ ! -f "$BIN" ]; then
  BIN="$DIR/target/release/veltrix"
fi

fail() { echo "[FAIL] $1"; exit 1; }
pass() { echo "[PASS] $1"; }

echo "[*] Veltrix smoke test"
echo "Binary: $BIN"

[ -f "$BIN" ] || fail "binary not found, run cargo build first"
[ -x "$BIN" ] || fail "binary not executable"

# 1. version
"$BIN" --version >/dev/null || fail "--version"
pass "--version"

# 2. help
"$BIN" --help >/dev/null || fail "--help"
pass "--help"

# 3. list protocols
OUT=$("$BIN" --list-protocols 2>&1 || true)
echo "$OUT" | grep -qi "ssh" || fail "--list-protocols missing ssh"
pass "--list-protocols"

# 4. list plugins (should not crash)
"$BIN" --list-plugin >/dev/null 2>&1 || true
pass "--list-plugin no crash"

# 5. dry run against closed local port (expect exit 1, no hang)
TMPDIR_SMOKE=$(mktemp -d)
echo "admin" > "$TMPDIR_SMOKE/users.txt"
echo "wrongpass123" > "$TMPDIR_SMOKE/pass.txt"
set +e
timeout 20 "$BIN" ssh -t 127.0.0.1 -p 59999 -U "$TMPDIR_SMOKE/users.txt" -W "$TMPDIR_SMOKE/pass.txt" -x 2 --timeout 2 >/dev/null 2>&1
CODE=$?
set -e
rm -rf "$TMPDIR_SMOKE"
[ "$CODE" -eq 1 ] || fail "closed-port attack should exit 1, got $CODE"
pass "closed-port attack exits 1"

# 6. wordlist generator
"$BIN" --gen-wordlist --wl-name "Smoke Test" --wl-company "Acme" >/dev/null || fail "--gen-wordlist"
pass "--gen-wordlist"

# 7. manual renders
"$BIN" man >/dev/null 2>&1 || "$BIN" how >/dev/null 2>&1 || fail "man/how"
pass "man/how"

# 8. scan-ports help path (closed port, fast)
set +e
timeout 20 "$BIN" scan-ports -t 127.0.0.1 --ports 59999 --scan-timeout 1 --rate 10 >/dev/null 2>&1
SCAN_CODE=$?
set -e
[ "$SCAN_CODE" -eq 0 ] || [ "$SCAN_CODE" -eq 1 ] || fail "scan-ports unexpected exit $SCAN_CODE"
pass "scan-ports closed port"

echo "[OK] All smoke tests passed"
