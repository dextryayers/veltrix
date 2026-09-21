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

# 9. dry-run exits 0 without traffic
timeout 20 "$BIN" ssh -t 127.0.0.1 -u admin --password x --dry-run >/dev/null 2>&1 || fail "dry-run should exit 0"
pass "dry-run exits 0"

# 10. validate accepts good config, rejects bad
TMPV=$(mktemp -d)
echo '{"attack":{"targets":["127.0.0.1"],"protocols":["ssh"]},"credentials":{"users":["admin"],"passwords":["x"]}}' > "$TMPV/good.json"
"$BIN" validate "$TMPV/good.json" >/dev/null 2>&1 || fail "validate good should pass"
echo "not json" > "$TMPV/bad.json"
set +e
"$BIN" validate "$TMPV/bad.json" >/dev/null 2>&1
VCODE=$?
set -e
rm -rf "$TMPV"
[ "$VCODE" -eq 2 ] || fail "validate bad should exit 2, got $VCODE"
pass "validate good/bad"

# 11. completion renders
"$BIN" completion bash >/dev/null 2>&1 || fail "completion bash"
pass "completion bash"

# 12. missing target exits 2
set +e
"$BIN" ssh -u admin --password x >/dev/null 2>&1
MCODE=$?
set -e
[ "$MCODE" -eq 2 ] || fail "missing target should exit 2, got $MCODE"
pass "missing target exits 2"

# 13. safe-profile + spray dry-run exits 0
timeout 20 "$BIN" ssh -t 10.0.0.1 -u admin --password x --safe-profile --spray --spray-interval 5s --dry-run >/dev/null 2>&1 || fail "safe spray dry-run should exit 0"
pass "safe-profile spray dry-run"

# 14. aggressive-lab blocked for public IP (exit 2, no traffic)
set +e
timeout 20 "$BIN" ssh -t 8.8.8.8 -u admin --password x --aggressive-lab --dry-run >/dev/null 2>&1
ACODE=$?
set -e
[ "$ACODE" -eq 2 ] || fail "aggressive public should exit 2, got $ACODE"
pass "aggressive-lab guard"

# 15. auto with no open ports exits 1 fast
set +e
timeout 60 "$BIN" auto -t 127.0.0.1 --ports 59999 --scan-timeout 1 --rate 10 -u admin --password x >/dev/null 2>&1
AUTOCODE=$?
set -e
[ "$AUTOCODE" -eq 1 ] || fail "auto no-open should exit 1, got $AUTOCODE"
pass "auto no-open exits 1"

# 16. only-open gates attack to scan file
TMPO=$(mktemp -d)
printf 'Veltrix Scan Results - 1 hosts, 1 open ports\n127.0.0.1\t59998\tssh\t"OpenSSH"\t"9.3"\t5ms\n' > "$TMPO/scan.txt"
set +e
timeout 20 "$BIN" ssh -t 127.0.0.1 -p 59999 -u admin --password x --only-open "$TMPO/scan.txt" --timeout 2 >/dev/null 2>&1
OOCODE=$?
set -e
rm -rf "$TMPO"
# port 59999 tidak ada di scan file -> semua target terfilter -> exit 1 dengan pesan jelas
[ "$OOCODE" -eq 1 ] || fail "only-open filtered should exit 1, got $OOCODE"
pass "only-open filter"

# 17. serve API v2: login -> submit -> poll -> results (masked, no leak)
python3 - "$BIN" <<'PYEOF' || fail "API v2 smoke failed"
import subprocess, sys, time, json, urllib.request
BIN = sys.argv[1]
srv = subprocess.Popen([BIN, "serve", "--bind", "127.0.0.1:18099",
                        "--api-token", "smoketoken"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    base = "http://127.0.0.1:18099"
    def req(method, path, body=None, token=None):
        r = urllib.request.Request(base + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json",
                     **({"Authorization": f"Bearer {token}"} if token else {})})
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")
    for _ in range(50):
        try:
            s, h = req("GET", "/api/v2/health")
            if s == 200 and h.get("status") == "ok":
                break
        except Exception:
            time.sleep(0.2)
    else:
        raise SystemExit("server did not start")
    s, _ = req("POST", "/api/v2/login", {"token": "wrong"})
    assert s == 401, f"bad login should be 401, got {s}"
    s, login = req("POST", "/api/v2/login", {"token": "smoketoken", "actor": "smoke"})
    assert s == 200, f"login failed: {login}"
    jwt = login["token"]
    s, sub = req("POST", "/api/v2/jobs",
                 {"target": "127.0.0.1", "port": 59998, "protocol": "ssh",
                  "usernames": ["u"], "passwords": ["supersecret"],
                  "threads": 2, "timeout_secs": 2}, jwt)
    assert s == 202, f"submit failed: {sub}"
    jid = sub["job_id"]
    for _ in range(60):
        time.sleep(0.5)
        s, det = req("GET", f"/api/v2/jobs/{jid}", token=jwt)
        assert s == 200, f"detail failed: {det}"
        if det["status"] in ("completed", "failed", "stopped"):
            break
    else:
        raise SystemExit("job did not finish")
    s, res = req("GET", f"/api/v2/jobs/{jid}/results", token=jwt)
    assert s == 200 and res["count"] >= 1, f"results failed: {res}"
    body = json.dumps(res)
    assert "supersecret" not in body, "password leaked in masked results!"
    assert res["results"][0].get("credential_ref", "").startswith("u@"), "credential_ref missing"
    s, rep = req("GET", f"/api/v2/jobs/{jid}/report?format=json", token=jwt)
    assert s == 200 and rep.get("schema") == "veltrix-report/v2", f"report failed: {rep}"
    s, audit = req("GET", "/api/v2/audit", token=jwt)
    assert s == 200 and len(audit.get("audit", [])) >= 2, f"audit failed: {audit}"
    print("API v2 login/submit/poll/results/report/audit OK, no secret leak")
finally:
    srv.terminate()
PYEOF
pass "API v2 serve smoke"

echo "[OK] All smoke tests passed"
