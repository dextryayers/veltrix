# Veltrix REST API v2 + Web UI

Server: `veltrix serve --bind 127.0.0.1:8080 [--api-token TOKEN] [--api-rate-limit 120]`.
Web UI: buka `http://127.0.0.1:8080/` di browser.

> Bind ke `127.0.0.1` atau jaringan manajemen tepercaya. Jangan expose ke
> internet tanpa reverse proxy + TLS. Token API bersifat sensitif.

## Auth

Pre-shared token dari `--api-token`, env `VELTRIX_API_TOKEN`, atau ephemeral
yang dicetak sekali saat start (stderr, `[!] Ephemeral API token`).

```bash
# 1. Login -> JWT 12 jam
JWT=$(curl -s -X POST http://127.0.0.1:8080/api/v2/login \
  -H 'Content-Type: application/json' \
  -d '{"token":"<API-TOKEN>","actor":"alice"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# Semua endpoint /api/v2/* (kecuali /login dan /health) wajib:
#   Authorization: Bearer $JWT
```

Rate limit default 120 req/menit/IP (429 bila lewat). Semua login, submit,
stop, dan akses secrets dicatat di audit log.

## Jobs (non-blocking)

```bash
# Submit -> 202 {job_id, status: queued}
JID=$(curl -s -X POST http://127.0.0.1:8080/api/v2/jobs \
  -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"target":"10.0.0.5","port":22,"protocol":"ssh",
       "usernames":["admin","root"],"passwords":["admin123","toor"],
       "threads":10,"timeout_secs":10}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['job_id'])")

# Detail + progres (progress = estimasi attempts/total, 1.0 saat selesai)
curl -s http://127.0.0.1:8080/api/v2/jobs/$JID -H "Authorization: Bearer $JWT"

# Daftar jobs (password tidak pernah muncul di sini)
curl -s http://127.0.0.1:8080/api/v2/jobs -H "Authorization: Bearer $JWT"

# Hentikan job berjalan
curl -s -X POST http://127.0.0.1:8080/api/v2/jobs/$JID/stop \
  -H "Authorization: Bearer $JWT"
```

Batas API: maks 1.000.000 kombinasi per job (lebih besar pakai CLI).
Status: `queued | running | completed | failed | stopped`.

## Hasil dan report (masked default)

```bash
# Hasil: password masked ("p***"), credential_ref tanpa plaintext
curl -s http://127.0.0.1:8080/api/v2/jobs/$JID/results \
  -H "Authorization: Bearer $JWT"

# Password penuh hanya dengan show_secrets eksplisit (dicatat di audit!)
curl -s "http://127.0.0.1:8080/api/v2/jobs/$JID/results?show_secrets=1" \
  -H "Authorization: Bearer $JWT"

# Report envelope v2 (skema veltrix-report/v2, findings = skema veltrix-finding/v2)
curl -s "http://127.0.0.1:8080/api/v2/jobs/$JID/report?format=json" \
  -H "Authorization: Bearer $JWT"

# Report HTML (executive summary + remediation + evidence, masked default)
curl -s "http://127.0.0.1:8080/api/v2/jobs/$JID/report?format=html" \
  -H "Authorization: Bearer $JWT" -o report.html
```

## Live progress via websocket

```
GET /api/v2/jobs/{id}/events?token=<JWT>
```

Auth lewat header `Authorization` atau query `?token=` (browser WS tidak bisa
set header). Server kirim snapshot lalu event `{job_id, status, progress,
attempts, successes, msg, ts}` tiap tick, dan menutup koneksi saat job
`completed|failed|stopped`.

```bash
# Contoh dengan websocat:
websocat "ws://127.0.0.1:8080/api/v2/jobs/$JID/events?token=$JWT"
```

## Endpoint lain

```bash
curl -s http://127.0.0.1:8080/api/v2/health          # tanpa auth (LB check)
curl -s http://127.0.0.1:8080/api/v2/status -H "Authorization: Bearer $JWT"
curl -s http://127.0.0.1:8080/api/v2/protocols -H "Authorization: Bearer $JWT"
curl -s "http://127.0.0.1:8080/api/v2/audit?limit=50" -H "Authorization: Bearer $JWT"
```

## Skema JSON v2 (file `-o -f json`)

Tiap baris = satu objek `veltrix-finding/v2` (JSONL): `schema, run_id, seq,
started_at, finished_at, target_host, target_port, protocol, username,
credential_ref (user@host:port#hash8, tanpa password), success, severity
(high/medium/info), duration_ms, timestamp, evidence (dipotong 200 char)`.

## Migrasi dari v1

Endpoint `/api/v1/*` (server HTTP manual tanpa auth) dihapus dan diganti v2.
Perbedaan utama: auth JWT wajib, `POST /jobs` async 202 (dulu sinkron
blocking), hasil masked default, dan ada websocket progres + audit log.
