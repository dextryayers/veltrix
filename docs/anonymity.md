# Anonimitas Brute-Force (Anti-Tracking)

> Berlaku untuk audit resmi. Anonimitas di sini = meminimalkan jejak
> operasional yang tidak perlu, BUKAN izin untuk menyerang tanpa otorisasi.

## 1. Model ancaman (jujur)

| Lapisan | Tertutup proxy? | Keterangan |
|---|---|---|
| Isi traffic (creds, body) | Ya | Semua socket via proxy tunnel / reqwest proxy |
| IP sumber di sisi target | Ya (IP proxy) | Selama proxy hidup & sehat |
| **Tujuan koneksi (metadata)** | **Tidak** | Lihat §5 DNS-leak |
| Pola ritme (timing) | Sebagian | Lihat §4 |
| Sidik jari TLS/HTTP | Sebagian | UA dirotasi; fingerprint TLS bawaan reqwest/native-tls |

Veltrix TIDAK menjanjikan "tidak terlacak 100%". Yang dijanjikan: setiap
lapisan di atas ditangani eksplisit, dan sisanya diperingatkan, bukan
disembunyikan.

## 2. Verifikasi egress dulu (`check-ip`)

```bash
veltrix check-ip --proxy socks5://127.0.0.1:9050
#   egress via socks5://127.0.0.1:9050
#   egress IP: 185.xxx.xxx.xxx
```

Tanpa proxy, `check-ip` keluar kode 2 (peringatan IP asli terekspos).
Jadikan kebiasaan: `check-ip` → `--dry-run` → attack.

## 3. Proxy: fail-closed + sehat

```bash
veltrix ssh -t TARGET -U u.txt -W p.txt \
  --proxy socks5://127.0.0.1:9050 \
  --proxy-required          # abort bila tanpa proxy (exit 2)
  --check-proxy             # strict pre-flight: abort bila ADA yang mati
  --rotate-proxy-every 50   # sebar egress tiap 50 attempt
```

Perilaku mesin:

1. **Pre-flight** (selalu, tiap run): semua proxy di-TCP-test concurrent
   (5 dtk). Mati → dibuang + warn. Semua mati → **fail-closed**, attack
   dibatalkan sebelum paket pertama ke target.
2. **Runtime health**: proxy yang gagal koneksi/Timeout 5x beruntun di-ban
   60 dtk dan dilewati otomatis; sukses me-reset strike.
3. **Rotasi sinyal**: rate-limit dari target memicu ganti proxy + cooldown.
4. Kredensial proxy (`user:pass@`) TIDAK PERNAH dicetak di log/console —
   hanya `host:port`.

Rotasi file: `--proxy-file proxies.txt` (satu `type://[user:pass@]host:port`
per baris) dengan round-robin per worker.

## 4. Anti-fingerprinting ritme & header

```bash
veltrix ssh ... --delay 300 --random-delay 400 --rate-limit 5 \
  --spray --spray-interval 30m --spray-jitter 20
```

- `--delay N` + `--random-delay M`: tiap attempt tidur `N + uniform(0,M)` ms
  (default M=100). Ritme mekanis murni mudah dikenali IDS.
- `--spray-interval` + `--spray-jitter`: jeda antar ronde spray tidak
  periodik sempurna.
- HTTP: User-Agent dirotasi per request dari pool realistis (atau
  `--user-agent` kustom); cookie jar + header Accept standar selalu aktif;
  probe scanner memakai UA pool (tidak ada lagi UA statis / EHLO identitas
  tool).

## 5. DNS-leak (baca ini!)

Resolusi nama memakai **resolver lokal**, bukan via proxy. Artinya: resolver
atau pengamat jaringan lokal tahu *kemana* Anda menyerang, walau isi
traffic tertutup proxy. Saat proxy aktif + target berupa hostname, Veltrix
mencetak `DNS-leak note` dengan daftar host yang di-resolve lokal.

Mitigasi, dari paling mudah ke paling kuat:

1. Pakai **IP literal** di `-t` (tidak ada DNS sama sekali).
2. Jalankan resolver lokal yang aman (DoH/DoT sistem) — di luar scope tool.
3. Untuk Tor: arahkan `--proxy socks5://127.0.0.1:9050` (Tor) dan pahami
   bahwa SOCKS5 handshake Veltrix mengirim **hostname** ke proxy (remote
   resolution di sisi Tor) untuk koneksi TCP mentah — tetapi resolusi awal
   target di orchestrator tetap lokal. IP literal tetap paling aman.

`--dry-run` TIDAK menyentuh proxy/DNS sama sekali dan mencatatnya eksplisit
di baris catatan rencana.

## 6. Egress via interface (`--source-ip`)

Multihomed/VPN: `--source-ip 10.8.0.5` mengikat semua socket egress mentah
ke IP lokal tersebut (berlaku untuk scanner, preflight proxy, dan protokol
TCP mentah). Catatan jujur: path HTTP `reqwest` tidak mendukung bind sumber
— untuk HTTP, anonimitas penuh = lewat proxy.

## 7. Jejak lokal (opsec mesin operator)

- Password default **masked** di console/file (`--show-secrets` untuk penuh).
- Session file berisi kredensial plaintext → otomatis `chmod 0600` (unix).
- `--encrypt` (AES-256-GCM + Argon2) untuk arsip output.
- Setelah engagement: `shred -u session.json hasil.*` dan putar kredensial
  yang berhasil ditemukan.

## 8. Checklist pra-attack anonim

```bash
veltrix check-ip --proxy "$P"              # 1. egress sesuai?
veltrix ssh ... --dry-run                  # 2. total & estimasi & Rules
veltrix ssh ... --proxy "$P" --proxy-required --check-proxy \
  --rotate-proxy-every 50 --random-delay 400 --rate-limit 5 \
  --resume session.json -o hasil.json -f json   # 3. eksekusi
```
