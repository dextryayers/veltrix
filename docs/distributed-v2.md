# Distributed Mode v2 (`veltrix-dist-v2`)

Skala horizontal untuk engagement besar: coordinator membagi kerja menjadi
chunk deterministik, worker menarik (pull) dan mengeksekusi.

## Protokol

Setiap pesan membawa `version, run_id, chunk_id, checksum, resume_offset`.
Chunk = N task (`target × credential`), di-hash untuk split deterministik:
3 node menghasilkan hasil identik dengan 1 node untuk input sama.

## Menjalankan

```bash
# Coordinator (butuh target + kredensial + token):
export VELTRIX_DIST_TOKEN="token-rahasia-kuat"
veltrix dist-coordinator --bind 127.0.0.1:5555 \
  -t 10.0.0.0/24 -U users.txt -W pass.txt --protocol ssh \
  --chunk-size 100 --chunk-timeout 120 --max-attempts 3

# Worker (1..N mesin):
veltrix dist-worker --connect 10.0.0.1:5555 \
  --dist-token "$VELTRIX_DIST_TOKEN" --name worker-1 --threads 10 \
  --checkpoint-file /tmp/worker-1.ckpt
```

## Keamanan

- Token per-run (`--dist-token` / `VELTRIX_DIST_TOKEN`), kedaluwarsa
  `--dist-token-ttl` (default 6 jam).
- Wajib mTLS/WireGuard bila coordinator dibuka ke network tidak tepercaya —
  transport bawaan BUKAN TLS.
- Bind default localhost; `0.0.0.0` hanya di net terpercaya.

## Ketahanan (chaos-tested)

- Worker mati di tengah jalan → chunk in-flight dikembalikan antre setelah
  `--chunk-timeout`, tidak ada kombinasi hilang/duplikat (lihat
  `tests/dist_chaos.rs`).
- Worker menyimpan checkpoint task yang sudah di-ack (`--checkpoint-file`)
  untuk resume cepat.
- Observability: throughput per node, daftar chunk gagal, heartbeat timeout
  (`--heartbeat-timeout`, default 60 dtk).

## Batasan v2.0

- Default tetap single-node; distributed di belakang subcommand eksplisit.
- Chunk gagal > `--max-attempts` ditandai failed dan dilaporkan, bukan
  di-retry selamanya — periksa daftarnya sebelum menyimpulkan "no finding".
