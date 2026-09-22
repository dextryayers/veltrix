# Bench Resmi v2.0 (Fase 8 + 9)

Tanggal: 2026-09-22
Cakupan: planner end-to-end via `--dry-run` (tanpa network I/O, reproducible).
Harness: `cargo test --test perf -- --nocapture` (debug) + pengukuran manual
profil release di bawah (mesin dev lokal).

> Catatan jujur: angka di bawah mengukur **planner** (parse target, hitung
> file wordlist via mmap, ekspansi rules dry-count, render rencana) — BUKAN
> throughput brute-force jaringan, yang didominasi latency target dan rate
> limit. Throughput jaringan hanya bermakna di lab Docker (`scripts/smoke.sh`,
> `docker/docker-compose.test.yml`) dan tidak diklaim di sini.

## Hasil release (`target/release/veltrix`, 9.9 MB)

| Skenario | Kombinasi | Waktu planner | Keterangan |
|---|---|---|---|
| Single target, 3 user x 4 pass | 12 | ~8 ms | parse + rencana |
| CIDR /24, 3 user x 4 pass | 3.048 | ~7 ms | expand 254 host, dedup |
| 1 target x 1M password (file 17 MB) | 1.000.000 | ~90 ms | mmap line-count, tanpa OOM |
| Proxy off vs on (dry-run) | 12 | 8 ms vs 7 ms | rasio ~1.0x, config path tanpa overhead |
| Rules dry-run (4 base, 5 rules) | estimasi akurat | ~27 ms (debug) | baris `Rules:` tampil, cap enforced |

## Hasil debug (`cargo test --test perf`)

| Skenario | Waktu (debug) |
|---|---|
| Single target (12) | ~20 ms (dominan spawn proses) |
| CIDR /24 (3048) | ~20 ms |
| 1M password | ~408 ms |
| Proxy off vs on | 19.9 ms vs 18.2 ms, rasio 0.92x |
| Rules expansion | ~27 ms + catatan `Rules:` |

## Interpretasi untuk operator

1. **Planner bukan bottleneck.** 1M password direncanakan dalam <100 ms
   release; file 17 MB tidak meledak di memori (mmap counting, bukan
   `Vec<String>` penuh di path dry-run).
2. **Runtime = jaringan.** Estimasi waktu (`Estimated:`) memakai model
   `total/rate` bila `--rate-limit` diset, else heuristik 10% timeout per
   attempt dibagi threads. Selalu mulai dari `--dry-run` untuk run besar.
3. **Proxy gratis di config path.** Tidak ada alasan melewatkan proxy demi
   "kecepatan planner"; overhead proxy nyata hanya handshake TCP per koneksi.
4. **Rules aman.** Ekspansi di-dry-run sebelum traffic; cap
   `--max-mutations` ditegakkan; kata dasar selalu dipertahankan (dicek test
   `test_base_words_always_kept`).
5. **Binary 9.9 MB** — di batas target <10 MB (Fase 9.1). Kompresi UPX opsional
   untuk distribusi (lihat F9.6).

## Cara mereproduksi

```bash
cargo test --test perf -- --nocapture   # debug, ~0.4 dtk
cargo build --release
time ./target/release/veltrix ssh -t 192.168.1.0/24 \
  -U /tmp/veltrix-perf/perf_users3.txt \
  -W /tmp/veltrix-perf/perf_passwords4.txt --dry-run
```

## Tindak lanjut (di luar v2.0)

- Bench throughput jaringan riil per protokol di lab Docker tertutup
  (attempts/s untuk ssh/ftp/http, 10 threads) — butuh matriks kontainer.
- Profil memori RSS puncak untuk run 10M kombinasi (target <500 MB).
- `cargo bench` Criterion bila butuh mikro-bench regresi per rilis.
