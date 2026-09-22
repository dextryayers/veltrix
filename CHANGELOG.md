# Changelog Veltrix

## v2.0.0 (2026-09-22) — Fase 8 + 9: Wordlist/ML + QA/Rilis + Anonimitas

### Fase 8 — Wordlist, Rules, ML Pipeline

- **Rule engine v2**: sintaks `$ ^ @ ! ~ & D R T` terdokumentasi
  (`rules/common.rule` + `docs/wordlist-ml.md`); `max_mutations` ditegakkan;
  **kata dasar selalu dipertahankan** (bug lama: password mentah hilang saat
  `--rule` dipakai); `dry_count` akurat dan tampil di `--dry-run` (`Rules:`);
  guard warning untuk `$N` raksasa (kemungkinan maksud literal `@N`).
- **Wordlist generator v2**: profil target/perusahaan/DOB/keyword +
  basis musim+tahun + keyboard-walk (+reversed) + leet level 0–3;
  **fix ekstraksi tahun DOB** (`1990-05-14` sebelumnya salah jadi `514`).
- **ML ranker**: `wordlist rank --input --model --order --top --min-score -o`
  terverifikasi end-to-end (probable-first).
- **Evaluasi jujur**: `wordlist eval --ranked --relevant --k` → precision@K
  terukur; tidak ada klaim tanpa angka (`docs/wordlist-ml.md` §4).
- Tes baru: `parse_k_list`, `parse_ranked_lines`, planner note,
  `test_base_words_always_kept`, DOB multi-format.

### Fase 9 — QA, Performance, Docs, Rilis

- **Tes**: 290+ hijau (unit + `tests/bench.rs` + `tests/perf.rs` baru +
  `tests/dist_chaos.rs` + `tests/protocol_matrix.rs`).
- **Fuzz ringan**: target spec, combo line (parser diekstrak jadi
  `parse_combo_line` murni), HTTP Digest params + form classifier
  (diekstrak dari nested fn), banner/service-db, rules, proxy, fingerprint.
- **Bench resmi**: `tests/perf.rs` (single, CIDR /24, 1M password,
  proxy on/off, rules) + `docs/bench-v2.md` angka release
  (1M password ~90 ms, proxy rasio ~1.0x, biner 9.9 MB).
- **Security review**: `docs/security-review.md` (2 `unsafe` mmap sah,
  tanpa shell, creds via stdin ke plugin, session file `0600` — baru).
- **Docs**: `docs/usage.md`, `docs/wordlist-ml.md`, `docs/distributed-v2.md`,
  `docs/bench-v2.md`, `docs/security-review.md`, `docs/anonymity.md` (baru).
- **Rilis**: versi tunggal `Cargo.toml 2.0.0`, `scripts/package.sh`
  (biner + SHA256 + Docker), catatan migrasi di bawah.

### Anonimitas brute-force (todo tambahan)

- Fix kebocoran UA: path tanpa proxy kini rotasi pool (sebelumnya statis).
- Peringatan DNS-leak saat `--proxy-required` + mitigasi terdokumentasi.
- Proxy health tracking + auto-skip sementara proxy mati + `--check-proxy`.
- `--random-delay` (Manusiawi: base ± jitter%) + jitter aktif default 100 ms.
- `check-ip`: verifikasi egress sebelum menyerang; redaksi kredensial proxy
  di log; `--proxy-required` fail-closed tetap ditegakkan.

### Migrasi v1 → v2

- `--rule` kini **menambah** mutasi di samping kata dasar (dulu me-replace);
  total attempt bisa naik — cek `--dry-run` sebelum run panjang.
- `rules/common.rule` ditulis ulang ke sintaks benar (`@2024` literal,
  bukan `$2024` range); file rule lama bergaya `$TAHUN` akan memicu warning
  dan ekspansi besar — perbaiki ke `@TAHUN`.
- Session file lama tetap dibaca (fallback tanpa integrity check + warning).
- HTTP form error message berubah (`bad status` vs `ok`) — kosmetik.

## v1.2.0 — sebelumnya (Fase 0–7)

Streaming engine, CLI/config wiring, transport unifikasi 47 protokol,
stealth & anti-lockout, scan→auto attack, output/API/Web UI, distributed v2.
