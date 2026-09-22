# Security Review v2.0 (F9.4)

Tanggal: 2026-09-22. Metode: audit kode manual + `grep` + `cargo clippy`.
Lingkup: `unsafe`, eksekusi eksternal, secret handling, network fail-closed.

## 1. `unsafe` — BERSIH (2 lokasi, keduanya mmap read-only)

| Lokasi | Penggunaan | Verdict |
|---|---|---|
| `src/core/wordlist.rs:179` | `Mmap::map` untuk wordlist besar | Aman: mapping read-only, lifetime terikat `File`, akses via slice bounds-checked |
| `src/utils/mem_load.rs:15` | `Mmap::map` untuk prefetch | Aman: pola sama, tidak ada raw pointer arithmetic |

Tidak ada `unsafe` baru di Fase 8/9. Tidak ada `transmute`, raw pointer,
atau `static mut`.

## 2. Eksekusi eksternal — BERSIH

- Tidak ada `sh -c`, `system()`, atau shell string di manapun.
- Satu-satunya spawn: `src/core/plugin.rs::execute_plugin` memakai
  `tokio::process::Command::new(path)` langsung (tanpa shell) dengan SATU arg
  statis `--authenticate`.
- Validasi plugin (`validate_plugin_binary`): path harus file, harus executable
  (bit `0o111` di unix). Tidak ada auto-load direktori / PATH lookup.
- Kredensial ke plugin via **stdin JSON**, bukan argv → tidak bocor di `ps`.

## 3. Secret handling — DIPERKUAT di v2.0

| Jalur | Status |
|---|---|
| Console/report/file output | Default **masked** (`P***`); plaintext hanya dengan `--show-secrets` eksplisit |
| Log (`RUST_LOG=debug`) | Tidak ada nilai password; hanya hitungan (`Expanded N passwords`, `Generated N`) |
| Session/resume file | Plaintext combos (kebutuhan resume) + HMAC integrity; **baru**: file dikunci `0600` (unix) saat save |
| Output terenkripsi | AES-256-GCM + Argon2 (`--encrypt`), passphrase via prompt tersembunyi |
| Proxy auth di log | `ProxyConfig::display()` tidak mencetak username/password |
| Plugin stdin | JSON via pipe tertutup, tidak via argv/env |

Rekomendasi operator (tetap berlaku): hapus session/output setelah engagement
(`shred -u`), jangan commit wordlist klien, pakai `--encrypt` untuk arsip.

## 4. Network fail-closed

- `--proxy-required`: abort exit-2 bila tidak ada proxy terkonfigurasi
  (dicek di `AttackConfig::validate`, sebelum traffic apapun).
- `--dry-run` keluar sebelum socket pertama (dicek di `AttackOrchestrator::run`).
- `--aggressive-lab` diblokir untuk target non-RFC1918 tanpa `--i-understand-risk`.
- DNS resolution memakai resolver sistem untuk koneksi langsung; bila
  `--proxy-required`, operator diperingatkan bahwa resolusi nama tetap lokal
  (lihat `docs/anonymity.md`) — gunakan IP literal atau DNS-over-proxy
  bila model ancaman membutuhkannya.

## 5. Dependency surface

Tidak ada dependency baru di Fase 8/9 (`parse_k_list`, `parse_ranked_lines`,
`classify_form_body`, `parse_digest_params` = kode murni std). Tidak ada
fitur `reqwest`/`tokio` baru yang memperlebar surface.

## 6. Gate otomatis

```bash
cargo fmt --check        # harus bersih
cargo clippy -D warnings # harus lolos (lihat catatan pre-existing di bawah)
cargo test               # 290+ test hijau (unit + integration + fuzz ringan)
```

Status lingkungan ini (2026-09-22): toolchain sistem `rustc 1.95.0` TANPA
komponen rustfmt/clippy (tanpa rustup), sehingga `fmt --check`/`clippy`
tidak dapat dieksekusi di sini — wajib dijalankan di CI (`rust-toolchain.toml`
meminta channel 1.77 + komponen rustfmt/clippy). Sebagai gantinya di sini:
`cargo build` + `cargo test` hijau, dan semua edit Fase 8/9 ditulis mengikuti
gaya rustfmt sekitarnya (indent 4, import order, trailing comma).

Catatan: repo memiliki 127 warning pre-existing (mayoritas `dead_code` /
`unused` di modul eksperimental). Gate yang ditegakkan untuk kode Fase 8/9:
**nol warning baru** dari file yang disentuh (`rules.rs`, `wordlist_gen.rs`,
`ml_predict.rs`, `http/mod.rs`, `wordlist.rs`, `planner.rs`, `resume.rs`,
`tests/perf.rs`).
