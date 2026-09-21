# Bench Baseline Fase 0-1

Tanggal: 2026-09-21
Mesin: dev lokal, profile debug, `cargo test --test bench -- --nocapture`
Tujuan: baseline sebelum optimasi lanjutan Fase 2+.

## Hasil

| Bench | Hasil |
|---|---|
| Target parse 100k | 43.3 ms, 433 ns per parse |
| Credential parse 100k | 23.2 ms, 232 ns per parse |
| Combo parse 100k | 33.6 ms |
| String format 100k | 7.1 ms, 71 ns each |
| HashSet insert 10k | 9.8 ms, 979 ns each |
| Lazy cartesian 1M combos | 8.7 ms counting only, tanpa alokasi String |
| Dedup 100k | 58.9 ms |

## Interpretasi untuk Fase 1

- Lazy cartesian counting 1M dalam 8.7 ms membuktikan iterator tanpa alokasi jauh lebih murah daripada `Vec<Credential>` penuh. Inilah alasan `CredentialStream` dipakai untuk estimasi dry-run dan rencana batch.
- Dedup 100k dalam 59 ms masih oke, tapi untuk 10M+ perlu `HashedPairDedup` berbasis u64 agar memori 8 byte per entri, bukan dua String.
- Target dan combo parse di bawah 500 ns, bukan bottleneck. Bottleneck nyata tetap network I/O dan semaphore, bukan parser.
- `load_wordlist_mmap` dipakai untuk file di atas 64 KB agar loading wordlist besar tidak blocking. Throughput berkali lipat dibanding line-by-line async untuk file besar.

## Tindak lanjut

- [ ] Ulangi bench di profile release untuk angka resmi v2.0
- [ ] Tambah bench mmap 10 MB dan 100 MB wordlist
- [ ] Tambah bench `CredentialStream::next_batch(2048)` 1M kombinasi dengan alokasi nyata
