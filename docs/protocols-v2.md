# Protokol v2: Port, TLS, Proxy, dan Keterbatasan

Tanggal: 2026-09-21
Sumber kebenaran kode: `src/protocols/transport.rs`, `src/protocols/mod.rs`, `src/proxy/mod.rs`.

## 1. Aturan transport baru (Fase 3)

- Semua protokol baru WAJIB memakai `transport::tcp_connect()`.
- 9 protokol sudah terverifikasi unified: ssh, ftp, smtp, mysql, postgres, smb, rdp, redis, mongodb.
  - smtp dan postgres memakai `core::engine::connect_tcp` yang sudah proxy-aware.
  - 7 lainnya dimigrasi ke `transport::tcp_connect` pada Fase 3.
- Pola lama `match proxy { Some(p) => p.tcp_connect ... }` dilarang untuk kode baru.

## 2. Tabel inti

| Protokol | Port default | TLS mode | Proxy raw TCP | Proxy HTTP reqwest | Fingerprint |
|---|---|---|---|---|---|
| ssh | 22 | via blocking ssh2 handshake | full + chain | n/a | ya |
| ftp | 21, 990 | explicit FTPS di 990 | full + chain | n/a | ya |
| smtp | 25, 465, 587 | STARTTLS | full via engine | n/a | ya |
| mysql | 3306 | native | full + chain | n/a | ya |
| postgres | 5432 | SSL capable | full via engine | n/a | ya |
| smb | 445 | NTLM, no TLS | full + chain | n/a | ya |
| rdp | 3389 | NLA/CredSSP | full + chain | n/a | ya |
| redis | 6379, 6380 | TLS di 6380 | full + chain | n/a | ya |
| mongodb | 27017 | SCRAM | full + chain | n/a | parsial |
| http | 80, 443, 8080, 8443 | rustls/native via reqwest | n/a | single-hop, chain pakai hop pertama + warning | ya |

## 3. Keterbatasan yang harus operator tahu

1. **HTTP proxy chain parsial.** reqwest hanya mendukung satu proxy per client.
   Implementasi memakai hop pertama dan log warning. Raw TCP chain tetap full multi-hop.
   Mitigasi: untuk HTTP multi-hop gunakan proxychains eksternal atau satu hop stabil.
2. **RDP NLA berat.** Handshake CredSSP sensitif timeout. Naikkan `--timeout 15` di jaringan lambat.
3. **SMB lockout agresif.** Jangan spray SMB produksi tanpa `--spray --delay 1000 --rate-limit 5`.
4. **FTP 990 vs 21.** Port 990 otomatis TLS. Port 21 plaintext kecuali server upgrade.
5. **Fingerprint bukan bukti final.** `--fp-check` melakukan re-auth sekali untuk sukses yang diklaim.
   Tetap verifikasi manual untuk temuan kritis sebelum dilaporkan.

## 4. Cara tambah protokol baru

1. Buat `src/protocols/nama/mod.rs`, implement `Protocol` trait.
2. Pakai `transport::tcp_connect()` untuk koneksi, jangan `TcpStream::connect` langsung.
3. Daftarkan di `src/protocols/mod.rs` (`mod`, `get_protocol`, `list_protocols`, `default_ports`).
4. Tambah CLI subcommand di `src/cli.rs` + wiring `main.rs`.
5. Tambah fingerprint di `transport::fingerprint_for()` bila ada success/fail marker jelas.
6. Tambah test di `tests/protocol_matrix.rs` + fixture banner sukses dan gagal.
