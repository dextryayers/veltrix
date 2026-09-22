# Panduan Penggunaan Veltrix v2.0

> Hanya untuk pengujian resmi dengan izin tertulis pemilik sistem.

## 1. Alur 5 menit (operator baru)

```bash
veltrix --help                          # flag otoritatif
veltrix ssh -t 192.168.1.1 -u admin -W passwords.txt --dry-run   # rencanakan
veltrix ssh -t 192.168.1.1 -u admin -W passwords.txt             # eksekusi
```

## 2. Scan lalu attack (satu alur)

```bash
veltrix scan-ports -t 10.0.0.0/24 --ports common -o scan.txt
veltrix ssh -T targets.txt -U users.txt -W pass.txt --only-open scan.txt
# atau otomatis:
veltrix auto -t 10.0.0.0/24 --policy policy.toml
```

## 3. Kredensial: 4 mode

| Mode | Flag | Kapan |
|---|---|---|
| Dictionary | `-U users.txt -W pass.txt` | umum (cartesian) |
| Single user | `--single-user` + `-W` | 1 akun, banyak password |
| Combo | `-C combos.txt` (`user:pass`) | bocoran kredensial |
| Spray | `--spray --spray-interval 30m` | anti-lockout (1 pass → semua user) |

`--dry-run` selalu menampilkan total kombinasi + estimasi waktu + `Rules:`
bila `--rule` dipakai. `-w` = `--password` singkat; `-q/--quiet` = hanya
sukses (tanpa dashboard). **`-y/--yes` = sikat SEMUA kombinasi dari awal
user.txt + pass.txt sampai akhir tanpa prompt, lalu summary** (wajib untuk
run panjang/pipe/CI agar tidak berhenti di tengah). Exit code: `0` ada temuan, `1` nihil/gagal,
`2` config invalid, `130` interupsi.

## 4. Profil keamanan operasional

```bash
# Konservatif (produksi): threads 3, delay 1000ms, rate 5/s, retries 1
veltrix ssh ... --safe-profile
# Agresif (LAB ISOLASI milik sendiri saja):
veltrix ssh -t 192.168.0.0/24 ... --aggressive-lab
```

## 5. Anonimitas (ringkas; detail: `docs/anonymity.md`)

```bash
veltrix ssh -t TARGET -U u.txt -W p.txt \
  --proxy socks5://127.0.0.1:9050 \
  --proxy-required --rotate-proxy-every 50 \
  --rate-limit 5 --delay 300
```

Tanpa proxy yang sehat, jangan serang target sensitif — IP asli terekspos.

## 6. Output & kerahasiaan

- `-o hasil -f json|csv|html|yaml|plain`; password tampil **penuh** default.
- `--hide-secrets` untuk mask (`root:a***`) bila layar di-share/direkam.
- `--encrypt` (AES-256-GCM) untuk arsip; session file otomatis `0600`.
- `shred -u` file sensitif setelah engagement selesai.

## 7. Resume & validasi

```bash
veltrix ssh ... --resume session.json --checkpoint 100
veltrix validate veltrix.toml        # cek config tanpa menyerang
veltrix completion bash >> ~/.bashrc # tab-completion
```
