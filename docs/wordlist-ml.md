# Wordlist, Rules & ML Pipeline (Fase 8)

Tujuan: *fewer attempts, more hits* — kirim kandidat paling probable dulu,
bukan membabi-buta.

## 1. Rule engine (`--rule FILE --max-mutations N`)

File: `rules/common.rule` (contoh siap pakai, 38 aturan).

Sintaks per baris (token spasi, `#` komentar):

| Token | Arti | Contoh |
|---|---|---|
| `$n` | Append angka `0..=n` (**range**, bukan literal!) | `$9` → `pass0`..`pass9` |
| `^n` | Prepend angka `0..=n` | `^9` → `0pass`..`9pass` |
| `@str` | Append string **literal** | `@2024` → `pass2024` |
| `!str` | Prepend string **literal** | `!admin` → `adminpass` |
| `~m` | Case: `0` lower, `1` UPPER, `2` Title | `~2` → `Pass` |
| `&a:b` | Leet: ganti char `a` jadi `b` | `&a:4` → `p4ss` |
| `D` | Duplicate | `pass` → `passpass` |
| `R` | Reverse | `pass` → `ssap` |
| `Tn` | Truncate n char pertama | `T4` → `pass` |

Aturan penting:

- **Kata dasar selalu dipertahankan** paling depan — password mentah tetap
  dicoba walau `--rule` dipakai.
- Total ekspansi dipotong `--max-mutations` (default 500).
- `$N` besar (`$2024` = 2025 mutasi!) memicu warning — maksud literal?
  pakai `@2024`.
- Selalu `--dry-run` dulu: baris `Rules:` menampilkan estimasi ekspansi.

```bash
veltrix ssh -t 192.168.1.1 -U users.txt -W base.txt \
  --rule rules/common.rule --max-mutations 500 --dry-run
# Rules: 38 rule(s) expand 3 base -> 303 estimated (cap 500)
```

## 2. Wordlist generator (`create` / `--gen-wordlist`)

Profil target → kandidat: nama, perusahaan, DOB (tahun diekstrak dari format
`YYYY-MM-DD`, `DD/MM/YYYY`, `DDMMYYYY`), keyword, musim+musim+tahun,
keyboard-walk (+reversed), leet level 0–3.

```bash
veltrix create -n "John Smith" -c Acme -d "1990-05-14" -k admin -o /tmp/wl.txt
veltrix create -n "John" --leet-level 3 --min-len 8 --max-len 24 -o /tmp/wl.txt
```

Level leet: `0` mati, `1` substitusi tunggal, `2` +kombinasi pasangan,
`3` +varian Title/UPPER. `--no-seasons` / `--no-keyboard` mematikan basis.

## 3. ML ranker (`wordlist rank`)

Model Markov order-N dilatih dari wordlist, kandidat diurut probable-first:

```bash
# 1. Rank kandidat dengan model dari wordlist pelatihan:
veltrix wordlist rank --input cands.txt --model train.txt \
  --order 3 --top 10000 -o ranked.txt
# 2. Pakai hasil rank sebagai password file (probable-first = dicoba dulu):
veltrix ssh -t 10.0.0.5 -u admin -W ranked.txt --dry-run
```

Format `ranked.txt`: `password<TAB>skor` (skor kecil = lebih probable).
`--top 0` = semua; `--min-score F` = buang skor di atas F.

## 4. Evaluasi (`wordlist eval`) — angka, bukan klaim

```bash
veltrix wordlist eval --ranked ranked.txt --relevant heldout.txt --k 10,20,50
# ranked=100 relevant=10 K=[10, 20, 50]
# precision@10     1.0000  (10/10 hits in top 10)
# precision@20     0.5000  (10/20 hits in top 20)
```

Alur evaluasi jujur: latih di `train.txt`, rank kandidat campuran,
ukur terhadap `heldout.txt` yang TIDAK ada di training. Klaim "ML menaikkan
hit rate awal" hanya valid bila `precision@K` terukur di dataset uji
operator sendiri — contoh sintetis di repo (`adminNN` vs junk) mencapai
precision@10 ≥ 0.8 (lihat test `precision_at_k_family_vs_junk`).

## 5. Pipeline yang disarankan (audit resmi)

```bash
veltrix create -n "..." -c "..." -o base.txt        # 1. basis profil
veltrix wordlist rank --input base.txt \             # 2. rank probable-first
  --model train.txt --top 20000 -o ranked.txt
veltrix wordlist eval --ranked ranked.txt \          # 3. ukur dulu
  --relevant heldout.txt --k 10,50,100
veltrix ssh -t TARGET -U users.txt -W ranked.txt \   # 4. serang, aman & terukur
  --rule rules/common.rule --dry-run                 #    selalu dry-run dulu
```
