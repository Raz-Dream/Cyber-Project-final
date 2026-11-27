# File Integrity Monitor (FIM)

Tool Python untuk mendeteksi perubahan file (ditambah, diubah, dihapus) menggunakan hash SHA-256.

## Cara pakai
```bash
# 1. Catat kondisi awal folder yang dianggap aman
python fim.py init folder_target

# 2. Nanti, cek apakah ada yang berubah
python fim.py check folder_target
```

Opsi: `-b` nama file baseline, `-x` file/folder tambahan yang diabaikan (hanya untuk `init`).
Exit code `0` = tidak ada perubahan, `1` = ada perubahan (berguna untuk otomatisasi).

## Cara kerja
- Setiap file dihitung hash SHA-256-nya. Perubahan 1 byte saja menghasilkan hash yang sama sekali berbeda.
- Baseline (path, hash, ukuran) disimpan ke `baseline.json`.
- Saat `check`, kondisi sekarang dibandingkan dengan baseline untuk menemukan file baru, berubah, atau hilang.

## Yang dipelajari
- Fungsi hash kriptografi dan sifatnya (deterministik, efek avalanche)
- Konsep file integrity monitoring pada sistem keamanan (Tripwire, AIDE)
- Menelusuri direktori dan membaca file besar per potongan (chunk)

## Keterbatasan
- `baseline.json` sendiri bisa diubah penyerang. Simpan di tempat aman atau tanda tangani.
- Pengecekan hanya berjalan saat dijalankan manual, bukan real-time.

## Ide pengembangan
- Jadwalkan otomatis (cron / Task Scheduler)
- Tambah notifikasi email atau Telegram
- Tanda tangan digital (HMAC) untuk baseline
- Mode real-time dengan library `watchdog`