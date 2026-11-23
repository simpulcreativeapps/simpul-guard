# Changelog

Semua perubahan pada simpul-guard dicatat di sini.
Format mengikuti [Keep a Changelog](https://keepachangelog.com/id-ID/1.1.0/).

## [Belum dirilis]

### Ditambahkan
- Manifest: `min_version` (versi terendah aplikasi yang masih boleh dipakai) dan
  `min_launcher` (versi launcher terendah untuk membuka atau memasang aplikasi).
  Keduanya opsional, jadi manifest lama tetap sah.
- `UpdateInfo.mandatory`: bernilai benar bila versi terpasang di bawah `min_version`.
- `Manifest::min_launcher_for(app_id)`.

### Ditambahkan
- `Guard::cached_manifest()`: manifest sah terakhir dari cache, diverifikasi ulang saat
  dibaca. Dipakai launcher untuk menyusun katalog.
- Kolom opsional `tagline` pada setiap aplikasi di manifest.
- Kunci publik produksi (utama dan cadangan) di `src/keys.rs`, beserta tes terhadap
  manifest pertama yang diterbitkan.

## [0.1.0] - 2026-11-23

### Ditambahkan
- Verifikasi tanda tangan Ed25519 atas `manifest.json`.
- Penilaian status hijau, kuning, dan merah dengan masa tenggang.
- Info pembaruan dan unduhan installer dengan pengecekan sha256 dan daftar host yang diizinkan.
- Cache manifest sah terakhir, perlindungan putar ulang, dan perilaku gagal-terbuka.
