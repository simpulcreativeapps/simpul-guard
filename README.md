# simpul-guard

Modul Rust bersama untuk **Simpul Launcher** dan **setiap aplikasi Simpul Creative Apps** (termasuk yang dipasang tanpa launcher). Satu kali pengecekan menjawab dua pertanyaan:

1. **Ada versi baru?** → info versi, URL installer, dan sha256-nya
2. **Status aplikasi ini apa?** → hijau / kuning / merah (hitung mundur lalu nonaktif)

Sumbernya adalah [`simpul-manifest`](https://github.com/simpulcreativeapps/simpul-manifest), yang hanya dipercaya kalau tanda tangan Ed25519-nya sah.

## Pemakaian

```toml
[dependencies]
simpul-guard = { git = "https://github.com/simpulcreativeapps/simpul-guard" }
```

```rust
use simpul_guard::{Guard, Verdict};

// Saat aplikasi dibuka (jalankan di thread latar supaya tidak menahan UI).
let guard = Guard::new("sync", env!("CARGO_PKG_VERSION"), cache_dir);
let report = guard.check();

match &report.verdict {
    Verdict::Ok | Verdict::Unknown => {}                       // jalan normal
    Verdict::Warn(n) => show_banner(&n.title, &n.message),       // kuning
    Verdict::Sunset { notice, remaining } => show_countdown(notice, *remaining), // merah, masa tenggang
    Verdict::Disabled(notice) => show_discontinued_screen(notice), // merah, habis: jangan buka aplikasi
}

if let Some(update) = report.update {
    // Tanyakan ke pengguna, lalu:
    let installer = simpul_guard::net::download_update(&update, &download_dir)?; // sha256 sudah dicek
    // jalankan installer saat aplikasi ditutup
}
```

| Verdict | Aplikasi | Yang ditampilkan |
|---|---|---|
| `Ok` / `Unknown` | jalan normal | tidak ada |
| `Warn` | jalan normal | banner pemberitahuan |
| `Sunset` | jalan normal | pemberitahuan + sisa waktu + tautan source code |
| `Disabled` | **tidak dibuka** | layar "dihentikan": tombol **Uninstall** (uninstaller resmi) dan **Buka source code** |

**File kerja pengguna tidak boleh dihapus** dalam keadaan apa pun. Uninstall hanya menghapus file program.

### Launcher vs aplikasi mandiri

- **Launcher** memanggil `Guard::new(id, …)` untuk setiap aplikasi yang terpasang, lalu mengurus update semuanya.
- **Aplikasi yang dipasang sendiri** memanggil `Guard` untuk dirinya sendiri. Kalau launcher terpasang, aplikasi cukup menampilkan verdict dan menyerahkan update ke launcher, supaya tidak diupdate dua kali.
- Pakai `cache_dir` yang sama (misalnya `%LOCALAPPDATA%\Simpul\guard`) supaya launcher dan aplikasi berbagi manifest sah terakhir.

### Klien HTTP sendiri

Matikan fitur bawaan (`default-features = false`), ambil `manifest.json` dan `manifest.json.sig` dengan klien Anda, lalu panggil `guard.check_with(vec![(url, body, sig)], Utc::now())`.

## Kunci tepercaya

Isi `src/keys.rs` dengan keluaran `node tools/simpul-sign.mjs keygen` dari repo simpul-manifest: kunci **utama** dan **cadangan**. Selama daftar itu kosong, semua manifest ditolak dan aplikasi berjalan normal.

## Pengaman

- Tanda tangan Ed25519 (verifikasi ketat) dari kunci yang tertanam di aplikasi; kunci tak dikenal ditolak.
- **Anti putar ulang:** manifest dengan `issued_at` lebih tua dari yang terakhir diterima ditolak.
- **Gagal terbuka:** server tidak bisa dihubungi atau manifest tidak sah → pakai manifest sah terakhir; kalau belum pernah ada, jalan normal.
- Cache di disk diverifikasi ulang setiap kali dibaca; file yang diubah diabaikan.
- Hanya HTTPS; URL unduhan dibatasi ke host yang diizinkan; installer dicek sha256 dan dihapus kalau tidak cocok.
- Batas ukuran manifest (256 KB) dan installer (4 GB).
- Tidak ada telemetri: hanya mengambil file.

## Uji

```bash
cargo test
```

Data uji di `tests/fixtures/` ditandatangani dengan **kunci uji** yang hanya dikenal oleh `tests/guard.rs`. Kunci itu tidak ada di `src/keys.rs` dan tidak pernah dipercaya oleh build aplikasi.
