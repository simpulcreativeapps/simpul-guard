//! Kunci publik yang dipercaya untuk memverifikasi `manifest.json`.
//!
//! Isi dengan keluaran `node tools/simpul-sign.mjs keygen` dari repo simpul-manifest.
//! Masukkan DUA kunci (utama dan cadangan). Kalau kunci utama bocor, tanda tangani dengan
//! kunci cadangan lalu hapus kunci yang bocor dari daftar ini di rilis berikutnya.
//!
//! Selama daftar ini kosong, semua manifest ditolak dan aplikasi berjalan normal (gagal terbuka).

/// Kunci publik Ed25519 (32 byte, base64) beserta id-nya (16 karakter hex pertama sha256 kunci).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedKey {
    pub id: &'static str,
    pub public_key_b64: &'static str,
}

pub const TRUSTED_KEYS: &[TrustedKey] = &[
    // TrustedKey { id: "…", public_key_b64: "…" }, // utama
    // TrustedKey { id: "…", public_key_b64: "…" }, // cadangan
];
