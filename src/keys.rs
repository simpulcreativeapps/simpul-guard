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
    // utama (dipakai untuk menandatangani manifest sehari-hari)
    TrustedKey { id: "f2559a7d4050782e", public_key_b64: "MwVg/bB4PvAdFRZXGU6tYBeDlyxVOQCebquisopk1pQ=" },
    // cadangan (disimpan offline; hanya dipakai bila kunci utama bocor atau hilang)
    TrustedKey { id: "dbe26ff02233cfbc", public_key_b64: "EvEXi9kYkOG2Rn9c0TItlp/12ernpJz4TC+kHbiaU2E=" },
];
