//! # simpul-guard
//!
//! Modul bersama untuk Simpul Launcher dan setiap aplikasi Simpul Creative Apps:
//!
//! - membaca `manifest.json` bertanda tangan dari GitHub (dan alamat cadangan),
//! - memverifikasi tanda tangan Ed25519 terhadap kunci yang tertanam di aplikasi,
//! - menolak manifest lama yang diputar ulang,
//! - menentukan status aplikasi: hijau, kuning, atau merah (hitung mundur lalu nonaktif),
//! - memberi tahu bila ada versi baru, dan mengunduh installer dengan cek sha256.
//!
//! Prinsip keamanan:
//! - **Gagal terbuka.** Kalau manifest tidak bisa diambil atau tidak sah, aplikasi tetap berjalan
//!   dengan status terakhir yang sah. Server mati tidak boleh mematikan aplikasi pengguna.
//! - **Data saja.** Manifest tidak pernah berisi perintah. Satu-satunya yang dijalankan adalah installer
//!   yang lolos cek sha256 dari manifest bertanda tangan.
//! - **Tanpa telemetri.** Pengecekan hanya mengambil file; tidak mengirim data pengguna.
//!
//! ```no_run
//! use simpul_guard::{Guard, Verdict};
//!
//! let guard = Guard::new("sync", env!("CARGO_PKG_VERSION"), "C:/Users/me/AppData/Local/Simpul/guard");
//! let report = guard.check();
//! match &report.verdict {
//!     Verdict::Ok | Verdict::Unknown => {}
//!     Verdict::Warn(notice) => println!("{}: {}", notice.title, notice.message),
//!     Verdict::Sunset { notice, remaining } => {
//!         println!("{} — nonaktif dalam {} jam", notice.title, remaining.num_hours())
//!     }
//!     Verdict::Disabled(notice) => {
//!         println!("{}", notice.message);
//!         // tampilkan layar "dihentikan" dengan tombol Uninstall & Buka source code
//!     }
//! }
//! if let Some(update) = &report.update {
//!     println!("Versi {} tersedia", update.version);
//! }
//! ```

mod keys;
pub mod manifest;
pub mod policy;
pub mod verify;

#[cfg(feature = "net")]
pub mod net;

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

pub use keys::{TrustedKey, TRUSTED_KEYS};
pub use manifest::{AppEntry, Manifest, Notice, Release, Status};
pub use policy::{evaluate, Verdict};
pub use verify::{verify_manifest, VerifyError};

/// Alamat manifest, dicoba berurutan. Alamat kedua adalah cadangan di situs sendiri.
pub const MANIFEST_SOURCES: &[&str] = &[
    "https://raw.githubusercontent.com/simpulcreativeapps/simpul-manifest/main/manifest.json",
    "https://apps.simpulproject.com/manifest.json",
];

/// Host yang boleh dipakai untuk URL unduhan installer. Harus sama dengan `ALLOWED_HOSTS` di `simpul-sign.mjs`.
pub const ALLOWED_DOWNLOAD_HOSTS: &[&str] = &["github.com", "apps.simpulproject.com"];

const CACHE_FILE: &str = "manifest.json";
const CACHE_SIG_FILE: &str = "manifest.json.sig";

/// Dari mana manifest yang dipakai berasal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// Baru diambil dari salah satu alamat dan lolos verifikasi.
    Fresh(String),
    /// Tidak ada yang bisa diambil; memakai salinan sah terakhir di disk.
    Cached,
    /// Belum pernah ada manifest sah. Aplikasi berjalan normal.
    None,
}

/// Info versi baru yang tersedia untuk aplikasi ini.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateInfo {
    pub version: semver::Version,
    pub url: String,
    pub sha256: String,
    pub notes_url: Option<String>,
}

/// Hasil satu kali pengecekan.
#[derive(Debug, Clone)]
pub struct Report {
    pub verdict: Verdict,
    pub update: Option<UpdateInfo>,
    pub origin: Origin,
    /// Catatan untuk log (sumber gagal, tanda tangan tidak sah, dll). Jangan ditampilkan sebagai error ke pengguna.
    pub warnings: Vec<String>,
}

/// Pemeriksa untuk satu aplikasi.
#[derive(Debug, Clone)]
pub struct Guard {
    pub app_id: String,
    pub current_version: String,
    pub cache_dir: PathBuf,
    pub sources: Vec<String>,
    pub keys: &'static [TrustedKey],
}

impl Guard {
    /// `cache_dir`: folder milik aplikasi untuk menyimpan manifest sah terakhir,
    /// misalnya `%LOCALAPPDATA%/Simpul/guard`. Launcher dan aplikasi boleh memakai folder yang sama.
    pub fn new(app_id: &str, current_version: &str, cache_dir: impl Into<PathBuf>) -> Self {
        Guard {
            app_id: app_id.to_string(),
            current_version: current_version.to_string(),
            cache_dir: cache_dir.into(),
            sources: MANIFEST_SOURCES.iter().map(|s| s.to_string()).collect(),
            keys: TRUSTED_KEYS,
        }
    }

    /// Ambil manifest dari jaringan (bila fitur `net` aktif), lalu nilai statusnya.
    #[cfg(feature = "net")]
    pub fn check(&self) -> Report {
        let mut fetched = Vec::new();
        let mut warnings = Vec::new();
        for url in &self.sources {
            match net::fetch_manifest(url) {
                Ok((body, sig)) => fetched.push((url.clone(), body, sig)),
                Err(e) => warnings.push(format!("{url}: {e}")),
            }
        }
        let mut report = self.check_with(fetched, Utc::now());
        warnings.append(&mut report.warnings);
        report.warnings = warnings;
        report
    }

    /// Inti pengecekan tanpa jaringan: terima hasil unduhan (alamat, isi manifest, isi .sig),
    /// pilih manifest sah yang paling baru, simpan ke cache, lalu nilai statusnya.
    /// Dipakai oleh [`Guard::check`] dan oleh aplikasi yang punya klien HTTP sendiri.
    pub fn check_with(&self, fetched: Vec<(String, Vec<u8>, Vec<u8>)>, now: DateTime<Utc>) -> Report {
        let mut warnings = Vec::new();
        let cached = self.load_cache(&mut warnings);
        let floor = cached.as_ref().map(|(m, _, _)| m.issued_at);

        // Dari semua sumber yang sah, pakai yang issued_at-nya paling baru.
        let mut best: Option<(String, Manifest, Vec<u8>, Vec<u8>)> = None;
        for (url, body, sig) in fetched {
            match verify_manifest(&body, &sig, self.keys) {
                Ok(m) => {
                    if let Some(f) = floor {
                        if m.issued_at < f {
                            warnings.push(format!("{url}: manifest lebih lama dari yang terakhir diterima, ditolak"));
                            continue;
                        }
                    }
                    if best.as_ref().is_none_or(|(_, b, _, _)| m.issued_at > b.issued_at) {
                        best = Some((url, m, body, sig));
                    }
                }
                Err(e) => warnings.push(format!("{url}: {e}")),
            }
        }

        let (manifest, origin) = match best {
            Some((url, m, body, sig)) => {
                if let Err(e) = self.save_cache(&body, &sig) {
                    warnings.push(format!("gagal menyimpan cache: {e}"));
                }
                (Some(m), Origin::Fresh(url))
            }
            None => match cached {
                Some((m, _, _)) => (Some(m), Origin::Cached),
                None => (None, Origin::None),
            },
        };

        match manifest {
            Some(m) => {
                let (verdict, update) = evaluate(&m, &self.app_id, &self.current_version, now);
                Report { verdict, update, origin, warnings }
            }
            None => Report { verdict: Verdict::Unknown, update: None, origin, warnings },
        }
    }

    fn load_cache(&self, warnings: &mut Vec<String>) -> Option<(Manifest, Vec<u8>, Vec<u8>)> {
        let body = fs::read(self.cache_dir.join(CACHE_FILE)).ok()?;
        let sig = fs::read(self.cache_dir.join(CACHE_SIG_FILE)).ok()?;
        // Cache juga diverifikasi ulang: file di disk bisa saja diubah.
        match verify_manifest(&body, &sig, self.keys) {
            Ok(m) => Some((m, body, sig)),
            Err(e) => {
                warnings.push(format!("cache diabaikan: {e}"));
                None
            }
        }
    }

    fn save_cache(&self, body: &[u8], sig: &[u8]) -> std::io::Result<()> {
        fs::create_dir_all(&self.cache_dir)?;
        write_atomic(&self.cache_dir.join(CACHE_FILE), body)?;
        write_atomic(&self.cache_dir.join(CACHE_SIG_FILE), sig)
    }
}

fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data)?;
    fs::rename(tmp, path)
}

/// sha256 dalam bentuk heksadesimal huruf kecil.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// Apakah URL unduhan aman dipakai: https dan host-nya ada di [`ALLOWED_DOWNLOAD_HOSTS`].
pub fn is_allowed_download_url(raw: &str) -> bool {
    match url::Url::parse(raw) {
        Ok(u) => u.scheme() == "https" && u.host_str().is_some_and(|h| ALLOWED_DOWNLOAD_HOSTS.contains(&h)),
        Err(_) => false,
    }
}
