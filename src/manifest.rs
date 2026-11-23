//! Struktur `manifest.json` (schema 1) dan validasinya. Aturannya sama dengan `simpul-sign.mjs validate`.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub schema: u32,
    pub issued_at: DateTime<Utc>,
    pub apps: BTreeMap<String, AppEntry>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AppEntry {
    pub name: String,
    /// Keterangan satu baris untuk katalog launcher (opsional).
    #[serde(default)]
    pub tagline: Option<String>,
    pub status: Status,
    #[serde(default)]
    pub notice: Option<Notice>,
    #[serde(default)]
    pub release: Option<Release>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Green,
    Yellow,
    Red,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Notice {
    pub title: String,
    pub message: String,
    #[serde(default)]
    pub disable_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub source_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub url: String,
    pub sha256: String,
    #[serde(default)]
    pub notes_url: Option<String>,
}

impl Manifest {
    /// Cek aturan yang tidak bisa diwakili oleh tipe data. Kembalikan daftar masalah (kosong = valid).
    pub fn problems(&self) -> Vec<String> {
        let mut errs = Vec::new();
        if self.schema != 1 {
            errs.push(format!("schema {} tidak didukung", self.schema));
        }
        for (id, a) in &self.apps {
            match a.status {
                Status::Green => {
                    if a.notice.is_some() {
                        errs.push(format!("{id}: notice harus kosong saat green"));
                    }
                }
                Status::Yellow => match &a.notice {
                    None => errs.push(format!("{id}: notice wajib saat yellow")),
                    Some(n) if n.disable_at.is_some() => errs.push(format!("{id}: disable_at hanya untuk red")),
                    _ => {}
                },
                Status::Red => {
                    match &a.notice {
                        Some(n) if n.disable_at.is_some() => {}
                        _ => errs.push(format!("{id}: notice dengan disable_at wajib saat red")),
                    }
                    if a.release.is_some() {
                        errs.push(format!("{id}: release harus null saat red"));
                    }
                }
            }
            if let Some(r) = &a.release {
                if semver::Version::parse(&r.version).is_err() {
                    errs.push(format!("{id}: versi rilis tidak valid"));
                }
                if !crate::is_allowed_download_url(&r.url) {
                    errs.push(format!("{id}: URL unduhan tidak diizinkan"));
                }
                if r.sha256.len() != 64 || !r.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                    errs.push(format!("{id}: sha256 tidak valid"));
                }
            }
        }
        errs
    }
}
