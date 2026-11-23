//! Ambil manifest dan unduh installer lewat HTTPS (fitur `net`).

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::UpdateInfo;
use crate::verify::MAX_MANIFEST_BYTES;

/// Batas ukuran installer yang mau diunduh.
pub const MAX_INSTALLER_BYTES: u64 = 4 * 1024 * 1024 * 1024;

fn client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .user_agent(concat!("simpul-guard/", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())
}

fn get_limited(url: &str, limit: u64) -> Result<Vec<u8>, String> {
    let resp = client()?.get(url).send().map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let mut buf = Vec::new();
    resp.take(limit + 1).read_to_end(&mut buf).map_err(|e| e.to_string())?;
    if buf.len() as u64 > limit {
        return Err("respons terlalu besar".into());
    }
    Ok(buf)
}

/// Ambil `manifest.json` dan `manifest.json.sig` dari satu alamat.
pub fn fetch_manifest(url: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let body = get_limited(url, MAX_MANIFEST_BYTES as u64)?;
    let sig = get_limited(&format!("{url}.sig"), 4096)?;
    Ok((body, sig))
}

/// Unduh installer ke `dir`, cek sha256 terhadap manifest, lalu kembalikan path-nya.
/// File yang tidak cocok dihapus dan tidak pernah dijalankan.
pub fn download_update(update: &UpdateInfo, dir: &Path) -> Result<PathBuf, String> {
    if !crate::is_allowed_download_url(&update.url) {
        return Err("URL unduhan tidak diizinkan".into());
    }
    let name = update
        .url
        .rsplit('/')
        .next()
        .filter(|n| !n.is_empty() && !n.contains(['\\', ':']) && n != &".." && n != &".")
        .ok_or("nama file tidak valid")?;
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let part = dir.join(format!("{name}.part"));
    let dest = dir.join(name);

    let mut resp = client()?.get(&update.url).send().map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let mut file = File::create(&part).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = resp.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_INSTALLER_BYTES {
            drop(file);
            let _ = fs::remove_file(&part);
            return Err("installer terlalu besar".into());
        }
        hasher.update(&chunk[..n]);
        file.write_all(&chunk[..n]).map_err(|e| e.to_string())?;
    }
    file.flush().map_err(|e| e.to_string())?;
    drop(file);

    let got: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if got != update.sha256 {
        let _ = fs::remove_file(&part);
        return Err("sha256 installer tidak cocok dengan manifest; file dihapus".into());
    }
    fs::rename(&part, &dest).map_err(|e| e.to_string())?;
    Ok(dest)
}
