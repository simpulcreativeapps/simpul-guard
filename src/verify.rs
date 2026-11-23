//! Verifikasi tanda tangan `manifest.json.sig` dan validasi isi manifest.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

use crate::keys::TrustedKey;
use crate::manifest::Manifest;

/// Batas ukuran manifest yang mau diproses (melindungi dari file raksasa).
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    TooLarge,
    NoTrustedKeys,
    BadSignatureFile(String),
    UnknownKey(String),
    BadSignature,
    BadManifest(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::TooLarge => write!(f, "manifest terlalu besar"),
            VerifyError::NoTrustedKeys => write!(f, "belum ada kunci tepercaya di keys.rs"),
            VerifyError::BadSignatureFile(e) => write!(f, "file tanda tangan rusak: {e}"),
            VerifyError::UnknownKey(id) => write!(f, "ditandatangani kunci tak dikenal {id}"),
            VerifyError::BadSignature => write!(f, "tanda tangan tidak cocok"),
            VerifyError::BadManifest(e) => write!(f, "isi manifest tidak valid: {e}"),
        }
    }
}

impl std::error::Error for VerifyError {}

#[derive(Deserialize)]
struct SigFile {
    alg: String,
    key_id: String,
    sig: String,
}

/// Verifikasi `body` (isi persis `manifest.json`) terhadap `sig` (isi `manifest.json.sig`),
/// lalu parse dan validasi. Hanya manifest yang lolos semua langkah ini yang boleh dipakai.
pub fn verify_manifest(body: &[u8], sig: &[u8], keys: &[TrustedKey]) -> Result<Manifest, VerifyError> {
    if body.len() > MAX_MANIFEST_BYTES || sig.len() > 4096 {
        return Err(VerifyError::TooLarge);
    }
    if keys.is_empty() {
        return Err(VerifyError::NoTrustedKeys);
    }
    let sf: SigFile = serde_json::from_slice(sig).map_err(|e| VerifyError::BadSignatureFile(e.to_string()))?;
    if sf.alg != "ed25519" {
        return Err(VerifyError::BadSignatureFile(format!("algoritme {} tidak didukung", sf.alg)));
    }
    let key = keys.iter().find(|k| k.id == sf.key_id).ok_or_else(|| VerifyError::UnknownKey(sf.key_id.clone()))?;

    let pk_bytes: [u8; 32] = B64
        .decode(key.public_key_b64)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| VerifyError::UnknownKey(format!("{} (kunci di keys.rs rusak)", key.id)))?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| VerifyError::UnknownKey(format!("{} (kunci tidak valid)", key.id)))?;
    let sig_bytes: [u8; 64] = B64
        .decode(sf.sig.as_bytes())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| VerifyError::BadSignatureFile("panjang tanda tangan salah".into()))?;
    let signature = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(body, &signature).map_err(|_| VerifyError::BadSignature)?;

    let manifest: Manifest = serde_json::from_slice(body).map_err(|e| VerifyError::BadManifest(e.to_string()))?;
    let problems = manifest.problems();
    if !problems.is_empty() {
        return Err(VerifyError::BadManifest(problems.join("; ")));
    }
    Ok(manifest)
}
