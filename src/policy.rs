//! Menentukan apa yang harus dilakukan aplikasi berdasarkan manifest yang sudah diverifikasi.

use chrono::{DateTime, Duration, Utc};

use crate::UpdateInfo;
use crate::manifest::{Manifest, Notice, Status};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Hijau: berjalan normal.
    Ok,
    /// Aplikasi tidak tercantum di manifest, atau belum ada manifest sah. Berjalan normal.
    Unknown,
    /// Kuning: tampilkan pemberitahuan, aplikasi tetap bisa dipakai.
    Warn(Notice),
    /// Merah, masih dalam masa tenggang: tampilkan pemberitahuan + sisa waktu.
    Sunset { notice: Notice, remaining: Duration },
    /// Merah, masa tenggang habis: jangan buka aplikasi. Tampilkan layar "dihentikan"
    /// dengan tombol Uninstall (jalankan uninstaller resmi) dan Buka source code.
    /// File kerja pengguna TIDAK BOLEH dihapus.
    Disabled(Notice),
}

impl Verdict {
    /// Boleh membuka aplikasi seperti biasa?
    pub fn may_run(&self) -> bool {
        !matches!(self, Verdict::Disabled(_))
    }
}

/// Nilai status satu aplikasi dan cek apakah ada versi lebih baru dari `current_version`.
pub fn evaluate(m: &Manifest, app_id: &str, current_version: &str, now: DateTime<Utc>) -> (Verdict, Option<UpdateInfo>) {
    let Some(app) = m.apps.get(app_id) else {
        return (Verdict::Unknown, None);
    };

    let verdict = match (app.status, &app.notice) {
        (Status::Green, _) => Verdict::Ok,
        (Status::Yellow, Some(n)) => Verdict::Warn(n.clone()),
        (Status::Red, Some(n)) => match n.disable_at {
            Some(at) if now < at => Verdict::Sunset { notice: n.clone(), remaining: at - now },
            _ => Verdict::Disabled(n.clone()),
        },
        // Tidak terjadi pada manifest yang lolos validasi; aman-kan ke berjalan normal.
        _ => Verdict::Ok,
    };

    // Saat merah tidak ada update sama sekali.
    let update = if app.status == Status::Red {
        None
    } else {
        app.release.as_ref().and_then(|r| {
            let latest = semver::Version::parse(&r.version).ok()?;
            let current = semver::Version::parse(current_version).ok()?;
            (latest > current).then(|| UpdateInfo {
                version: latest,
                url: r.url.clone(),
                sha256: r.sha256.clone(),
                notes_url: r.notes_url.clone(),
            })
        })
    };

    (verdict, update)
}
