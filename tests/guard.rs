//! Uji alur lengkap dengan manifest bertanda tangan KUNCI UJI (bukan kunci produksi).

use chrono::{DateTime, Utc};
use simpul_guard::{Guard, Origin, TrustedKey, Verdict, verify_manifest, VerifyError};

static TEST_KEYS: &[TrustedKey] = &[TrustedKey {
    id: "289a942fc13eb4a1",
    public_key_b64: "0Qmos6Pf/tdujEAuJSm5GWKjmLM+2ZF96NmdRdFtk2Y=",
}];

fn fx(name: &str) -> (Vec<u8>, Vec<u8>) {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
    (
        std::fs::read(format!("{dir}{name}.json")).unwrap(),
        std::fs::read(format!("{dir}{name}.json.sig")).unwrap(),
    )
}

fn at(s: &str) -> DateTime<Utc> {
    s.parse().unwrap()
}

fn guard(dir: &std::path::Path, version: &str) -> Guard {
    let mut g = Guard::new("sync", version, dir);
    g.keys = TEST_KEYS;
    g
}

fn src(name: &str) -> (String, Vec<u8>, Vec<u8>) {
    let (b, s) = fx(name);
    (format!("https://contoh/{name}"), b, s)
}

#[test]
fn signature_valid_and_tamper_rejected() {
    let (body, sig) = fx("green_update");
    assert!(verify_manifest(&body, &sig, TEST_KEYS).is_ok());

    let tampered = String::from_utf8(body).unwrap().replace("\"green\"", "\"red\"");
    assert_eq!(verify_manifest(tampered.as_bytes(), &sig, TEST_KEYS), Err(VerifyError::BadSignature));
}

#[test]
fn production_build_without_keys_trusts_nothing() {
    let (body, sig) = fx("red");
    assert_eq!(verify_manifest(&body, &sig, &[]), Err(VerifyError::NoTrustedKeys));
}

#[test]
fn unknown_key_rejected() {
    let (body, sig) = fx("green_update");
    let other: &[TrustedKey] = &[TrustedKey { id: "0000000000000000", public_key_b64: "0Qmos6Pf/tdujEAuJSm5GWKjmLM+2ZF96NmdRdFtk2Y=" }];
    assert!(matches!(verify_manifest(&body, &sig, other), Err(VerifyError::UnknownKey(_))));
}

#[test]
fn green_reports_update_only_when_newer() {
    let dir = tempfile::tempdir().unwrap();
    let r = guard(dir.path(), "0.1.0").check_with(vec![src("green_update")], at("2026-11-23T00:00:00Z"));
    assert_eq!(r.verdict, Verdict::Ok);
    assert_eq!(r.update.as_ref().map(|u| u.version.to_string()), Some("0.2.0".into()));
    assert!(matches!(r.origin, Origin::Fresh(_)));

    let r = guard(dir.path(), "0.2.0").check_with(vec![src("green_update")], at("2026-11-23T00:00:00Z"));
    assert!(r.update.is_none());
}

#[test]
fn yellow_warns_but_runs() {
    let dir = tempfile::tempdir().unwrap();
    let r = guard(dir.path(), "0.1.0").check_with(vec![src("yellow")], at("2026-11-23T00:00:00Z"));
    assert!(matches!(r.verdict, Verdict::Warn(_)));
    assert!(r.verdict.may_run());
    assert!(r.update.is_some());
}

#[test]
fn red_counts_down_then_disables_and_stops_updates() {
    let dir = tempfile::tempdir().unwrap();
    let g = guard(dir.path(), "0.1.0");

    let r = g.check_with(vec![src("red")], at("2026-11-23T00:00:00Z"));
    match &r.verdict {
        Verdict::Sunset { remaining, .. } => assert_eq!(remaining.num_hours(), 48),
        v => panic!("harusnya Sunset, dapat {v:?}"),
    }
    assert!(r.verdict.may_run());
    assert!(r.update.is_none());

    let r = g.check_with(vec![src("red")], at("2026-11-26T00:00:00Z"));
    assert!(matches!(r.verdict, Verdict::Disabled(_)));
    assert!(!r.verdict.may_run());
}

#[test]
fn offline_uses_last_valid_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let g = guard(dir.path(), "0.1.0");
    g.check_with(vec![src("red")], at("2026-11-23T00:00:00Z"));

    // Tidak ada sumber yang bisa diambil: status merah tetap berlaku dari cache.
    let r = g.check_with(vec![], at("2026-11-26T00:00:00Z"));
    assert_eq!(r.origin, Origin::Cached);
    assert!(matches!(r.verdict, Verdict::Disabled(_)));
}

#[test]
fn never_seen_manifest_fails_open() {
    let dir = tempfile::tempdir().unwrap();
    let r = guard(dir.path(), "0.1.0").check_with(vec![], at("2026-11-23T00:00:00Z"));
    assert_eq!(r.origin, Origin::None);
    assert_eq!(r.verdict, Verdict::Unknown);
    assert!(r.verdict.may_run());
}

#[test]
fn replayed_older_manifest_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let g = guard(dir.path(), "0.1.0");
    g.check_with(vec![src("red")], at("2026-11-23T00:00:00Z"));

    // Penyerang memutar ulang manifest hijau lama yang tanda tangannya sah.
    let r = g.check_with(vec![src("older")], at("2026-11-23T01:00:00Z"));
    assert_eq!(r.origin, Origin::Cached);
    assert!(matches!(r.verdict, Verdict::Sunset { .. }));
    assert!(r.warnings.iter().any(|w| w.contains("lebih lama")));
}

#[test]
fn newest_valid_source_wins_and_bad_source_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let (body, _) = fx("green_update");
    let forged = ("https://palsu".to_string(), body, br#"{"alg":"ed25519","key_id":"289a942fc13eb4a1","sig":"AAAA"}"#.to_vec());
    let r = guard(dir.path(), "0.1.0").check_with(vec![forged, src("green_update"), src("yellow")], at("2026-11-23T00:00:00Z"));
    assert!(matches!(r.verdict, Verdict::Warn(_)), "yellow lebih baru dari green_update");
    assert_eq!(r.origin, Origin::Fresh("https://contoh/yellow".into()));
    assert!(r.warnings.iter().any(|w| w.starts_with("https://palsu")));
}

#[test]
fn tampered_cache_on_disk_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let g = guard(dir.path(), "0.1.0");
    g.check_with(vec![src("red")], at("2026-11-23T00:00:00Z"));
    let path = dir.path().join("manifest.json");
    let edited = std::fs::read_to_string(&path).unwrap().replace("\"red\"", "\"green\"");
    std::fs::write(&path, edited).unwrap();

    let r = g.check_with(vec![], at("2026-11-26T00:00:00Z"));
    assert_eq!(r.origin, Origin::None);
    assert!(r.warnings.iter().any(|w| w.contains("cache diabaikan")));
}

#[test]
fn app_not_listed_is_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let mut g = guard(dir.path(), "0.1.0");
    g.app_id = "tidak-ada".into();
    let r = g.check_with(vec![src("red")], at("2026-11-23T00:00:00Z"));
    assert_eq!(r.verdict, Verdict::Unknown);
}

#[test]
fn download_url_allowlist() {
    assert!(simpul_guard::is_allowed_download_url("https://github.com/simpulcreativeapps/x/releases/download/v1/a.exe"));
    assert!(!simpul_guard::is_allowed_download_url("http://github.com/a.exe"));
    assert!(!simpul_guard::is_allowed_download_url("https://github.com.evil.example/a.exe"));
    assert!(!simpul_guard::is_allowed_download_url("https://evil.example/a.exe"));
}

#[test]
fn production_keys_verify_the_first_published_manifest() {
    // Manifest pertama yang ditandatangani dengan kunci UTAMA produksi.
    let (body, sig) = fx("production");
    let m = verify_manifest(&body, &sig, simpul_guard::TRUSTED_KEYS).expect("kunci produksi harus memverifikasi manifest asli");
    assert!(m.apps.contains_key("sync"));
    // Kunci uji tidak boleh dipercaya oleh build produksi.
    let (tbody, tsig) = fx("green_update");
    assert!(verify_manifest(&tbody, &tsig, simpul_guard::TRUSTED_KEYS).is_err());
}
