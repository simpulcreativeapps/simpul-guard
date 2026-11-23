//! Aturan versi minimal: `min_version` (pembaruan wajib) dan `min_launcher`.

use simpul_guard::policy::evaluate;
use simpul_guard::Manifest;

fn manifest(app_extra: &str) -> Manifest {
    let text = format!(
        r#"{{
  "schema": 1,
  "issued_at": "2026-11-23T00:00:00Z",
  "apps": {{
    "sync": {{
      "name": "Simpul Sync",
      "status": "green",
      "release": {{
        "version": "2.0.0",
        "url": "https://github.com/simpulcreativeapps/simpul-sync/releases/download/v2.0.0/setup.exe",
        "sha256": "{}"
      }}{app_extra}
    }}
  }}
}}"#,
        "a".repeat(64)
    );
    serde_json::from_str(&text).unwrap()
}

fn now() -> chrono::DateTime<chrono::Utc> {
    "2026-11-23T01:00:00Z".parse().unwrap()
}

#[test]
fn old_manifest_without_new_fields_is_still_valid() {
    let m = manifest("");
    assert!(m.problems().is_empty());
    let (_, update) = evaluate(&m, "sync", "1.0.0", now());
    assert!(!update.unwrap().mandatory);
    assert!(m.min_launcher_for("sync").is_none());
}

#[test]
fn below_min_version_update_is_mandatory() {
    let m = manifest(r#", "min_version": "1.5.0""#);
    assert!(m.problems().is_empty());
    assert!(evaluate(&m, "sync", "1.4.9", now()).1.unwrap().mandatory);
    assert!(!evaluate(&m, "sync", "1.5.0", now()).1.unwrap().mandatory);
    assert!(evaluate(&m, "sync", "2.0.0", now()).1.is_none());
}

#[test]
fn min_launcher_is_exposed() {
    let m = manifest(r#", "min_launcher": "1.2.0""#);
    assert!(m.problems().is_empty());
    assert_eq!(m.min_launcher_for("sync"), Some(semver::Version::new(1, 2, 0)));
    assert!(m.min_launcher_for("lain").is_none());
}

#[test]
fn impossible_or_malformed_minimums_are_rejected() {
    assert!(!manifest(r#", "min_version": "3.0.0""#).problems().is_empty());
    assert!(!manifest(r#", "min_version": "abc""#).problems().is_empty());
    assert!(!manifest(r#", "min_launcher": "1.2""#).problems().is_empty());
}
