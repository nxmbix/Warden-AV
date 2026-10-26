use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use warden_core::engine::{Engine, EngineOptions};
use warden_core::scan::{run_scan, FileFilter};
use warden_core::signatures::SignatureDb;
use warden_core::{Quarantine, Severity};

fn engine() -> Engine {
    Engine::new(SignatureDb::builtin().unwrap(), EngineOptions::default())
}

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("warden-test-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn every_sample_gets_the_expected_verdict() {
    let dir = tmp("samples");
    let samples = warden_core::samples::generate(&dir).unwrap();
    let report = run_scan(
        &engine(),
        &[dir.clone()],
        &FileFilter::default(),
        &AtomicBool::new(false),
        &|_| {},
    );
    let mut by_file: HashMap<String, Vec<String>> = HashMap::new();
    for d in &report.detections {
        by_file
            .entry(d.path.clone())
            .or_default()
            .push(d.name.clone());
    }
    for s in &samples {
        let hits = by_file.get(&s.path).cloned().unwrap_or_default();
        if s.tests == "clean" {
            assert!(
                hits.is_empty(),
                "false positive on {}: {hits:?}",
                s.file_name
            );
        } else {
            assert!(!hits.is_empty(), "{} was not detected", s.file_name);
        }
    }
    let readme = dir.join("README-WARDEN-TEST-SAMPLES.txt");
    assert!(
        !by_file.contains_key(&readme.to_string_lossy().to_string()),
        "readme flagged"
    );
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn eicar_in_zip_is_reported_once_with_inner_location() {
    let dir = tmp("zip");
    warden_core::samples::generate(&dir).unwrap();
    let hits = engine()
        .scan_file(&dir.join("eicar-inside-archive.zip"))
        .unwrap();
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(
        hits[0].location.ends_with("deep/nested/eicar.com"),
        "{}",
        hits[0].location
    );
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn exclusions_are_respected() {
    let dir = tmp("excl");
    warden_core::samples::generate(&dir).unwrap();
    let mut e = engine();
    e.options.exclusions = vec![dir.to_string_lossy().to_string()];
    let report = run_scan(
        &e,
        &[dir.clone()],
        &FileFilter::default(),
        &AtomicBool::new(false),
        &|_| {},
    );
    assert!(report.detections.is_empty());
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn quarantine_encrypts_and_restores() {
    let dir = tmp("q");
    warden_core::samples::generate(&dir).unwrap();
    let target = dir.join("eicar-test-file.txt");
    let original = std::fs::read(&target).unwrap();
    let det = engine().scan_file(&target).unwrap().remove(0);
    assert_eq!(det.severity, Severity::Medium);

    let q = Quarantine::new(dir.join("vault")).unwrap();
    let entry = q.add(&det).unwrap();
    assert!(!target.exists(), "original should be removed");
    let stored = std::fs::read(dir.join("vault/files").join(format!("{}.bin", entry.id))).unwrap();
    assert!(
        !stored
            .windows(original.len())
            .any(|w| w == original.as_slice()),
        "stored file must be encrypted"
    );
    assert_eq!(q.list().len(), 1);

    let restored = q.restore(&entry.id).unwrap();
    assert_eq!(std::fs::read(restored).unwrap(), original);
    assert!(q.list().is_empty());
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn feed_hashes_are_detected() {
    let dir = tmp("feed");
    let f = dir.join("x.bin");
    std::fs::write(&f, b"pretend malware").unwrap();
    let sha = Engine::sha256_file(&f).unwrap();
    let mut e = engine();
    e.db.add_feed_hashes("sha256", vec![sha]);
    let hits = e.scan_file(&f).unwrap();
    assert_eq!(hits[0].name, "Malware.KnownHash");
    std::fs::remove_dir_all(dir).ok();
}
