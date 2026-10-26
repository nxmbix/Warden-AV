//! Directory walking, progress reporting and cancellation.

use crate::engine::Engine;
use crate::filetype::{extension, RISKY_EXTS};
use crate::types::Detection;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileFilter {
    /// Only open files with an extension worth scanning (plus anything starting with `MZ`).
    pub risky_only: bool,
    pub follow_symlinks: bool,
    /// Directory names skipped everywhere (case-insensitive).
    pub skip_dirs: Vec<String>,
}

impl Default for FileFilter {
    fn default() -> Self {
        Self {
            risky_only: false,
            follow_symlinks: false,
            skip_dirs: vec![
                "$recycle.bin".into(),
                "system volume information".into(),
                "windows/winsxs".into(),
                "node_modules".into(),
                ".git".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanProgress {
    pub files_total: u64,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub current_file: String,
    pub detections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u128,
    pub files_scanned: u64,
    pub files_total: u64,
    pub bytes_scanned: u64,
    pub skipped: u64,
    pub errors: Vec<String>,
    pub detections: Vec<Detection>,
    pub cancelled: bool,
}

fn should_skip_dir(path: &Path, filter: &FileFilter) -> bool {
    let p = path
        .to_string_lossy()
        .to_ascii_lowercase()
        .replace('\\', "/");
    filter.skip_dirs.iter().any(|d| {
        let d = d.to_ascii_lowercase();
        p.ends_with(&format!("/{d}")) || p.contains(&format!("/{d}/"))
    })
}

fn worth_opening(path: &Path, filter: &FileFilter) -> bool {
    if !filter.risky_only {
        return true;
    }
    if RISKY_EXTS.contains(&extension(path).as_str()) {
        return true;
    }
    // Catch extension-less or renamed executables.
    let mut buf = [0u8; 2];
    use std::io::Read;
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .map(|_| &buf == b"MZ")
        .unwrap_or(false)
}

/// Enumerate every file under `roots` that passes the filter.
pub fn collect_files(roots: &[PathBuf], filter: &FileFilter, cancel: &AtomicBool) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in roots {
        if root.is_file() {
            files.push(root.clone());
            continue;
        }
        let walker = WalkDir::new(root)
            .follow_links(filter.follow_symlinks)
            .into_iter()
            .filter_entry(|e| !(e.file_type().is_dir() && should_skip_dir(e.path(), filter)));
        for entry in walker {
            if cancel.load(Ordering::Relaxed) {
                return files;
            }
            let Ok(entry) = entry else { continue };
            if entry.file_type().is_file() {
                files.push(entry.into_path());
            }
        }
    }
    files
}

/// Run a scan over `roots`, reporting progress and honouring cancellation.
pub fn run_scan(
    engine: &Engine,
    roots: &[PathBuf],
    filter: &FileFilter,
    cancel: &AtomicBool,
    on_progress: &(dyn Fn(ScanProgress) + Sync),
) -> ScanReport {
    let started = std::time::Instant::now();
    let started_at = chrono::Utc::now().to_rfc3339();
    let files = collect_files(roots, filter, cancel);
    let total = files.len() as u64;

    let scanned = AtomicU64::new(0);
    let bytes = AtomicU64::new(0);
    let skipped = AtomicU64::new(0);
    let detections: Mutex<Vec<Detection>> = Mutex::new(Vec::new());
    let errors: Mutex<Vec<String>> = Mutex::new(Vec::new());

    files.par_iter().for_each(|path| {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        if engine.is_excluded(path) || !worth_opening(path, filter) {
            skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        match engine.scan_file(path) {
            Ok(found) => {
                if let Ok(size) = std::fs::metadata(path).map(|m| m.len()) {
                    bytes.fetch_add(size, Ordering::Relaxed);
                }
                if !found.is_empty() {
                    detections.lock().unwrap().extend(found);
                }
            }
            Err(e) => {
                let mut errs = errors.lock().unwrap();
                if errs.len() < 200 {
                    errs.push(format!("{}: {e}", path.display()));
                }
            }
        }
        let done = scanned.fetch_add(1, Ordering::Relaxed) + 1;
        if done.is_multiple_of(25) || done == total {
            on_progress(ScanProgress {
                files_total: total,
                files_scanned: done,
                bytes_scanned: bytes.load(Ordering::Relaxed),
                current_file: path.to_string_lossy().to_string(),
                detections: detections.lock().unwrap().len(),
            });
        }
    });

    let mut detections = detections.into_inner().unwrap();
    detections.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.location.cmp(&b.location))
    });
    ScanReport {
        started_at,
        finished_at: chrono::Utc::now().to_rfc3339(),
        duration_ms: started.elapsed().as_millis(),
        files_scanned: scanned.load(Ordering::Relaxed),
        files_total: total,
        bytes_scanned: bytes.load(Ordering::Relaxed),
        skipped: skipped.load(Ordering::Relaxed),
        errors: errors.into_inner().unwrap(),
        detections,
        cancelled: cancel.load(Ordering::Relaxed),
    }
}
