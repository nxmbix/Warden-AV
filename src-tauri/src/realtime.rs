//! Real-time protection: watches folders and scans files as soon as they land.

use crate::{notify_user, push_event, AppState, ProtectionEvent};
use notify::{EventKind, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager};

const PARTIAL_EXTS: &[&str] = &["crdownload", "part", "partial", "download", "tmp", "opdownload"];

pub fn default_folders(app: &AppHandle) -> Vec<String> {
    let p = app.path();
    [p.download_dir().ok(), p.desktop_dir().ok(), p.document_dir().ok()]
        .into_iter()
        .flatten()
        .map(|d| d.to_string_lossy().to_string())
        .collect()
}

/// (Re)start the watcher according to the current settings.
pub fn restart(app: &AppHandle) {
    let state = app.state::<AppState>();
    *state.watcher.lock() = None;
    let settings = state.settings.lock().clone();
    if !settings.realtime_enabled {
        return;
    }

    let (tx, rx) = mpsc::channel::<PathBuf>();
    let watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res {
            if matches!(ev.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                for p in ev.paths {
                    let _ = tx.send(p);
                }
            }
        }
    });
    let mut watcher = match watcher {
        Ok(w) => w,
        Err(e) => {
            eprintln!("real-time protection failed to start: {e}");
            return;
        }
    };
    for folder in &settings.watched_folders {
        let path = Path::new(folder);
        if path.is_dir() {
            if let Err(e) = watcher.watch(path, RecursiveMode::Recursive) {
                eprintln!("cannot watch {folder}: {e}");
            }
        }
    }
    *state.watcher.lock() = Some(watcher);

    let app = app.clone();
    std::thread::spawn(move || worker(app, rx));
}

fn worker(app: AppHandle, rx: mpsc::Receiver<PathBuf>) {
    let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
    loop {
        match rx.recv_timeout(Duration::from_millis(400)) {
            Ok(p) => {
                pending.insert(p, Instant::now());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        let ready: Vec<PathBuf> = pending
            .iter()
            .filter(|(_, t)| t.elapsed() > Duration::from_millis(1500))
            .map(|(p, _)| p.clone())
            .collect();
        for p in ready {
            pending.remove(&p);
            handle(&app, &p);
        }
    }
}

fn handle(app: &AppHandle, path: &Path) {
    if !path.is_file() {
        return;
    }
    let ext = warden_core::filetype::extension(path);
    if PARTIAL_EXTS.contains(&ext.as_str()) {
        return;
    }
    let state = app.state::<AppState>();
    if path.starts_with(&state.data_dir) {
        return;
    }
    let engine = state.engine.read().clone();
    let Ok(detections) = engine.scan_file(path) else { return };
    let Some(worst) = detections.iter().max_by_key(|d| d.severity).cloned() else { return };

    let auto = state.settings.lock().auto_quarantine;
    let confident = detections.iter().any(|d| d.is_confident());
    let (action, detail) = if auto && confident {
        match state.quarantine.add(&worst) {
            Ok(_) => ("quarantined", "Moved to quarantine automatically.".to_string()),
            Err(e) => ("failed", format!("Could not quarantine: {e}")),
        }
    } else {
        ("detected", "Review it on the Protection page.".to_string())
    };

    let file = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    push_event(
        app,
        ProtectionEvent {
            id: uuid_like(),
            time: chrono::Utc::now().to_rfc3339(),
            path: path.to_string_lossy().to_string(),
            threat: worst.name.clone(),
            severity: worst.severity.as_str().to_string(),
            action: action.to_string(),
            detail: detail.clone(),
            detection: worst.clone(),
        },
    );
    let title = match action {
        "quarantined" => format!("Threat blocked: {}", worst.name),
        "failed" => format!("Threat found: {}", worst.name),
        _ => format!("Suspicious file: {}", worst.name),
    };
    notify_user(app, &title, &format!("{file}\n{detail}"));
}

fn uuid_like() -> String {
    format!("{:x}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default())
}
