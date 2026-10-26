mod realtime;
mod scheduler;
mod settings;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use settings::Settings;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};
use tauri_plugin_notification::NotificationExt;
use warden_core::feeds;
use warden_core::scan::{run_scan, FileFilter, ScanProgress, ScanReport};
use warden_core::signatures::{DbStats, SignatureDb, SignatureFile};
use warden_core::{Detection, Engine, Quarantine, QuarantineEntry};

const MAX_HISTORY: usize = 40;
const MAX_EVENTS: usize = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: String,
    pub kind: String,
    pub scheduled: bool,
    pub auto_quarantined: usize,
    pub report: ScanReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanStatus {
    pub kind: String,
    pub started_at: String,
    pub progress: Option<ScanProgress>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionEvent {
    pub id: String,
    pub time: String,
    pub path: String,
    pub threat: String,
    pub severity: String,
    /// `quarantined`, `detected` or `failed`.
    pub action: String,
    pub detail: String,
    pub detection: Detection,
}

pub struct AppState {
    pub data_dir: PathBuf,
    pub engine: RwLock<Arc<Engine>>,
    pub settings: Mutex<Settings>,
    pub quarantine: Quarantine,
    pub scan_cancel: Mutex<Option<Arc<AtomicBool>>>,
    pub scan_status: Mutex<Option<ScanStatus>>,
    pub history: Mutex<Vec<ScanRecord>>,
    pub events: Mutex<Vec<ProtectionEvent>>,
    pub watcher: Mutex<Option<notify::RecommendedWatcher>>,
    pub updating: AtomicBool,
    pub tray_hint_shown: AtomicBool,
}

fn read_json<T: for<'de> Deserialize<'de> + Default>(path: &std::path::Path) -> T {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn write_json<T: Serialize>(path: &std::path::Path, value: &T) {
    if let Ok(s) = serde_json::to_string(value) {
        let _ = std::fs::write(path, s);
    }
}

/// Paths Warden must never scan or flag: its own data and install folders.
fn self_paths(data_dir: &std::path::Path) -> Vec<PathBuf> {
    let mut v = vec![data_dir.to_path_buf()];
    if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.to_path_buf())) {
        v.push(dir);
    }
    v
}

fn build_engine(data_dir: &std::path::Path, settings: &Settings) -> Engine {
    let mut db = SignatureDb::builtin().expect("builtin signatures are valid");
    if let Ok(rd) = std::fs::read_dir(data_dir.join("signatures")) {
        for entry in rd.flatten() {
            if entry.path().extension().map(|e| e == "json").unwrap_or(false) {
                if let Err(e) = db.merge_json_path(&entry.path()) {
                    eprintln!("ignoring signature file {}: {e}", entry.path().display());
                }
            }
        }
    }
    for feed in settings.updates.feeds.iter().filter(|f| f.enabled && f.format != "warden-json") {
        if let Ok(text) = std::fs::read_to_string(data_dir.join("feeds").join(format!("{}.txt", feed.id))) {
            db.add_feed_hashes(&feed.format, text.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()));
        }
    }
    Engine::new(db, settings.engine_options(&self_paths(data_dir)))
}

pub fn rebuild_engine(app: &AppHandle) {
    let state = app.state::<AppState>();
    let settings = state.settings.lock().clone();
    let engine = build_engine(&state.data_dir, &settings);
    *state.engine.write() = Arc::new(engine);
}

pub fn notify_user(app: &AppHandle, title: &str, body: &str) {
    let enabled = app.state::<AppState>().settings.lock().notifications;
    if enabled {
        let _ = app.notification().builder().title(title).body(body).show();
    }
}

pub fn push_event(app: &AppHandle, event: ProtectionEvent) {
    let state = app.state::<AppState>();
    {
        let mut events = state.events.lock();
        events.insert(0, event.clone());
        events.truncate(MAX_EVENTS);
        write_json(&state.data_dir.join("events.json"), &*events);
    }
    let _ = app.emit("protection-event", event);
}

fn quick_roots(app: &AppHandle) -> Vec<PathBuf> {
    let p = app.path();
    let mut roots: Vec<PathBuf> = [p.download_dir().ok(), p.desktop_dir().ok(), p.temp_dir().ok()]
        .into_iter()
        .flatten()
        .collect();
    if let Ok(cfg) = p.config_dir() {
        roots.push(cfg.join("Microsoft/Windows/Start Menu/Programs/Startup"));
    }
    if let Ok(pd) = std::env::var("PROGRAMDATA") {
        roots.push(PathBuf::from(pd).join("Microsoft/Windows/Start Menu/Programs/StartUp"));
    }
    if let Ok(public) = std::env::var("PUBLIC") {
        roots.push(PathBuf::from(public).join("Downloads"));
    }
    roots.into_iter().filter(|r| r.exists()).collect()
}

fn full_roots(app: &AppHandle) -> Vec<PathBuf> {
    if cfg!(windows) {
        (b'A'..=b'Z')
            .map(|c| PathBuf::from(format!("{}:\\", c as char)))
            .filter(|p| p.exists())
            .collect()
    } else {
        app.path().home_dir().ok().into_iter().collect()
    }
}

pub fn start_scan_inner(app: &AppHandle, kind: &str, paths: Vec<String>, scheduled: bool) -> Result<String, String> {
    let state = app.state::<AppState>();
    let mut slot = state.scan_cancel.lock();
    if slot.is_some() {
        return Err("A scan is already running.".into());
    }
    let (roots, filter) = match kind {
        "quick" => (quick_roots(app), FileFilter::default()),
        "full" => (
            full_roots(app),
            FileFilter {
                risky_only: true,
                ..FileFilter::default()
            },
        ),
        "custom" => {
            let roots: Vec<PathBuf> = paths.iter().map(PathBuf::from).filter(|p| p.exists()).collect();
            if roots.is_empty() {
                return Err("Pick at least one file or folder that exists.".into());
            }
            (roots, FileFilter::default())
        }
        other => return Err(format!("unknown scan type {other}")),
    };

    let cancel = Arc::new(AtomicBool::new(false));
    *slot = Some(cancel.clone());
    drop(slot);
    let id = format!("{}", chrono::Utc::now().timestamp_millis());
    *state.scan_status.lock() = Some(ScanStatus {
        kind: kind.to_string(),
        started_at: chrono::Utc::now().to_rfc3339(),
        progress: None,
    });
    let _ = app.emit("scan-started", kind);

    let app = app.clone();
    let kind = kind.to_string();
    let scan_id = id.clone();
    std::thread::spawn(move || {
        let state = app.state::<AppState>();
        let engine = state.engine.read().clone();
        let last_emit = Mutex::new(Instant::now() - Duration::from_secs(1));
        let report = run_scan(&engine, &roots, &filter, &cancel, &|p: ScanProgress| {
            let mut last = last_emit.lock();
            if last.elapsed() >= Duration::from_millis(150) || p.files_scanned == p.files_total {
                *last = Instant::now();
                if let Some(s) = app.state::<AppState>().scan_status.lock().as_mut() {
                    s.progress = Some(p.clone());
                }
                let _ = app.emit("scan-progress", p);
            }
        });

        let mut auto_quarantined = 0;
        if scheduled && state.settings.lock().auto_quarantine {
            let mut done: Vec<String> = Vec::new();
            for d in report.detections.iter().filter(|d| d.is_confident()) {
                if done.contains(&d.path) {
                    continue;
                }
                if state.quarantine.add(d).is_ok() {
                    auto_quarantined += 1;
                }
                done.push(d.path.clone());
            }
        }

        let record = ScanRecord {
            id: scan_id,
            kind: kind.clone(),
            scheduled,
            auto_quarantined,
            report,
        };
        {
            let mut history = state.history.lock();
            history.insert(0, record.clone());
            history.truncate(MAX_HISTORY);
            write_json(&state.data_dir.join("history.json"), &*history);
        }
        *state.scan_cancel.lock() = None;
        *state.scan_status.lock() = None;

        let threats = record.report.detections.len();
        if threats > 0 {
            notify_user(
                &app,
                &format!("Scan found {threats} threat{}", if threats == 1 { "" } else { "s" }),
                if auto_quarantined > 0 {
                    "Confident detections were moved to quarantine."
                } else {
                    "Open Warden to review them."
                },
            );
        } else if scheduled {
            notify_user(&app, "Scheduled scan finished", "No threats found.");
        }
        let _ = app.emit("scan-finished", record);
    });
    Ok(id)
}

pub fn update_signatures_inner(app: &AppHandle) -> Result<UpdateResult, String> {
    let state = app.state::<AppState>();
    if state.updating.swap(true, Ordering::SeqCst) {
        return Err("An update is already running.".into());
    }
    let _ = app.emit("update-started", ());
    let feeds_list = state.settings.lock().updates.feeds.clone();
    let feeds_dir = state.data_dir.join("feeds");
    let sig_dir = state.data_dir.join("signatures");
    std::fs::create_dir_all(&feeds_dir).ok();
    std::fs::create_dir_all(&sig_dir).ok();

    let mut results = Vec::new();
    for feed in feeds_list.iter().filter(|f| f.enabled) {
        let outcome = if feed.format == "warden-json" {
            feeds::fetch_text(&feed.url).and_then(|body| {
                let parsed: SignatureFile = serde_json::from_str(&body)?;
                std::fs::write(sig_dir.join(format!("{}.json", feed.id)), &body)?;
                Ok(parsed.hashes.len() + parsed.rules.len())
            })
        } else {
            feeds::fetch(feed).and_then(|r| {
                std::fs::write(feeds_dir.join(format!("{}.txt", feed.id)), r.hashes.join("\n"))?;
                Ok(r.hashes.len())
            })
        };
        results.push(match outcome {
            Ok(n) => FeedOutcome {
                id: feed.id.clone(),
                name: feed.name.clone(),
                entries: n,
                error: None,
            },
            Err(e) => FeedOutcome {
                id: feed.id.clone(),
                name: feed.name.clone(),
                entries: 0,
                error: Some(format!("{e:#}")),
            },
        });
    }

    let ok = results.iter().any(|r| r.error.is_none()) || results.is_empty();
    let summary = if results.is_empty() {
        "No feeds enabled.".to_string()
    } else {
        results
            .iter()
            .map(|r| match &r.error {
                None => format!("{}: {} entries", r.name, r.entries),
                Some(e) => format!("{}: failed ({e})", r.name),
            })
            .collect::<Vec<_>>()
            .join("; ")
    };
    {
        let mut s = state.settings.lock();
        s.updates.last_update = Some(chrono::Utc::now().to_rfc3339());
        s.updates.last_result = Some(summary);
        s.save(&state.data_dir).ok();
    }
    rebuild_engine(app);
    state.updating.store(false, Ordering::SeqCst);
    let result = UpdateResult {
        ok,
        feeds: results,
        stats: state.engine.read().db.stats(),
        at: chrono::Utc::now().to_rfc3339(),
    };
    let _ = app.emit("update-finished", result.clone());
    Ok(result)
}

#[derive(Debug, Clone, Serialize)]
pub struct FeedOutcome {
    id: String,
    name: String,
    entries: usize,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateResult {
    ok: bool,
    feeds: Vec<FeedOutcome>,
    stats: DbStats,
    at: String,
}

#[derive(Serialize)]
struct Status {
    realtime_enabled: bool,
    watched_folders: Vec<String>,
    signatures: DbStats,
    last_update: Option<String>,
    updating: bool,
    last_scan: Option<ScanRecord>,
    quarantine_count: usize,
    scan: Option<ScanStatus>,
    next_scheduled_scan: Option<String>,
    recent_events: Vec<ProtectionEvent>,
}

#[tauri::command]
fn get_status(state: State<AppState>) -> Status {
    let settings = state.settings.lock().clone();
    let mut last = state.history.lock().first().cloned();
    if let Some(r) = last.as_mut() {
        r.report.detections.truncate(50);
    }
    Status {
        realtime_enabled: settings.realtime_enabled && state.watcher.lock().is_some(),
        watched_folders: settings.watched_folders.clone(),
        signatures: state.engine.read().db.stats(),
        last_update: settings.updates.last_update.clone(),
        updating: state.updating.load(Ordering::Relaxed),
        last_scan: last,
        quarantine_count: state.quarantine.list().len(),
        scan: state.scan_status.lock().clone(),
        next_scheduled_scan: scheduler::next_slot(&settings.schedule, chrono::Local::now()).map(|t| t.to_rfc3339()),
        recent_events: state.events.lock().iter().take(5).cloned().collect(),
    }
}

#[tauri::command]
fn start_scan(app: AppHandle, kind: String, paths: Option<Vec<String>>) -> Result<String, String> {
    start_scan_inner(&app, &kind, paths.unwrap_or_default(), false)
}

#[tauri::command]
fn cancel_scan(state: State<AppState>) {
    if let Some(c) = state.scan_cancel.lock().as_ref() {
        c.store(true, Ordering::Relaxed);
    }
}

#[tauri::command]
fn get_history(state: State<AppState>) -> Vec<ScanRecord> {
    state.history.lock().clone()
}

#[tauri::command]
fn clear_history(state: State<AppState>) {
    state.history.lock().clear();
    write_json(&state.data_dir.join("history.json"), &Vec::<ScanRecord>::new());
}

#[derive(Serialize)]
struct ActionResult {
    path: String,
    ok: bool,
    message: String,
}

#[tauri::command]
fn quarantine_detections(app: AppHandle, detections: Vec<Detection>) -> Vec<ActionResult> {
    let state = app.state::<AppState>();
    let mut seen: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for d in detections {
        if seen.contains(&d.path) {
            continue;
        }
        seen.push(d.path.clone());
        out.push(match state.quarantine.add(&d) {
            Ok(_) => ActionResult {
                path: d.path,
                ok: true,
                message: "Quarantined".into(),
            },
            Err(e) => ActionResult {
                path: d.path,
                ok: false,
                message: format!("{e:#}"),
            },
        });
    }
    out
}

#[tauri::command]
fn allow_hash(app: AppHandle, sha256: String) -> Result<(), String> {
    let state = app.state::<AppState>();
    {
        let mut s = state.settings.lock();
        let h = sha256.to_ascii_lowercase();
        if !s.allowed_hashes.contains(&h) {
            s.allowed_hashes.push(h);
        }
        s.save(&state.data_dir).map_err(|e| e.to_string())?;
    }
    rebuild_engine(&app);
    Ok(())
}

#[tauri::command]
fn list_quarantine(state: State<AppState>) -> Vec<QuarantineEntry> {
    state.quarantine.list()
}

#[tauri::command]
fn restore_quarantine(app: AppHandle, id: String) -> Result<String, String> {
    let state = app.state::<AppState>();
    let entry = state
        .quarantine
        .list()
        .into_iter()
        .find(|e| e.id == id)
        .ok_or("Not found")?;
    // Trust the file first so real-time protection does not grab it straight back.
    if !entry.sha256.is_empty() {
        allow_hash(app.clone(), entry.sha256.clone())?;
    }
    state.quarantine.restore(&id).map_err(|e| format!("{e:#}"))
}

#[tauri::command]
fn delete_quarantine(state: State<AppState>, id: String) -> Result<(), String> {
    state.quarantine.delete(&id).map_err(|e| format!("{e:#}"))
}

#[tauri::command]
fn clear_quarantine(state: State<AppState>) -> Result<usize, String> {
    state.quarantine.delete_all().map_err(|e| format!("{e:#}"))
}

#[tauri::command]
fn get_settings(state: State<AppState>) -> Settings {
    state.settings.lock().clone()
}

#[tauri::command]
fn save_settings(app: AppHandle, settings: Settings) -> Result<Settings, String> {
    let state = app.state::<AppState>();
    let mut settings = settings;
    {
        let old = state.settings.lock().clone();
        if settings.schedule.enabled && (!old.schedule.enabled || settings.schedule.last_run.is_none()) {
            settings.schedule.last_run = Some(chrono::Local::now().to_rfc3339());
        }
        let autostart = app.autolaunch();
        let _ = if settings.start_with_windows {
            autostart.enable()
        } else {
            autostart.disable()
        };
        *state.settings.lock() = settings.clone();
        settings.save(&state.data_dir).map_err(|e| e.to_string())?;
    }
    rebuild_engine(&app);
    realtime::restart(&app);
    update_tray(&app);
    Ok(settings)
}

#[tauri::command]
fn set_realtime(app: AppHandle, enabled: bool) -> Result<(), String> {
    let state = app.state::<AppState>();
    {
        let mut s = state.settings.lock();
        s.realtime_enabled = enabled;
        s.save(&state.data_dir).map_err(|e| e.to_string())?;
    }
    realtime::restart(&app);
    update_tray(&app);
    let _ = app.emit("realtime-changed", enabled);
    Ok(())
}

#[tauri::command]
async fn update_signatures(app: AppHandle) -> Result<UpdateResult, String> {
    tauri::async_runtime::spawn_blocking(move || update_signatures_inner(&app))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
fn get_events(state: State<AppState>) -> Vec<ProtectionEvent> {
    state.events.lock().clone()
}

#[tauri::command]
fn clear_events(state: State<AppState>) {
    state.events.lock().clear();
    write_json(&state.data_dir.join("events.json"), &Vec::<ProtectionEvent>::new());
}

#[derive(Serialize)]
struct SamplesResult {
    dir: String,
    samples: Vec<warden_core::samples::Sample>,
}

#[tauri::command]
fn generate_samples(app: AppHandle, dir: Option<String>) -> Result<SamplesResult, String> {
    let dir = match dir {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => app
            .path()
            .document_dir()
            .map_err(|e| e.to_string())?
            .join("Warden Test Samples"),
    };
    let samples = warden_core::samples::generate(&dir).map_err(|e| format!("{e:#}"))?;
    Ok(SamplesResult {
        dir: dir.to_string_lossy().to_string(),
        samples,
    })
}

#[tauri::command]
fn default_samples_dir(app: AppHandle) -> Result<String, String> {
    Ok(app
        .path()
        .document_dir()
        .map_err(|e| e.to_string())?
        .join("Warden Test Samples")
        .to_string_lossy()
        .to_string())
}

#[tauri::command]
fn reveal_path(path: String) -> Result<(), String> {
    let p = PathBuf::from(&path);
    #[cfg(windows)]
    {
        let arg = if p.is_dir() {
            path.clone()
        } else {
            format!("/select,{path}")
        };
        std::process::Command::new("explorer").arg(arg).spawn().map_err(|e| e.to_string())?;
    }
    #[cfg(not(windows))]
    {
        let target = if p.is_dir() {
            p
        } else {
            p.parent().map(|x| x.to_path_buf()).unwrap_or(p)
        };
        std::process::Command::new("xdg-open").arg(target).spawn().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

fn update_tray(app: &AppHandle) {
    let on = app.state::<AppState>().settings.lock().realtime_enabled;
    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_tooltip(Some(if on {
            "Warden - real-time protection on"
        } else {
            "Warden - real-time protection OFF"
        }));
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .setup(|app| {
            let handle = app.handle().clone();
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;

            let first_run = Settings::load(&data_dir).is_none();
            let mut settings = Settings::load(&data_dir).unwrap_or_default();
            if settings.watched_folders.is_empty() && first_run {
                settings.watched_folders = realtime::default_folders(&handle);
            }
            settings.save(&data_dir).ok();
            if first_run && settings.start_with_windows {
                let _ = app.autolaunch().enable();
            }

            let engine = build_engine(&data_dir, &settings);
            let quarantine = Quarantine::new(data_dir.join("quarantine"))?;
            let history: Vec<ScanRecord> = read_json(&data_dir.join("history.json"));
            let events: Vec<ProtectionEvent> = read_json(&data_dir.join("events.json"));

            app.manage(AppState {
                data_dir,
                engine: RwLock::new(Arc::new(engine)),
                settings: Mutex::new(settings),
                quarantine,
                scan_cancel: Mutex::new(None),
                scan_status: Mutex::new(None),
                history: Mutex::new(history),
                events: Mutex::new(events),
                watcher: Mutex::new(None),
                updating: AtomicBool::new(false),
                tray_hint_shown: AtomicBool::new(false),
            });

            let open = MenuItem::with_id(app, "open", "Open Warden", true, None::<&str>)?;
            let quick = MenuItem::with_id(app, "quick", "Run quick scan", true, None::<&str>)?;
            let toggle = MenuItem::with_id(app, "realtime", "Turn real-time protection on/off", true, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;
            let quit = MenuItem::with_id(app, "quit", "Quit Warden", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quick, &toggle, &sep, &quit])?;
            let mut tray = TrayIconBuilder::with_id("main")
                .tooltip("Warden")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => show_main(app),
                    "quick" => {
                        let _ = start_scan_inner(app, "quick", Vec::new(), false);
                        show_main(app);
                    }
                    "realtime" => {
                        let on = app.state::<AppState>().settings.lock().realtime_enabled;
                        let _ = set_realtime(app.clone(), !on);
                        notify_user(
                            app,
                            "Warden",
                            if on { "Real-time protection is OFF" } else { "Real-time protection is ON" },
                        );
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main(tray.app_handle());
                    }
                });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;
            update_tray(&handle);

            if std::env::args().any(|a| a == "--minimized") {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }

            realtime::restart(&handle);
            scheduler::spawn(handle.clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let app = window.app_handle();
                let state = app.state::<AppState>();
                if state.settings.lock().minimize_to_tray {
                    api.prevent_close();
                    let _ = window.hide();
                    if !state.tray_hint_shown.swap(true, Ordering::Relaxed) {
                        notify_user(
                            app,
                            "Warden is still protecting you",
                            "It keeps running in the system tray. Right-click the shield icon to quit.",
                        );
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            start_scan,
            cancel_scan,
            get_history,
            clear_history,
            quarantine_detections,
            allow_hash,
            list_quarantine,
            restore_quarantine,
            delete_quarantine,
            clear_quarantine,
            get_settings,
            save_settings,
            set_realtime,
            update_signatures,
            get_events,
            clear_events,
            generate_samples,
            default_samples_dir,
            reveal_path,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Warden");
}
