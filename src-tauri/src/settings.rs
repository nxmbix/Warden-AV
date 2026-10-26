use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use warden_core::engine::{EngineOptions, HeuristicsLevel};
use warden_core::feeds::{default_feeds, Feed};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Schedule {
    pub enabled: bool,
    /// `daily` or `weekly`.
    pub frequency: String,
    /// 0 = Monday .. 6 = Sunday (weekly only).
    pub weekday: u32,
    /// Local time, `HH:MM`.
    pub time: String,
    /// `quick` or `full`.
    pub scan_type: String,
    pub last_run: Option<String>,
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            enabled: true,
            frequency: "daily".into(),
            weekday: 0,
            time: "12:00".into(),
            scan_type: "quick".into(),
            last_run: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Updates {
    pub auto_update: bool,
    pub interval_hours: u32,
    pub feeds: Vec<Feed>,
    pub last_update: Option<String>,
    pub last_result: Option<String>,
}

impl Default for Updates {
    fn default() -> Self {
        Self {
            auto_update: true,
            interval_hours: 6,
            feeds: default_feeds(),
            last_update: None,
            last_result: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub realtime_enabled: bool,
    pub watched_folders: Vec<String>,
    pub auto_quarantine: bool,
    pub heuristics: HeuristicsLevel,
    pub scan_archives: bool,
    pub max_file_size_mb: u64,
    pub exclusions: Vec<String>,
    pub allowed_hashes: Vec<String>,
    pub notifications: bool,
    pub start_with_windows: bool,
    pub minimize_to_tray: bool,
    pub schedule: Schedule,
    pub updates: Updates,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            realtime_enabled: true,
            watched_folders: Vec::new(),
            auto_quarantine: true,
            heuristics: HeuristicsLevel::Balanced,
            scan_archives: true,
            max_file_size_mb: 256,
            exclusions: Vec::new(),
            allowed_hashes: Vec::new(),
            notifications: true,
            start_with_windows: true,
            minimize_to_tray: true,
            schedule: Schedule::default(),
            updates: Updates::default(),
        }
    }
}

impl Settings {
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("settings.json")
    }

    pub fn load(data_dir: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(Self::path(data_dir)).ok()?;
        let mut s: Settings = serde_json::from_str(&text).ok()?;
        // Pick up feeds added in newer versions.
        for f in default_feeds() {
            if !s.updates.feeds.iter().any(|x| x.id == f.id) {
                s.updates.feeds.push(f);
            }
        }
        Some(s)
    }

    pub fn save(&self, data_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(data_dir)?;
        std::fs::write(Self::path(data_dir), serde_json::to_string_pretty(self).unwrap_or_default())
    }

    pub fn engine_options(&self, self_paths: &[PathBuf]) -> EngineOptions {
        let mut exclusions = self.exclusions.clone();
        exclusions.extend(self_paths.iter().map(|p| p.to_string_lossy().to_string()));
        EngineOptions {
            heuristics: self.heuristics,
            scan_archives: self.scan_archives,
            max_file_size: self.max_file_size_mb.max(1) * 1024 * 1024,
            exclusions,
            allowed_hashes: self.allowed_hashes.clone(),
            ..EngineOptions::default()
        }
    }
}
