//! Warden scan engine: signatures, rules, heuristics, archives, quarantine and harmless test samples.

pub mod engine;
pub mod feeds;
pub mod filetype;
pub mod heuristics;
pub mod quarantine;
pub mod rules;
pub mod samples;
pub mod scan;
pub mod signatures;
pub mod types;

pub use engine::{Engine, EngineOptions, HeuristicsLevel};
pub use quarantine::{Quarantine, QuarantineEntry};
pub use scan::{run_scan, FileFilter, ScanProgress, ScanReport};
pub use signatures::SignatureDb;
pub use types::{Detection, DetectionKind, Severity};
