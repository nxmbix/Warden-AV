//! Ties the three detection layers together for a single file.

use crate::filetype;
use crate::heuristics;
use crate::rules::match_rules;
use crate::signatures::SignatureDb;
use crate::types::{Detection, DetectionKind, Severity};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HeuristicsLevel {
    Off,
    Balanced,
    Aggressive,
}

impl HeuristicsLevel {
    fn threshold(&self) -> u32 {
        match self {
            HeuristicsLevel::Off => u32::MAX,
            HeuristicsLevel::Balanced => 45,
            HeuristicsLevel::Aggressive => 25,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineOptions {
    pub heuristics: HeuristicsLevel,
    pub scan_archives: bool,
    /// Files bigger than this are hashed only, never fully analysed.
    pub max_file_size: u64,
    pub max_archive_entries: usize,
    pub max_archive_depth: usize,
    /// Paths (prefix match, case-insensitive) and `*.ext` patterns that are never reported.
    pub exclusions: Vec<String>,
    /// SHA-256 hashes the user explicitly allowed ("this is fine").
    #[serde(default)]
    pub allowed_hashes: Vec<String>,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            heuristics: HeuristicsLevel::Balanced,
            scan_archives: true,
            max_file_size: 256 * 1024 * 1024,
            max_archive_entries: 512,
            max_archive_depth: 3,
            exclusions: Vec::new(),
            allowed_hashes: Vec::new(),
        }
    }
}

pub struct Engine {
    pub db: SignatureDb,
    pub options: EngineOptions,
}

impl Engine {
    pub fn new(db: SignatureDb, options: EngineOptions) -> Self {
        Self { db, options }
    }

    pub fn is_excluded(&self, path: &Path) -> bool {
        let p = path
            .to_string_lossy()
            .to_ascii_lowercase()
            .replace('\\', "/");
        self.options.exclusions.iter().any(|raw| {
            let e = raw.trim().to_ascii_lowercase().replace('\\', "/");
            if e.is_empty() {
                return false;
            }
            if let Some(ext) = e.strip_prefix("*.") {
                return p.ends_with(&format!(".{ext}"));
            }
            p == e || p.starts_with(&format!("{}/", e.trim_end_matches('/')))
        })
    }

    pub fn sha256_file(path: &Path) -> Result<String> {
        let mut file =
            std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    /// Scan one file on disk. Archive members are scanned too when enabled.
    pub fn scan_file(&self, path: &Path) -> Result<Vec<Detection>> {
        if self.is_excluded(path) {
            return Ok(Vec::new());
        }
        let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        let display = path.to_string_lossy().to_string();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| display.clone());

        if meta.len() > self.options.max_file_size {
            let sha = Self::sha256_file(path)?;
            let mut out = Vec::new();
            if let Some(hit) = self.db.lookup_sha256(&sha) {
                out.push(hash_detection(&display, &name, &sha, hit));
            }
            return Ok(out);
        }

        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let mut detections = self.scan_bytes(&name, &name, &bytes, 0);
        if !self.options.allowed_hashes.is_empty() {
            let outer = hex::encode(Sha256::digest(&bytes));
            if self
                .options
                .allowed_hashes
                .iter()
                .any(|h| h.eq_ignore_ascii_case(&outer))
            {
                return Ok(Vec::new());
            }
            detections.retain(|d| {
                d.sha256
                    .as_ref()
                    .map(|h| {
                        !self
                            .options
                            .allowed_hashes
                            .iter()
                            .any(|a| a.eq_ignore_ascii_case(h))
                    })
                    .unwrap_or(true)
            });
        }
        for d in &mut detections {
            d.path = display.clone();
            if d.location == name {
                d.location = display.clone();
            } else {
                d.location = format!(
                    "{display} > {}",
                    d.location.trim_start_matches(&format!("{name} > "))
                );
            }
        }
        Ok(detections)
    }

    /// Scan an in-memory buffer. `location` is the readable path used in results.
    pub fn scan_bytes(
        &self,
        name: &str,
        location: &str,
        bytes: &[u8],
        depth: usize,
    ) -> Vec<Detection> {
        let mut out = Vec::new();
        let sha = hex::encode(Sha256::digest(bytes));

        if let Some(hit) = self.db.lookup_sha256(&sha) {
            out.push(hash_detection("", location, &sha, hit));
        }
        if self.db.has_md5_feed() {
            let md5 = hex::encode(md5::Md5::digest(bytes));
            if self.db.lookup_md5(&md5) {
                out.push(Detection {
                    path: String::new(),
                    location: location.to_string(),
                    name: "Malware.KnownHash".into(),
                    kind: DetectionKind::Signature,
                    severity: Severity::Critical,
                    category: "malware".into(),
                    description: "This exact file is listed in a public malware-hash feed.".into(),
                    reasons: vec![format!("MD5 {md5} is a known-bad hash")],
                    sha256: Some(sha.clone()),
                    score: None,
                });
            }
        }

        let ft = filetype::detect(name, bytes);
        for mut d in match_rules(&self.db.rules, location, ft, bytes) {
            d.sha256 = Some(sha.clone());
            out.push(d);
        }
        if let Some(mut d) =
            heuristics::analyze(name, ft, bytes, self.options.heuristics.threshold())
        {
            d.location = location.to_string();
            d.sha256 = Some(sha.clone());
            out.push(d);
        }

        if self.options.scan_archives
            && depth < self.options.max_archive_depth
            && filetype::is_zip(bytes)
        {
            let inner = self.scan_zip(location, bytes, depth);
            // Prefer the precise inner hit over a duplicate match on the container bytes.
            out.retain(|o| {
                !inner.iter().any(|i| {
                    i.name == o.name || (o.kind == DetectionKind::Rule && i.category == o.category)
                })
            });
            out.extend(inner);
        }
        dedupe(out)
    }

    fn scan_zip(&self, location: &str, bytes: &[u8], depth: usize) -> Vec<Detection> {
        let mut out = Vec::new();
        let reader = std::io::Cursor::new(bytes);
        let Ok(mut zip) = zip::ZipArchive::new(reader) else {
            return out;
        };
        let count = zip.len().min(self.options.max_archive_entries);
        for i in 0..count {
            let Ok(entry) = zip.by_index(i) else { continue };
            if !entry.is_file() {
                continue;
            }
            // Guard against zip bombs: skip absurdly large members.
            if entry.size() > self.options.max_file_size {
                continue;
            }
            let inner_name = entry
                .enclosed_name()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| entry.name().to_string());
            let mut buf = Vec::with_capacity(entry.size().min(16 * 1024 * 1024) as usize);
            if entry
                .take(self.options.max_file_size)
                .read_to_end(&mut buf)
                .is_err()
            {
                continue;
            }
            let base = inner_name
                .rsplit('/')
                .next()
                .unwrap_or(&inner_name)
                .to_string();
            let inner_location = format!("{location} > {inner_name}");
            out.extend(self.scan_bytes(&base, &inner_location, &buf, depth + 1));
        }
        out
    }
}

fn hash_detection(
    path: &str,
    location: &str,
    sha: &str,
    hit: crate::signatures::HashSig,
) -> Detection {
    Detection {
        path: path.to_string(),
        location: location.to_string(),
        name: hit.name,
        kind: DetectionKind::Signature,
        severity: hit.severity,
        category: hit.category,
        description: hit.description,
        reasons: vec![format!("SHA-256 {sha} matches a known-bad hash")],
        sha256: Some(sha.to_string()),
        score: None,
    }
}

/// When an exact hash match exists, drop rule hits of the same category for the same location.
fn dedupe(mut out: Vec<Detection>) -> Vec<Detection> {
    let sig: Vec<(String, String)> = out
        .iter()
        .filter(|d| d.kind == DetectionKind::Signature)
        .map(|d| (d.location.clone(), d.category.clone()))
        .collect();
    out.retain(|d| {
        d.kind != DetectionKind::Rule
            || !sig
                .iter()
                .any(|(l, c)| *l == d.location && *c == d.category)
    });
    out
}
