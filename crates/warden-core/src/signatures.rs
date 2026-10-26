//! Signature database: known-bad hashes plus content rules.

use crate::rules::{CompiledRule, Rule};
use crate::types::Severity;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub const BUILTIN_JSON: &str = include_str!("../signatures/signatures.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashSig {
    pub sha256: String,
    pub name: String,
    pub severity: Severity,
    pub category: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureFile {
    pub version: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub updated: String,
    #[serde(default)]
    pub hashes: Vec<HashSig>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DbStats {
    pub version: String,
    pub named_hashes: usize,
    pub feed_hashes: usize,
    pub rules: usize,
}

pub struct SignatureDb {
    pub version: String,
    named: HashMap<String, HashSig>,
    /// Bulk hashes from public feeds (sha256 hex, or md5 hex).
    feed_sha256: HashSet<String>,
    feed_md5: HashSet<String>,
    pub rules: Vec<CompiledRule>,
}

impl SignatureDb {
    pub fn from_file(file: SignatureFile) -> Result<Self> {
        let mut db = Self {
            version: file.version.clone(),
            named: HashMap::new(),
            feed_sha256: HashSet::new(),
            feed_md5: HashSet::new(),
            rules: Vec::new(),
        };
        db.merge(file)?;
        Ok(db)
    }

    pub fn builtin() -> Result<Self> {
        let file: SignatureFile =
            serde_json::from_str(BUILTIN_JSON).context("parsing builtin signatures")?;
        Self::from_file(file)
    }

    /// Merge another signature file (e.g. a downloaded update). Rules with the same id are replaced.
    pub fn merge(&mut self, file: SignatureFile) -> Result<()> {
        for h in file.hashes {
            self.named.insert(h.sha256.to_ascii_lowercase(), h);
        }
        for r in file.rules {
            let compiled = CompiledRule::compile(r).map_err(anyhow::Error::msg)?;
            self.rules.retain(|c| c.rule.id != compiled.rule.id);
            self.rules.push(compiled);
        }
        if file.version > self.version {
            self.version = file.version;
        }
        Ok(())
    }

    pub fn merge_json_path(&mut self, path: &Path) -> Result<()> {
        let text = std::fs::read_to_string(path)?;
        self.merge(serde_json::from_str(&text)?)
    }

    pub fn add_feed_hashes(&mut self, format: &str, hashes: impl IntoIterator<Item = String>) {
        let set = if format == "md5" {
            &mut self.feed_md5
        } else {
            &mut self.feed_sha256
        };
        set.extend(hashes);
    }

    pub fn lookup_sha256(&self, sha256: &str) -> Option<HashSig> {
        if let Some(h) = self.named.get(sha256) {
            return Some(h.clone());
        }
        if self.feed_sha256.contains(sha256) {
            return Some(HashSig {
                sha256: sha256.to_string(),
                name: "Malware.KnownHash".into(),
                severity: Severity::Critical,
                category: "malware".into(),
                description: "This exact file is listed in a public malware-hash feed.".into(),
            });
        }
        None
    }

    pub fn has_md5_feed(&self) -> bool {
        !self.feed_md5.is_empty()
    }

    pub fn lookup_md5(&self, md5: &str) -> bool {
        self.feed_md5.contains(md5)
    }

    pub fn stats(&self) -> DbStats {
        DbStats {
            version: self.version.clone(),
            named_hashes: self.named.len(),
            feed_hashes: self.feed_sha256.len() + self.feed_md5.len(),
            rules: self.rules.len(),
        }
    }
}
