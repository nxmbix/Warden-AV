//! Encrypted quarantine vault.
//!
//! Quarantined files are AES-256-GCM encrypted on disk so nothing can execute
//! them (and so other scanners stop screaming about them), with an index that
//! remembers where each file came from.

use crate::types::{Detection, Severity};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub file_name: String,
    pub threat_name: String,
    pub severity: Severity,
    pub category: String,
    pub description: String,
    pub reasons: Vec<String>,
    pub sha256: String,
    pub size: u64,
    pub quarantined_at: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Index {
    #[serde(default)]
    entries: Vec<QuarantineEntry>,
}

pub struct Quarantine {
    dir: PathBuf,
}

impl Quarantine {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(dir.join("files")).context("creating quarantine folder")?;
        Ok(Self { dir })
    }

    fn index_path(&self) -> PathBuf {
        self.dir.join("index.json")
    }

    fn key_path(&self) -> PathBuf {
        self.dir.join("vault.key")
    }

    fn key(&self) -> Result<Key<Aes256Gcm>> {
        let path = self.key_path();
        if let Ok(bytes) = fs::read(&path) {
            if bytes.len() == 32 {
                return Ok(*Key::<Aes256Gcm>::from_slice(&bytes));
            }
        }
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        fs::write(&path, raw).context("writing vault key")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        Ok(*Key::<Aes256Gcm>::from_slice(&raw))
    }

    fn read_index(&self) -> Index {
        fs::read_to_string(self.index_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn write_index(&self, index: &Index) -> Result<()> {
        fs::write(self.index_path(), serde_json::to_string_pretty(index)?)
            .context("writing quarantine index")
    }

    pub fn list(&self) -> Vec<QuarantineEntry> {
        let mut entries = self.read_index().entries;
        entries.sort_by(|a, b| b.quarantined_at.cmp(&a.quarantined_at));
        entries
    }

    /// Move a detected file into the vault. The original is removed from disk.
    pub fn add(&self, detection: &Detection) -> Result<QuarantineEntry> {
        let path = Path::new(&detection.path);
        let data = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let id = uuid::Uuid::new_v4().to_string();

        let cipher = Aes256Gcm::new(&self.key()?);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let sealed = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), data.as_ref())
            .map_err(|e| anyhow!("encrypting quarantined file: {e}"))?;

        let mut blob = Vec::with_capacity(12 + sealed.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&sealed);
        fs::write(self.dir.join("files").join(format!("{id}.bin")), blob)
            .context("writing quarantined file")?;
        fs::remove_file(path).with_context(|| format!("removing original {}", path.display()))?;

        let entry = QuarantineEntry {
            id,
            original_path: detection.path.clone(),
            file_name: path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| detection.path.clone()),
            threat_name: detection.name.clone(),
            severity: detection.severity,
            category: detection.category.clone(),
            description: detection.description.clone(),
            reasons: detection.reasons.clone(),
            sha256: detection.sha256.clone().unwrap_or_default(),
            size: data.len() as u64,
            quarantined_at: chrono::Utc::now().to_rfc3339(),
        };
        let mut index = self.read_index();
        index.entries.push(entry.clone());
        self.write_index(&index)?;
        Ok(entry)
    }

    fn decrypt(&self, id: &str) -> Result<Vec<u8>> {
        let blob = fs::read(self.dir.join("files").join(format!("{id}.bin")))
            .context("reading quarantined file")?;
        if blob.len() < 13 {
            return Err(anyhow!("quarantined file is corrupted"));
        }
        let cipher = Aes256Gcm::new(&self.key()?);
        cipher
            .decrypt(Nonce::from_slice(&blob[..12]), &blob[12..])
            .map_err(|e| anyhow!("decrypting quarantined file: {e}"))
    }

    /// Put a file back where it came from. Returns the path it was restored to.
    pub fn restore(&self, id: &str) -> Result<String> {
        let mut index = self.read_index();
        let pos = index
            .entries
            .iter()
            .position(|e| e.id == id)
            .ok_or_else(|| anyhow!("no quarantined file with id {id}"))?;
        let data = self.decrypt(id)?;
        let entry = index.entries[pos].clone();
        let mut target = PathBuf::from(&entry.original_path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).ok();
        }
        if target.exists() {
            let stem = target
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "restored".into());
            let ext = target
                .extension()
                .map(|e| format!(".{}", e.to_string_lossy()))
                .unwrap_or_default();
            target.set_file_name(format!("{stem} (restored){ext}"));
        }
        fs::write(&target, data).with_context(|| format!("restoring to {}", target.display()))?;
        fs::remove_file(self.dir.join("files").join(format!("{id}.bin"))).ok();
        index.entries.remove(pos);
        self.write_index(&index)?;
        Ok(target.to_string_lossy().to_string())
    }

    /// Permanently delete a quarantined file.
    pub fn delete(&self, id: &str) -> Result<()> {
        let mut index = self.read_index();
        let before = index.entries.len();
        index.entries.retain(|e| e.id != id);
        if index.entries.len() == before {
            return Err(anyhow!("no quarantined file with id {id}"));
        }
        fs::remove_file(self.dir.join("files").join(format!("{id}.bin"))).ok();
        self.write_index(&index)
    }

    pub fn delete_all(&self) -> Result<usize> {
        let index = self.read_index();
        let n = index.entries.len();
        for e in &index.entries {
            fs::remove_file(self.dir.join("files").join(format!("{}.bin", e.id))).ok();
        }
        self.write_index(&Index::default())?;
        Ok(n)
    }
}
