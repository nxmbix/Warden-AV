//! Signature updates: pulls public malware-hash feeds and merges them into the database.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feed {
    pub id: String,
    pub name: String,
    pub url: String,
    /// `sha256`, `md5`, `sha1` or `warden-json` (a full Warden signature file).
    pub format: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Public hash feeds that need no API key.
pub fn default_feeds() -> Vec<Feed> {
    vec![
        Feed {
            id: "marcoux-sha256".into(),
            name: "Aggregated malware SHA-256 list (romainmarcoux/malicious-hash)".into(),
            url: "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha256-aa.txt"
                .into(),
            format: "sha256".into(),
            enabled: true,
        },
        Feed {
            id: "marcoux-md5".into(),
            name: "Aggregated malware MD5 list (romainmarcoux/malicious-hash)".into(),
            url: "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-md5-aa.txt"
                .into(),
            format: "md5".into(),
            enabled: false,
        },
    ]
}

pub struct FeedResult {
    pub feed_id: String,
    pub hashes: Vec<String>,
    pub bytes: usize,
}

pub fn fetch_text(url: &str) -> Result<String> {
    let resp = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(120))
        .user_agent("Warden-AV/0.1 (+https://github.com/nxmbix/Warden-AV)")
        .build()
        .get(url)
        .call()
        .with_context(|| format!("downloading {url}"))?;
    let mut body = String::new();
    std::io::Read::read_to_string(&mut resp.into_reader().take(256 * 1024 * 1024), &mut body)
        .context("reading feed body")?;
    Ok(body)
}

pub fn fetch(feed: &Feed) -> Result<FeedResult> {
    let body = fetch_text(&feed.url)?;

    let width = match feed.format.as_str() {
        "md5" => 32,
        "sha1" => 40,
        _ => 64,
    };
    let mut hashes = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Accept bare hashes and CSV rows that contain one.
        for token in line.split([',', ';', '\t', ' ', '"']) {
            let token = token.trim().trim_matches('"');
            if token.len() == width && token.chars().all(|c| c.is_ascii_hexdigit()) {
                hashes.push(token.to_ascii_lowercase());
                break;
            }
        }
    }
    hashes.sort();
    hashes.dedup();
    Ok(FeedResult {
        feed_id: feed.id.clone(),
        hashes,
        bytes: body.len(),
    })
}
