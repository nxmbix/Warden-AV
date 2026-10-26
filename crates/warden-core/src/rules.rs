use crate::filetype::FileType;
use crate::types::{Detection, DetectionKind, Severity};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "kind", content = "value")]
pub enum Pattern {
    /// Case-insensitive ASCII text match.
    Text(String),
    /// Hex byte string, e.g. "4d5a9000".
    Hex(String),
    /// Regular expression (bytes, case-insensitive).
    Regex(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub category: String,
    pub description: String,
    /// Patterns to look for; the rule fires when at least `min_matches` of them hit.
    pub patterns: Vec<Pattern>,
    #[serde(default = "one")]
    pub min_matches: usize,
    /// Restrict to these file types (`pe`, `script`, `office`, `lnk`, `pdf`, `archive`, `text`, `other`).
    #[serde(default)]
    pub file_types: Vec<String>,
    /// Maximum file size this rule applies to, in bytes.
    #[serde(default)]
    pub max_size: Option<u64>,
}

fn one() -> usize {
    1
}

#[derive(Debug)]
enum Compiled {
    Bytes(Vec<u8>),
    Lower(Vec<u8>),
    Re(Regex),
}

#[derive(Debug)]
pub struct CompiledRule {
    pub rule: Rule,
    patterns: Vec<Compiled>,
}

impl CompiledRule {
    pub fn compile(rule: Rule) -> Result<Self, String> {
        let mut patterns = Vec::with_capacity(rule.patterns.len());
        for p in &rule.patterns {
            patterns.push(match p {
                Pattern::Text(t) => Compiled::Lower(t.to_ascii_lowercase().into_bytes()),
                Pattern::Hex(h) => Compiled::Bytes(
                    hex::decode(h.replace([' ', '\n'], ""))
                        .map_err(|e| format!("rule {}: bad hex: {e}", rule.id))?,
                ),
                Pattern::Regex(r) => Compiled::Re(
                    Regex::new(&format!("(?i){r}"))
                        .map_err(|e| format!("rule {}: bad regex: {e}", rule.id))?,
                ),
            });
        }
        Ok(Self { rule, patterns })
    }

    fn applies(&self, ft: FileType, size: u64) -> bool {
        if let Some(max) = self.rule.max_size {
            if size > max {
                return false;
            }
        }
        self.rule.file_types.is_empty() || self.rule.file_types.iter().any(|t| t == ft.key())
    }

    /// Returns the patterns that matched, as readable strings.
    fn hits(&self, bytes: &[u8], lower: &[u8]) -> Vec<String> {
        let mut hits = Vec::new();
        for (p, c) in self.rule.patterns.iter().zip(&self.patterns) {
            let found = match c {
                Compiled::Lower(needle) => find(lower, needle),
                Compiled::Bytes(needle) => find(bytes, needle),
                Compiled::Re(re) => re.is_match(bytes),
            };
            if found {
                hits.push(match p {
                    Pattern::Text(t) => format!("contains \"{t}\""),
                    Pattern::Hex(h) => format!("contains bytes {h}"),
                    Pattern::Regex(r) => format!("matches /{r}/"),
                });
            }
        }
        hits
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Evaluate every rule against one file's contents.
pub fn match_rules(
    rules: &[CompiledRule],
    name: &str,
    ft: FileType,
    bytes: &[u8],
) -> Vec<Detection> {
    let lower: Vec<u8> = bytes.to_ascii_lowercase();
    let mut out = Vec::new();
    for cr in rules {
        if !cr.applies(ft, bytes.len() as u64) {
            continue;
        }
        let hits = cr.hits(bytes, &lower);
        if hits.len() >= cr.rule.min_matches.max(1) {
            out.push(Detection {
                path: String::new(),
                location: name.to_string(),
                name: cr.rule.name.clone(),
                kind: DetectionKind::Rule,
                severity: cr.rule.severity,
                category: cr.rule.category.clone(),
                description: cr.rule.description.clone(),
                reasons: hits,
                sha256: None,
                score: None,
            });
        }
    }
    out
}
