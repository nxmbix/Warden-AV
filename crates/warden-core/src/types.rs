use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionKind {
    /// Exact SHA-256 match against a known-bad hash.
    Signature,
    /// Content rule (byte / text / regex patterns).
    Rule,
    /// Behavioural / structural heuristics score.
    Heuristic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// File on disk that contains the threat (the outer archive for nested hits).
    pub path: String,
    /// Human readable location, e.g. `C:\x\a.zip › inner/evil.exe`.
    pub location: String,
    pub name: String,
    pub kind: DetectionKind,
    pub severity: Severity,
    pub category: String,
    pub description: String,
    pub reasons: Vec<String>,
    pub sha256: Option<String>,
    pub score: Option<u32>,
}

impl Detection {
    /// Threats that are confident enough to be quarantined automatically.
    pub fn is_confident(&self) -> bool {
        match self.kind {
            DetectionKind::Signature => true,
            DetectionKind::Rule => self.severity >= Severity::High,
            DetectionKind::Heuristic => self.severity >= Severity::High,
        }
    }
}
