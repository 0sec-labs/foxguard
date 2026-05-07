pub mod app;
pub mod baseline;
pub mod cli;
pub mod compliance;
pub mod config;
pub mod diff;
pub mod engine;
pub mod fix;
pub mod git;
pub mod report;
pub mod rules;
pub mod secrets;
pub mod tui;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    JavaScript,
    Python,
    Go,
    Ruby,
    Java,
    Php,
    Rust,
    CSharp,
    Swift,
    Kotlin,
    C,
    NginxConf,
    ApacheConf,
    HAProxyConf,
    Dockerfile,
    Manifest,
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Language::JavaScript => write!(f, "javascript"),
            Language::Python => write!(f, "python"),
            Language::Go => write!(f, "go"),
            Language::Ruby => write!(f, "ruby"),
            Language::Java => write!(f, "java"),
            Language::Php => write!(f, "php"),
            Language::Rust => write!(f, "rust"),
            Language::CSharp => write!(f, "csharp"),
            Language::Swift => write!(f, "swift"),
            Language::Kotlin => write!(f, "kotlin"),
            Language::C => write!(f, "c"),
            Language::NginxConf => write!(f, "nginxconf"),
            Language::ApacheConf => write!(f, "apacheconf"),
            Language::HAProxyConf => write!(f, "haproxyconf"),
            Language::Dockerfile => write!(f, "dockerfile"),
            Language::Manifest => write!(f, "manifest"),
        }
    }
}

/// Default confidence score for a finding when nothing else is specified.
/// Used by [`Finding::confidence`] via `#[serde(default)]` so baseline files
/// written before the field existed still deserialize correctly.
pub fn default_confidence() -> f32 {
    1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub cwe: Option<String>,
    pub description: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub snippet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_suggestion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink_start_byte: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink_end_byte: Option<usize>,
    /// Detection certainty in the closed interval [0.0, 1.0].
    ///
    /// Defaults to 1.0 ("no confidence information; treat as certain").
    /// Taint findings lower this based on hop count; Semgrep-compat
    /// findings default to 0.7 because external pattern rules are
    /// inherently fuzzier than curated built-in AST-walked rules.
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    /// Number of taint propagation hops (1 = direct, 2 = cross-file).
    /// `None` for non-taint rules. Used by `scan.thresholds.taint.max_hops`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint_hops: Option<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Cryptographic algorithm name (e.g. "RSA", "ECDSA", "TLS").
    /// Set by crypto-related rules at emission time. Used by the CBOM formatter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_algorithm: Option<String>,
    /// CNSA 2.0 compliance deadline (e.g. "2030"). Populated by the
    /// compliance module after scanning. `None` for non-crypto findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnsa2_deadline: Option<String>,
    /// Dependency name for manifest-level findings (e.g. "rustls", "paramiko").
    /// `None` for source-level rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dep_name: Option<String>,
}
