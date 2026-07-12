pub mod adapter;
pub mod app;
pub mod baseline;
pub mod certscan;
pub mod cli;
pub mod compliance;
pub mod config;
pub mod deps;
pub mod diff;
pub mod engine;
pub mod fix;
pub mod git;
#[cfg(feature = "github-app")]
pub mod github_app;
pub mod output;
pub mod path_identity;
pub mod report;
pub mod rules;
pub mod scan_plan;
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
    Hcl,
    Solidity,
    Yaml,
    NginxConf,
    ApacheConf,
    HAProxyConf,
    Dockerfile,
    Manifest,
    Bash,
    Ocaml,
    Scala,
    Elixir,
    Json,
    Apex,
    Clojure,
    Html,
    Xml,
    Dart,
    Haskell,
    /// Pseudo-language for Semgrep `languages: [regex]` rules.
    ///
    /// A `Regex`-language rule carries only `pattern-regex` / `pattern-not-regex`
    /// matchers and is run against the raw text of **every** scanned file (no
    /// tree-sitter parse required).  The scanner fans out one rule instance per
    /// detectable language (mirroring the `generic` mode fan-out) so that the
    /// existing `rule.language() == file_language` dispatch continues to work.
    Regex,
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
            Language::Hcl => write!(f, "hcl"),
            Language::Solidity => write!(f, "solidity"),
            Language::Yaml => write!(f, "yaml"),
            Language::NginxConf => write!(f, "nginxconf"),
            Language::ApacheConf => write!(f, "apacheconf"),
            Language::HAProxyConf => write!(f, "haproxyconf"),
            Language::Dockerfile => write!(f, "dockerfile"),
            Language::Manifest => write!(f, "manifest"),
            Language::Bash => write!(f, "bash"),
            Language::Ocaml => write!(f, "ocaml"),
            Language::Scala => write!(f, "scala"),
            Language::Elixir => write!(f, "elixir"),
            Language::Json => write!(f, "json"),
            Language::Apex => write!(f, "apex"),
            Language::Clojure => write!(f, "clojure"),
            Language::Html => write!(f, "html"),
            Language::Xml => write!(f, "xml"),
            Language::Dart => write!(f, "dart"),
            Language::Haskell => write!(f, "haskell"),
            Language::Regex => write!(f, "regex"),
        }
    }
}

/// Default confidence score for a finding when nothing else is specified.
/// Used by [`Finding::confidence`] via `#[serde(default)]` so baseline files
/// written before the field existed still deserialize correctly.
pub fn default_confidence() -> f32 {
    1.0
}

/// Tag applied to informational "post-quantum ready" findings.
///
/// The vulnerable side of the PQC audit tags findings `"PQ"` (see the
/// `pq-vulnerable-crypto` rules). The migration-target side tags findings
/// with this marker instead. A finding carrying [`PQ_READY_TAG`] describes a
/// *post-quantum / quantum-resistant* algorithm already in use — it is a
/// positive inventory entry, **not** a vulnerability. Modeling this as a tag
/// (rather than a new `Finding` field) keeps it symmetric with the existing
/// `"PQ"` marker, serializes for free, and lets the CBOM / migration
/// scorecard partition findings without a schema change.
pub const PQ_READY_TAG: &str = "PQ-READY";

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
    /// Installed dependency version when a lockfile format exposes one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dep_version: Option<String>,
    /// Package ecosystem name used by the vulnerability source (e.g. "npm", "PyPI").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dep_ecosystem: Option<String>,
    /// Package URL for the dependency when foxguard can construct one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dep_purl: Option<String>,
    /// Vulnerability identifier from the dependency advisory database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dep_vulnerability_id: Option<String>,
    /// First fixed version reported by the advisory, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dep_fixed_version: Option<String>,
    /// Dependency advisory source database, e.g. "OSV".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dep_source: Option<String>,
    /// Advisory-native severity text when supplied by the source database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dep_vulnerability_severity: Option<String>,
    /// Dependency path from manifest root to vulnerable package when known.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dep_path: Vec<String>,
    /// Parsed cryptographic material (X.509 certificate or standalone key)
    /// backing this finding. Populated only by the certificate/key scan pass
    /// (`foxguard pqc`); `None` for source-, config-, and dependency-level
    /// findings. Carries algorithm identity + metadata ONLY — never key bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto_material: Option<CryptoMaterial>,
}

/// Cryptographic material extracted from a real certificate or key file.
///
/// Emitted by the `foxguard pqc` cert/key scan pass and consumed by the CBOM
/// formatter to build CycloneDX `certificate` / `related-crypto-material`
/// assets. Contains only algorithm identity and public metadata — **never**
/// private-key bytes or other secret material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoMaterial {
    /// CBOM asset type: `"certificate"` for a parsed X.509 cert, or
    /// `"related-crypto-material"` for a standalone public/private key.
    pub asset_kind: String,
    /// Human-readable subject public-key algorithm identity, e.g.
    /// `"RSA-2048"`, `"ECDSA P-256"`, `"Ed25519"`, `"DSA-1024"`, `"ML-DSA"`.
    pub subject_public_key_algorithm: String,
    /// Certificate signature algorithm (present for full certs), e.g.
    /// `"sha256WithRSAEncryption"`. `None` for standalone keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    /// Encoding the material was parsed from: `"PEM"` or `"DER"`.
    pub format: String,
    /// Certificate `notValidAfter` timestamp in RFC 3339 / ISO-8601 form,
    /// when available. `None` for standalone keys or unparseable validity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_valid_after: Option<String>,
    /// Whether this material's public-key algorithm is quantum-vulnerable
    /// (classical RSA/EC/DSA). Post-quantum material (ML-DSA/ML-KEM) is
    /// `false`.
    pub quantum_vulnerable: bool,
}

impl Finding {
    /// `true` when this finding is an informational post-quantum inventory
    /// entry (see [`PQ_READY_TAG`]) rather than a vulnerability. Used by the
    /// CBOM formatter and migration scorecard to keep quantum-resistant
    /// algorithms out of the vulnerability set.
    pub fn is_pq_ready(&self) -> bool {
        self.tags.iter().any(|t| t == PQ_READY_TAG)
    }
}
