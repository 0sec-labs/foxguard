pub mod baseline;
pub mod cli;
pub mod config;
pub mod diff;
pub mod engine;
pub mod git;
pub mod report;
pub mod rules;
pub mod secrets;

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
        }
    }
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
}
