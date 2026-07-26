//! Migration-readiness reporting for imported Semgrep rule packs.
//!
//! Readiness consumes the same original-file import transaction as
//! [`super::semgrep_compat::load_semgrep_rules`]. It never re-parses a single
//! source node to guess whether that node would load in isolation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::semgrep_compat::{
    import_semgrep_file, SemgrepImportDiagnostic, SemgrepImportSourceOutcome,
};

/// Version of the Semgrep-import migration-readiness JSON contract.
///
/// Bump this when a field is removed, changes type, or changes meaning.
pub const SEMGREP_MIGRATION_READINESS_SCHEMA_VERSION: &str = "1.0.0";

/// The importer disposition for one source Semgrep rule.
///
/// `Exact` means the production importer emitted a live rule and recorded no
/// reduction. It is not an empirical parity claim. `Degraded` means a live
/// rule was emitted after a recorded reduction. `Skipped` means no live rule
/// was emitted by the original-file import transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemgrepMigrationDisposition {
    Exact,
    Degraded,
    Skipped,
}

impl std::fmt::Display for SemgrepMigrationDisposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exact => write!(f, "exact"),
            Self::Degraded => write!(f, "degraded"),
            Self::Skipped => write!(f, "skipped"),
        }
    }
}

/// Stable machine-readable reason for an import disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemgrepMigrationReasonCode {
    Exact,
    UnsupportedFixRegex,
    UnsupportedLanguage,
    UnsupportedMode,
    UnsupportedConstruct,
    UnsupportedTaintShape,
    UnsupportedPatternEitherRegex,
    UnsupportedPatternNotRegex,
    UnsupportedPatternRegex,
    EngineCodeql,
    EngineCoccinelle,
    InvalidRule,
    InvalidDocument,
    FileImportFailed,
    LoaderRejected,
}

impl std::fmt::Display for SemgrepMigrationReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::Exact => "exact",
            Self::UnsupportedFixRegex => "unsupported-fix-regex",
            Self::UnsupportedLanguage => "unsupported-language",
            Self::UnsupportedMode => "unsupported-mode",
            Self::UnsupportedConstruct => "unsupported-construct",
            Self::UnsupportedTaintShape => "unsupported-taint-shape",
            Self::UnsupportedPatternEitherRegex => "unsupported-pattern-either-regex",
            Self::UnsupportedPatternNotRegex => "unsupported-pattern-not-regex",
            Self::UnsupportedPatternRegex => "unsupported-pattern-regex",
            Self::EngineCodeql => "engine-codeql",
            Self::EngineCoccinelle => "engine-coccinelle",
            Self::InvalidRule => "invalid-rule",
            Self::InvalidDocument => "invalid-document",
            Self::FileImportFailed => "file-import-failed",
            Self::LoaderRejected => "loader-rejected",
        };
        f.write_str(code)
    }
}

impl From<SemgrepImportDiagnostic> for SemgrepMigrationReasonCode {
    fn from(diagnostic: SemgrepImportDiagnostic) -> Self {
        match diagnostic {
            SemgrepImportDiagnostic::EngineCodeql => Self::EngineCodeql,
            SemgrepImportDiagnostic::EngineCoccinelle => Self::EngineCoccinelle,
            SemgrepImportDiagnostic::FileImportFailed => Self::FileImportFailed,
            SemgrepImportDiagnostic::InvalidDocument => Self::InvalidDocument,
            SemgrepImportDiagnostic::UnsupportedFixRegex => Self::UnsupportedFixRegex,
            SemgrepImportDiagnostic::UnsupportedLanguage => Self::UnsupportedLanguage,
            SemgrepImportDiagnostic::UnsupportedPatternEitherRegex => {
                Self::UnsupportedPatternEitherRegex
            }
            SemgrepImportDiagnostic::UnsupportedPatternNotRegex => Self::UnsupportedPatternNotRegex,
            SemgrepImportDiagnostic::UnsupportedPatternRegex => Self::UnsupportedPatternRegex,
            SemgrepImportDiagnostic::UnsupportedTaintShape => Self::UnsupportedTaintShape,
            SemgrepImportDiagnostic::UnsupportedConstruct => Self::UnsupportedConstruct,
        }
    }
}

/// One deterministic source-rule migration record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemgrepMigrationReadinessRecord {
    pub source_id: String,
    /// The first declared source language, normalized to FoxGuard's loader
    /// bucket. `<none>` denotes a document without a recoverable source rule.
    pub language: String,
    pub disposition: SemgrepMigrationDisposition,
    pub reason_code: SemgrepMigrationReasonCode,
}

/// Versioned JSON report for an imported Semgrep pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemgrepMigrationReadinessReport {
    pub schema_version: String,
    pub records: Vec<SemgrepMigrationReadinessRecord>,
}

impl SemgrepMigrationReadinessReport {
    fn new(mut records: Vec<SemgrepMigrationReadinessRecord>) -> Self {
        records.sort_by(|left, right| {
            (
                &left.source_id,
                &left.language,
                left.disposition,
                left.reason_code,
            )
                .cmp(&(
                    &right.source_id,
                    &right.language,
                    right.disposition,
                    right.reason_code,
                ))
        });
        Self {
            schema_version: SEMGREP_MIGRATION_READINESS_SCHEMA_VERSION.to_string(),
            records,
        }
    }

    pub fn total_by_disposition(&self) -> BTreeMap<SemgrepMigrationDisposition, usize> {
        let mut totals = BTreeMap::new();
        for record in &self.records {
            *totals.entry(record.disposition).or_default() += 1;
        }
        totals
    }

    pub fn total_by_language(
        &self,
    ) -> BTreeMap<String, BTreeMap<SemgrepMigrationDisposition, usize>> {
        let mut totals = BTreeMap::new();
        for record in &self.records {
            *totals
                .entry(record.language.clone())
                .or_insert_with(BTreeMap::new)
                .entry(record.disposition)
                .or_default() += 1;
        }
        totals
    }

    pub fn total_by_reason(&self) -> BTreeMap<SemgrepMigrationReasonCode, usize> {
        let mut totals = BTreeMap::new();
        for record in &self.records {
            *totals.entry(record.reason_code).or_default() += 1;
        }
        totals
    }
}

/// Assess an explicitly supplied Semgrep YAML file or a recursively imported
/// rule-pack directory. Explicit files are assessed regardless of extension;
/// directories use the production `.yaml`/`.yml` filter.
pub fn assess_semgrep_migration_readiness(
    path: &Path,
) -> Result<SemgrepMigrationReadinessReport, String> {
    let files = semgrep_rule_files(path)?;
    let mut records = Vec::new();
    for file in files {
        let outcome = import_semgrep_file(&file);
        records.extend(outcome.source_rules.iter().map(readiness_record));
    }
    Ok(SemgrepMigrationReadinessReport::new(records))
}

fn semgrep_rule_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        return Err(format!(
            "Semgrep rule pack path does not exist: {}",
            path.display()
        ));
    }

    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file() && is_semgrep_yaml(entry.path()))
        .map(|entry| entry.into_path())
        .collect();
    files.sort();
    Ok(files)
}

fn is_semgrep_yaml(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("yaml" | "yml")
    )
}

fn readiness_record(source: &SemgrepImportSourceOutcome) -> SemgrepMigrationReadinessRecord {
    let reason_code = if source.emitted {
        source
            .diagnostics
            .first()
            .copied()
            .map(Into::into)
            .unwrap_or(SemgrepMigrationReasonCode::Exact)
    } else {
        source
            .diagnostics
            .iter()
            .find(|diagnostic| **diagnostic == SemgrepImportDiagnostic::InvalidDocument)
            .copied()
            .or_else(|| {
                source
                    .diagnostics
                    .iter()
                    .find(|diagnostic| **diagnostic == SemgrepImportDiagnostic::FileImportFailed)
                    .copied()
            })
            .or_else(|| source.diagnostics.first().copied())
            .map(Into::into)
            .unwrap_or(SemgrepMigrationReasonCode::LoaderRejected)
    };
    let disposition = if source.emitted {
        if source.diagnostics.is_empty() {
            SemgrepMigrationDisposition::Exact
        } else {
            SemgrepMigrationDisposition::Degraded
        }
    } else {
        SemgrepMigrationDisposition::Skipped
    };

    SemgrepMigrationReadinessRecord {
        source_id: source.source_id.clone(),
        language: source.language.clone(),
        disposition,
        reason_code,
    }
}
