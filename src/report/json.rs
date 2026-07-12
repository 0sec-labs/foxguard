use crate::{Finding, Severity};
use serde::Serialize;
use std::time::Duration;

pub const JSON_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone)]
pub struct JsonReportMetadata<'a> {
    pub command: &'a str,
    pub config: JsonConfigMetadata,
    pub target: JsonTargetMetadata<'a>,
    pub duration: Duration,
}

#[derive(Debug, Clone)]
pub struct JsonConfigMetadata {
    pub source: &'static str,
    pub path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct JsonTargetMetadata<'a> {
    pub path: &'a str,
    pub kind: &'static str,
    pub changed_only: bool,
    pub files_scanned: usize,
    pub diff_base: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct JsonReportEnvelope<'a> {
    schema_version: &'static str,
    scanner: ScannerMetadata<'a>,
    config: ConfigMetadata<'a>,
    target: TargetMetadata<'a>,
    timing: TimingMetadata,
    finding_counts: FindingCounts,
    findings: &'a [Finding],
}

#[derive(Debug, Serialize)]
struct ScannerMetadata<'a> {
    name: &'static str,
    version: &'static str,
    command: &'a str,
}

#[derive(Debug, Serialize)]
struct ConfigMetadata<'a> {
    source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct TargetMetadata<'a> {
    path: &'a str,
    kind: &'static str,
    changed_only: bool,
    files_scanned: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff_base: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct TimingMetadata {
    duration_ms: u128,
}

#[derive(Debug, Serialize)]
struct FindingCounts {
    total: usize,
    by_severity: SeverityCounts,
}

#[derive(Debug, Serialize)]
struct SeverityCounts {
    low: usize,
    medium: usize,
    high: usize,
    critical: usize,
}

pub fn build_json_report(
    findings: &[Finding],
    metadata: JsonReportMetadata<'_>,
) -> serde_json::Value {
    let counts = finding_counts(findings);
    let envelope = JsonReportEnvelope {
        schema_version: JSON_SCHEMA_VERSION,
        scanner: ScannerMetadata {
            name: "foxguard",
            version: env!("CARGO_PKG_VERSION"),
            command: metadata.command,
        },
        config: ConfigMetadata {
            source: metadata.config.source,
            path: metadata.config.path.as_deref(),
        },
        target: TargetMetadata {
            path: metadata.target.path,
            kind: metadata.target.kind,
            changed_only: metadata.target.changed_only,
            files_scanned: metadata.target.files_scanned,
            diff_base: metadata.target.diff_base,
        },
        timing: TimingMetadata {
            duration_ms: metadata.duration.as_millis(),
        },
        finding_counts: counts,
        findings,
    };

    serde_json::to_value(envelope).expect("Failed to serialize JSON report")
}

fn finding_counts(findings: &[Finding]) -> FindingCounts {
    let mut by_severity = SeverityCounts {
        low: 0,
        medium: 0,
        high: 0,
        critical: 0,
    };

    for finding in findings {
        match finding.severity {
            Severity::Low => by_severity.low += 1,
            Severity::Medium => by_severity.medium += 1,
            Severity::High => by_severity.high += 1,
            Severity::Critical => by_severity.critical += 1,
        }
    }

    FindingCounts {
        total: findings.len(),
        by_severity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule_id: &str, severity: Severity) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity,
            cwe: Some("CWE-79".to_string()),
            description: "Use of dangerous HTML sink".to_string(),
            file: "src/app.js".to_string(),
            line: 3,
            column: 5,
            end_line: 3,
            end_column: 12,
            snippet: "sink(value)".to_string(),
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: 1.0,
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
            dep_name: None,
            dep_version: None,
            dep_ecosystem: None,
            dep_purl: None,
            dep_vulnerability_id: None,
            dep_fixed_version: None,
            dep_source: None,
            dep_vulnerability_severity: None,
            dep_path: vec![],
            crypto_material: None,
        }
    }

    #[test]
    fn json_report_wraps_findings_in_versioned_envelope() {
        let findings = vec![
            finding("js/no-innerhtml", Severity::High),
            finding("js/no-eval", Severity::Medium),
        ];
        let report = build_json_report(
            &findings,
            JsonReportMetadata {
                command: "scan",
                config: JsonConfigMetadata {
                    source: "explicit",
                    path: Some("/dev/null".to_string()),
                },
                target: JsonTargetMetadata {
                    path: ".",
                    kind: "directory",
                    changed_only: false,
                    files_scanned: 12,
                    diff_base: None,
                },
                duration: Duration::from_millis(420),
            },
        );

        assert_eq!(report["schema_version"].as_str(), Some(JSON_SCHEMA_VERSION));
        assert_eq!(report["scanner"]["name"].as_str(), Some("foxguard"));
        assert_eq!(report["scanner"]["command"].as_str(), Some("scan"));
        assert_eq!(report["config"]["source"].as_str(), Some("explicit"));
        assert_eq!(report["config"]["path"].as_str(), Some("/dev/null"));
        assert_eq!(report["target"]["files_scanned"].as_u64(), Some(12));
        assert_eq!(report["timing"]["duration_ms"].as_u64(), Some(420));
        assert_eq!(report["finding_counts"]["total"].as_u64(), Some(2));
        assert_eq!(
            report["finding_counts"]["by_severity"]["medium"].as_u64(),
            Some(1)
        );
        assert_eq!(
            report["finding_counts"]["by_severity"]["high"].as_u64(),
            Some(1)
        );
        assert_eq!(report["findings"].as_array().map(Vec::len), Some(2));
    }
}
