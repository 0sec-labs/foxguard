//! Semgrep-compatible JSON output (`--format semgrep-json`).
//!
//! Foxguard's native `--format json` emits its own envelope (schema_version,
//! scanner, config, target, timing, finding_counts, findings). That is NOT the
//! schema `semgrep --json` produces, so any pipeline that does
//! `semgrep --json | jq '.results[]...'` cannot consume foxguard output.
//!
//! This module emits the Semgrep CLI JSON shape so foxguard can be a drop-in
//! replacement in those pipelines:
//!
//! ```json
//! {
//!   "version": "1.0.0",
//!   "results": [
//!     {
//!       "check_id": "py/taint-sql-injection",
//!       "path": "app/views.py",
//!       "start": { "line": 12, "col": 5, "offset": 0 },
//!       "end":   { "line": 12, "col": 24, "offset": 0 },
//!       "extra": {
//!         "message": "...",
//!         "metadata": { "cwe": ["CWE-89"], "confidence": "HIGH" },
//!         "severity": "ERROR",
//!         "lines": "cursor.execute(sql)",
//!         "fingerprint": "..."
//!       }
//!     }
//!   ],
//!   "errors": [],
//!   "paths": { "scanned": ["app/views.py"] }
//! }
//! ```
//!
//! Faithfulness notes (documented divergences from upstream Semgrep):
//! - Foxguard does not track byte offsets per finding, so `start.offset` /
//!   `end.offset` are emitted as `0`. The `line`/`col` fields are accurate.
//!   Most consumers key on line/col, not offset.
//! - Severity maps foxguard's 4-level scale onto Semgrep's 3-level
//!   (ERROR/WARNING/INFO): Critical+High -> ERROR, Medium -> WARNING,
//!   Low -> INFO. This mirrors the inverse of the loader mapping in
//!   `semgrep_compat.rs` (ERROR->Critical, WARNING->High, INFO->Medium).
//! - `metadata` carries `cwe` (as a list, matching Semgrep) plus foxguard's
//!   `confidence` (HIGH/MEDIUM/LOW bucketed from the numeric score) and the
//!   raw `confidence_score`. Foxguard does not retain other upstream metadata
//!   (references, technology, ...) past load, so those are absent.

use crate::{Finding, Severity};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Version tag for the emitted document. This identifies foxguard's
/// Semgrep-JSON emitter shape, not the Semgrep CLI version being mimicked.
pub const SEMGREP_JSON_SCHEMA_VERSION: &str = "1.0.0";

/// Map foxguard's 4-level severity onto Semgrep's 3-level CLI severity.
fn semgrep_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "ERROR",
        Severity::Medium => "WARNING",
        Severity::Low => "INFO",
    }
}

/// Bucket a numeric confidence (0.0–1.0) into Semgrep's HIGH/MEDIUM/LOW.
fn confidence_bucket(confidence: f32) -> &'static str {
    let c = confidence.clamp(0.0, 1.0);
    if c >= 0.8 {
        "HIGH"
    } else if c >= 0.5 {
        "MEDIUM"
    } else {
        "LOW"
    }
}

/// Stable per-finding fingerprint, mirroring the SARIF
/// `partialFingerprints` approach (rule + path + span + snippet).
fn fingerprint(finding: &Finding) -> String {
    let mut hasher = Sha256::new();
    hasher.update(finding.rule_id.as_bytes());
    hasher.update([0]);
    hasher.update(finding.file.as_bytes());
    hasher.update([0]);
    hasher.update(finding.line.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(finding.column.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(finding.end_line.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(finding.end_column.to_string().as_bytes());
    hasher.update([0]);
    let snippet = finding
        .snippet
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .chars()
        .filter(|c| *c != ' ' && *c != '\t')
        .collect::<String>();
    hasher.update(snippet.as_bytes());
    let digest = hasher.finalize();
    digest
        .iter()
        .take(16)
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn position(line: usize, col: usize) -> Value {
    // Semgrep positions are 1-based line, 1-based col. Foxguard's `column`
    // and `end_column` follow the same convention as the SARIF emitter.
    json!({
        "line": line,
        "col": col,
        "offset": 0
    })
}

fn metadata(finding: &Finding) -> Value {
    let mut map = serde_json::Map::new();
    // Semgrep represents CWE as a list of "CWE-NNN: Title" strings; foxguard
    // stores a single bare id, so emit a one-element list to match the shape.
    if let Some(cwe) = &finding.cwe {
        map.insert("cwe".to_string(), json!([cwe]));
    }
    map.insert(
        "confidence".to_string(),
        json!(confidence_bucket(finding.confidence)),
    );
    map.insert(
        "confidence_score".to_string(),
        json!(finding.confidence.clamp(0.0, 1.0)),
    );
    if let Some(hops) = finding.taint_hops {
        map.insert("taint_hops".to_string(), json!(hops));
    }
    if !finding.tags.is_empty() {
        map.insert("tags".to_string(), json!(finding.tags));
    }
    Value::Object(map)
}

fn result(finding: &Finding) -> Value {
    json!({
        "check_id": finding.rule_id,
        "path": finding.file.replace('\\', "/"),
        "start": position(finding.line, finding.column),
        "end": position(finding.end_line, finding.end_column),
        "extra": {
            "message": finding.description,
            "metadata": metadata(finding),
            "severity": semgrep_severity(finding.severity),
            "lines": finding.snippet,
            "fingerprint": fingerprint(finding),
        }
    })
}

/// Build the Semgrep-compatible JSON document for a finding set.
pub fn build_semgrep_json(findings: &[Finding]) -> Value {
    let results: Vec<Value> = findings.iter().map(result).collect();

    // De-duplicated, sorted list of scanned paths, matching `paths.scanned`.
    let scanned: BTreeSet<String> = findings
        .iter()
        .map(|f| f.file.replace('\\', "/"))
        .filter(|p| !p.is_empty())
        .collect();

    json!({
        "version": SEMGREP_JSON_SCHEMA_VERSION,
        "results": results,
        "errors": [],
        "paths": {
            "scanned": scanned.into_iter().collect::<Vec<_>>()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule_id: &str, severity: Severity) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity,
            cwe: Some("CWE-89".to_string()),
            description: "Tainted input reaches SQL sink".to_string(),
            file: "app/views.py".to_string(),
            line: 12,
            column: 5,
            end_line: 12,
            end_column: 24,
            snippet: "cursor.execute(sql)".to_string(),
            source_line: Some(10),
            source_description: Some("request.GET".to_string()),
            sink_line: Some(12),
            sink_description: Some("cursor.execute".to_string()),
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: 0.9,
            taint_hops: Some(1),
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
    fn emits_semgrep_result_shape() {
        let doc = build_semgrep_json(&[finding("py/taint-sql-injection", Severity::Critical)]);

        assert_eq!(doc["version"].as_str(), Some(SEMGREP_JSON_SCHEMA_VERSION));
        assert_eq!(doc["errors"].as_array().map(Vec::len), Some(0));
        assert_eq!(
            doc["paths"]["scanned"][0].as_str(),
            Some("app/views.py"),
            "scanned paths should list the finding's file"
        );

        let r = &doc["results"][0];
        assert_eq!(r["check_id"].as_str(), Some("py/taint-sql-injection"));
        assert_eq!(r["path"].as_str(), Some("app/views.py"));
        assert_eq!(r["start"]["line"].as_u64(), Some(12));
        assert_eq!(r["start"]["col"].as_u64(), Some(5));
        assert_eq!(r["end"]["line"].as_u64(), Some(12));
        assert_eq!(r["end"]["col"].as_u64(), Some(24));
        // Critical -> ERROR on Semgrep's 3-level scale.
        assert_eq!(r["extra"]["severity"].as_str(), Some("ERROR"));
        assert_eq!(
            r["extra"]["message"].as_str(),
            Some("Tainted input reaches SQL sink")
        );
        assert_eq!(r["extra"]["lines"].as_str(), Some("cursor.execute(sql)"));
        // CWE is a list, matching Semgrep.
        assert_eq!(r["extra"]["metadata"]["cwe"][0].as_str(), Some("CWE-89"));
        assert_eq!(r["extra"]["metadata"]["confidence"].as_str(), Some("HIGH"));
        assert!(r["extra"]["fingerprint"].as_str().is_some());
    }

    #[test]
    fn severity_maps_four_levels_to_three() {
        assert_eq!(semgrep_severity(Severity::Critical), "ERROR");
        assert_eq!(semgrep_severity(Severity::High), "ERROR");
        assert_eq!(semgrep_severity(Severity::Medium), "WARNING");
        assert_eq!(semgrep_severity(Severity::Low), "INFO");
    }

    #[test]
    fn confidence_buckets() {
        assert_eq!(confidence_bucket(1.0), "HIGH");
        assert_eq!(confidence_bucket(0.8), "HIGH");
        assert_eq!(confidence_bucket(0.7), "MEDIUM");
        assert_eq!(confidence_bucket(0.5), "MEDIUM");
        assert_eq!(confidence_bucket(0.3), "LOW");
    }

    #[test]
    fn fingerprint_is_stable_and_distinct() {
        let a = finding("py/a", Severity::High);
        let mut b = finding("py/b", Severity::High);
        assert_eq!(fingerprint(&a), fingerprint(&a), "stable across calls");
        assert_ne!(
            fingerprint(&a),
            fingerprint(&b),
            "different rule_id -> different fingerprint"
        );
        b.rule_id = "py/a".to_string();
        b.line = 99;
        assert_ne!(
            fingerprint(&a),
            fingerprint(&b),
            "different line -> different fingerprint"
        );
    }

    #[test]
    fn paths_scanned_dedups_and_sorts() {
        let doc = build_semgrep_json(&[
            finding("py/a", Severity::High),
            finding("py/b", Severity::High),
        ]);
        // Both findings share app/views.py -> a single scanned entry.
        assert_eq!(doc["paths"]["scanned"].as_array().map(Vec::len), Some(1));
        assert_eq!(doc["results"].as_array().map(Vec::len), Some(2));
    }
}
