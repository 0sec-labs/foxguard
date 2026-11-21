//! Bitbucket Code Insights reporter (Cloud and Data Center).
//!
//! Emits one JSON envelope holding the report body plus annotations already
//! split into request-sized batches, so a CI step only has to PUT the report
//! and POST each batch.
//!
//! Limits (Atlassian public docs):
//! - Cloud: 1000 annotations per report, 100 per bulk request (JSON array body),
//!   up to 10 report data elements. Severities CRITICAL/HIGH/MEDIUM/LOW.
//! - Data Center: 1000 annotations per report by default
//!   (`plugin.bitbucket-code-insights.report.annotations.max`), up to 6 data
//!   fields, severities LOW/MEDIUM/HIGH only, body `{"annotations": [...]}`.
//!   The per-request cap is not stated in the public how-to; 1000 is used.
//!
//! When over the cap the most severe findings are kept and the number dropped
//! is reported in the envelope and in the report details.

use crate::{Finding, Severity};
use serde_json::{json, Value};
use std::collections::HashMap;

pub const REPORT_ID: &str = "foxguard";
pub const MAX_ANNOTATIONS: usize = 1000;
pub const CLOUD_BATCH_SIZE: usize = 100;
pub const DC_BATCH_SIZE: usize = 1000;
const CLOUD_SUMMARY_MAX: usize = 450;
const DETAILS_MAX: usize = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Cloud,
    DataCenter,
}

/// Drop duplicate findings sharing path + line + CWE (rule id stands in when
/// there is no CWE), keeping the highest-severity one. Order of first
/// occurrence is preserved.
fn dedupe(findings: &[Finding]) -> Vec<&Finding> {
    let mut out: Vec<&Finding> = Vec::new();
    let mut index: HashMap<(String, usize, String), usize> = HashMap::new();
    for f in findings {
        let key = (
            normalize_path(&f.file),
            f.line,
            f.cwe
                .clone()
                .unwrap_or_else(|| format!("rule:{}", f.rule_id)),
        );
        match index.get(&key) {
            Some(&i) => {
                if f.severity > out[i].severity {
                    out[i] = f;
                }
            }
            None => {
                index.insert(key, out.len());
                out.push(f);
            }
        }
    }
    out
}

/// Bitbucket wants repo-relative paths with forward slashes.
fn normalize_path(file: &str) -> String {
    let mut p = file.replace('\\', "/");
    if let Ok(cwd) = std::env::current_dir() {
        let prefix = format!("{}/", cwd.to_string_lossy().replace('\\', "/"));
        if let Some(rest) = p.strip_prefix(&prefix) {
            p = rest.to_string();
        }
    }
    while let Some(rest) = p.strip_prefix("./") {
        p = rest.to_string();
    }
    p
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max.saturating_sub(3)).collect();
    t.push_str("...");
    t
}

/// Stable, bounded external id so re-runs update rather than duplicate.
fn external_id(f: &Finding, path: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in format!("{}\0{}\0{}", f.rule_id, path, f.line).bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("foxguard-{h:016x}")
}

fn severity_name(platform: Platform, s: Severity) -> &'static str {
    match (platform, s) {
        (Platform::Cloud, Severity::Critical) => "CRITICAL",
        (Platform::DataCenter, Severity::Critical) => "HIGH",
        (_, Severity::High) => "HIGH",
        (_, Severity::Medium) => "MEDIUM",
        (_, Severity::Low) => "LOW",
    }
}

fn message(f: &Finding) -> String {
    let cwe = f
        .cwe
        .as_ref()
        .map(|c| format!(" ({c})"))
        .unwrap_or_default();
    format!("[{}]{} {}", f.rule_id, cwe, f.description)
}

fn details(f: &Finding) -> String {
    let mut d = format!("Rule: {}", f.rule_id);
    if let Some(cwe) = &f.cwe {
        d.push_str(&format!("\nCWE: {cwe}"));
    }
    d.push_str(&format!("\n{}", f.description));
    if let Some(fix) = &f.fix_suggestion {
        d.push_str(&format!("\nFix: {fix}"));
    }
    truncate(&d, DETAILS_MAX)
}

fn annotation(platform: Platform, f: &Finding) -> Value {
    let path = normalize_path(&f.file);
    let line = f.line.max(1);
    match platform {
        Platform::Cloud => json!({
            "external_id": external_id(f, &path),
            "annotation_type": "VULNERABILITY",
            "severity": severity_name(platform, f.severity),
            "path": path,
            "line": line,
            "summary": truncate(&message(f), CLOUD_SUMMARY_MAX),
            "details": details(f),
        }),
        Platform::DataCenter => {
            let mut msg = message(f);
            if let Some(fix) = &f.fix_suggestion {
                msg.push_str(&format!("\nFix: {fix}"));
            }
            json!({
                "externalId": external_id(f, &path),
                "type": "VULNERABILITY",
                "severity": severity_name(platform, f.severity),
                "path": path,
                "line": line,
                "message": truncate(&msg, DETAILS_MAX),
            })
        }
    }
}

fn data_entry(title: &str, value: usize) -> Value {
    json!({"title": title, "type": "NUMBER", "value": value})
}

pub fn build_code_insights(findings: &[Finding], platform: Platform) -> Value {
    let mut unique = dedupe(findings);
    // Most severe first, so the cap drops the least important findings.
    unique.sort_by(|a, b| b.severity.cmp(&a.severity));
    let total = unique.len();
    let dropped = total.saturating_sub(MAX_ANNOTATIONS);
    unique.truncate(MAX_ANNOTATIONS);

    let count = |s: Severity| unique_count(findings, s);
    let mut data = vec![
        data_entry("Findings", total),
        data_entry("Critical", count(Severity::Critical)),
        data_entry("High", count(Severity::High)),
        data_entry("Medium", count(Severity::Medium)),
        data_entry("Low", count(Severity::Low)),
    ];
    if dropped > 0 {
        data.push(data_entry("Not annotated (cap)", dropped));
    }

    let mut report_details = if total == 0 {
        "No findings.".to_string()
    } else {
        format!("{total} unique finding(s) after path+line+CWE dedupe.")
    };
    if dropped > 0 {
        report_details.push_str(&format!(
            " {dropped} lower-severity finding(s) exceeded the {MAX_ANNOTATIONS}-annotation cap and were not annotated."
        ));
    }

    let (result, batch_size, platform_name) = match platform {
        Platform::Cloud => (
            if total == 0 { "PASSED" } else { "FAILED" },
            CLOUD_BATCH_SIZE,
            "bitbucket-cloud",
        ),
        Platform::DataCenter => (
            if total == 0 { "PASS" } else { "FAIL" },
            DC_BATCH_SIZE,
            "bitbucket-data-center",
        ),
    };

    let mut report = json!({
        "title": "foxguard security scan",
        "details": report_details,
        "reporter": "foxguard",
        "result": result,
        "data": data,
    });
    if platform == Platform::Cloud {
        report["report_type"] = json!("SECURITY");
    }

    let annotations: Vec<Value> = unique.iter().map(|f| annotation(platform, f)).collect();
    let batches: Vec<Value> = annotations
        .chunks(batch_size)
        .map(|chunk| match platform {
            Platform::Cloud => Value::Array(chunk.to_vec()),
            Platform::DataCenter => json!({"annotations": chunk}),
        })
        .collect();

    json!({
        "platform": platform_name,
        "report_id": REPORT_ID,
        "report": report,
        "annotation_batches": batches,
        "annotations_total": total,
        "annotations_emitted": annotations.len(),
        "annotations_dropped": dropped,
    })
}

fn unique_count(findings: &[Finding], s: Severity) -> usize {
    dedupe(findings).iter().filter(|f| f.severity == s).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str, sev: Severity, cwe: Option<&str>, file: &str, line: usize) -> Finding {
        serde_json::from_value(json!({
            "rule_id": rule, "severity": sev, "cwe": cwe, "description": "desc",
            "file": file, "line": line, "column": 1, "end_line": line,
            "end_column": 2, "snippet": "x", "fix_suggestion": "use a safer API"
        }))
        .unwrap()
    }

    #[test]
    fn dedupes_by_path_line_cwe_keeping_highest() {
        let f = vec![
            finding("a", Severity::Low, Some("CWE-89"), "./src/x.py", 3),
            finding("b", Severity::High, Some("CWE-89"), "src/x.py", 3),
            finding("c", Severity::High, Some("CWE-79"), "src/x.py", 3),
        ];
        let out = build_code_insights(&f, Platform::Cloud);
        assert_eq!(out["annotations_total"], 2);
        let batch = out["annotation_batches"][0].as_array().unwrap();
        assert!(batch
            .iter()
            .any(|a| a["summary"].as_str().unwrap().contains("[b]")));
    }

    #[test]
    fn cloud_batches_and_cap() {
        let f: Vec<Finding> = (1..=1105)
            .map(|i| finding("r", Severity::Low, Some("CWE-1"), "f.py", i))
            .collect();
        let out = build_code_insights(&f, Platform::Cloud);
        let batches = out["annotation_batches"].as_array().unwrap();
        assert_eq!(batches.len(), 10);
        assert!(batches.iter().all(|b| b.as_array().unwrap().len() <= 100));
        assert_eq!(out["annotations_emitted"], 1000);
        assert_eq!(out["annotations_dropped"], 105);
    }

    #[test]
    fn cap_keeps_most_severe() {
        let mut f: Vec<Finding> = (1..=1000)
            .map(|i| finding("low", Severity::Low, Some("CWE-1"), "f.py", i))
            .collect();
        f.push(finding(
            "crit",
            Severity::Critical,
            Some("CWE-2"),
            "g.py",
            1,
        ));
        let out = build_code_insights(&f, Platform::Cloud);
        assert_eq!(out["annotation_batches"][0][0]["severity"], "CRITICAL");
    }

    #[test]
    fn empty_passes() {
        assert_eq!(
            build_code_insights(&[], Platform::Cloud)["report"]["result"],
            "PASSED"
        );
        assert_eq!(
            build_code_insights(&[], Platform::DataCenter)["report"]["result"],
            "PASS"
        );
    }
}
