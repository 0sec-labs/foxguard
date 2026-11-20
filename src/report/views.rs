//! Curated result views and cross-engine finding dedupe.
//!
//! One bug must not appear as two findings when a pattern rule and a taint
//! rule both fire on the same sink. [`dedupe_findings`] collapses findings
//! that share `(path, line, CWE)` and keeps the most informative one.
//! [`apply_views`] implements the reviewer-facing filters (production code
//! only, taint rules only).

use crate::Finding;
use clap::Args;
use std::collections::HashMap;

/// Reviewer-facing result filters shared by `scan` and `diff`.
///
/// A "new findings only" view is `foxguard diff <base>`, which already
/// reports only findings introduced relative to the base ref.
#[derive(Args, Debug, Clone, Default)]
pub struct ViewArgs {
    /// Drop findings in test, generated and vendored paths
    #[arg(long, default_value_t = false)]
    pub production_only: bool,

    /// Keep only findings from taint (source-to-sink) rules
    #[arg(long, default_value_t = false)]
    pub taint_only: bool,
}

const VENDORED_DIRS: &[&str] = &[
    "node_modules",
    "vendor",
    "third_party",
    "third-party",
    "thirdparty",
    "bower_components",
    "site-packages",
    "Pods",
    "Carthage",
    "target",
    "dist",
    "build",
    ".gradle",
];

const TEST_DIRS: &[&str] = &[
    "test",
    "tests",
    "__tests__",
    "__test__",
    "spec",
    "specs",
    "testdata",
    "fixtures",
    "e2e",
    "src/test",
];

const GENERATED_MARKERS: &[&str] = &[
    ".generated.",
    ".gen.",
    ".g.cs",
    ".designer.cs",
    ".pb.go",
    ".pb.cc",
    ".pb.h",
    "_pb2.py",
    "_pb2_grpc.py",
    ".min.js",
    "-min.js",
    ".bundle.js",
    "_generated.",
];

/// True when `path` looks like test, generated or vendored code.
pub fn is_non_production_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();
    let segments: Vec<&str> = normalized.split('/').collect();
    let dir_segments = &segments[..segments.len().saturating_sub(1)];

    if dir_segments
        .iter()
        .any(|s| VENDORED_DIRS.iter().any(|v| s.eq_ignore_ascii_case(v)))
    {
        return true;
    }
    if dir_segments.iter().any(|s| {
        TEST_DIRS
            .iter()
            .any(|t| !t.contains('/') && s.eq_ignore_ascii_case(t))
    }) || lower.contains("/src/test/")
        || lower.starts_with("src/test/")
    {
        return true;
    }
    if GENERATED_MARKERS.iter().any(|m| lower.contains(m))
        || dir_segments
            .iter()
            .any(|s| s.eq_ignore_ascii_case("generated") || s.eq_ignore_ascii_case("__generated__"))
    {
        return true;
    }
    let file = segments.last().copied().unwrap_or("");
    let stem = file.rsplit_once('.').map_or(file, |(s, _)| s);
    let stem_lower = stem.to_ascii_lowercase();
    stem_lower.ends_with("_test")
        || stem_lower.ends_with(".test")
        || stem_lower.ends_with(".spec")
        || stem_lower.ends_with("_spec")
        || stem_lower.ends_with("test") && stem.chars().next().is_some_and(|c| c.is_uppercase())
        || stem_lower.starts_with("test_")
}

/// Apply the reviewer-facing filters in place.
pub fn apply_views(findings: &mut Vec<Finding>, views: &ViewArgs) {
    if views.production_only {
        findings.retain(|f| !is_non_production_path(&f.file));
    }
    if views.taint_only {
        findings.retain(|f| f.taint_hops.is_some());
    }
}

fn normalize_cwe(cwe: &str) -> String {
    let upper = cwe.trim().to_ascii_uppercase();
    // Accept "CWE-89", "cwe-89", "CWE-89: SQL Injection" and "89".
    let head = upper.split([':', ' ']).next().unwrap_or("");
    let digits = head.trim_start_matches("CWE-").trim_start_matches("CWE");
    format!("CWE-{}", digits.trim_start_matches('-'))
}

/// Is `candidate` a better representative than `current` for the same bug?
fn prefer(candidate: &Finding, current: &Finding) -> bool {
    if candidate.severity != current.severity {
        return candidate.severity > current.severity;
    }
    // Taint findings carry a source-to-sink trace, so they explain more.
    let (c_taint, k_taint) = (candidate.taint_hops.is_some(), current.taint_hops.is_some());
    if c_taint != k_taint {
        return c_taint;
    }
    candidate.confidence > current.confidence
}

/// Collapse findings sharing `(path, line, CWE)` to one, keeping the highest
/// severity (then taint over pattern, then highest confidence). Findings
/// without a CWE are never merged. Order of first appearance is preserved.
pub fn dedupe_findings(findings: &[Finding]) -> Vec<Finding> {
    let mut index: HashMap<(String, usize, String), usize> = HashMap::new();
    let mut out: Vec<Finding> = Vec::with_capacity(findings.len());
    for f in findings {
        let Some(cwe) = f.cwe.as_deref().filter(|c| !c.trim().is_empty()) else {
            out.push(f.clone());
            continue;
        };
        let key = (f.file.replace('\\', "/"), f.line, normalize_cwe(cwe));
        match index.get(&key) {
            Some(&i) => {
                if prefer(f, &out[i]) {
                    out[i] = f.clone();
                }
            }
            None => {
                index.insert(key, out.len());
                out.push(f.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;

    fn finding(rule: &str, sev: Severity, cwe: Option<&str>, line: usize, taint: bool) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            severity: sev,
            cwe: cwe.map(str::to_string),
            description: String::new(),
            file: "src/Dao.java".to_string(),
            line,
            column: 1,
            end_line: line,
            end_column: 2,
            snippet: String::new(),
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: 1.0,
            taint_hops: taint.then_some(1),
            tags: Vec::new(),
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
    fn pattern_and_taint_on_same_sink_reported_once() {
        let f = vec![
            finding(
                "java/sql-pattern",
                Severity::High,
                Some("CWE-89"),
                10,
                false,
            ),
            finding(
                "java/sql-taint",
                Severity::Critical,
                Some("cwe-89"),
                10,
                true,
            ),
        ];
        let d = dedupe_findings(&f);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].rule_id, "java/sql-taint");
    }

    #[test]
    fn equal_severity_prefers_taint() {
        let f = vec![
            finding("pattern", Severity::High, Some("CWE-89"), 10, false),
            finding("taint", Severity::High, Some("CWE-89"), 10, true),
        ];
        assert_eq!(dedupe_findings(&f)[0].rule_id, "taint");
    }

    #[test]
    fn different_line_cwe_or_missing_cwe_kept() {
        let f = vec![
            finding("a", Severity::High, Some("CWE-89"), 10, false),
            finding("b", Severity::High, Some("CWE-89"), 11, false),
            finding("c", Severity::High, Some("CWE-78"), 10, false),
            finding("d", Severity::High, None, 10, false),
            finding("e", Severity::High, None, 10, false),
        ];
        assert_eq!(dedupe_findings(&f).len(), 5);
    }

    #[test]
    fn production_path_classification() {
        for p in [
            "src/test/java/FooTest.java",
            "app/tests/a.py",
            "node_modules/x/index.js",
            "vendor/lib/a.go",
            "gen/api.pb.go",
            "web/app.min.js",
            "src/foo_test.go",
            "src/generated/Model.java",
        ] {
            assert!(is_non_production_path(p), "{p}");
        }
        for p in [
            "src/main/java/Dao.java",
            "app/handler.py",
            "lib/contest.rs",
            "src/latest.go",
        ] {
            assert!(!is_non_production_path(p), "{p}");
        }
    }

    #[test]
    fn views_filter() {
        let mut f = vec![
            finding("a", Severity::High, Some("CWE-89"), 1, true),
            finding("b", Severity::High, Some("CWE-89"), 2, false),
        ];
        f[0].file = "src/test/A.java".into();
        let mut x = f.clone();
        apply_views(
            &mut x,
            &ViewArgs {
                production_only: true,
                taint_only: false,
            },
        );
        assert_eq!(x.len(), 1);
        let mut y = f.clone();
        apply_views(
            &mut y,
            &ViewArgs {
                production_only: false,
                taint_only: true,
            },
        );
        assert_eq!(y.len(), 1);
        assert_eq!(y[0].rule_id, "a");
    }
}
