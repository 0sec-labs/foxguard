// Integration test for the realistic test corpus (issue #35).
//
// Each fixture under `tests/fixtures/realistic/` is a small-but-complete
// vulnerable application for one supported framework. We pin the exact
// total finding count and the exact count per taint rule. Any rule
// addition or engine change will break these counts, which is the whole
// point: it forces explicit acknowledgment of precision shifts.
//
// The fixtures also contain NEAR-MISS functions whose line ranges must
// not contain any `*/taint-*` findings. We check that indirectly by
// pinning the total taint-finding count per file — if a NEAR-MISS
// function started firing, the total would change.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn foxguard_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_foxguard"))
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("realistic")
        .join(name)
}

/// Scan a realistic fixture and assert exact total finding count and
/// exact per-taint-rule counts. `taint_counts` lists every taint rule
/// that must fire, with the expected count. Any taint rule observed in
/// the output that is not in `taint_counts` (or with a different count)
/// fails the test — this catches accidental false positives on the
/// NEAR-MISS sections.
fn assert_fixture(file: &str, expected_total: usize, taint_counts: &[(&str, usize)]) {
    let path = fixture_path(file);
    let output = foxguard_cmd()
        .args([path.to_str().unwrap(), "-f", "json"])
        .output()
        .unwrap_or_else(|e| panic!("failed to run foxguard on {}: {}", file, e));

    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("invalid JSON output for {}: {}", file, e));

    assert_eq!(
        findings.len(),
        expected_total,
        "{}: expected {} total findings, got {}. findings={:?}",
        file,
        expected_total,
        findings.len(),
        findings
            .iter()
            .map(|f| f["rule_id"].as_str().unwrap_or(""))
            .collect::<Vec<_>>()
    );

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for f in &findings {
        if let Some(rule) = f["rule_id"].as_str() {
            *counts.entry(rule).or_insert(0) += 1;
        }
    }

    // Every expected taint rule must fire exactly the expected number
    // of times.
    for (rule, want) in taint_counts {
        let got = counts.get(rule).copied().unwrap_or(0);
        assert_eq!(
            got, *want,
            "{}: taint rule {} expected {} times, got {}. counts={:?}",
            file, rule, want, got, counts
        );
    }

    // Any taint finding for a rule NOT in `taint_counts` is an
    // unexpected false positive — likely on the NEAR-MISS section.
    let expected_rules: std::collections::HashSet<&str> =
        taint_counts.iter().map(|(r, _)| *r).collect();
    for (rule, count) in &counts {
        if rule.contains("/taint-") && !expected_rules.contains(rule) {
            panic!(
                "{}: unexpected taint rule {} fired {} times (likely NEAR-MISS false positive). counts={:?}",
                file, rule, count, counts
            );
        }
    }
}

#[test]
fn realistic_flask_app() {
    assert_fixture(
        "flask_app.py",
        14,
        &[
            ("py/taint-pickle-deserialization", 1),
            ("py/taint-eval", 1),
            ("py/taint-command-injection", 2),
            ("py/taint-ssrf", 1),
            ("py/taint-yaml-load", 1),
            ("py/taint-sql-injection", 1),
        ],
    );
}

#[test]
fn realistic_django_views() {
    assert_fixture(
        "django_views.py",
        9,
        &[
            ("py/taint-command-injection", 2),
            ("py/taint-sql-injection", 1),
            ("py/taint-ssrf", 1),
            ("py/taint-pickle-deserialization", 1),
        ],
    );
}

#[test]
fn realistic_fastapi_app() {
    assert_fixture(
        "fastapi_app.py",
        8,
        &[
            ("py/taint-eval", 1),
            ("py/taint-pickle-deserialization", 1),
            ("py/taint-ssrf", 1),
        ],
    );
}

#[test]
fn realistic_cli_tool() {
    assert_fixture(
        "cli_tool.py",
        9,
        &[("py/taint-command-injection", 2), ("py/taint-eval", 2)],
    );
}

#[test]
fn realistic_express_app() {
    assert_fixture("express_app.js", 12, &[("js/taint-xss-innerhtml", 5)]);
}

#[test]
fn realistic_nextjs_handlers() {
    assert_fixture("nextjs_handlers.ts", 7, &[("js/taint-xss-innerhtml", 3)]);
}

#[test]
fn realistic_hono_app() {
    assert_fixture("hono_app.ts", 7, &[("js/taint-xss-innerhtml", 3)]);
}
