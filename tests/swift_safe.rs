// Safe-fixture integration test for the Swift built-in rules (Refs #462).
//
// Swift previously had NO safe-fixture integration test, so false positives
// in the Swift rules could regress silently. This test runs foxguard on the
// benign `tests/fixtures/safe.swift` corpus and asserts ZERO findings.
//
// The fixture exercises the const-folding paths added to the
// command-injection, eval-js, path-traversal, and SSRF rules: `Process()`
// with a `let`-bound launch path, `URL(string:)` / FileManager /
// `evaluateJavaScript` with `let`-bound string-literal constants. None of
// these are user-controlled, so none must flag.
//
// The harness mirrors `tests/realistic_fixtures.rs`: `--config /dev/null`
// isolates the run from any developer-local `.foxguard.yml` baseline.

use std::path::{Path, PathBuf};
use std::process::Command;

fn foxguard_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_foxguard"));
    cmd.args(["--config", "/dev/null"]);
    cmd
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn scan_json_findings(stdout: &[u8], file: &str) -> Vec<serde_json::Value> {
    let report: serde_json::Value = serde_json::from_slice(stdout)
        .unwrap_or_else(|e| panic!("invalid JSON output for {}: {}", file, e));
    report["findings"]
        .as_array()
        .cloned()
        .expect("JSON report missing findings array")
}

#[test]
fn swift_safe_fixture_has_zero_findings() {
    let path = fixture_path("safe.swift");
    let output = foxguard_cmd()
        .args([path.to_str().unwrap(), "-f", "json"])
        .output()
        .expect("failed to run foxguard on safe.swift");

    let findings = scan_json_findings(&output.stdout, "safe.swift");

    assert!(
        findings.is_empty(),
        "safe.swift expected ZERO findings, got {}: {:?}",
        findings.len(),
        findings
            .iter()
            .map(|f| format!(
                "{}@{}",
                f["rule_id"].as_str().unwrap_or(""),
                f["line"].as_u64().unwrap_or(0)
            ))
            .collect::<Vec<_>>()
    );
}
