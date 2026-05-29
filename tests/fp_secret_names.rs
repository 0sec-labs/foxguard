//! False-positive regression test for the shared hardcoded-secret matcher
//! (`src/rules/common.rs`).
//!
//! The base secret-name regex used to match a keyword as a *substring* of a
//! larger identifier (`author` → `auth`, `tokenizer` → `token`,
//! `passwordField` → `password`) and would flag low-signal names whose value
//! was clearly not a secret (env-sourced lookups). After adding identifier-
//! component word boundaries to the regex and value-gating low-signal names,
//! the benign fixtures below must produce ZERO findings.
//!
//! Each fixture under `tests/fixtures/safe_secret_names.*` contains only
//! benign code: secret-ish NAMES bound to non-secret values (URLs, paths,
//! env lookups) or names that merely contain a keyword substring.
//!
//! This complements the positive coverage in `integration.rs` /
//! `semgrep_parity*`, which prove genuine hardcoded secrets are still flagged.

use std::path::{Path, PathBuf};
use std::process::Command;

fn foxguard_cmd() -> Command {
    // `--config /dev/null` isolates the test from any developer-local
    // `.foxguard.yml`, matching the convention in `realistic_fixtures.rs`.
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

/// Scan a single fixture and assert it produces no findings at all.
fn assert_no_findings(fixture: &str) {
    let path = fixture_path(fixture);
    let output = foxguard_cmd()
        .args([path.to_str().unwrap(), "-f", "json"])
        .output()
        .unwrap_or_else(|e| panic!("failed to run foxguard on {fixture}: {e}"));

    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("invalid JSON output for {fixture}: {e}"));
    let findings = report["findings"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("JSON report for {fixture} missing findings array"));

    assert!(
        findings.is_empty(),
        "{fixture}: expected ZERO findings, got {}: {:?}",
        findings.len(),
        findings
            .iter()
            .map(|f| (
                f["rule_id"].as_str().unwrap_or(""),
                f["line"].as_u64().unwrap_or(0)
            ))
            .collect::<Vec<_>>()
    );
}

macro_rules! fp_fixture_test {
    ($name:ident, $fixture:expr) => {
        #[test]
        fn $name() {
            assert_no_findings($fixture);
        }
    };
}

fp_fixture_test!(no_fp_secret_names_python, "safe_secret_names.py");
fp_fixture_test!(no_fp_secret_names_go, "safe_secret_names.go");
fp_fixture_test!(no_fp_secret_names_java, "safe_secret_names.java");
fp_fixture_test!(no_fp_secret_names_csharp, "safe_secret_names.cs");
fp_fixture_test!(no_fp_secret_names_php, "safe_secret_names.php");
fp_fixture_test!(no_fp_secret_names_kotlin, "safe_secret_names.kt");
fp_fixture_test!(no_fp_secret_names_javascript, "safe_secret_names.js");
fp_fixture_test!(no_fp_secret_names_ruby, "safe_secret_names.rb");
