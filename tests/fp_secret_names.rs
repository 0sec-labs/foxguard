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

fn javascript_secret_lines(source: &str, filename: &str) -> Vec<u64> {
    let directory = tempfile::tempdir().expect("create source directory");
    let path = directory.path().join(filename);
    std::fs::write(&path, source).expect("write source");
    let output = foxguard_cmd()
        .arg(&path)
        .args(["--format", "json"])
        .output()
        .expect("run scanner");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("scanner must return JSON");
    report["findings"].as_array().expect("findings array").iter()
        .filter(|finding| finding["rule_id"] == "js/no-hardcoded-secret")
        .map(|finding| finding["line"].as_u64().expect("finding line"))
        .collect()
}

#[test]
fn typescript_metadata_has_the_same_noncredential_proof() {
    let source = include_str!("fixtures/safe_secret_names.js")
        .replace("providerForModel(model)", "providerForModel(model: string)");
    assert_eq!(javascript_secret_lines(&source, "metadata.ts"), Vec::<u64>::new());
}

#[test]
fn test_files_and_metadata_names_do_not_hide_credentials() {
    let source = [
        r#"const secret = "sk-live-K9xP2mV7qR4tN8wA6zY3";"#,
        r#"const REDACTED_SECRET = "sk-live-K9xP2mV7qR4tN8wA6zY3";"#,
        r#"const PASSWORD_MODEL = "correct horse battery staple";"#,
        r#"const TOKEN_MODEL = "vendor-v4-0731";"#,
        r#"const CREDENTIAL_NAME = "secret|token"; sendCredential(CREDENTIAL_NAME);"#,
        r#"process.env.DEEPSEEK_API_KEY = "ds-key";"#,
        r#"process.env.API_KEY = "<REDACTED-SECRET>";"#,
    ].join("\n");
    for filename in ["credentials.js", "credentials.test.ts"] {
        assert_eq!(javascript_secret_lines(&source, filename), vec![1, 2, 3, 4, 5, 6, 7]);
    }
}

#[test]
fn regex_metadata_must_not_have_credential_consumers() {
    let source = r#"const CREDENTIAL_NAME = "password|secret";
const matcher = new RegExp(CREDENTIAL_NAME);
sendCredential({ CREDENTIAL_NAME });"#;
    assert_eq!(javascript_secret_lines(source, "mixed.ts"), vec![1]);
}

#[test]
fn shadowed_regexp_is_not_a_metadata_consumer() {
    let source = r#"function consume(RegExp) {
  const CREDENTIAL_NAME = "password|secret";
  return new RegExp(CREDENTIAL_NAME);
}"#;
    assert_eq!(javascript_secret_lines(source, "shadowed.ts"), vec![2]);
}

#[test]
fn mutated_model_parameter_does_not_prove_model_metadata() {
    let source = r#"const TOKEN_MODEL = "vendor-v4-0731";
function route(model) {
  model = process.env.PASSWORD;
  return model === TOKEN_MODEL;
}"#;
    assert_eq!(javascript_secret_lines(source, "mutated.ts"), vec![1]);
}
