#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn foxguard_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_foxguard"))
}

fn fixture_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("coccinelle")
        .join(relative)
}

fn write_fake_spatch(dir: &Path, hunk_line: usize) -> PathBuf {
    let path = dir.join("spatch");
    let script = format!(
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "spatch version fake"
  exit 0
fi
last=""
while [ "$#" -gt 0 ]; do
  last="$1"
  shift
done
echo "--- $last"
echo "+++ /tmp/cocci-output"
echo "@@ -{hunk_line},7 +{hunk_line},7 @@"
exit 0
"#
    );
    fs::write(&path, script).expect("failed to write fake spatch");

    let mut perms = fs::metadata(&path)
        .expect("failed to stat fake spatch")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).expect("failed to chmod fake spatch");
    path
}

fn repo_with_c_fixture() -> TempDir {
    let repo = TempDir::new().expect("failed to create temp repo");
    fs::copy(
        fixture_path("dirty_frag_vulnerable.c"),
        repo.path().join("vulnerable.c"),
    )
    .expect("failed to copy C fixture");
    repo
}

fn json_findings(stdout: &[u8]) -> Vec<serde_json::Value> {
    let report: serde_json::Value = serde_json::from_slice(stdout).expect("invalid JSON output");
    report["findings"]
        .as_array()
        .expect("JSON report should include findings array")
        .clone()
}

#[test]
fn coccinelle_rule_runs_via_spatch_and_normalizes_json() {
    let repo = repo_with_c_fixture();
    let fake_spatch = write_fake_spatch(repo.path(), 11);
    let rules = fixture_path("dirty-frag-rules.yml");

    let output = foxguard_cmd()
        .current_dir(repo.path())
        .env(
            "PATH",
            fake_spatch
                .parent()
                .expect("fake spatch should have a parent"),
        )
        .args([
            ".",
            "-f",
            "json",
            "--no-builtins",
            "--rules",
            rules.to_str().expect("rules path is UTF-8"),
        ])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        !output.status.success(),
        "findings should make foxguard exit non-zero"
    );

    let findings = json_findings(&output.stdout);
    assert_eq!(findings.len(), 1, "expected one Coccinelle finding");

    let finding = &findings[0];
    assert_eq!(
        finding["rule_id"].as_str(),
        Some("kernel/dirty-frag-inplace-crypto-no-cow")
    );
    assert_eq!(finding["severity"].as_str(), Some("high"));
    assert_eq!(finding["cwe"].as_str(), Some("CWE-362"));
    assert_eq!(finding["line"].as_u64(), Some(11));
    assert_eq!(finding["column"].as_u64(), Some(1));
    assert!(
        finding["file"]
            .as_str()
            .unwrap_or_default()
            .ends_with("vulnerable.c"),
        "unexpected file field: {:?}",
        finding["file"]
    );
    assert!(finding["snippet"]
        .as_str()
        .unwrap_or_default()
        .contains("crypto_aead_decrypt"));
}

#[test]
fn missing_spatch_skips_coccinelle_once_without_failing_scan() {
    let repo = repo_with_c_fixture();
    let rules = fixture_path("dirty-frag-rules.yml");

    let output = foxguard_cmd()
        .current_dir(repo.path())
        .env("PATH", repo.path())
        .args([
            ".",
            "-f",
            "json",
            "--no-builtins",
            "--rules",
            rules.to_str().expect("rules path is UTF-8"),
        ])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        output.status.success(),
        "missing spatch should skip Coccinelle rules, not fail the scan"
    );

    let findings = json_findings(&output.stdout);
    assert!(
        findings.is_empty(),
        "missing spatch should emit no findings"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("spatch not found"),
        "expected missing spatch warning, got: {stderr}"
    );
    assert_eq!(
        stderr.matches("Coccinelle engine skipped").count(),
        1,
        "expected a single missing dependency warning, got: {stderr}"
    );
}
