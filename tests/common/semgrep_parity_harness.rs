//! Shared test harness for the Semgrep parity suites.
//!
//! Provides command building, output parsing, finding normalization,
//! skip logic, and the `assert_parity` entry point used by every
//! language-specific parity test file (`semgrep_parity*.rs`).
//!
//! Extracted from the formerly-duplicated per-language harnesses
//! (issue #408).

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// ── Normalized finding ───────────────────────────────────────────────

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct NormalizedFinding {
    pub path: String,
    pub line: u64,
    pub message: String,
}

// ── Helpers ──────────────────────────────────────────────────────────

pub fn foxguard_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_foxguard"))
}

pub fn semgrep_bin() -> String {
    std::env::var("SEMGREP_BIN").unwrap_or_else(|_| "semgrep".to_string())
}

pub fn semgrep_available() -> bool {
    Command::new(semgrep_bin())
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub fn write_file(dir: &Path, relative_path: &str, content: &str) -> PathBuf {
    let path = dir.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("failed to create test directory");
    }
    fs::write(&path, content).expect("failed to write test file");
    path
}

pub fn normalize_path(path: &str, repo: &Path) -> String {
    let candidate = Path::new(path);
    let normalized = candidate
        .strip_prefix(repo)
        .unwrap_or(candidate)
        .to_string_lossy()
        .replace('\\', "/");

    normalized
        .strip_prefix("./")
        .unwrap_or(&normalized)
        .to_string()
}

/// Returns `true` (and prints a skip message) when `semgrep` is not
/// installed, so callers can `return` early from individual `#[test]`
/// functions.
pub fn skip_if_semgrep_missing() -> bool {
    if semgrep_available() {
        return false;
    }

    eprintln!("semgrep not installed; skipping parity test");
    true
}

// ── Parsing ──────────────────────────────────────────────────────────

pub fn parse_foxguard_findings(output: &[u8], repo: &Path) -> Vec<NormalizedFinding> {
    let report: Value = serde_json::from_slice(output).expect("invalid foxguard JSON output");
    let findings = report["findings"]
        .as_array()
        .cloned()
        .expect("foxguard JSON report missing findings array");
    let mut normalized = findings
        .into_iter()
        .map(|finding| NormalizedFinding {
            path: normalize_path(
                finding["file"]
                    .as_str()
                    .expect("foxguard finding missing file"),
                repo,
            ),
            line: finding["line"]
                .as_u64()
                .expect("foxguard finding missing line"),
            message: finding["description"]
                .as_str()
                .expect("foxguard finding missing description")
                .to_string(),
        })
        .collect::<Vec<_>>();
    normalized.sort();
    normalized
}

pub fn parse_semgrep_findings(output: &[u8], repo: &Path) -> Vec<NormalizedFinding> {
    let payload: Value = serde_json::from_slice(output).expect("invalid semgrep JSON output");
    let results = payload["results"]
        .as_array()
        .expect("semgrep output missing results");

    let mut normalized = results
        .iter()
        .map(|finding| NormalizedFinding {
            path: normalize_path(
                finding["path"]
                    .as_str()
                    .expect("semgrep finding missing path"),
                repo,
            ),
            line: finding["start"]["line"]
                .as_u64()
                .expect("semgrep finding missing start line"),
            message: finding["extra"]["message"]
                .as_str()
                .expect("semgrep finding missing message")
                .to_string(),
        })
        .collect::<Vec<_>>();
    normalized.sort();
    normalized
}

// ── Command wrappers ─────────────────────────────────────────────────

pub fn foxguard_findings(
    repo: &Path,
    rules_path: &Path,
    scan_target: &str,
) -> Vec<NormalizedFinding> {
    let output = foxguard_cmd()
        .current_dir(repo)
        .args([
            "--no-builtins",
            "--rules",
            rules_path.to_str().expect("non-utf8 rules path"),
            scan_target,
            "-f",
            "json",
        ])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        output.status.success() || !output.stdout.is_empty(),
        "foxguard failed without JSON output: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    parse_foxguard_findings(&output.stdout, repo)
}

pub fn semgrep_findings(
    repo: &Path,
    rules_path: &Path,
    scan_target: &str,
) -> Vec<NormalizedFinding> {
    let output = Command::new(semgrep_bin())
        .current_dir(repo)
        .args([
            "--config",
            rules_path.to_str().expect("non-utf8 rules path"),
            "--json",
            "--quiet",
            scan_target,
        ])
        .output()
        .expect("failed to execute semgrep");

    assert!(
        output.status.success(),
        "semgrep failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    parse_semgrep_findings(&output.stdout, repo)
}

// ── Parity assertion ─────────────────────────────────────────────────

pub fn assert_parity(repo: &Path, rules_path: &Path, scan_target: &str) {
    let foxguard = foxguard_findings(repo, rules_path, scan_target);
    let semgrep = semgrep_findings(repo, rules_path, scan_target);

    assert_eq!(foxguard, semgrep, "foxguard and semgrep results diverged");
}
