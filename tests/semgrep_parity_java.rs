//! Java Semgrep parity micro-pattern suite.
//!
//! Mirrors the structure of `tests/semgrep_parity.rs` (Python) but uses
//! Java-native sinks (`Runtime.getRuntime().exec`, `String.format`) and
//! rule syntax. Each test runs both foxguard and `semgrep` against the
//! same temp directory + YAML rule and asserts byte-identical normalized
//! findings. Tests are skipped gracefully when `semgrep` is not on PATH
//! so the suite remains green in restricted environments.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct NormalizedFinding {
    path: String,
    line: u64,
    message: String,
}

fn foxguard_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_foxguard"))
}

fn semgrep_bin() -> String {
    std::env::var("SEMGREP_BIN").unwrap_or_else(|_| "semgrep".to_string())
}

fn semgrep_available() -> bool {
    Command::new(semgrep_bin())
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn write_file(dir: &Path, relative_path: &str, content: &str) -> PathBuf {
    let path = dir.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("failed to create test directory");
    }
    fs::write(&path, content).expect("failed to write test file");
    path
}

fn normalize_path(path: &str, repo: &Path) -> String {
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

fn parse_foxguard_findings(output: &[u8], repo: &Path) -> Vec<NormalizedFinding> {
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

fn parse_semgrep_findings(output: &[u8], repo: &Path) -> Vec<NormalizedFinding> {
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

fn foxguard_findings(repo: &Path, rules_path: &Path, scan_target: &str) -> Vec<NormalizedFinding> {
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

fn semgrep_findings(repo: &Path, rules_path: &Path, scan_target: &str) -> Vec<NormalizedFinding> {
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

fn assert_parity(repo: &Path, rules_path: &Path, scan_target: &str) {
    let foxguard = foxguard_findings(repo, rules_path, scan_target);
    let semgrep = semgrep_findings(repo, rules_path, scan_target);

    assert_eq!(foxguard, semgrep, "foxguard and semgrep results diverged");
}

fn skip_if_semgrep_missing() -> bool {
    if semgrep_available() {
        return false;
    }

    eprintln!("semgrep not installed; skipping parity test");
    true
}

#[test]
fn test_parity_pattern_either() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/exec.yaml",
        r#"
rules:
  - id: dangerous-java-sink
    pattern-either:
      - pattern: Runtime.getRuntime().exec(...)
      - pattern: String.format(...)
    message: dangerous java call
    severity: ERROR
    languages: [java]
"#,
    );
    write_file(
        repo.path(),
        "A.java",
        "public class A {\n    public static void main(String[] args) {\n        Runtime.getRuntime().exec(\"ls\");\n        String.format(\"%s\", args[0]);\n        System.out.println(\"safe\");\n    }\n}\n",
    );

    assert_parity(repo.path(), &rules, "A.java");
}

#[test]
fn test_parity_binary_operator_and_metavariable_regex() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/format.yaml",
        r#"
rules:
  - id: tainted-format
    patterns:
      - pattern: String.format($FMT, $VAR)
      - metavariable-regex:
          metavariable: $VAR
          regex: ^userInput$
    message: tainted format call
    severity: ERROR
    languages: [java]
"#,
    );
    write_file(
        repo.path(),
        "A.java",
        "public class A {\n    void m() {\n        String.format(\"%s\", userInput);\n        String.format(\"%s\", safeValue);\n    }\n}\n",
    );

    assert_parity(repo.path(), &rules, "A.java");
}

#[test]
fn test_parity_pattern_inside() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/inside.yaml",
        r#"
rules:
  - id: exec-in-handle
    patterns:
      - pattern: Runtime.getRuntime().exec(...)
      - pattern-inside: |
          void handle(...) {
            ...
          }
    message: exec inside handle()
    severity: ERROR
    languages: [java]
"#,
    );
    write_file(
        repo.path(),
        "A.java",
        "public class A {\n    void handle(String args) {\n        Runtime.getRuntime().exec(args);\n    }\n    void helper(String args) {\n        Runtime.getRuntime().exec(args);\n    }\n}\n",
    );

    assert_parity(repo.path(), &rules, "A.java");
}

#[test]
fn test_parity_pattern_not_inside() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/not-inside.yaml",
        r#"
rules:
  - id: exec-outside-helper
    patterns:
      - pattern: Runtime.getRuntime().exec(...)
      - pattern-not-inside: |
          void safeExec(...) {
            ...
          }
    message: exec outside safeExec()
    severity: WARNING
    languages: [java]
"#,
    );
    write_file(
        repo.path(),
        "A.java",
        "public class A {\n    void safeExec(String args) {\n        Runtime.getRuntime().exec(args);\n    }\n    void doExec(String args) {\n        Runtime.getRuntime().exec(args);\n    }\n}\n",
    );

    assert_parity(repo.path(), &rules, "A.java");
}

#[test]
fn test_parity_pattern_regex_and_not_regex() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/regex.yaml",
        r#"
rules:
  - id: secret-field
    pattern-regex: '(?m)^\s*(String|final\s+String)\s+(password|secret)\s*='
    pattern-not-regex: '(?m)^\s*String\s+not_password\s*='
    message: secret field assignment
    severity: ERROR
    languages: [java]
"#,
    );
    write_file(
        repo.path(),
        "A.java",
        "public class A {\n    String password = \"secret\";\n    String not_password = \"safe\";\n    final String secret = \"abc\";\n}\n",
    );

    assert_parity(repo.path(), &rules, "A.java");
}

#[test]
fn test_parity_paths_include_exclude() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/paths.yaml",
        r#"
rules:
  - id: path-scoped-exec
    pattern: Runtime.getRuntime().exec(...)
    message: exec in app source
    severity: ERROR
    languages: [java]
    paths:
      include:
        - src/**/*.java
      exclude:
        - src/generated/**
"#,
    );
    write_file(
        repo.path(),
        "src/app/Main.java",
        "public class Main { static { Runtime.getRuntime().exec(\"ls\"); } }\n",
    );
    write_file(
        repo.path(),
        "src/generated/Gen.java",
        "public class Gen { static { Runtime.getRuntime().exec(\"ls\"); } }\n",
    );
    write_file(
        repo.path(),
        "tests/T.java",
        "public class T { static { Runtime.getRuntime().exec(\"ls\"); } }\n",
    );

    assert_parity(repo.path(), &rules, ".");
}
