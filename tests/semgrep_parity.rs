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
        "rules/eval.yaml",
        r#"
rules:
  - id: eval-usage
    pattern-either:
      - pattern: eval(...)
      - pattern: exec(...)
    message: eval or exec usage
    severity: ERROR
    languages: [python]
"#,
    );
    write_file(
        repo.path(),
        "app.py",
        "eval(user_input)\nexec(\"print(1)\")\nprint(\"safe\")\n",
    );

    assert_parity(repo.path(), &rules, "app.py");
}

#[test]
fn test_parity_binary_operator_and_metavariable_regex() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/query.yaml",
        r#"
rules:
  - id: tainted-string-concat
    patterns:
      - pattern: '"..." + $VAR'
      - metavariable-regex:
          metavariable: $VAR
          regex: ^user_input$
    message: tainted string concatenation
    severity: ERROR
    languages: [python]
"#,
    );
    write_file(
        repo.path(),
        "app.py",
        "query = \"SELECT \" + user_input\nquery2 = \"SELECT \" + safe_value\nquery3 = \"SELECT %s\" % user_input\n",
    );

    assert_parity(repo.path(), &rules, "app.py");
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
  - id: eval-in-handler
    patterns:
      - pattern: eval(...)
      - pattern-inside: |
          def handler(...):
            ...
    message: eval in handler
    severity: ERROR
    languages: [python]
"#,
    );
    write_file(
        repo.path(),
        "app.py",
        "def handler(user_input):\n    eval(user_input)\n\ndef helper(user_input):\n    eval(user_input)\n",
    );

    assert_parity(repo.path(), &rules, "app.py");
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
  - id: redirect-outside-helper
    patterns:
      - pattern: redirect(...)
      - pattern-not-inside: |
          def safe_redirect(...):
            ...
    message: redirect outside helper
    severity: WARNING
    languages: [python]
"#,
    );
    write_file(
        repo.path(),
        "app.py",
        "def safe_redirect(url):\n    return redirect(url)\n\ndef do_redirect(url):\n    return redirect(url)\n",
    );

    assert_parity(repo.path(), &rules, "app.py");
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
  - id: secret-assignment
    pattern-regex: '(?m)^(password|secret)\s*='
    pattern-not-regex: '(?m)^not_password\s*='
    message: secret assignment
    severity: ERROR
    languages: [python]
"#,
    );
    write_file(
        repo.path(),
        "app.py",
        "password = \"secret\"\nnot_password = \"safe\"\nsecret = \"abc\"\n",
    );

    assert_parity(repo.path(), &rules, "app.py");
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
  - id: path-scoped-eval
    pattern: eval(...)
    message: eval in app source
    severity: ERROR
    languages: [python]
    paths:
      include:
        - src/**/*.py
      exclude:
        - src/generated/**
"#,
    );
    write_file(repo.path(), "src/app/main.py", "eval(user_input)\n");
    write_file(repo.path(), "src/generated/main.py", "eval(user_input)\n");
    write_file(repo.path(), "tests/main.py", "eval(user_input)\n");

    assert_parity(repo.path(), &rules, ".");
}
