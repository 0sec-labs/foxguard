//! Go Semgrep parity micro-pattern suite.
//!
//! Mirrors the structure of `tests/semgrep_parity.rs` (Python) but uses
//! Go-native sinks (`exec.Command`, `os.Exec`) and rule syntax. Each test
//! runs both foxguard and `semgrep` against the same temp directory + YAML
//! rule and asserts byte-identical normalized findings. Tests are skipped
//! gracefully when `semgrep` is not on PATH so the suite remains green in
//! restricted environments.
//!
//! ## Go-specific caveat (resolved by #390)
//!
//! tree-sitter-go rejects Semgrep micro-syntax (`$X`, `...`) because Go
//! requires parser-valid identifiers/arguments and a `package` clause
//! before declarations. foxguard rewrites those Semgrep tokens to internal
//! Go-valid placeholders before AST matching, so all six micro-patterns
//! parity-test cleanly against Go.

mod common;

use common::semgrep_parity_harness::{assert_parity, skip_if_semgrep_missing, write_file};
use tempfile::TempDir;

#[test]
fn test_parity_pattern_either() {
    if skip_if_semgrep_missing() {
        return;
    }

    // `pattern-either` of regex sub-patterns is language-agnostic in
    // foxguard and matches Semgrep on Go.
    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/exec.yaml",
        r#"
rules:
  - id: dangerous-go-sink
    pattern-either:
      - pattern-regex: 'exec\.Command\('
      - pattern-regex: 'os\.Exec\('
    message: dangerous go call
    severity: ERROR
    languages: [go]
"#,
    );
    write_file(
        repo.path(),
        "app.go",
        "package main\n\nimport \"os/exec\"\n\nfunc main() {\n    exec.Command(\"ls\")\n    safe()\n}\n\nfunc safe() {}\n",
    );

    assert_parity(repo.path(), &rules, "app.go");
}

#[test]
fn test_parity_binary_operator_and_metavariable_regex() {
    if skip_if_semgrep_missing() {
        return;
    }

    // `metavariable-regex` requires foxguard to AST-bind `$VAR`. For Go,
    // foxguard rewrites Semgrep metavariables to parser-valid placeholders
    // and binds them back to their original `$VAR` names (see #390).
    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/tainted-exec.yaml",
        r#"
rules:
  - id: tainted-exec-call
    patterns:
      - pattern: exec.Command($VAR)
      - metavariable-regex:
          metavariable: $VAR
          regex: ^userInput$
    message: tainted exec call
    severity: ERROR
    languages: [go]
"#,
    );
    write_file(
        repo.path(),
        "app.go",
        "package main\n\nimport \"os/exec\"\n\nfunc main() {\n    exec.Command(userInput)\n    exec.Command(\"ls\")\n}\n",
    );

    assert_parity(repo.path(), &rules, "app.go");
}

#[test]
fn test_parity_pattern_inside() {
    if skip_if_semgrep_missing() {
        return;
    }

    // `pattern-inside` requires foxguard to AST-match the enclosing Go
    // function declaration; foxguard rewrites Semgrep ellipses to internal
    // placeholders before parsing (see #390) so the inside filter applies.
    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/inside.yaml",
        r#"
rules:
  - id: exec-in-handle
    patterns:
      - pattern: exec.Command(...)
      - pattern-inside: |
          func handle(...) {
            ...
          }
    message: exec inside handle()
    severity: ERROR
    languages: [go]
"#,
    );
    write_file(
        repo.path(),
        "app.go",
        "package main\n\nimport \"os/exec\"\n\nfunc handle(s string) {\n    exec.Command(s)\n}\n\nfunc helper(s string) {\n    exec.Command(s)\n}\n",
    );

    assert_parity(repo.path(), &rules, "app.go");
}

#[test]
fn test_parity_pattern_not_inside() {
    if skip_if_semgrep_missing() {
        return;
    }

    // `pattern-not-inside` has the same AST-matching constraint as
    // `pattern-inside`; resolved by the Go placeholder rewrite in #390.
    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/not-inside.yaml",
        r#"
rules:
  - id: exec-outside-helper
    patterns:
      - pattern: exec.Command(...)
      - pattern-not-inside: |
          func safeExec(...) {
            ...
          }
    message: exec outside safeExec()
    severity: WARNING
    languages: [go]
"#,
    );
    write_file(
        repo.path(),
        "app.go",
        "package main\n\nimport \"os/exec\"\n\nfunc safeExec(s string) {\n    exec.Command(s)\n}\n\nfunc doExec(s string) {\n    exec.Command(s)\n}\n",
    );

    assert_parity(repo.path(), &rules, "app.go");
}

#[test]
fn test_parity_pattern_regex_and_not_regex() {
    if skip_if_semgrep_missing() {
        return;
    }

    // Pure regex; language-agnostic in foxguard, matches Semgrep on Go.
    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/regex.yaml",
        r#"
rules:
  - id: secret-assignment
    pattern-regex: '(?m)^\s*(password|secret)\s*:?='
    pattern-not-regex: '(?m)^\s*not_password\s*:?='
    message: secret assignment
    severity: ERROR
    languages: [go]
"#,
    );
    write_file(
        repo.path(),
        "app.go",
        "package main\n\nvar password = \"secret\"\nvar not_password = \"safe\"\nvar secret = \"abc\"\n",
    );

    assert_parity(repo.path(), &rules, "app.go");
}

#[test]
fn test_parity_paths_include_exclude() {
    if skip_if_semgrep_missing() {
        return;
    }

    // Uses `pattern-regex` for the positive (avoids the Go-AST limitation)
    // so that `paths.include`/`paths.exclude` scoping is the variable under
    // test. Both tools see the same regex hits and apply identical path
    // filters.
    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/paths.yaml",
        r#"
rules:
  - id: path-scoped-exec
    pattern-regex: 'exec\.Command\('
    message: exec in app source
    severity: ERROR
    languages: [go]
    paths:
      include:
        - src/**/*.go
      exclude:
        - src/generated/**
"#,
    );
    write_file(
        repo.path(),
        "src/app/main.go",
        "package main\nimport \"os/exec\"\nfunc main() { exec.Command(\"ls\") }\n",
    );
    write_file(
        repo.path(),
        "src/generated/main.go",
        "package main\nimport \"os/exec\"\nfunc main() { exec.Command(\"ls\") }\n",
    );
    write_file(
        repo.path(),
        "tests/main.go",
        "package main\nimport \"os/exec\"\nfunc main() { exec.Command(\"ls\") }\n",
    );

    assert_parity(repo.path(), &rules, ".");
}
