//! JavaScript Semgrep parity micro-pattern suite.
//!
//! Mirrors the structure of `tests/semgrep_parity.rs` (Python) but uses
//! JavaScript-native sinks (`eval`, `document.write`, `child_process.exec`)
//! and rule syntax. Each test runs both foxguard and `semgrep` against the
//! same temp directory + YAML rule and asserts byte-identical normalized
//! findings. Tests are skipped gracefully when `semgrep` is not on PATH so
//! the suite remains green in restricted environments.

mod common;

use common::semgrep_parity_harness::{assert_parity, skip_if_semgrep_missing, write_file};
use tempfile::TempDir;

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
  - id: dangerous-js-sink
    pattern-either:
      - pattern: eval(...)
      - pattern: document.write(...)
    message: eval or document.write usage
    severity: ERROR
    languages: [javascript]
"#,
    );
    write_file(
        repo.path(),
        "app.js",
        "eval(userInput);\ndocument.write(payload);\nconsole.log(\"safe\");\n",
    );

    assert_parity(repo.path(), &rules, "app.js");
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
          regex: ^userInput$
    message: tainted string concatenation
    severity: ERROR
    languages: [javascript]
"#,
    );
    write_file(
        repo.path(),
        "app.js",
        "var query = \"SELECT \" + userInput;\nvar query2 = \"SELECT \" + safeValue;\n",
    );

    assert_parity(repo.path(), &rules, "app.js");
}

#[test]
fn test_parity_pattern_inside() {
    if skip_if_semgrep_missing() {
        return;
    }

    // Note: we use `$X` instead of `...` for the formal parameter list because
    // tree-sitter-javascript rejects `function f(...)` as a syntactic ellipsis
    // (it is a rest-param prefix in JS). `$X` is a regular identifier slot in
    // both Semgrep and foxguard's pattern parsers.
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
          function handler($X) {
            ...
          }
    message: eval in handler
    severity: ERROR
    languages: [javascript]
"#,
    );
    write_file(
        repo.path(),
        "app.js",
        "function handler(userInput) {\n    eval(userInput);\n}\n\nfunction helper(userInput) {\n    eval(userInput);\n}\n",
    );

    assert_parity(repo.path(), &rules, "app.js");
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
          function safeRedirect($X) {
            ...
          }
    message: redirect outside helper
    severity: WARNING
    languages: [javascript]
"#,
    );
    write_file(
        repo.path(),
        "app.js",
        "function safeRedirect(url) {\n    return redirect(url);\n}\n\nfunction doRedirect(url) {\n    return redirect(url);\n}\n",
    );

    assert_parity(repo.path(), &rules, "app.js");
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
    pattern-regex: '(?m)^(const|let|var)\s+(password|secret)\s*='
    pattern-not-regex: '(?m)^(const|let|var)\s+not_password\s*='
    message: secret assignment
    severity: ERROR
    languages: [javascript]
"#,
    );
    write_file(
        repo.path(),
        "app.js",
        "const password = \"secret\";\nconst not_password = \"safe\";\nlet secret = \"abc\";\n",
    );

    assert_parity(repo.path(), &rules, "app.js");
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
    languages: [javascript]
    paths:
      include:
        - src/**/*.js
      exclude:
        - src/generated/**
"#,
    );
    write_file(repo.path(), "src/app/main.js", "eval(userInput);\n");
    write_file(repo.path(), "src/generated/main.js", "eval(userInput);\n");
    write_file(repo.path(), "tests/main.js", "eval(userInput);\n");

    assert_parity(repo.path(), &rules, ".");
}
