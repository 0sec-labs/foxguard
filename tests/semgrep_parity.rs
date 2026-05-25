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
