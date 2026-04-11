use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn foxguard_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_foxguard"))
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn write_secrets_fixture(dir: &Path) -> PathBuf {
    let aws = ["AKIA", "1234567890ABCDEF"].concat();
    let aws_secret = ["ABCD1234+/", "wxyz5678+/", "MNOP9012+/", "qrst3456+/"].concat();
    let github = ["ghp_", "abcdefghijklmnopqrstuvwxyz1234567890"].concat();
    let gitlab = ["gl", "pat-abcdefghijklmnopqrstuvwx123456"].concat();
    let npm = ["npm_", "abcdefghijklmnopqrstuvwxyz1234567890"].concat();
    let slack = ["xoxb", "123456789012", "123456789012", "abcdefghijklmnop"].join("-");
    let stripe = ["sk", "live", "1234567890abcdefghijklmnop"].join("_");
    let private_key = ["-----BEGIN ", "PRIVATE KEY-----"].concat();

    let content = format!(
        "AWS_ACCESS_KEY_ID={aws}\nAWS_SECRET_ACCESS_KEY={aws_secret}\nGITHUB_TOKEN={github}\nGITLAB_TOKEN={gitlab}\nNPM_TOKEN={npm}\nSLACK_TOKEN={slack}\nSTRIPE_SECRET_KEY={stripe}\nPRIVATE_KEY_HEADER={private_key}\n"
    );

    let path = dir.join("secrets.txt");
    fs::write(&path, content).expect("failed to write secrets fixture");
    path
}

fn write_binary_secrets_fixture(dir: &Path) -> PathBuf {
    let secret = ["ghp_", "abcdefghijklmnopqrstuvwxyz1234567890"].concat();
    let path = dir.join("binary-secrets.bin");
    let mut bytes = b"\0BINARY\0".to_vec();
    bytes.extend_from_slice(secret.as_bytes());
    fs::write(&path, bytes).expect("failed to write binary secrets fixture");
    path
}

fn write_secret_file(dir: &Path, relative_path: &str) -> PathBuf {
    let github = ["ghp_", "abcdefghijklmnopqrstuvwxyz1234567890"].concat();
    let path = dir.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("failed to create secret fixture directory");
    }
    fs::write(&path, format!("GITHUB_TOKEN={github}\n")).expect("failed to write secret file");
    path
}

fn setup_git_repo(files: &[&str]) -> TempDir {
    let repo = TempDir::new().expect("failed to create temp repo");

    Command::new("git")
        .args(["init"])
        .current_dir(repo.path())
        .output()
        .expect("failed to initialize git repo");

    for file in files {
        let src = fixture_path(file);
        let dest = repo.path().join(file);
        fs::copy(src, dest).expect("failed to copy fixture");
    }

    repo
}

fn write_config_file(dir: &Path, relative_path: &str, content: &str) -> PathBuf {
    let path = dir.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("failed to create config directory");
    }
    fs::write(&path, content).expect("failed to write config file");
    path
}

fn copy_fixture_to(dir: &Path, fixture_name: &str, relative_path: &str) -> PathBuf {
    let src = fixture_path(fixture_name);
    let dest = dir.join(relative_path);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).expect("failed to create fixture directory");
    }
    fs::copy(src, &dest).expect("failed to copy fixture to target path");
    dest
}

// ─── Vulnerable file detection ──────────────────────────────────────────────

#[test]
fn test_vulnerable_js_finds_all_rules() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.js", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        !output.status.success(),
        "should exit non-zero when findings exist"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(
        findings.len(),
        30,
        "vulnerable.js should have 30 findings, got {}",
        findings.len()
    );

    // Verify all unique rule IDs are present
    let rule_ids: std::collections::HashSet<&str> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();

    let expected_rules = [
        "js/no-eval",
        "js/no-hardcoded-secret",
        "js/no-sql-injection",
        "js/no-xss-innerhtml",
        "js/no-command-injection",
        "js/no-document-write",
        "js/no-open-redirect",
        "js/no-weak-crypto",
        "js/no-path-traversal",
        "js/no-ssrf",
        "js/no-prototype-pollution",
        "js/no-unsafe-regex",
        "js/no-cors-star",
        "js/express-no-hardcoded-session-secret",
        "js/express-cookie-no-secure",
        "js/express-cookie-no-httponly",
        "js/express-cookie-no-samesite",
        "js/express-session-saveuninitialized-true",
        "js/express-direct-response-write",
        "js/jwt-hardcoded-secret",
        "js/jwt-none-algorithm",
        "js/jwt-ignore-expiration",
        "js/jwt-decode-without-verify",
        "js/jwt-verify-missing-algorithms",
    ];

    for rule in &expected_rules {
        assert!(rule_ids.contains(rule), "missing expected rule: {}", rule);
    }
}

#[test]
fn test_vulnerable_py_finds_all_rules() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.py", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(!output.status.success());

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(
        findings.len(),
        30,
        "vulnerable.py should have 30 findings, got {}",
        findings.len()
    );

    let rule_ids: std::collections::HashSet<&str> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();

    let expected_rules = [
        "py/no-eval",
        "py/no-hardcoded-secret",
        "py/no-sql-injection",
        "py/no-command-injection",
        "py/no-path-traversal",
        "py/no-ssrf",
        "py/no-weak-crypto",
        "py/no-pickle",
        "py/no-yaml-load",
        "py/no-debug-true",
        "py/no-open-redirect",
        "py/no-cors-star",
        "py/flask-debug-mode",
        "py/django-secret-key-hardcoded",
        "py/flask-secret-key-hardcoded",
        "py/session-cookie-secure-disabled",
        "py/session-cookie-httponly-disabled",
        "py/session-cookie-samesite-disabled",
        "py/csrf-cookie-secure-disabled",
        "py/csrf-cookie-httponly-disabled",
        "py/csrf-cookie-samesite-disabled",
        "py/csrf-exempt",
        "py/wtf-csrf-disabled",
        "py/wtf-csrf-check-default-disabled",
        "py/django-allowed-hosts-wildcard",
        "py/secure-ssl-redirect-disabled",
    ];

    for rule in &expected_rules {
        assert!(rule_ids.contains(rule), "missing expected rule: {}", rule);
    }
}

/// Regression test for issue #7: Python rules used to string-match callee
/// text against a fixed sink list, so `import pickle as p; p.loads(x)` and
/// every other aliased form slipped past. With the per-file import alias
/// table, each call site should resolve back to its canonical dotted path
/// and fire.
#[test]
fn test_vulnerable_py_aliases_catches_all_bypass_forms() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable_py_aliases.py", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(!output.status.success());

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(
        findings.len(),
        18,
        "vulnerable_py_aliases.py should have 18 findings, got {}",
        findings.len()
    );

    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for f in &findings {
        if let Some(rule) = f["rule_id"].as_str() {
            *counts.entry(rule).or_insert(0) += 1;
        }
    }

    // One row per rule that should be exercised by the aliased fixture,
    // with the exact number of bypass forms we expect it to catch.
    let expected: &[(&str, usize)] = &[
        ("py/no-pickle", 4),
        ("py/no-yaml-load", 2),
        ("py/no-weak-crypto", 4),
        ("py/no-ssrf", 2),
        ("py/no-command-injection", 4),
        ("py/no-path-traversal", 2),
    ];

    for (rule, want) in expected {
        let got = counts.get(rule).copied().unwrap_or(0);
        assert_eq!(
            got, *want,
            "rule {} caught {} bypass forms, expected {}",
            rule, got, want
        );
    }
}

/// POC for issue #10 intraprocedural taint tracking. Every function in
/// `vulnerable_py_taint.py` shows a different shape of untrusted Flask
/// input reaching `pickle.loads`. The taint rule must catch each flow,
/// and the existing conservative `py/no-pickle` rule must keep firing
/// alongside it (the two rules coexist by design).
#[test]
fn test_vulnerable_py_taint_catches_every_flow() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable_py_taint.py", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(!output.status.success());

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for f in &findings {
        if let Some(rule) = f["rule_id"].as_str() {
            *counts.entry(rule).or_insert(0) += 1;
        }
    }

    // Ten function bodies, each with one source→sink flow: one taint
    // finding per function. The conservative NoPickle rule fires on the
    // same ten calls because its scope is "any pickle.loads", so we
    // should see exactly ten of each.
    assert_eq!(
        counts.get("py/taint-pickle-deserialization").copied(),
        Some(10),
        "taint rule should fire ten times, one per handler. counts={:?}",
        counts
    );
    assert_eq!(
        counts.get("py/no-pickle").copied(),
        Some(10),
        "NoPickle should still fire ten times alongside the taint rule. counts={:?}",
        counts
    );
    assert_eq!(
        findings.len(),
        20,
        "expected 20 total findings (10 taint + 10 NoPickle), got {}",
        findings.len()
    );
}

/// Negative counterpart for the taint POC. Every pickle.loads call in
/// `safe_py_taint.py` receives a non-tainted argument (static literal,
/// reassignment kills taint, local variable named `request`, cross-function
/// taint that the engine intentionally does not track). The taint rule
/// must not fire at all. NoPickle still fires on every call — that's the
/// intended division of labor between the conservative and precision
/// rules.
#[test]
fn test_safe_py_taint_has_no_taint_findings() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/safe_py_taint.py", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    let taint_findings = findings
        .iter()
        .filter(|f| f["rule_id"].as_str() == Some("py/taint-pickle-deserialization"))
        .count();
    assert_eq!(
        taint_findings, 0,
        "taint rule should not fire on safe_py_taint.py, got {} findings: {:?}",
        taint_findings, findings
    );
}

/// Negative regression for issue #7: aliased imports of the *same* sensitive
/// modules, but called in safe shapes (static literals, SafeLoader, sha256,
/// write-only pickle methods). Alias resolution must not silently widen the
/// match surface — this file should still produce zero findings.
#[test]
fn test_safe_py_aliases_no_findings() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/safe_py_aliases.py", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        output.status.success(),
        "safe_py_aliases.py should exit zero"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(
        findings.len(),
        0,
        "safe_py_aliases.py should have 0 findings, got {:?}",
        findings
    );
}

#[test]
fn test_vulnerable_go_finds_all_rules() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.go", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(!output.status.success());

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(
        findings.len(),
        10,
        "vulnerable.go should have 10 findings, got {}",
        findings.len()
    );

    let rule_ids: std::collections::HashSet<&str> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();

    let expected_rules = [
        "go/no-sql-injection",
        "go/no-command-injection",
        "go/no-hardcoded-secret",
        "go/no-weak-crypto",
        "go/no-ssrf",
        "go/insecure-tls-skip-verify",
        "go/net-http-no-timeout",
    ];

    for rule in &expected_rules {
        assert!(rule_ids.contains(rule), "missing expected rule: {}", rule);
    }
}

#[test]
fn test_vulnerable_java_finds_all_rules() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.java", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(!output.status.success());

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(
        findings.len(),
        16,
        "vulnerable.java should have 16 findings, got {}",
        findings.len()
    );

    let rule_ids: std::collections::HashSet<&str> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();

    let expected_rules = [
        "java/no-sql-injection",
        "java/no-command-injection",
        "java/no-unsafe-deserialization",
        "java/no-ssrf",
        "java/no-path-traversal",
        "java/no-weak-crypto",
        "java/no-hardcoded-secret",
        "java/no-xxe",
        "java/spring-csrf-disabled",
        "java/spring-cors-permissive",
    ];

    for rule in &expected_rules {
        assert!(rule_ids.contains(rule), "missing expected rule: {}", rule);
    }
}

#[test]
fn test_vulnerable_php_finds_all_rules() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.php", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(!output.status.success());

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(
        findings.len(),
        20,
        "vulnerable.php should have 20 findings, got {}",
        findings.len()
    );

    let rule_ids: std::collections::HashSet<&str> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();

    let expected_rules = [
        "php/no-eval",
        "php/no-command-injection",
        "php/no-sql-injection",
        "php/no-unserialize",
        "php/no-file-inclusion",
        "php/no-weak-crypto",
        "php/no-hardcoded-secret",
        "php/no-ssrf",
        "php/no-extract",
        "php/no-preg-eval",
    ];

    for rule in &expected_rules {
        assert!(rule_ids.contains(rule), "missing expected rule: {}", rule);
    }
}

#[test]
fn test_vulnerable_ruby_finds_all_rules() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.rb", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(!output.status.success());

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(
        findings.len(),
        18,
        "vulnerable.rb should have 18 findings, got {}",
        findings.len()
    );

    let rule_ids: std::collections::HashSet<&str> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();

    let expected_rules = [
        "rb/no-eval",
        "rb/no-command-injection",
        "rb/no-sql-injection",
        "rb/no-mass-assignment",
        "rb/no-unsafe-deserialization",
        "rb/no-open-redirect",
        "rb/no-csrf-skip",
        "rb/no-html-safe",
        "rb/no-hardcoded-secret",
        "rb/no-weak-crypto",
    ];

    for rule in &expected_rules {
        assert!(rule_ids.contains(rule), "missing expected rule: {}", rule);
    }
}

#[test]
fn test_vulnerable_csharp_finds_all_rules() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.cs", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(!output.status.success());

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(
        findings.len(),
        15,
        "vulnerable.cs should have 15 findings, got {}",
        findings.len()
    );

    let rule_ids: std::collections::HashSet<&str> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();

    let expected_rules = [
        "cs/no-sql-injection",
        "cs/no-command-injection",
        "cs/no-unsafe-deserialization",
        "cs/no-ssrf",
        "cs/no-path-traversal",
        "cs/no-weak-crypto",
        "cs/no-hardcoded-secret",
        "cs/no-xxe",
        "cs/no-ldap-injection",
        "cs/no-cors-star",
    ];

    for rule in &expected_rules {
        assert!(rule_ids.contains(rule), "missing expected rule: {}", rule);
    }
}

#[test]
fn test_vulnerable_swift_finds_all_rules() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.swift", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(!output.status.success());

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(
        findings.len(),
        19,
        "vulnerable.swift should have 19 findings, got {}",
        findings.len()
    );

    let rule_ids: std::collections::HashSet<&str> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();

    let expected_rules = [
        "swift/no-hardcoded-secret",
        "swift/no-command-injection",
        "swift/no-weak-crypto",
        "swift/no-insecure-transport",
        "swift/no-eval-js",
        "swift/no-sql-injection",
        "swift/no-insecure-keychain",
        "swift/no-tls-disabled",
        "swift/no-path-traversal",
        "swift/no-ssrf",
    ];

    for rule in &expected_rules {
        assert!(rule_ids.contains(rule), "missing expected rule: {}", rule);
    }
}

#[test]
fn test_vulnerable_rust_finds_all_rules() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.rs", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(!output.status.success());

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(
        findings.len(),
        18,
        "vulnerable.rs should have 18 findings, got {}",
        findings.len()
    );

    let rule_ids: std::collections::HashSet<&str> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();

    let expected_rules = [
        "rs/unsafe-block",
        "rs/transmute-usage",
        "rs/no-command-injection",
        "rs/no-sql-injection",
        "rs/no-weak-hash",
        "rs/no-hardcoded-secret",
        "rs/tls-verify-disabled",
        "rs/no-ssrf",
        "rs/no-path-traversal",
        "rs/no-unwrap-in-lib",
    ];

    for rule in &expected_rules {
        assert!(rule_ids.contains(rule), "missing expected rule: {}", rule);
    }
}

// ─── Safe file detection ────────────────────────────────────────────────────

#[test]
fn test_safe_js_no_findings() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/safe.js", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(output.status.success(), "safe.js should exit zero");

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(findings.len(), 0, "safe.js should have 0 findings");
}

#[test]
fn test_safe_py_no_findings() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/safe.py", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(output.status.success(), "safe.py should exit zero");

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(findings.len(), 0, "safe.py should have 0 findings");
}

#[test]
fn test_safe_go_no_findings() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/safe.go", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(output.status.success(), "safe.go should exit zero");

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(findings.len(), 0, "safe.go should have 0 findings");
}

#[test]
fn test_invalid_path_exits_nonzero() {
    let output = foxguard_cmd()
        .args(["not_a_real_path_foxguard_test", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        !output.status.success(),
        "invalid paths should exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not exist"),
        "expected missing path error, got: {}",
        stderr
    );
}

#[test]
fn test_no_builtins_without_external_rules_finds_nothing() {
    let output = foxguard_cmd()
        .args([
            "tests/fixtures/vulnerable.js",
            "-f",
            "json",
            "--no-builtins",
        ])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        output.status.success(),
        "no built-ins and no external rules should exit zero"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(findings.len(), 0, "expected no findings without any rules");
}

#[test]
fn test_no_builtins_with_external_rules_still_finds_matches() {
    let output = foxguard_cmd()
        .args([
            "tests/fixtures/vulnerable.py",
            "-f",
            "json",
            "--no-builtins",
            "--rules",
            "tests/semgrep_rules",
        ])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        !output.status.success(),
        "external rules should still report findings"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert!(
        !findings.is_empty(),
        "expected findings from external rules when built-ins are disabled"
    );
}

#[test]
fn test_external_rules_respect_semgrep_paths_filters() {
    let repo = TempDir::new().expect("failed to create temp repo");
    copy_fixture_to(repo.path(), "vulnerable.py", "src/vulnerable.py");
    copy_fixture_to(repo.path(), "vulnerable.py", "tests/vulnerable.py");

    let rules_dir = repo.path().join("rules");
    fs::create_dir_all(&rules_dir).expect("failed to create rules directory");
    fs::write(
        rules_dir.join("path-filter.yaml"),
        r#"
rules:
  - id: path-filtered-eval
    pattern: eval(...)
    message: eval usage
    severity: ERROR
    languages: [python]
    paths:
      include:
        - src/**/*.py
"#,
    )
    .expect("failed to write rules file");

    let output = foxguard_cmd()
        .current_dir(repo.path())
        .args([".", "-f", "json", "--no-builtins", "--rules", "rules"])
        .output()
        .expect("failed to execute foxguard with path-filtered rules");

    assert!(
        !output.status.success(),
        "path-filtered external rule should still report findings"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert!(
        findings.iter().all(|finding| finding["file"]
            .as_str()
            .unwrap_or_default()
            .contains("/src/")),
        "expected path filters to restrict findings to src/"
    );
}

#[test]
fn test_write_and_apply_baseline() {
    let repo = TempDir::new().expect("failed to create temp dir");
    let source = fixture_path("vulnerable.js");
    let target = repo.path().join("vulnerable.js");
    fs::copy(source, &target).expect("failed to copy fixture");
    let baseline = repo.path().join("baseline.json");

    let initial = foxguard_cmd()
        .args([
            target.to_str().expect("non-utf8 path"),
            "-f",
            "json",
            "--write-baseline",
            baseline.to_str().expect("non-utf8 path"),
        ])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        !initial.status.success(),
        "writing a baseline should still report current findings"
    );
    assert!(baseline.exists(), "baseline file should be created");

    let suppressed = foxguard_cmd()
        .args([
            target.to_str().expect("non-utf8 path"),
            "-f",
            "json",
            "--baseline",
            baseline.to_str().expect("non-utf8 path"),
        ])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        suppressed.status.success(),
        "baseline should suppress the existing findings"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&suppressed.stdout).expect("invalid JSON output");
    assert_eq!(findings.len(), 0, "expected no findings after baseline");
}

#[test]
fn test_scan_uses_discovered_config_baseline() {
    let repo = TempDir::new().expect("failed to create temp dir");
    fs::copy(
        fixture_path("vulnerable.js"),
        repo.path().join("vulnerable.js"),
    )
    .expect("failed to copy vulnerable fixture");

    let baseline = repo.path().join(".foxguard").join("baseline.json");
    fs::create_dir_all(baseline.parent().expect("missing baseline parent"))
        .expect("failed to create baseline directory");

    let initial = foxguard_cmd()
        .current_dir(repo.path())
        .args([
            "vulnerable.js",
            "-f",
            "json",
            "--write-baseline",
            baseline.to_str().expect("non-utf8 path"),
        ])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        !initial.status.success(),
        "writing the baseline should still report findings"
    );

    write_config_file(
        repo.path(),
        ".foxguard.yml",
        "scan:\n  baseline: .foxguard/baseline.json\n",
    );

    let suppressed = foxguard_cmd()
        .current_dir(repo.path())
        .args(["vulnerable.js", "-f", "json"])
        .output()
        .expect("failed to execute foxguard with config");

    assert!(
        suppressed.status.success(),
        "configured baseline should suppress the existing findings"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&suppressed.stdout).expect("invalid JSON output");
    assert_eq!(
        findings.len(),
        0,
        "expected no findings after config baseline"
    );
}

#[test]
fn test_inline_ignore_suppresses_same_line_js_finding() {
    let repo = TempDir::new().expect("failed to create temp dir");
    let target = repo.path().join("ignored.js");
    fs::write(
        &target,
        "const user_input = process.argv[2];\neval(user_input); // foxguard: ignore[js/no-eval]\n",
    )
    .expect("failed to write fixture");

    let output = foxguard_cmd()
        .args([target.to_str().expect("non-utf8 path"), "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        output.status.success(),
        "same-line ignore should suppress the matching finding"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");
    assert!(
        findings.is_empty(),
        "expected no findings after same-line ignore"
    );
}

#[test]
fn test_inline_ignore_suppresses_next_python_line_after_blank_lines() {
    let repo = TempDir::new().expect("failed to create temp dir");
    let target = repo.path().join("ignored.py");
    fs::write(&target, "# foxguard: ignore[py/no-eval]\n\neval(input())\n")
        .expect("failed to write fixture");

    let output = foxguard_cmd()
        .args([target.to_str().expect("non-utf8 path"), "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        output.status.success(),
        "comment-only ignore should suppress the next code-line finding"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");
    assert!(
        findings.is_empty(),
        "expected no findings after next-line ignore"
    );
}

#[test]
fn test_inline_ignore_remains_rule_specific() {
    let repo = TempDir::new().expect("failed to create temp dir");
    let target = repo.path().join("not-ignored.js");
    fs::write(
        &target,
        "const user_input = process.argv[2];\neval(user_input); // foxguard: ignore[js/no-sql-injection]\n",
    )
    .expect("failed to write fixture");

    let output = foxguard_cmd()
        .args([target.to_str().expect("non-utf8 path"), "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        !output.status.success(),
        "mismatched rule ID should not suppress the finding"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");
    assert_eq!(findings.len(), 1, "expected the finding to remain");
    assert_eq!(findings[0]["rule_id"], "js/no-eval");
}

#[test]
fn test_inline_ignore_without_rule_list_suppresses_all_findings_on_line() {
    let repo = TempDir::new().expect("failed to create temp dir");
    let target = repo.path().join("ignored-all.js");
    fs::write(
        &target,
        "const user_input = process.argv[2];\neval(user_input); // foxguard: ignore\n",
    )
    .expect("failed to write fixture");

    let output = foxguard_cmd()
        .args([target.to_str().expect("non-utf8 path"), "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        output.status.success(),
        "ignore without rule list should suppress all findings on the line"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");
    assert!(findings.is_empty(), "expected no findings after ignore-all");
}

#[test]
fn test_inline_ignore_suppresses_multiline_finding_when_directive_is_on_end_line() {
    let repo = TempDir::new().expect("failed to create temp dir");
    let target = repo.path().join("multiline-ignored.js");
    fs::write(
        &target,
        "const user_input = process.argv[2];\neval(\n  user_input // foxguard: ignore[js/no-eval]\n);\n",
    )
    .expect("failed to write fixture");

    let output = foxguard_cmd()
        .args([target.to_str().expect("non-utf8 path"), "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        output.status.success(),
        "directive on the end line of a multiline finding should still suppress it"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");
    assert!(
        findings.is_empty(),
        "expected no findings after multiline inline ignore"
    );
}

#[test]
fn test_changed_mode_scans_only_staged_files() {
    let repo = setup_git_repo(&["vulnerable.js", "safe.py"]);

    Command::new("git")
        .args(["add", "vulnerable.js"])
        .current_dir(repo.path())
        .output()
        .expect("failed to stage vulnerable.js");

    let output = foxguard_cmd()
        .args(["--changed", "-f", "json", "."])
        .current_dir(repo.path())
        .output()
        .expect("failed to execute foxguard");

    assert!(
        !output.status.success(),
        "changed-mode scan should report findings from staged vulnerable.js"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");
    assert!(
        findings.iter().all(|finding| finding["file"]
            .as_str()
            .unwrap_or_default()
            .ends_with("vulnerable.js")),
        "changed mode should only scan the staged file"
    );
}

#[test]
fn test_init_installs_hook_and_baseline() {
    let repo = setup_git_repo(&["vulnerable.js"]);

    let output = foxguard_cmd()
        .args(["init", "--path", ".", "--force"])
        .current_dir(repo.path())
        .output()
        .expect("failed to execute foxguard init");

    assert!(output.status.success(), "init should succeed");
    assert!(
        repo.path().join(".git/hooks/pre-commit").exists(),
        "pre-commit hook should be installed"
    );
    assert!(
        repo.path().join(".foxguard/baseline.json").exists(),
        "baseline should be created by default"
    );
    assert!(
        repo.path().join(".foxguard/secrets-baseline.json").exists(),
        "secrets baseline should be created by default"
    );
    assert!(
        repo.path().join(".foxguard.yml").exists(),
        "starter config should be created by default"
    );

    let hook = fs::read_to_string(repo.path().join(".git/hooks/pre-commit"))
        .expect("failed to read pre-commit hook");
    assert!(
        hook.contains("foxguard --config \".foxguard.yml\" --changed"),
        "hook should use the generated config"
    );
    assert!(
        hook.contains("foxguard secrets --config \".foxguard.yml\" --changed"),
        "hook should run the secrets scanner"
    );

    let config = fs::read_to_string(repo.path().join(".foxguard.yml"))
        .expect("failed to read generated config");
    assert!(
        config.contains("scan:\n  baseline: .foxguard/baseline.json"),
        "generated config should include the code baseline"
    );
    assert!(
        config.contains("secrets:\n  baseline: .foxguard/secrets-baseline.json"),
        "generated config should include the secrets baseline"
    );
}

#[test]
fn test_init_preserves_existing_config_and_keeps_baseline_flags_when_needed() {
    let repo = setup_git_repo(&["vulnerable.js"]);
    write_config_file(
        repo.path(),
        ".foxguard.yml",
        "secrets:\n  exclude_paths:\n    - fixtures\n",
    );

    let output = foxguard_cmd()
        .args(["init", "--path", ".", "--force"])
        .current_dir(repo.path())
        .output()
        .expect("failed to execute foxguard init");

    assert!(output.status.success(), "init should succeed");

    let hook = fs::read_to_string(repo.path().join(".git/hooks/pre-commit"))
        .expect("failed to read pre-commit hook");
    assert!(
        hook.contains("--config \".foxguard.yml\""),
        "hook should still use the existing config"
    );
    assert!(
        hook.contains("--baseline \".foxguard/baseline.json\""),
        "hook should keep explicit code baseline flags when existing config lacks them"
    );
    assert!(
        hook.contains("--baseline \".foxguard/secrets-baseline.json\""),
        "hook should keep explicit secrets baseline flags when existing config lacks them"
    );

    let config = fs::read_to_string(repo.path().join(".foxguard.yml"))
        .expect("failed to read preserved config");
    assert!(
        config.contains("exclude_paths:\n    - fixtures"),
        "existing config should be preserved"
    );
}

// ─── Severity filtering ─────────────────────────────────────────────────────

#[test]
fn test_severity_filter_high() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.js", "-f", "json", "-s", "high"])
        .output()
        .expect("failed to execute foxguard");

    assert!(!output.status.success());

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    // High and Critical only
    assert_eq!(
        findings.len(),
        19,
        "high severity filter on vulnerable.js should yield 19 findings, got {}",
        findings.len()
    );

    // All findings should be High or Critical
    for finding in &findings {
        let severity = finding["severity"].as_str().unwrap();
        assert!(
            severity == "high" || severity == "critical",
            "expected high or critical, got: {}",
            severity
        );
    }
}

#[test]
fn test_secrets_mode_finds_common_credentials() {
    let repo = TempDir::new().expect("failed to create temp dir");
    let path = write_secrets_fixture(repo.path());

    let output = foxguard_cmd()
        .args([
            "secrets",
            path.to_str().expect("non-utf8 path"),
            "-f",
            "json",
        ])
        .output()
        .expect("failed to execute foxguard secrets");

    assert!(
        !output.status.success(),
        "secrets mode should exit non-zero when findings exist"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(
        findings.len(),
        8,
        "secrets fixture should yield 8 findings, got {}",
        findings.len()
    );

    let rule_ids: std::collections::HashSet<&str> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();

    let expected_rules = [
        "secret/aws-access-key-id",
        "secret/aws-secret-access-key",
        "secret/github-token",
        "secret/gitlab-token",
        "secret/npm-token",
        "secret/slack-token",
        "secret/stripe-live-key",
        "secret/private-key",
    ];

    for rule in &expected_rules {
        assert!(
            rule_ids.contains(rule),
            "missing expected secret rule: {}",
            rule
        );
    }
}

#[test]
fn test_secrets_mode_changed_scans_only_staged_files() {
    let repo = setup_git_repo(&["safe.py"]);
    write_secrets_fixture(repo.path());

    Command::new("git")
        .args(["add", "secrets.txt"])
        .current_dir(repo.path())
        .output()
        .expect("failed to stage secrets fixture");

    let output = foxguard_cmd()
        .args(["secrets", "--changed", "-f", "json", "."])
        .current_dir(repo.path())
        .output()
        .expect("failed to execute foxguard secrets --changed");

    assert!(
        !output.status.success(),
        "changed secrets scan should report staged secrets"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");
    assert!(
        findings.iter().all(|finding| finding["file"]
            .as_str()
            .unwrap_or_default()
            .ends_with("secrets.txt")),
        "changed secrets scan should only scan the staged secret fixture"
    );
}

#[test]
fn test_secrets_mode_skips_binary_files() {
    let repo = TempDir::new().expect("failed to create temp dir");
    let path = write_binary_secrets_fixture(repo.path());

    let output = foxguard_cmd()
        .args([
            "secrets",
            path.to_str().expect("non-utf8 path"),
            "-f",
            "json",
        ])
        .output()
        .expect("failed to execute foxguard secrets");

    assert!(output.status.success(), "binary file should be skipped");

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");
    assert_eq!(
        findings.len(),
        0,
        "binary secrets fixture should be skipped"
    );
}

#[test]
fn test_write_and_apply_secrets_baseline() {
    let repo = TempDir::new().expect("failed to create temp dir");
    let target = write_secrets_fixture(repo.path());
    let baseline = repo.path().join("secrets-baseline.json");

    let initial = foxguard_cmd()
        .args([
            "secrets",
            target.to_str().expect("non-utf8 path"),
            "-f",
            "json",
            "--write-baseline",
            baseline.to_str().expect("non-utf8 path"),
        ])
        .output()
        .expect("failed to execute foxguard secrets");

    assert!(
        !initial.status.success(),
        "writing a secrets baseline should still report current findings"
    );
    assert!(baseline.exists(), "secrets baseline file should be created");

    let suppressed = foxguard_cmd()
        .args([
            "secrets",
            target.to_str().expect("non-utf8 path"),
            "-f",
            "json",
            "--baseline",
            baseline.to_str().expect("non-utf8 path"),
        ])
        .output()
        .expect("failed to execute foxguard secrets with baseline");

    assert!(
        suppressed.status.success(),
        "secrets baseline should suppress the existing findings"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&suppressed.stdout).expect("invalid JSON output");
    assert_eq!(
        findings.len(),
        0,
        "expected no findings after applying the secrets baseline"
    );

    let baseline_content = fs::read_to_string(&baseline).expect("failed to read secrets baseline");
    assert!(
        !baseline_content.contains("\"snippet\""),
        "secrets baseline should not persist snippets"
    );
    assert!(
        !baseline_content.contains("[REDACTED]"),
        "secrets baseline should only store suppression metadata"
    );
}

#[test]
fn test_secrets_mode_redacts_snippets() {
    let repo = TempDir::new().expect("failed to create temp dir");
    let path = write_secrets_fixture(repo.path());

    let output = foxguard_cmd()
        .args([
            "secrets",
            path.to_str().expect("non-utf8 path"),
            "-f",
            "json",
        ])
        .output()
        .expect("failed to execute foxguard secrets");

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    for finding in findings {
        let snippet = finding["snippet"].as_str().expect("missing snippet");
        assert!(
            snippet.contains("[REDACTED]"),
            "secrets snippet should be redacted"
        );
        assert!(
            !snippet.contains("1234567890ABCDEF")
                && !snippet.contains("abcdefghijklmnopqrstuvwxyz1234567890"),
            "secrets snippet should not contain raw secrets"
        );
    }
}

#[test]
fn test_secrets_mode_exclude_path_skips_matching_files() {
    let repo = TempDir::new().expect("failed to create temp dir");
    write_secret_file(repo.path(), "included.txt");
    write_secret_file(repo.path(), "fixtures/ignored.txt");

    let output = foxguard_cmd()
        .args([
            "secrets",
            "--exclude-path",
            "fixtures",
            repo.path().to_str().expect("non-utf8 path"),
            "-f",
            "json",
        ])
        .output()
        .expect("failed to execute foxguard secrets");

    assert!(
        !output.status.success(),
        "non-excluded secrets should still produce findings"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(findings.len(), 1, "expected only one non-excluded finding");
    assert!(
        findings[0]["file"]
            .as_str()
            .is_some_and(|file| file.ends_with("included.txt")),
        "expected only the included file to be scanned"
    );
}

#[test]
fn test_secrets_mode_exclude_path_file_skips_matching_files() {
    let repo = TempDir::new().expect("failed to create temp dir");
    write_secret_file(repo.path(), "fixtures/ignored.txt");
    let ignore_file = repo.path().join(".foxguard").join("secrets.ignore");
    fs::create_dir_all(ignore_file.parent().expect("missing ignore directory"))
        .expect("failed to create ignore directory");
    fs::write(&ignore_file, "# comment\nfixtures\n").expect("failed to write ignore file");

    let output = foxguard_cmd()
        .args([
            "secrets",
            "--exclude-path-file",
            ignore_file.to_str().expect("non-utf8 path"),
            repo.path().to_str().expect("non-utf8 path"),
            "-f",
            "json",
        ])
        .output()
        .expect("failed to execute foxguard secrets");

    assert!(
        output.status.success(),
        "excluded secrets should not produce findings"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");
    assert!(findings.is_empty(), "expected excluded file to be skipped");
}

#[test]
fn test_secrets_mode_ignore_rule_skips_specific_patterns() {
    let repo = TempDir::new().expect("failed to create temp dir");
    write_secrets_fixture(repo.path());

    let output = foxguard_cmd()
        .args([
            "secrets",
            "--ignore-rule",
            "secret/github-token",
            repo.path().to_str().expect("non-utf8 path"),
            "-f",
            "json",
        ])
        .output()
        .expect("failed to execute foxguard secrets");

    assert!(
        !output.status.success(),
        "remaining secrets should still produce findings"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(
        findings.len(),
        7,
        "expected github token finding to be ignored"
    );
    assert!(
        findings
            .iter()
            .all(|finding| finding["rule_id"].as_str() != Some("secret/github-token")),
        "ignored rule should be absent from findings"
    );
}

#[test]
fn test_secrets_mode_uses_explicit_config_file() {
    let repo = TempDir::new().expect("failed to create temp dir");
    write_secret_file(repo.path(), "fixtures/ignored.txt");

    let config = write_config_file(
        repo.path(),
        "config/foxguard.yml",
        "secrets:\n  exclude_paths:\n    - ../fixtures\n",
    );

    let output = foxguard_cmd()
        .current_dir(repo.path())
        .args([
            "secrets",
            "--config",
            config.to_str().expect("non-utf8 path"),
            ".",
            "-f",
            "json",
        ])
        .output()
        .expect("failed to execute foxguard secrets with config");

    assert!(
        output.status.success(),
        "configured excludes should suppress matching secret findings"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");
    assert!(
        findings.is_empty(),
        "expected no findings after config excludes"
    );
}

#[test]
fn test_severity_filter_critical() {
    let output = foxguard_cmd()
        .args([
            "tests/fixtures/vulnerable.js",
            "-f",
            "json",
            "-s",
            "critical",
        ])
        .output()
        .expect("failed to execute foxguard");

    assert!(!output.status.success());

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    // All findings should be Critical
    for finding in &findings {
        let severity = finding["severity"].as_str().unwrap();
        assert_eq!(severity, "critical", "expected critical, got: {}", severity);
    }
}

// ─── JSON output structure ──────────────────────────────────────────────────

#[test]
fn test_json_output_structure() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.js", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert!(!findings.is_empty());

    let first = &findings[0];

    // Verify all expected fields exist
    assert!(first["rule_id"].is_string(), "missing rule_id");
    assert!(first["severity"].is_string(), "missing severity");
    assert!(first["description"].is_string(), "missing description");
    assert!(first["file"].is_string(), "missing file");
    assert!(first["line"].is_number(), "missing line");
    assert!(first["column"].is_number(), "missing column");
    assert!(first["end_line"].is_number(), "missing end_line");
    assert!(first["end_column"].is_number(), "missing end_column");
    assert!(first["snippet"].is_string(), "missing snippet");
}

// ─── SARIF output ───────────────────────────────────────────────────────────

#[test]
fn test_sarif_output_valid() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.js", "-f", "sarif"])
        .output()
        .expect("failed to execute foxguard");

    let sarif: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("invalid SARIF JSON");

    assert_eq!(sarif["version"].as_str(), Some("2.1.0"));
    assert!(sarif["runs"].is_array());
    assert!(sarif["$schema"].is_string());

    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("missing results array");
    assert!(!results.is_empty(), "SARIF results should not be empty");
}
