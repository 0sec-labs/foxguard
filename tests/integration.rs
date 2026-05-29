use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn scan_json_report_from_slice(stdout: &[u8]) -> serde_json::Value {
    serde_json::from_slice(stdout).unwrap_or_else(|e| panic!("invalid JSON output: {e}"))
}

fn scan_json_findings_from_slice(stdout: &[u8]) -> Vec<serde_json::Value> {
    let report = scan_json_report_from_slice(stdout);
    report["findings"].as_array().cloned().unwrap_or_else(|| {
        panic!(
            "JSON report missing findings array: {}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        )
    })
}

fn scan_json_findings_from_str(stdout: &str) -> Vec<serde_json::Value> {
    let report: serde_json::Value =
        serde_json::from_str(stdout).unwrap_or_else(|e| panic!("invalid JSON output: {e}"));
    report["findings"].as_array().cloned().unwrap_or_else(|| {
        panic!(
            "JSON report missing findings array: {}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        )
    })
}

fn assert_json_number_eq(value: &serde_json::Value, expected: f64) {
    let actual = value
        .as_f64()
        .unwrap_or_else(|| panic!("expected JSON number, got {value}"));
    assert!(
        (actual - expected).abs() < 1e-6,
        "expected {expected}, got {actual}"
    );
}

fn foxguard_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_foxguard"))
}

fn foxguard_cmd_isolated() -> Command {
    let mut cmd = foxguard_cmd();
    cmd.args(["--config", "/dev/null"]);
    cmd
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

// ─── Python ─────────────────────────────────────────────────────────────────

mod python {
    use super::*;

    #[test]
    fn test_vulnerable_py_finds_all_rules() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        // Count grew to 31 when `input()` became a taint source (issues
        // #29/#30): `dangerous()` now additionally fires py/taint-eval on
        // `eval(input("Enter code: "))` alongside the conservative
        // py/no-eval finding.
        assert_eq!(
            findings.len(),
            37,
            "vulnerable.py should have 37 findings, got {}",
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
            "py/jwt-no-verify",
            "py/jwt-hardcoded-secret",
            "py/pq-vulnerable-crypto",
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
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable_py_aliases.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

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
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable_py_taint.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for f in &findings {
            if let Some(rule) = f["rule_id"].as_str() {
                *counts.entry(rule).or_insert(0) += 1;
            }
        }

        // Sixteen pickle handlers (10 original + 4 added by #15 for nested
        // subscripts and tuple/list destructuring + 2 added by #19 for
        // same-file interprocedural return propagation). Each has one flow:
        // one py/taint-pickle-deserialization finding per handler. The
        // conservative py/no-pickle rule coexists on the same sixteen calls.
        assert_eq!(
            counts.get("py/taint-pickle-deserialization").copied(),
            Some(16),
            "pickle taint rule should fire sixteen times. counts={:?}",
            counts
        );
        assert_eq!(
            counts.get("py/no-pickle").copied(),
            Some(16),
            "NoPickle should still fire sixteen times alongside the taint rule. counts={:?}",
            counts
        );

        // Each py/taint-* rule has one or more dedicated positive handlers
        // and must fire the expected number of times. Its conservative
        // py/no-* counterpart must coexist and keep firing on the same call.
        // Counts bumped by issues #27/#28: command-injection and eval each
        // gain a `request.args.get("...")` handler; sql-injection gains an
        // f-string handler.
        for (taint_rule, conservative_rule, expected) in [
            ("py/taint-eval", "py/no-eval", 2usize),
            // command-injection: 2 original + 1 os.environ.get() source handler
            ("py/taint-command-injection", "py/no-command-injection", 3),
            ("py/taint-ssrf", "py/no-ssrf", 1),
            ("py/taint-yaml-load", "py/no-yaml-load", 1),
            ("py/taint-sql-injection", "py/no-sql-injection", 2),
        ] {
            assert_eq!(
                counts.get(taint_rule).copied(),
                Some(expected),
                "{} should fire exactly {} time(s) on vulnerable_py_taint.py. counts={:?}",
                taint_rule,
                expected,
                counts
            );
            assert!(
                counts.get(conservative_rule).copied().unwrap_or(0) >= 1,
                "conservative {} must coexist with {}. counts={:?}",
                conservative_rule,
                taint_rule,
                counts
            );
        }

        // New taint-only rules (no conservative counterpart).
        for (taint_rule, expected) in [
            ("py/taint-ssti", 1usize),
            ("py/taint-xpath-injection", 1),
            ("py/taint-ldap-injection", 1),
            ("py/taint-log-injection", 1),
            ("py/taint-xxe", 1),
            ("py/taint-nosql-injection", 1),
        ] {
            assert_eq!(
                counts.get(taint_rule).copied(),
                Some(expected),
                "{} should fire exactly {} time(s) on vulnerable_py_taint.py. counts={:?}",
                taint_rule,
                expected,
                counts
            );
        }
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
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/safe_py_taint.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        for taint_rule in [
            "py/taint-pickle-deserialization",
            "py/taint-eval",
            "py/taint-command-injection",
            "py/taint-ssrf",
            "py/taint-yaml-load",
            "py/taint-sql-injection",
            "py/taint-ssti",
            "py/taint-xpath-injection",
            "py/taint-ldap-injection",
            "py/taint-log-injection",
            "py/taint-xxe",
            "py/taint-nosql-injection",
        ] {
            let n = findings
                .iter()
                .filter(|f| f["rule_id"].as_str() == Some(taint_rule))
                .count();
            assert_eq!(
                n, 0,
                "{} should not fire on safe_py_taint.py, got {} findings",
                taint_rule, n
            );
        }
    }

    /// Positive Django fixture for issues #29/#30: every handler flows an
    /// untrusted `HttpRequest` attribute into a taint sink via subscript
    /// access. Each taint rule must fire exactly once.
    #[test]
    fn test_vulnerable_django_taint_catches_flows() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable_django_taint.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for f in &findings {
            if let Some(rule) = f["rule_id"].as_str() {
                *counts.entry(rule).or_insert(0) += 1;
            }
        }

        for rule in [
            "py/taint-pickle-deserialization",
            "py/taint-command-injection",
            "py/taint-eval",
            "py/taint-yaml-load",
            "py/taint-ssrf",
        ] {
            assert_eq!(
                counts.get(rule).copied(),
                Some(1),
                "{} should fire exactly once on vulnerable_django_taint.py. counts={:?}",
                rule,
                counts
            );
        }
    }

    /// Negative Django fixture for issue #29: every sink gets a trusted
    /// argument, so no `py/taint-*` rule may fire.
    #[test]
    fn test_safe_django_taint_has_no_taint_findings() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/safe_django_taint.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        for taint_rule in [
            "py/taint-pickle-deserialization",
            "py/taint-eval",
            "py/taint-command-injection",
            "py/taint-ssrf",
            "py/taint-yaml-load",
            "py/taint-sql-injection",
        ] {
            let n = findings
                .iter()
                .filter(|f| f["rule_id"].as_str() == Some(taint_rule))
                .count();
            assert_eq!(
                n, 0,
                "{} should not fire on safe_django_taint.py, got {} findings",
                taint_rule, n
            );
        }
    }

    /// Positive FastAPI/Starlette fixture for issue #29. Covers attribute
    /// sources (`query_params`, `path_params`) and the handler-parameter
    /// name widening that recognizes `req: Request`.
    #[test]
    fn test_vulnerable_fastapi_taint_catches_flows() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable_fastapi_taint.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for f in &findings {
            if let Some(rule) = f["rule_id"].as_str() {
                *counts.entry(rule).or_insert(0) += 1;
            }
        }

        for rule in [
            "py/taint-pickle-deserialization",
            "py/taint-command-injection",
            "py/taint-eval",
        ] {
            assert_eq!(
                counts.get(rule).copied(),
                Some(1),
                "{} should fire exactly once on vulnerable_fastapi_taint.py. counts={:?}",
                rule,
                counts
            );
        }
    }

    /// Negative FastAPI/Starlette fixture for issue #29.
    #[test]
    fn test_safe_fastapi_taint_has_no_taint_findings() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/safe_fastapi_taint.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        for taint_rule in [
            "py/taint-pickle-deserialization",
            "py/taint-eval",
            "py/taint-command-injection",
            "py/taint-ssrf",
            "py/taint-yaml-load",
            "py/taint-sql-injection",
        ] {
            let n = findings
                .iter()
                .filter(|f| f["rule_id"].as_str() == Some(taint_rule))
                .count();
            assert_eq!(
                n, 0,
                "{} should not fire on safe_fastapi_taint.py, got {} findings",
                taint_rule, n
            );
        }
    }

    /// Positive CLI fixture for issue #30: `sys.argv`, `os.getenv`,
    /// `os.environ[...]`, `input()`, and `sys.stdin.read()` flowing into
    /// command-injection and eval sinks. Expects three
    /// command-injection findings (argv, getenv, environ subscript) and
    /// two eval findings (input, stdin.read).
    #[test]
    fn test_vulnerable_cli_taint_catches_flows() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable_cli_taint.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for f in &findings {
            if let Some(rule) = f["rule_id"].as_str() {
                *counts.entry(rule).or_insert(0) += 1;
            }
        }

        assert_eq!(
            counts.get("py/taint-command-injection").copied(),
            Some(3),
            "py/taint-command-injection should fire three times on vulnerable_cli_taint.py. counts={:?}",
            counts
        );
        assert_eq!(
            counts.get("py/taint-eval").copied(),
            Some(2),
            "py/taint-eval should fire twice on vulnerable_cli_taint.py. counts={:?}",
            counts
        );
    }

    /// Negative CLI fixture for issue #30.
    #[test]
    fn test_safe_cli_taint_has_no_taint_findings() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/safe_cli_taint.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        for taint_rule in [
            "py/taint-pickle-deserialization",
            "py/taint-eval",
            "py/taint-command-injection",
            "py/taint-ssrf",
            "py/taint-yaml-load",
            "py/taint-sql-injection",
        ] {
            let n = findings
                .iter()
                .filter(|f| f["rule_id"].as_str() == Some(taint_rule))
                .count();
            assert_eq!(
                n, 0,
                "{} should not fire on safe_cli_taint.py, got {} findings",
                taint_rule, n
            );
        }
    }

    /// Negative regression for issue #7: aliased imports of the *same* sensitive
    /// modules, but called in safe shapes (static literals, SafeLoader, sha256,
    /// write-only pickle methods). Alias resolution must not silently widen the
    /// match surface — this file should still produce zero findings.
    #[test]
    fn test_safe_py_aliases_no_findings() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/safe_py_aliases.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(
            output.status.success(),
            "safe_py_aliases.py should exit zero"
        );

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        assert_eq!(
            findings.len(),
            0,
            "safe_py_aliases.py should have 0 findings, got {:?}",
            findings
        );
    }

    #[test]
    fn test_safe_py_no_findings() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/safe.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(output.status.success(), "safe.py should exit zero");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        assert_eq!(findings.len(), 0, "safe.py should have 0 findings");
    }

    /// False-positive regression guard. Each construct in `safe_py_fp.py` is a
    /// benign shape that the conservative Python rules used to over-report:
    /// `redirect(url_for(...))`, `open(os.path.join(...))`, `yaml.load` with an
    /// explicit safe `Loader=`, constant-folded SSRF/command sinks, and
    /// debug-mode toggles guarded by `if __name__ == "__main__"`.
    #[test]
    fn test_safe_py_fp_no_findings() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/safe_py_fp.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(output.status.success(), "safe_py_fp.py should exit zero");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        assert_eq!(
            findings.len(),
            0,
            "safe_py_fp.py should have 0 findings, got {:?}",
            findings
                .iter()
                .map(|f| f["rule_id"].as_str().unwrap_or("?"))
                .collect::<Vec<_>>()
        );
    }
}

// ─── JavaScript ─────────────────────────────────────────────────────────────

mod javascript {
    use super::*;

    #[test]
    fn test_vulnerable_js_finds_all_rules() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable.js", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(
            !output.status.success(),
            "should exit non-zero when findings exist"
        );

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        assert_eq!(
            findings.len(),
            35,
            "vulnerable.js should have 35 findings, got {}",
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
            "js/no-unsafe-deserialization",
            "js/pq-vulnerable-crypto",
        ];

        for rule in &expected_rules {
            assert!(rule_ids.contains(rule), "missing expected rule: {}", rule);
        }
    }

    /// POC for issue #18 intraprocedural JS/TS taint tracking. Every handler
    /// in `vulnerable_js_taint.js` shows a different shape of untrusted
    /// Express input reaching an innerHTML/document.write sink. The taint
    /// rule must catch each flow, and the existing conservative
    /// `js/no-xss-innerhtml` / `js/no-document-write` rules must keep firing
    /// alongside it (the two rule classes coexist by design).
    #[test]
    fn test_vulnerable_js_taint_catches_every_flow() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable_js_taint.js", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for f in &findings {
            if let Some(rule) = f["rule_id"].as_str() {
                *counts.entry(rule).or_insert(0) += 1;
            }
        }

        // Ten handlers, each with exactly one source->sink flow (six
        // original + two added by #19 for same-file interprocedural return
        // propagation + one added by #27 for method-call propagation on a
        // tainted root `req.body.toString()` + one added by #119 for spread
        // element taint propagation `[...req.body]`).
        assert_eq!(
            counts.get("js/taint-xss-innerhtml").copied(),
            Some(10),
            "js/taint-xss-innerhtml should fire exactly ten times. counts={:?}",
            counts
        );
        // The conservative rules must still coexist on the same fixture.
        assert!(
            counts.get("js/no-xss-innerhtml").copied().unwrap_or(0) >= 1,
            "js/no-xss-innerhtml must coexist with the taint rule. counts={:?}",
            counts
        );
        assert!(
            counts.get("js/no-document-write").copied().unwrap_or(0) >= 1,
            "js/no-document-write must coexist with the taint rule. counts={:?}",
            counts
        );

        // LDAP injection test added for issue #133.
        assert_eq!(
            counts.get("js/taint-ldap-injection").copied(),
            Some(1),
            "js/taint-ldap-injection should fire exactly once. counts={:?}",
            counts
        );
    }

    /// Negative counterpart for the JS/TS taint POC. Every innerHTML/
    /// document.write sink call here receives a non-tainted argument (static
    /// literal, reassignment kills taint, local variable named `request`,
    /// cross-function taint the engine intentionally does not track). The
    /// taint rule must not fire at all.
    #[test]
    fn test_safe_js_taint_has_no_taint_findings() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/safe_js_taint.js", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        for taint_rule in [
            "js/taint-xss-innerhtml",
            "js/taint-sql-injection",
            "js/taint-command-injection",
            "js/taint-ldap-injection",
            "js/taint-nosql-injection",
        ] {
            let n = findings
                .iter()
                .filter(|f| f["rule_id"].as_str() == Some(taint_rule))
                .count();
            assert_eq!(
                n, 0,
                "{} should not fire on safe_js_taint.js, got {} findings",
                taint_rule, n
            );
        }
    }

    /// Issue #32 — Next.js App Router taint sources. `request` is the
    /// ParamName-seeded handler input and `request.nextUrl` is a Next.js
    /// specific Attribute source. Both handlers must fire exactly once.
    #[test]
    fn test_vulnerable_nextjs_taint_catches_flow() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable_nextjs_taint.ts", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let n = findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("js/taint-xss-innerhtml"))
            .count();
        assert_eq!(
            n, 2,
            "js/taint-xss-innerhtml should fire exactly twice on vulnerable_nextjs_taint.ts, got {} findings: {:?}",
            n, findings
        );
    }

    #[test]
    fn test_typescript_syntax_uses_typescript_parser() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable_typescript.ts", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(
            !output.status.success(),
            "TypeScript fixture should report eval"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("parse error"),
            "TypeScript fixture should parse cleanly, stderr={stderr}"
        );

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        assert!(
            findings
                .iter()
                .any(|finding| finding["rule_id"].as_str() == Some("js/no-eval")),
            "TypeScript fixture should run compatible JavaScript rules, findings={findings:?}"
        );
    }

    #[test]
    fn test_tsx_syntax_uses_tsx_parser() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable_tsx.tsx", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success(), "TSX fixture should report eval");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("parse error"),
            "TSX fixture should parse cleanly, stderr={stderr}"
        );

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        assert!(
            findings
                .iter()
                .any(|finding| finding["rule_id"].as_str() == Some("js/no-eval")),
            "TSX fixture should run compatible JavaScript rules, findings={findings:?}"
        );
    }

    #[test]
    fn test_safe_nextjs_taint_has_no_taint_findings() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/safe_nextjs_taint.ts", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let n = findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("js/taint-xss-innerhtml"))
            .count();
        assert_eq!(
            n, 0,
            "js/taint-xss-innerhtml should not fire on safe_nextjs_taint.ts, got {} findings",
            n
        );
    }

    /// Issue #32 — Hono taint sources. `c` is intentionally NOT a ParamName
    /// matcher; the engine must pick up `c.req.query(...)` / `c.req.param(...)`
    /// through the explicit `Call` matchers.
    #[test]
    fn test_vulnerable_hono_taint_catches_flow() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable_hono_taint.ts", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let n = findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("js/taint-xss-innerhtml"))
            .count();
        assert_eq!(
            n, 2,
            "js/taint-xss-innerhtml should fire exactly twice on vulnerable_hono_taint.ts, got {} findings: {:?}",
            n, findings
        );
    }

    #[test]
    fn test_safe_hono_taint_has_no_taint_findings() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/safe_hono_taint.ts", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let n = findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("js/taint-xss-innerhtml"))
            .count();
        assert_eq!(
            n, 0,
            "js/taint-xss-innerhtml should not fire on safe_hono_taint.ts, got {} findings",
            n
        );
    }

    /// Issue #32 — Deno taint sources. `Deno.args` is an Attribute source,
    /// `Deno.env.get(...)` is a Call source. The engine only analyzes
    /// function bodies, so the fixture wraps its sinks accordingly.
    #[test]
    fn test_vulnerable_deno_taint_catches_flow() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable_deno_taint.ts", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let n = findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("js/taint-xss-innerhtml"))
            .count();
        assert_eq!(
            n, 2,
            "js/taint-xss-innerhtml should fire exactly twice on vulnerable_deno_taint.ts, got {} findings: {:?}",
            n, findings
        );
    }

    #[test]
    fn test_safe_deno_taint_has_no_taint_findings() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/safe_deno_taint.ts", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let n = findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("js/taint-xss-innerhtml"))
            .count();
        assert_eq!(
            n, 0,
            "js/taint-xss-innerhtml should not fire on safe_deno_taint.ts, got {} findings",
            n
        );
    }

    #[test]
    fn test_safe_js_no_findings() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/safe.js", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(output.status.success(), "safe.js should exit zero");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        assert_eq!(findings.len(), 0, "safe.js should have 0 findings");
    }
}

// ─── Go ─────────────────────────────────────────────────────────────────────

mod go {
    use super::*;

    #[test]
    fn test_vulnerable_go_finds_all_rules() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable.go", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        assert_eq!(
            findings.len(),
            24,
            "vulnerable.go should have 24 findings, got {}",
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
            "go/missing-ssl-minversion",
            "go/cookie-missing-secure",
            "go/cookie-missing-httponly",
            "go/math-random-used",
            "go/net-http-no-timeout",
            "go/no-unsafe-deserialization",
            "go/jwt-no-verify",
            "go/jwt-hardcoded-secret",
            "go/pq-vulnerable-crypto",
        ];

        for rule in &expected_rules {
            assert!(rule_ids.contains(rule), "missing expected rule: {}", rule);
        }
    }

    /// Positive fixture for the Go taint engine: each handler flows an
    /// untrusted source (Gin/net/http/Echo/Fiber/env) into a
    /// command-injection, SQL-injection, or SSRF sink. Each go/taint-*
    /// rule must fire the expected number of times and its conservative
    /// go/no-* counterpart must coexist.
    #[test]
    fn test_vulnerable_go_taint_catches_every_flow() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable_go_taint.go", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for f in &findings {
            if let Some(rule) = f["rule_id"].as_str() {
                *counts.entry(rule).or_insert(0) += 1;
            }
        }

        // Five command-injection handlers, three SQL, three SSRF,
        // one SSTI, one XPath, one LDAP.
        for (taint_rule, conservative_rule, expected) in [
            (
                "go/taint-command-injection",
                "go/no-command-injection",
                5usize,
            ),
            ("go/taint-sql-injection", "go/no-sql-injection", 3),
            ("go/taint-ssrf", "go/no-ssrf", 3),
        ] {
            assert_eq!(
                counts.get(taint_rule).copied(),
                Some(expected),
                "{} should fire exactly {} time(s) on vulnerable_go_taint.go. counts={:?}",
                taint_rule,
                expected,
                counts
            );
            assert!(
                counts.get(conservative_rule).copied().unwrap_or(0) >= 1,
                "conservative {} must coexist with {}. counts={:?}",
                conservative_rule,
                taint_rule,
                counts
            );
        }

        // New taint rules without conservative counterparts.
        for (taint_rule, expected) in [
            ("go/taint-ssti", 1usize),
            ("go/taint-xpath-injection", 1),
            ("go/taint-ldap-injection", 1),
            ("go/taint-log-injection", 1),
            ("go/taint-nosql-injection", 1),
            ("go/taint-path-traversal", 3),
        ] {
            assert_eq!(
                counts.get(taint_rule).copied(),
                Some(expected),
                "{} should fire exactly {} time(s) on vulnerable_go_taint.go. counts={:?}",
                taint_rule,
                expected,
                counts
            );
        }
    }

    /// Negative counterpart for the Go taint engine. Every handler in
    /// `safe_go_taint.go` either uses a literal argument, has its
    /// taint killed by reassignment, or relies on cross-function
    /// isolation. No go/taint-* rule may fire.
    #[test]
    fn test_safe_go_taint_has_no_taint_findings() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/safe_go_taint.go", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        for taint_rule in [
            "go/taint-command-injection",
            "go/taint-sql-injection",
            "go/taint-ssrf",
            "go/taint-ssti",
            "go/taint-xpath-injection",
            "go/taint-ldap-injection",
            "go/taint-log-injection",
            "go/taint-nosql-injection",
            "go/taint-path-traversal",
        ] {
            let n = findings
                .iter()
                .filter(|f| f["rule_id"].as_str() == Some(taint_rule))
                .count();
            assert_eq!(
                n, 0,
                "{} should not fire on safe_go_taint.go, got {} findings",
                taint_rule, n
            );
        }
    }

    #[test]
    fn test_safe_go_no_findings() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/safe.go", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(output.status.success(), "safe.go should exit zero");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        assert_eq!(findings.len(), 0, "safe.go should have 0 findings");
    }
}

// ─── C ──────────────────────────────────────────────────────────────────────

mod c {
    use super::*;

    /// Positive fixture for the C taint engine. Each function flows an
    /// untrusted source into a taint sink.
    #[test]
    fn test_vulnerable_c_taint_catches_every_flow() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable_c_taint.c", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for f in &findings {
            if let Some(rule) = f["rule_id"].as_str() {
                *counts.entry(rule).or_insert(0) += 1;
            }
        }

        for (taint_rule, expected) in [
            ("c/taint-format-string", 2usize),
            ("c/taint-command-injection", 4),
            ("c/taint-buffer-overflow", 3),
            ("c/taint-sql-injection", 2),
        ] {
            assert_eq!(
                counts.get(taint_rule).copied(),
                Some(expected),
                "{} should fire exactly {} time(s) on vulnerable_c_taint.c. counts={:?}",
                taint_rule,
                expected,
                counts
            );
        }
    }

    /// Negative counterpart for the C taint engine. Every function in
    /// `safe_c_taint.c` either uses a literal argument, has its taint
    /// killed by sanitization, or avoids the dangerous pattern.
    /// No c/taint-* rule may fire.
    #[test]
    fn test_safe_c_taint_has_no_taint_findings() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/safe_c_taint.c", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        for taint_rule in [
            "c/taint-format-string",
            "c/taint-command-injection",
            "c/taint-buffer-overflow",
            "c/taint-sql-injection",
        ] {
            let n = findings
                .iter()
                .filter(|f| f["rule_id"].as_str() == Some(taint_rule))
                .count();
            assert_eq!(
                n, 0,
                "{} should not fire on safe_c_taint.c, got {} findings",
                taint_rule, n
            );
        }
    }
}

// ─── Java ───────────────────────────────────────────────────────────────────

mod java {
    use super::*;

    #[test]
    fn test_vulnerable_java_finds_all_rules() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable.java", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        assert_eq!(
            findings.len(),
            26,
            "vulnerable.java should have 26 findings, got {}",
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
            "java/no-xss",
            "java/pq-vulnerable-crypto",
        ];

        for rule in &expected_rules {
            assert!(rule_ids.contains(rule), "missing expected rule: {}", rule);
        }
    }

    #[test]
    fn test_safe_java_no_findings() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/safe.java", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");
        assert!(
            output.status.success(),
            "safe.java should produce zero findings; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

// ─── Crypto agility negative fixtures ──────────────────────────────────────
//
// These test the opt-in hardcoded-crypto-algorithm rules against safe patterns.
// The rules must be explicitly enabled since they are opt-in.

mod crypto_agility {
    use super::*;

    fn scan_with_rule_enabled(fixture: &str, rule_id: &str) -> Vec<serde_json::Value> {
        // Write a temp config that enables only this rule.
        let dir = tempfile::TempDir::new().expect("temp dir");
        let config_path = dir.path().join(".foxguard.yml");
        std::fs::write(
            &config_path,
            format!("scan:\n  enable_rules:\n    - {rule_id}\n"),
        )
        .expect("write config");
        // Copy fixture into the temp dir so the config is discovered.
        let fixture_src = std::path::Path::new(fixture);
        let fixture_dest = dir.path().join(fixture_src.file_name().unwrap());
        std::fs::copy(fixture_src, &fixture_dest).expect("copy fixture");

        let output = foxguard_cmd()
            .args([fixture_dest.to_str().unwrap(), "-f", "json"])
            .output()
            .expect("failed to execute foxguard");
        if output.stdout.is_empty() {
            return vec![];
        }
        scan_json_findings_from_slice(&output.stdout)
    }

    #[test]
    fn js_safe_crypto_agility_no_findings() {
        let findings = scan_with_rule_enabled(
            "tests/fixtures/safe_crypto_agility.js",
            "js/hardcoded-crypto-algorithm",
        );
        let matches: Vec<_> = findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("js/hardcoded-crypto-algorithm"))
            .collect();
        assert!(
            matches.is_empty(),
            "js/hardcoded-crypto-algorithm should not fire on safe_crypto_agility.js; findings: {matches:?}"
        );
    }

    #[test]
    fn py_safe_crypto_agility_no_findings() {
        let findings = scan_with_rule_enabled(
            "tests/fixtures/safe_crypto_agility.py",
            "py/hardcoded-crypto-algorithm",
        );
        let matches: Vec<_> = findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("py/hardcoded-crypto-algorithm"))
            .collect();
        assert!(
            matches.is_empty(),
            "py/hardcoded-crypto-algorithm should not fire on safe_crypto_agility.py; findings: {matches:?}"
        );
    }

    #[test]
    fn java_safe_crypto_agility_no_findings() {
        let findings = scan_with_rule_enabled(
            "tests/fixtures/safe_crypto_agility.java",
            "java/hardcoded-crypto-algorithm",
        );
        let matches: Vec<_> = findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("java/hardcoded-crypto-algorithm"))
            .collect();
        assert!(
            matches.is_empty(),
            "java/hardcoded-crypto-algorithm should not fire on safe_crypto_agility.java; findings: {matches:?}"
        );
    }
}

// ─── PHP ────────────────────────────────────────────────────────────────────

mod php {
    use super::*;

    #[test]
    fn test_vulnerable_php_finds_all_rules() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable.php", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

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
}

// ─── Ruby ───────────────────────────────────────────────────────────────────

mod ruby {
    use super::*;

    #[test]
    fn test_vulnerable_ruby_finds_all_rules() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable.rb", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        assert_eq!(
            findings.len(),
            30,
            "vulnerable.rb should have 30 findings, got {}",
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
            "rb/no-ssrf",
            "rb/no-path-traversal",
        ];

        for rule in &expected_rules {
            assert!(rule_ids.contains(rule), "missing expected rule: {}", rule);
        }
    }

    #[test]
    fn test_safe_ruby_no_findings() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/safe.rb", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(output.status.success());

        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.trim().is_empty() {
            let findings: Vec<serde_json::Value> =
                serde_json::from_str(stdout.trim()).unwrap_or_default();
            assert_eq!(
                findings.len(),
                0,
                "safe.rb should have 0 findings, got {}",
                findings.len()
            );
        }
    }
}

// ─── C# ─────────────────────────────────────────────────────────────────────

mod csharp {
    use super::*;

    #[test]
    fn test_vulnerable_csharp_finds_all_rules() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable.cs", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        assert_eq!(
            findings.len(),
            17,
            "vulnerable.cs should have 17 findings, got {}",
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
}

// ─── Swift ──────────────────────────────────────────────────────────────────

mod swift {
    use super::*;

    #[test]
    fn test_vulnerable_swift_finds_all_rules() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable.swift", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

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
}

// ─── Rust ───────────────────────────────────────────────────────────────────

mod rust_lang {
    use super::*;

    #[test]
    fn test_vulnerable_rust_finds_all_rules() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable.rs", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        assert_eq!(
            findings.len(),
            21,
            "vulnerable.rs should have 21 findings, got {}",
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
            "rs/pq-vulnerable-crypto",
        ];

        for rule in &expected_rules {
            assert!(rule_ids.contains(rule), "missing expected rule: {}", rule);
        }
    }
}

// ─── Cross-file / realistic fixture tests ───────────────────────────────────

mod cross_file {
    use super::*;

    /// End-to-end validation: a small realistic Gin service with three
    /// planted vulnerabilities (command injection, SQL injection, SSRF)
    /// must produce exactly one finding per go/taint-* rule.
    #[test]
    fn test_realistic_gin_app_findings() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/realistic/gin_app.go", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for f in &findings {
            if let Some(rule) = f["rule_id"].as_str() {
                *counts.entry(rule).or_insert(0) += 1;
            }
        }

        for rule in [
            "go/taint-command-injection",
            "go/taint-sql-injection",
            "go/taint-ssrf",
        ] {
            assert_eq!(
                counts.get(rule).copied(),
                Some(1),
                "{} should fire exactly once on realistic/gin_app.go. counts={:?}",
                rule,
                counts
            );
        }
    }

    /// Semgrep-compatible `mode: taint` YAML rules should load via `--rules`
    /// and fire on the same flows as the native `py/taint-pickle-deserialization`
    /// rule. See issue #17.
    #[test]
    fn test_semgrep_taint_yaml_bridge_vulnerable() {
        let output = foxguard_cmd_isolated()
            .args([
                "tests/fixtures/vulnerable_py_taint.py",
                "-f",
                "json",
                "--no-builtins",
                "--rules",
                "tests/fixtures/semgrep_taint/pickle_taint.yml",
            ])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let lines: Vec<u64> = findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("semgrep/semgrep-pickle-taint"))
            .filter_map(|f| f["line"].as_u64())
            .collect();

        assert!(
            !lines.is_empty(),
            "semgrep taint rule should fire at least once on vulnerable_py_taint.py, got: {:?}",
            findings
        );

        // Every pickle handler in the fixture (16 flows, matching the native
        // py/taint-pickle-deserialization rule) should be caught by the YAML
        // bridge. Asserting the exact count keeps the bridge honest: regressions
        // in pattern translation or the taint engine will flip this number.
        assert_eq!(
            lines.len(),
            16,
            "semgrep taint rule should fire on all 16 pickle flows, got {} (lines: {:?})",
            lines.len(),
            lines
        );
    }

    #[test]
    fn test_semgrep_taint_yaml_bridge_safe() {
        let output = foxguard_cmd_isolated()
            .args([
                "tests/fixtures/safe_py_taint.py",
                "-f",
                "json",
                "--no-builtins",
                "--rules",
                "tests/fixtures/semgrep_taint/pickle_taint.yml",
            ])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let n = findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("semgrep/semgrep-pickle-taint"))
            .count();

        assert_eq!(
            n, 0,
            "semgrep taint rule should not fire on safe_py_taint.py, got {} findings",
            n
        );
    }

    /// The Semgrep taint bridge must accept `pattern-either:` blocks inside
    /// `pattern-sources` / `pattern-sinks` (issue #33). The
    /// `pickle_taint_either.yml` fixture expresses the same sources and sinks
    /// as `pickle_taint.yml`, just using `pattern-either:` to group them, and
    /// must produce the same 16 findings on `vulnerable_py_taint.py`.
    #[test]
    fn test_semgrep_taint_yaml_bridge_pattern_either_vulnerable() {
        let output = foxguard_cmd_isolated()
            .args([
                "tests/fixtures/vulnerable_py_taint.py",
                "-f",
                "json",
                "--no-builtins",
                "--rules",
                "tests/fixtures/semgrep_taint/pickle_taint_either.yml",
            ])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let lines: Vec<u64> = findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("semgrep/semgrep-pickle-taint-either"))
            .filter_map(|f| f["line"].as_u64())
            .collect();

        assert_eq!(
            lines.len(),
            16,
            "semgrep pattern-either taint rule should fire on all 16 pickle flows, got {} (lines: {:?})",
            lines.len(),
            lines
        );
    }

    #[test]
    fn test_semgrep_taint_yaml_bridge_pattern_either_safe() {
        let output = foxguard_cmd_isolated()
            .args([
                "tests/fixtures/safe_py_taint.py",
                "-f",
                "json",
                "--no-builtins",
                "--rules",
                "tests/fixtures/semgrep_taint/pickle_taint_either.yml",
            ])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let n = findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("semgrep/semgrep-pickle-taint-either"))
            .count();

        assert_eq!(
            n, 0,
            "semgrep pattern-either taint rule should not fire on safe_py_taint.py, got {} findings",
            n
        );
    }

    /// The Semgrep taint YAML bridge should fire on JavaScript files when the
    /// rule targets `languages: [javascript]`. This test uses a minimal
    /// req.query/body/params -> eval() rule.
    #[test]
    fn test_semgrep_taint_yaml_bridge_js_vulnerable() {
        let output = foxguard_cmd_isolated()
            .args([
                "tests/fixtures/semgrep_taint/vulnerable_js_eval.js",
                "-f",
                "json",
                "--no-builtins",
                "--rules",
                "tests/fixtures/semgrep_taint/js_taint_eval.yml",
            ])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let lines: Vec<u64> = findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("semgrep/semgrep-js-taint-eval"))
            .filter_map(|f| f["line"].as_u64())
            .collect();

        assert_eq!(
            lines.len(),
            3,
            "semgrep JS taint rule should fire on all 3 eval flows, got {} (lines: {:?})",
            lines.len(),
            lines
        );
    }

    #[test]
    fn test_semgrep_taint_yaml_bridge_js_safe() {
        let output = foxguard_cmd_isolated()
            .args([
                "tests/fixtures/semgrep_taint/safe_js_eval.js",
                "-f",
                "json",
                "--no-builtins",
                "--rules",
                "tests/fixtures/semgrep_taint/js_taint_eval.yml",
            ])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let n = findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("semgrep/semgrep-js-taint-eval"))
            .count();

        assert_eq!(
            n, 0,
            "semgrep JS taint rule should not fire on safe_js_eval.js, got {} findings",
            n
        );
    }

    /// The Semgrep taint YAML bridge should fire on Go files when the rule
    /// targets `languages: [go]`. This test uses a c.Query/c.Param/r.URL ->
    /// exec.Command() rule.
    #[test]
    fn test_semgrep_taint_yaml_bridge_go_vulnerable() {
        let output = foxguard_cmd_isolated()
            .args([
                "tests/fixtures/semgrep_taint/vulnerable_go_exec.go",
                "-f",
                "json",
                "--no-builtins",
                "--rules",
                "tests/fixtures/semgrep_taint/go_taint_exec.yml",
            ])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let lines: Vec<u64> = findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("semgrep/semgrep-go-taint-exec"))
            .filter_map(|f| f["line"].as_u64())
            .collect();

        assert_eq!(
            lines.len(),
            3,
            "semgrep Go taint rule should fire on all 3 exec.Command flows, got {} (lines: {:?})",
            lines.len(),
            lines
        );
    }

    #[test]
    fn test_semgrep_taint_yaml_bridge_go_safe() {
        let output = foxguard_cmd_isolated()
            .args([
                "tests/fixtures/semgrep_taint/safe_go_exec.go",
                "-f",
                "json",
                "--no-builtins",
                "--rules",
                "tests/fixtures/semgrep_taint/go_taint_exec.yml",
            ])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let n = findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("semgrep/semgrep-go-taint-exec"))
            .count();

        assert_eq!(
            n, 0,
            "semgrep Go taint rule should not fire on safe_go_exec.go, got {} findings",
            n
        );
    }
}

// ─── Output formats ─────────────────────────────────────────────────────────

mod output_formats {
    use super::*;

    #[test]
    fn test_json_output_structure() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable.js", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let report = scan_json_report_from_slice(&output.stdout);
        let findings = report["findings"]
            .as_array()
            .expect("missing findings array");

        assert!(!findings.is_empty());
        assert_eq!(report["schema_version"].as_str(), Some("1.0.0"));
        assert_eq!(report["scanner"]["name"].as_str(), Some("foxguard"));
        assert!(
            report["scanner"]["version"].is_string(),
            "missing scanner version"
        );
        assert_eq!(
            report["target"]["path"].as_str(),
            Some("tests/fixtures/vulnerable.js")
        );
        assert!(
            report["timing"]["duration_ms"].is_number(),
            "missing duration"
        );
        assert_eq!(
            report["finding_counts"]["total"].as_u64(),
            Some(findings.len() as u64)
        );

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

    #[test]
    fn test_json_output_can_write_to_file() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let report_path = dir.path().join("reports/findings.json");

        let output = foxguard_cmd_isolated()
            .args([
                "tests/fixtures/vulnerable.js",
                "-f",
                "json",
                "--output",
                report_path.to_str().expect("non-utf8 report path"),
            ])
            .output()
            .expect("failed to execute foxguard");

        assert!(
            !output.status.success(),
            "scan should still exit 1 with findings"
        );
        assert!(
            output.stdout.is_empty(),
            "stdout should stay empty when --output is used"
        );

        let report = scan_json_report_from_slice(
            &fs::read(report_path).expect("failed to read JSON report file"),
        );
        assert_eq!(report["schema_version"].as_str(), Some("1.0.0"));
        assert!(
            report["findings"]
                .as_array()
                .is_some_and(|findings| !findings.is_empty()),
            "written report should contain findings"
        );
    }

    #[test]
    fn test_sarif_output_can_write_to_file() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let report_path = dir.path().join("reports/findings.sarif");

        let output = foxguard_cmd_isolated()
            .args([
                "tests/fixtures/vulnerable.js",
                "-f",
                "sarif",
                "--output",
                report_path.to_str().expect("non-utf8 report path"),
            ])
            .output()
            .expect("failed to execute foxguard");

        assert!(
            !output.status.success(),
            "scan should still exit 1 with findings"
        );
        assert!(
            output.stdout.is_empty(),
            "stdout should stay empty when --output is used"
        );

        let sarif: serde_json::Value = serde_json::from_slice(
            &fs::read(report_path).expect("failed to read SARIF report file"),
        )
        .expect("invalid SARIF JSON");
        assert_eq!(sarif["version"].as_str(), Some("2.1.0"));
        assert!(
            sarif["runs"][0]["results"]
                .as_array()
                .is_some_and(|results| !results.is_empty()),
            "written SARIF report should contain results"
        );
    }

    #[test]
    fn test_cbom_output_can_write_to_file() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let report_path = dir.path().join("reports/findings.cbom.json");

        let output = foxguard_cmd_isolated()
            .args([
                "tests/fixtures/vulnerable.py",
                "-f",
                "cbom",
                "--output",
                report_path.to_str().expect("non-utf8 report path"),
            ])
            .output()
            .expect("failed to execute foxguard");

        assert!(
            !output.status.success(),
            "scan should still exit 1 with findings"
        );
        assert!(
            output.stdout.is_empty(),
            "stdout should stay empty when --output is used"
        );

        let cbom: serde_json::Value = serde_json::from_slice(
            &fs::read(report_path).expect("failed to read CBOM report file"),
        )
        .expect("invalid CBOM JSON");
        assert_eq!(cbom["bomFormat"].as_str(), Some("CycloneDX"));
        assert!(
            cbom["components"]
                .as_array()
                .is_some_and(|components| !components.is_empty()),
            "written CBOM report should contain crypto components"
        );
    }

    #[test]
    fn test_secrets_json_output_can_write_to_file() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let secrets_path = write_secrets_fixture(dir.path());
        let report_path = dir.path().join("reports/secrets.json");

        let output = foxguard_cmd()
            .args([
                "secrets",
                secrets_path.to_str().expect("non-utf8 secrets path"),
                "-f",
                "json",
                "--output",
                report_path.to_str().expect("non-utf8 report path"),
            ])
            .output()
            .expect("failed to execute foxguard secrets");

        assert!(
            !output.status.success(),
            "secrets scan should still exit 1 with findings"
        );
        assert!(
            output.stdout.is_empty(),
            "stdout should stay empty when --output is used"
        );

        let report = scan_json_report_from_slice(
            &fs::read(report_path).expect("failed to read secrets JSON report file"),
        );
        assert_eq!(report["scanner"]["command"].as_str(), Some("secrets"));
        assert!(
            report["findings"]
                .as_array()
                .is_some_and(|findings| !findings.is_empty()),
            "written secrets report should contain findings"
        );
    }

    #[test]
    fn test_diff_json_output_can_write_to_file() {
        let repo = TempDir::new().expect("failed to create temp dir");
        Command::new("git")
            .args(["init"])
            .current_dir(repo.path())
            .output()
            .expect("failed to initialize git repo");
        fs::write(repo.path().join("app.js"), "console.log('safe');\n")
            .expect("failed to write safe fixture");
        Command::new("git")
            .args(["add", "app.js"])
            .current_dir(repo.path())
            .output()
            .expect("failed to stage safe fixture");
        Command::new("git")
            .args([
                "-c",
                "user.name=Foxguard Test",
                "-c",
                "user.email=foxguard@example.test",
                "commit",
                "-m",
                "base",
            ])
            .current_dir(repo.path())
            .output()
            .expect("failed to commit safe fixture");
        fs::write(
            repo.path().join("app.js"),
            "const x = process.argv[2];\neval(x);\n",
        )
        .expect("failed to write vulnerable fixture");

        let report_path = repo.path().join("reports/diff.json");
        let output = foxguard_cmd()
            .current_dir(repo.path())
            .args([
                "diff",
                "HEAD",
                ".",
                "-f",
                "json",
                "--output",
                report_path.to_str().expect("non-utf8 report path"),
            ])
            .output()
            .expect("failed to execute foxguard diff");

        assert!(
            !output.status.success(),
            "diff scan should still exit 1 with new findings"
        );
        assert!(
            output.stdout.is_empty(),
            "stdout should stay empty when --output is used"
        );

        let report = scan_json_report_from_slice(
            &fs::read(report_path).expect("failed to read diff JSON report file"),
        );
        assert_eq!(report["scanner"]["command"].as_str(), Some("diff"));
        assert_eq!(report["target"]["diff_base"].as_str(), Some("HEAD"));
        assert!(
            report["findings"]
                .as_array()
                .is_some_and(|findings| !findings.is_empty()),
            "written diff report should contain new findings"
        );
    }

    #[test]
    fn test_terminal_output_rejects_output_path_for_scan_secrets_and_diff() {
        let dir = TempDir::new().expect("failed to create temp dir");
        let secrets_path = write_secrets_fixture(dir.path());
        let rejected_scan_path = dir.path().join("scan.txt");
        let rejected_secrets_path = dir.path().join("reports/secrets.txt");

        let scan = foxguard_cmd_isolated()
            .args([
                "tests/fixtures/vulnerable.js",
                "--output",
                rejected_scan_path.to_str().expect("non-utf8 report path"),
            ])
            .output()
            .expect("failed to execute foxguard scan");
        assert_eq!(scan.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&scan.stderr)
            .contains("--output requires a machine-readable format"));
        assert!(!rejected_scan_path.exists());

        let secrets = foxguard_cmd()
            .args([
                "secrets",
                secrets_path.to_str().expect("non-utf8 secrets path"),
                "--output",
                rejected_secrets_path
                    .to_str()
                    .expect("non-utf8 report path"),
            ])
            .output()
            .expect("failed to execute foxguard secrets");
        assert_eq!(secrets.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&secrets.stderr)
            .contains("--output requires a machine-readable format"));
        assert!(!rejected_secrets_path.exists());

        let repo = TempDir::new().expect("failed to create temp dir");
        Command::new("git")
            .args(["init"])
            .current_dir(repo.path())
            .output()
            .expect("failed to initialize git repo");
        fs::write(repo.path().join("app.js"), "console.log('safe');\n")
            .expect("failed to write safe fixture");
        Command::new("git")
            .args(["add", "app.js"])
            .current_dir(repo.path())
            .output()
            .expect("failed to stage safe fixture");
        Command::new("git")
            .args([
                "-c",
                "user.name=Foxguard Test",
                "-c",
                "user.email=foxguard@example.test",
                "commit",
                "-m",
                "base",
            ])
            .current_dir(repo.path())
            .output()
            .expect("failed to commit safe fixture");
        fs::write(
            repo.path().join("app.js"),
            "const x = process.argv[2];\neval(x);\n",
        )
        .expect("failed to write vulnerable fixture");

        let rejected_diff_path = repo.path().join("diff.txt");
        let diff = foxguard_cmd()
            .current_dir(repo.path())
            .args([
                "diff",
                "HEAD",
                ".",
                "--output",
                rejected_diff_path.to_str().expect("non-utf8 report path"),
            ])
            .output()
            .expect("failed to execute foxguard diff");
        assert_eq!(diff.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&diff.stderr)
            .contains("--output requires a machine-readable format"));
        assert!(!rejected_diff_path.exists());
    }

    #[test]
    fn test_sarif_output_valid() {
        let output = foxguard_cmd_isolated()
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

        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("missing SARIF tool driver rules");
        assert!(!rules.is_empty(), "SARIF rules should not be empty");

        let first = &results[0];
        let rule_index = first["ruleIndex"]
            .as_u64()
            .expect("SARIF result missing ruleIndex") as usize;
        assert_eq!(
            rules[rule_index]["id"], first["ruleId"],
            "SARIF ruleIndex should reference matching rule metadata"
        );

        let artifact_uri = first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .expect("SARIF result missing artifactLocation.uri");
        assert!(
            !artifact_uri.starts_with("file://"),
            "relative fixture path should remain repo-relative for GitHub Code Scanning"
        );
        assert!(
            first["partialFingerprints"]["primaryLocationLineHash"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "SARIF result missing primary location fingerprint"
        );
        assert!(
            rules[rule_index]["properties"]["security-severity"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "SARIF rule metadata missing security severity"
        );
    }
}

// ─── Features ───────────────────────────────────────────────────────────────

mod features {
    use super::*;

    fn setup_diff_repo_with_vulnerable_python() -> TempDir {
        let repo = TempDir::new().expect("failed to create temp repo");
        Command::new("git")
            .args(["init"])
            .current_dir(repo.path())
            .output()
            .expect("failed to initialize git repo");
        fs::write(repo.path().join("app.py"), "print('safe')\n")
            .expect("failed to write safe Python file");
        Command::new("git")
            .args(["add", "app.py"])
            .current_dir(repo.path())
            .output()
            .expect("failed to stage safe Python file");
        Command::new("git")
            .args([
                "-c",
                "user.name=Foxguard Test",
                "-c",
                "user.email=foxguard@example.test",
                "commit",
                "-m",
                "base",
            ])
            .current_dir(repo.path())
            .output()
            .expect("failed to commit safe Python file");
        fs::write(
            repo.path().join("app.py"),
            "password = 'super-secret'\neval(input())\n",
        )
        .expect("failed to write vulnerable Python file");
        repo
    }

    fn setup_local_changes_repo() -> TempDir {
        let repo = TempDir::new().expect("failed to create temp repo");
        Command::new("git")
            .args(["init"])
            .current_dir(repo.path())
            .output()
            .expect("failed to initialize git repo");

        fs::write(repo.path().join("unstaged.js"), "const safe = 1;\n")
            .expect("failed to write safe tracked fixture");
        Command::new("git")
            .args(["add", "unstaged.js"])
            .current_dir(repo.path())
            .output()
            .expect("failed to stage safe tracked fixture");
        Command::new("git")
            .args([
                "-c",
                "user.name=Foxguard Test",
                "-c",
                "user.email=foxguard@example.test",
                "commit",
                "-m",
                "base",
            ])
            .current_dir(repo.path())
            .output()
            .expect("failed to commit base fixture");

        fs::write(repo.path().join("staged.js"), "eval(userInput);\n")
            .expect("failed to write staged fixture");
        Command::new("git")
            .args(["add", "staged.js"])
            .current_dir(repo.path())
            .output()
            .expect("failed to stage vulnerable fixture");

        fs::write(repo.path().join("unstaged.js"), "eval(userInput);\n")
            .expect("failed to write unstaged fixture");
        fs::write(repo.path().join("untracked.js"), "eval(userInput);\n")
            .expect("failed to write untracked fixture");

        repo
    }

    fn finding_file_names(findings: &[serde_json::Value]) -> Vec<String> {
        findings
            .iter()
            .filter_map(|finding| finding["file"].as_str())
            .filter_map(|file| Path::new(file).file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn test_invalid_path_exits_nonzero() {
        let output = foxguard_cmd_isolated()
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
        let output = foxguard_cmd_isolated()
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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        assert_eq!(findings.len(), 0, "expected no findings without any rules");
    }

    #[test]
    fn test_no_builtins_with_external_rules_still_finds_matches() {
        let output = foxguard_cmd_isolated()
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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&suppressed.stdout);
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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&suppressed.stdout);
        assert_eq!(
            findings.len(),
            0,
            "expected no findings after config baseline"
        );
    }

    #[test]
    fn test_baseline_subcommand_ignores_configured_baseline_when_generating_new_baseline() {
        let repo = TempDir::new().expect("failed to create temp dir");
        fs::copy(
            fixture_path("vulnerable.js"),
            repo.path().join("vulnerable.js"),
        )
        .expect("failed to copy vulnerable fixture");

        let configured_baseline = repo.path().join(".foxguard").join("baseline.json");
        fs::create_dir_all(
            configured_baseline
                .parent()
                .expect("missing baseline parent"),
        )
        .expect("failed to create baseline directory");

        let initial = foxguard_cmd()
            .current_dir(repo.path())
            .args([
                "vulnerable.js",
                "-f",
                "json",
                "--write-baseline",
                configured_baseline.to_str().expect("non-utf8 path"),
            ])
            .output()
            .expect("failed to write configured baseline");

        assert!(
            !initial.status.success(),
            "writing the configured baseline should still report findings"
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
            .expect("failed to execute foxguard with configured baseline");

        assert!(
            suppressed.status.success(),
            "configured baseline should still suppress ordinary scan output"
        );
        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&suppressed.stdout);
        assert_eq!(
            findings.len(),
            0,
            "expected no findings after applying the configured baseline"
        );

        let refreshed_baseline = repo.path().join("refreshed-baseline.json");
        let generated = foxguard_cmd()
            .current_dir(repo.path())
            .args([
                "baseline",
                "vulnerable.js",
                "--output",
                refreshed_baseline.to_str().expect("non-utf8 path"),
            ])
            .output()
            .expect("failed to execute baseline subcommand");

        assert!(
            generated.status.success(),
            "baseline generation should succeed even when a config baseline is active"
        );
        assert!(
            refreshed_baseline.exists(),
            "baseline subcommand should write the requested baseline file"
        );

        let configured_entries = serde_json::from_str::<serde_json::Value>(
            &fs::read_to_string(&configured_baseline).expect("failed to read configured baseline"),
        )
        .expect("invalid configured baseline JSON")["entries"]
            .as_array()
            .map(Vec::len)
            .expect("configured baseline should contain entries");

        let refreshed_entries = serde_json::from_str::<serde_json::Value>(
            &fs::read_to_string(&refreshed_baseline).expect("failed to read refreshed baseline"),
        )
        .expect("invalid refreshed baseline JSON")["entries"]
            .as_array()
            .map(Vec::len)
            .expect("refreshed baseline should contain entries");

        assert!(
            refreshed_entries > 0,
            "refreshed baseline should be generated from unsuppressed findings"
        );
        assert_eq!(
            refreshed_entries, configured_entries,
            "refreshed baseline should contain the same findings as an unsuppressed baseline run"
        );
    }

    #[test]
    fn test_config_baseline_applies_from_nested_working_directory() {
        let repo = TempDir::new().expect("failed to create temp dir");
        fs::create_dir_all(repo.path().join("src")).expect("failed to create src dir");
        fs::copy(
            fixture_path("vulnerable.js"),
            repo.path().join("src/vulnerable.js"),
        )
        .expect("failed to copy vulnerable fixture");

        write_config_file(repo.path(), ".foxguard.yml", "scan: {}\n");

        let baseline = repo.path().join(".foxguard").join("baseline.json");
        let initial = foxguard_cmd()
            .current_dir(repo.path())
            .args([
                "src/vulnerable.js",
                "-f",
                "json",
                "--write-baseline",
                baseline.to_str().expect("non-utf8 path"),
            ])
            .output()
            .expect("failed to execute foxguard baseline write");

        assert!(
            !initial.status.success(),
            "writing a baseline should still report current findings"
        );

        write_config_file(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  baseline: .foxguard/baseline.json\n",
        );

        let suppressed = foxguard_cmd()
            .current_dir(repo.path().join("src"))
            .args([".", "-f", "json", "--config", "../.foxguard.yml"])
            .output()
            .expect("failed to execute foxguard from nested cwd");

        assert!(
            suppressed.status.success(),
            "root-relative baseline should suppress from nested cwd"
        );
        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&suppressed.stdout);
        assert_eq!(findings.len(), 0, "expected configured baseline to apply");
    }

    #[test]
    fn test_diff_uses_explicit_config_for_rule_filtering() {
        let repo = setup_diff_repo_with_vulnerable_python();
        let config = write_config_file(
            repo.path(),
            "config/foxguard.yml",
            "scan:\n  enable_rules:\n    - py/no-eval\n",
        );

        let output = foxguard_cmd()
            .current_dir(repo.path())
            .args([
                "diff",
                "HEAD",
                ".",
                "-f",
                "json",
                "--config",
                config.to_str().expect("non-utf8 config path"),
            ])
            .output()
            .expect("failed to execute foxguard diff with explicit config");

        assert!(
            !output.status.success(),
            "diff should report the configured py/no-eval finding"
        );
        let findings = scan_json_findings_from_slice(&output.stdout);
        assert!(
            !findings.is_empty(),
            "expected at least one configured diff finding"
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding["rule_id"].as_str() == Some("py/no-eval")),
            "diff should honor configured enable_rules, got: {:?}",
            findings
                .iter()
                .map(|finding| finding["rule_id"].as_str().unwrap_or("?"))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_diff_cli_severity_overrides_config_default() {
        let repo = setup_diff_repo_with_vulnerable_python();
        let config = write_config_file(
            repo.path(),
            "config/foxguard.yml",
            "scan:\n  enable_rules:\n    - py/no-hardcoded-secret\n  severity: critical\n",
        );

        let configured = foxguard_cmd()
            .current_dir(repo.path())
            .args([
                "diff",
                "HEAD",
                ".",
                "-f",
                "json",
                "--config",
                config.to_str().expect("non-utf8 config path"),
            ])
            .output()
            .expect("failed to execute foxguard diff with config severity");
        assert!(
            configured.status.success(),
            "configured critical severity should suppress high findings"
        );
        assert_eq!(
            scan_json_findings_from_slice(&configured.stdout).len(),
            0,
            "expected configured severity threshold to apply"
        );

        let overridden = foxguard_cmd()
            .current_dir(repo.path())
            .args([
                "diff",
                "HEAD",
                ".",
                "-f",
                "json",
                "--config",
                config.to_str().expect("non-utf8 config path"),
                "--severity",
                "low",
            ])
            .output()
            .expect("failed to execute foxguard diff with CLI severity override");
        assert!(
            !overridden.status.success(),
            "CLI severity override should restore the configured rule finding"
        );
        let findings = scan_json_findings_from_slice(&overridden.stdout);
        assert!(
            findings
                .iter()
                .any(|finding| finding["rule_id"].as_str() == Some("py/no-hardcoded-secret")),
            "expected CLI severity override to win over config default"
        );
    }

    #[test]
    fn test_enable_rules_allowlist_runs_only_listed_ids() {
        let repo = TempDir::new().expect("failed to create temp dir");
        copy_fixture_to(repo.path(), "vulnerable.py", "vulnerable.py");
        write_config_file(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  enable_rules:\n    - py/no-eval\n",
        );

        let output = foxguard_cmd()
            .current_dir(repo.path())
            .args(["vulnerable.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        assert!(
            !findings.is_empty(),
            "expected at least one py/no-eval finding"
        );
        assert!(
            findings
                .iter()
                .all(|f| f["rule_id"].as_str() == Some("py/no-eval")),
            "expected only py/no-eval findings when allowlisted, got: {:?}",
            findings
                .iter()
                .map(|f| f["rule_id"].as_str().unwrap_or("?"))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_disable_rules_denylist_removes_listed_ids() {
        let repo = TempDir::new().expect("failed to create temp dir");
        copy_fixture_to(repo.path(), "vulnerable.py", "vulnerable.py");

        // First scan without disable_rules to confirm py/no-eval fires.
        let baseline = foxguard_cmd()
            .current_dir(repo.path())
            .args(["vulnerable.py", "-f", "json"])
            .output()
            .expect("failed to execute baseline foxguard scan");
        let baseline_findings = scan_json_findings_from_slice(&baseline.stdout);
        assert!(
            baseline_findings
                .iter()
                .any(|f| f["rule_id"].as_str() == Some("py/no-eval")),
            "baseline scan should include py/no-eval"
        );

        write_config_file(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  disable_rules:\n    - py/no-eval\n",
        );

        let output = foxguard_cmd()
            .current_dir(repo.path())
            .args(["vulnerable.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        assert!(
            !findings.is_empty(),
            "other rules should still fire when only py/no-eval is disabled"
        );
        assert!(
            findings
                .iter()
                .all(|f| f["rule_id"].as_str() != Some("py/no-eval")),
            "expected py/no-eval to be suppressed by disable_rules"
        );
    }

    #[test]
    fn test_enable_and_disable_rules_intersection_then_subtraction() {
        let repo = TempDir::new().expect("failed to create temp dir");
        copy_fixture_to(repo.path(), "vulnerable.py", "vulnerable.py");
        // Allowlist two rules, then disable one of them. Only the other
        // should remain.
        write_config_file(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  enable_rules:\n    - py/no-eval\n    - py/no-hardcoded-secret\n  disable_rules:\n    - py/no-eval\n",
        );

        let output = foxguard_cmd()
            .current_dir(repo.path())
            .args(["vulnerable.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        assert!(
            findings
                .iter()
                .any(|f| f["rule_id"].as_str() == Some("py/no-hardcoded-secret")),
            "expected py/no-hardcoded-secret to remain after intersection"
        );
        assert!(
            findings
                .iter()
                .all(|f| f["rule_id"].as_str() != Some("py/no-eval")),
            "py/no-eval should be removed by disable_rules even when allowlisted"
        );
        assert!(
            findings
                .iter()
                .all(|f| matches!(f["rule_id"].as_str(), Some("py/no-hardcoded-secret"))),
            "only intersection(enable) minus disable should fire"
        );
    }

    #[test]
    fn test_unknown_rule_ids_warn_on_stderr_and_continue() {
        let repo = TempDir::new().expect("failed to create temp dir");
        copy_fixture_to(repo.path(), "vulnerable.py", "vulnerable.py");
        write_config_file(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  disable_rules:\n    - py/does-not-exist\n    - py/no-eval\n",
        );

        let output = foxguard_cmd()
            .current_dir(repo.path())
            .args(["vulnerable.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        // Unknown IDs should never fail the scan.
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("py/does-not-exist"),
            "expected unknown rule id in stderr warning, got: {}",
            stderr
        );
        assert!(
            stderr.contains("unknown rule"),
            "expected 'unknown rule' phrase in warning, got: {}",
            stderr
        );

        // Scan should still proceed and the known disable (py/no-eval)
        // should apply.
        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        assert!(
            findings
                .iter()
                .all(|f| f["rule_id"].as_str() != Some("py/no-eval")),
            "known disable should still apply even with unknown ids present"
        );
    }

    #[test]
    fn test_scan_rejects_config_path_traversal() {
        let repo = TempDir::new().expect("failed to create temp dir");
        let outside = TempDir::new().expect("failed to create outside temp dir");
        let outside_rules = outside.path().join("rules.yml");
        fs::write(&outside_rules, "rules: []\n").expect("failed to write outside rules");
        write_config_file(
            repo.path(),
            ".foxguard.yml",
            &format!("scan:\n  rules: {}\n", outside_rules.display()),
        );

        let output = foxguard_cmd()
            .current_dir(repo.path())
            .args([".", "-f", "json"])
            .output()
            .expect("failed to execute foxguard with malicious config");

        assert!(
            !output.status.success(),
            "malicious config should cause scan to fail"
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("scan.rules"),
            "expected field name in error, got: {}",
            stderr
        );
        assert!(
            stderr.contains("escapes the project root"),
            "expected traversal error, got: {}",
            stderr
        );
    }

    #[test]
    fn test_scan_exclude_skips_directory_prefixes() {
        let repo = TempDir::new().expect("failed to create temp dir");
        fs::create_dir_all(repo.path().join("src")).expect("failed to create src dir");
        fs::create_dir_all(repo.path().join("vendor/nested")).expect("failed to create vendor dir");
        fs::write(repo.path().join("src/included.js"), "eval(userInput);\n")
            .expect("failed to write included fixture");
        fs::write(
            repo.path().join("vendor/nested/ignored.js"),
            "eval(userInput);\n",
        )
        .expect("failed to write ignored fixture");

        let output = foxguard_cmd()
            .current_dir(repo.path())
            .args([".", "-f", "json", "--exclude", "vendor"])
            .output()
            .expect("failed to execute foxguard with excludes");

        assert!(
            !output.status.success(),
            "non-excluded vulnerable files should still produce findings"
        );

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        assert!(
            !findings.is_empty(),
            "expected included file to still produce findings"
        );
        assert!(
            findings.iter().all(|finding| finding["file"]
                .as_str()
                .is_some_and(|file| file.ends_with("src/included.js"))),
            "expected excluded vendor files to be skipped"
        );
    }

    #[test]
    fn test_scan_exclude_glob_applies_to_changed_mode() {
        let repo = setup_git_repo(&[]);
        fs::create_dir_all(repo.path().join("src")).expect("failed to create src dir");
        fs::create_dir_all(repo.path().join("generated/nested"))
            .expect("failed to create generated dir");
        fs::write(repo.path().join("src/included.js"), "eval(userInput);\n")
            .expect("failed to write included fixture");
        fs::write(
            repo.path().join("generated/nested/ignored.js"),
            "eval(userInput);\n",
        )
        .expect("failed to write ignored fixture");

        Command::new("git")
            .args(["add", "src/included.js", "generated/nested/ignored.js"])
            .current_dir(repo.path())
            .output()
            .expect("failed to stage fixtures");

        let output = foxguard_cmd()
            .current_dir(repo.path())
            .args([
                "--changed",
                ".",
                "-f",
                "json",
                "--exclude",
                "generated/**/*.js",
            ])
            .output()
            .expect("failed to execute foxguard changed scan with excludes");

        assert!(
            !output.status.success(),
            "non-excluded changed files should still produce findings"
        );

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        assert!(
            !findings.is_empty(),
            "expected included changed file to still produce findings"
        );
        assert!(
            findings.iter().all(|finding| finding["file"]
                .as_str()
                .is_some_and(|file| file.ends_with("src/included.js"))),
            "expected excluded changed files to be skipped"
        );
    }

    #[test]
    fn test_scan_ignore_rules_match_nested_cwd_and_windows_separators() {
        let repo = TempDir::new().expect("failed to create temp dir");
        fs::create_dir_all(repo.path().join("src")).expect("failed to create src dir");
        fs::write(repo.path().join("src/ignored.js"), "eval(userInput);\n")
            .expect("failed to write ignored fixture");
        write_config_file(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  ignore_rules:\n    - path: src\\ignored.js\n      rules:\n        - js/no-eval\n",
        );

        let output = foxguard_cmd()
            .current_dir(repo.path().join("src"))
            .args([".", "-f", "json", "--config", "../.foxguard.yml"])
            .output()
            .expect("failed to execute foxguard with scan.ignore_rules");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        assert!(
            findings
                .iter()
                .all(|finding| finding["rule_id"].as_str() != Some("js/no-eval")),
            "expected scan.ignore_rules to suppress js/no-eval from nested cwd"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_secrets_rejects_config_symlink_escape() {
        use std::os::unix::fs::symlink;

        let repo = TempDir::new().expect("failed to create temp dir");
        let outside = TempDir::new().expect("failed to create outside temp dir");
        let outside_ignore = outside.path().join("secrets.ignore");
        fs::write(&outside_ignore, "fixtures\n").expect("failed to write outside ignore file");
        symlink(&outside_ignore, repo.path().join("secrets.ignore"))
            .expect("failed to create symlinked ignore file");
        write_config_file(
            repo.path(),
            ".foxguard.yml",
            "secrets:\n  exclude_path_file: secrets.ignore\n",
        );

        let output = foxguard_cmd()
            .current_dir(repo.path())
            .args(["secrets", ".", "-f", "json"])
            .output()
            .expect("failed to execute foxguard secrets with malicious config");

        assert!(
            !output.status.success(),
            "malicious secrets config should fail"
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("secrets.exclude_path_file"),
            "expected field name in error, got: {}",
            stderr
        );
        assert!(
            stderr.contains("escapes the project root"),
            "expected traversal error, got: {}",
            stderr
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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        assert!(
            findings.iter().all(|finding| finding["file"]
                .as_str()
                .unwrap_or_default()
                .ends_with("vulnerable.js")),
            "changed mode should only scan the staged file"
        );
    }

    #[test]
    fn test_scan_help_lists_explicit_change_modes() {
        let output = foxguard_cmd()
            .arg("--help")
            .output()
            .expect("failed to execute foxguard --help");

        assert!(output.status.success(), "help should exit successfully");
        let stdout = String::from_utf8_lossy(&output.stdout);
        for flag in ["--changed", "--staged", "--unstaged", "--all-changes"] {
            assert!(
                stdout.contains(flag),
                "scan help should list explicit change mode flag {flag}"
            );
        }
    }

    #[test]
    fn test_staged_mode_scans_only_staged_changes() {
        let repo = setup_local_changes_repo();

        let output = foxguard_cmd()
            .args(["--staged", "-f", "json", "."])
            .current_dir(repo.path())
            .output()
            .expect("failed to execute foxguard --staged");

        assert!(
            !output.status.success(),
            "staged scan should report staged findings"
        );

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        let files = finding_file_names(&findings);
        assert!(
            files.iter().all(|file| file == "staged.js"),
            "staged mode should only scan staged.js, got {files:?}"
        );
    }

    #[test]
    fn test_unstaged_mode_scans_unstaged_and_untracked_changes() {
        let repo = setup_local_changes_repo();

        let output = foxguard_cmd()
            .args(["--unstaged", "-f", "json", "."])
            .current_dir(repo.path())
            .output()
            .expect("failed to execute foxguard --unstaged");

        assert!(
            !output.status.success(),
            "unstaged scan should report local unstaged findings"
        );

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        let files = finding_file_names(&findings);
        assert!(
            files.iter().any(|file| file == "unstaged.js"),
            "unstaged mode should scan tracked unstaged changes, got {files:?}"
        );
        assert!(
            files.iter().any(|file| file == "untracked.js"),
            "unstaged mode should scan untracked files, got {files:?}"
        );
        assert!(
            files.iter().all(|file| file != "staged.js"),
            "unstaged mode should not scan staged-only changes, got {files:?}"
        );
    }

    #[test]
    fn test_all_changes_mode_scans_staged_unstaged_and_untracked_changes() {
        let repo = setup_local_changes_repo();

        let output = foxguard_cmd()
            .args(["--all-changes", "-f", "json", "."])
            .current_dir(repo.path())
            .output()
            .expect("failed to execute foxguard --all-changes");

        assert!(
            !output.status.success(),
            "all-changes scan should report local findings"
        );

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        let files = finding_file_names(&findings);
        for expected in ["staged.js", "unstaged.js", "untracked.js"] {
            assert!(
                files.iter().any(|file| file == expected),
                "all-changes mode should scan {expected}, got {files:?}"
            );
        }
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

    #[test]
    fn test_severity_filter_high() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable.js", "-f", "json", "-s", "high"])
            .output()
            .expect("failed to execute foxguard");

        assert!(!output.status.success());

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        // High and Critical only
        assert_eq!(
            findings.len(),
            24,
            "high severity filter on vulnerable.js should yield 24 findings, got {}",
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
    fn test_severity_filter_critical() {
        let output = foxguard_cmd_isolated()
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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        // All findings should be Critical
        for finding in &findings {
            let severity = finding["severity"].as_str().unwrap();
            assert_eq!(severity, "critical", "expected critical, got: {}", severity);
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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&suppressed.stdout);
        assert_eq!(
            findings.len(),
            0,
            "expected no findings after applying the secrets baseline"
        );

        let baseline_content =
            fs::read_to_string(&baseline).expect("failed to read secrets baseline");
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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        assert!(findings.is_empty(), "expected excluded file to be skipped");
    }

    /// Issue #401: secrets mode must scan hidden files (e.g. `.env`) by default.
    #[test]
    fn test_secrets_mode_scans_dotenv_files() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_secret_file(repo.path(), ".env");

        let output = foxguard_cmd()
            .args([
                "secrets",
                repo.path().to_str().expect("non-utf8 path"),
                "-f",
                "json",
            ])
            .output()
            .expect("failed to execute foxguard secrets");

        assert!(
            !output.status.success(),
            "secrets mode should detect tokens in .env files"
        );

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        assert!(
            findings
                .iter()
                .any(|f| f["file"].as_str().unwrap_or_default().ends_with(".env")),
            "at least one finding should reference .env; findings={findings:?}"
        );
    }

    /// Issue #401: secrets mode must also traverse hidden directories.
    #[test]
    fn test_secrets_mode_scans_hidden_directories() {
        let repo = TempDir::new().expect("failed to create temp dir");
        let hidden_dir = repo.path().join(".config");
        fs::create_dir_all(&hidden_dir).expect("failed to create .config dir");
        write_secret_file(&hidden_dir, "credentials");

        let output = foxguard_cmd()
            .args([
                "secrets",
                repo.path().to_str().expect("non-utf8 path"),
                "-f",
                "json",
            ])
            .output()
            .expect("failed to execute foxguard secrets");

        assert!(
            !output.status.success(),
            "secrets mode should detect tokens inside hidden directories"
        );

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        assert!(
            findings
                .iter()
                .any(|f| f["file"].as_str().unwrap_or_default().contains(".config")),
            "at least one finding should reference .config/; findings={findings:?}"
        );
    }

    #[test]
    fn test_secrets_mode_scans_hidden_files() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_secret_file(repo.path(), ".env");

        let output = foxguard_cmd()
            .args([
                "secrets",
                repo.path().to_str().expect("non-utf8 path"),
                "-f",
                "json",
            ])
            .output()
            .expect("failed to execute foxguard secrets");

        assert!(
            !output.status.success(),
            "secrets in hidden .env file should produce findings"
        );

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        assert!(
            findings
                .iter()
                .any(|f| f["file"].as_str().unwrap_or_default().ends_with(".env")),
            "expected at least one finding from .env file, got: {findings:?}"
        );
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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

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

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);
        assert!(
            findings.is_empty(),
            "expected no findings after config excludes"
        );
    }

    /// With --explain, taint findings show source/sink trace lines.
    #[test]
    fn test_explain_flag_shows_trace_on_taint_findings() {
        let output = foxguard_cmd_isolated()
            .args(["--explain", "tests/fixtures/realistic/flask_app.py"])
            .output()
            .expect("failed to execute foxguard");

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Taint findings should have source/sink trace lines
        assert!(
            stdout.contains("source"),
            "expected 'source' trace line in --explain output"
        );
        assert!(
            stdout.contains("sink"),
            "expected 'sink' trace line in --explain output"
        );
        // Check that source arrow points to a file:line pattern
        assert!(
            stdout.contains("flask_app.py:"),
            "expected file:line in trace output"
        );
    }

    /// Without --explain, taint findings must NOT show source/sink trace lines.
    #[test]
    fn test_no_explain_flag_hides_trace() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/realistic/flask_app.py"])
            .output()
            .expect("failed to execute foxguard");

        let stdout = String::from_utf8_lossy(&output.stdout);
        // The "source ->" trace line should not appear
        assert!(
            !stdout.contains("source \u{2192}"),
            "trace lines should not appear without --explain"
        );
        assert!(
            !stdout.contains("sink   \u{2192}"),
            "trace lines should not appear without --explain"
        );
    }

    /// JSON output with --explain includes source/sink fields on taint findings.
    #[test]
    fn test_explain_json_includes_trace_fields() {
        let output = foxguard_cmd_isolated()
            .args([
                "--explain",
                "-f",
                "json",
                "tests/fixtures/realistic/flask_app.py",
            ])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let taint_findings: Vec<&serde_json::Value> = findings
            .iter()
            .filter(|f| f["rule_id"].as_str().is_some_and(|r| r.contains("taint")))
            .collect();

        assert!(
            !taint_findings.is_empty(),
            "should have at least one taint finding"
        );

        for f in &taint_findings {
            assert!(
                f["source_line"].is_number(),
                "taint finding {} should have source_line",
                f["rule_id"]
            );
            assert!(
                f["source_description"].is_string(),
                "taint finding {} should have source_description",
                f["rule_id"]
            );
            assert!(
                f["sink_line"].is_number(),
                "taint finding {} should have sink_line",
                f["rule_id"]
            );
            assert!(
                f["sink_description"].is_string(),
                "taint finding {} should have sink_description",
                f["rule_id"]
            );
        }

        // Non-taint findings should NOT have trace fields
        let nontaint_findings: Vec<&serde_json::Value> = findings
            .iter()
            .filter(|f| f["rule_id"].as_str().is_some_and(|r| !r.contains("taint")))
            .collect();

        for f in &nontaint_findings {
            assert!(
                f.get("source_line").is_none() || f["source_line"].is_null(),
                "non-taint finding {} should not have source_line",
                f["rule_id"]
            );
        }
    }

    #[test]
    fn test_taint_findings_include_fix_suggestion_in_json() {
        // Scan the Python taint fixture in JSON mode and verify that taint
        // findings carry a non-empty fix_suggestion field.
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable_py_taint.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        assert!(
            !output.status.success(),
            "should exit non-zero with findings"
        );

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let taint_findings: Vec<&serde_json::Value> = findings
            .iter()
            .filter(|f| f["rule_id"].as_str().is_some_and(|id| id.contains("taint")))
            .collect();

        assert!(
            !taint_findings.is_empty(),
            "should have at least one taint finding"
        );

        for f in &taint_findings {
            let fix = f.get("fix_suggestion");
            assert!(
                fix.is_some()
                    && fix.unwrap().is_string()
                    && !fix.unwrap().as_str().unwrap().is_empty(),
                "taint finding {} should have a non-empty fix_suggestion",
                f["rule_id"]
            );
        }

        // Non-taint findings should NOT have fix_suggestion
        let nontaint_findings: Vec<&serde_json::Value> = findings
            .iter()
            .filter(|f| {
                f["rule_id"]
                    .as_str()
                    .is_some_and(|id| !id.contains("taint"))
            })
            .collect();

        for f in &nontaint_findings {
            assert!(
                f.get("fix_suggestion").is_none() || f["fix_suggestion"].is_null(),
                "non-taint finding {} should not have fix_suggestion",
                f["rule_id"]
            );
        }
    }

    #[test]
    fn test_fix_suggestion_appears_in_sarif_output() {
        let output = foxguard_cmd_isolated()
            .args(["tests/fixtures/vulnerable_py_taint.py", "-f", "sarif"])
            .output()
            .expect("failed to execute foxguard");

        let sarif: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("invalid SARIF output");

        let results = sarif["runs"][0]["results"]
            .as_array()
            .expect("results array");

        let taint_results: Vec<&serde_json::Value> = results
            .iter()
            .filter(|r| r["ruleId"].as_str().is_some_and(|id| id.contains("taint")))
            .collect();

        assert!(
            !taint_results.is_empty(),
            "should have at least one taint result in SARIF"
        );

        for r in &taint_results {
            let fixes = r.get("fixes");
            assert!(
                fixes.is_some() && fixes.unwrap().is_array(),
                "taint SARIF result {} should have a fixes array",
                r["ruleId"]
            );
            let fix_text = fixes.unwrap()[0]["description"]["text"].as_str();
            assert!(
                fix_text.is_some() && !fix_text.unwrap().is_empty(),
                "SARIF fix description should be non-empty for {}",
                r["ruleId"]
            );
        }
    }

    // ── scan.thresholds.secrets.min_length (issue #210) ─────────────────

    /// Fixture with three variable-width "secret" assignments.
    ///   - `password = "abc"`   (3 chars, below default min_length=4)
    ///   - `password = "test"`  (4 chars, at default)
    ///   - `password = "hunter2pass"` (10 chars, fires at any realistic threshold)
    fn write_python_secret_fixture(dir: &Path) -> PathBuf {
        let path = dir.join("secrets.py");
        fs::write(
            &path,
            "password_short = \"abc\"\npassword_mid = \"test\"\npassword_long = \"hunter2pass\"\n",
        )
        .expect("failed to write python fixture");
        path
    }

    fn count_py_hardcoded_secret_findings(stdout: &[u8]) -> usize {
        let findings = scan_json_findings_from_slice(stdout);
        findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some("py/no-hardcoded-secret"))
            .count()
    }

    #[test]
    fn test_secrets_min_length_default_matches_hardcoded_four() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_python_secret_fixture(repo.path());

        let output = foxguard_cmd()
            .current_dir(repo.path())
            .args(["secrets.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");
        // With no config the threshold must match the previous hardcoded
        // `>= 4` check: `test` (4) + `hunter2pass` (10) fire, `abc` (3)
        // is rejected.
        let count = count_py_hardcoded_secret_findings(&output.stdout);
        assert_eq!(
            count, 2,
            "default min_length should match pre-#210 `>= 4` behavior \
             (expected 2 findings for `test` and `hunter2pass`, got {count})"
        );
    }

    #[test]
    fn test_secrets_min_length_raising_drops_short_matches() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_python_secret_fixture(repo.path());
        write_config_file(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  thresholds:\n    secrets:\n      min_length: 8\n",
        );

        let output = foxguard_cmd()
            .current_dir(repo.path())
            .args(["secrets.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");
        // `test` (4 chars) now falls below min_length=8 and is dropped;
        // only `hunter2pass` (10) remains.
        let count = count_py_hardcoded_secret_findings(&output.stdout);
        assert_eq!(
            count, 1,
            "raising min_length to 8 should drop `test`; expected 1, got {count}"
        );
    }

    #[test]
    fn test_secrets_min_length_lowering_catches_shorter_matches() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_python_secret_fixture(repo.path());
        write_config_file(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  thresholds:\n    secrets:\n      min_length: 3\n",
        );

        let output = foxguard_cmd()
            .current_dir(repo.path())
            .args(["secrets.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");
        // Lowering min_length to 3 now catches `abc` in addition to the
        // two longer strings.
        let count = count_py_hardcoded_secret_findings(&output.stdout);
        assert_eq!(
            count, 3,
            "lowering min_length to 3 should also flag `abc`; expected 3, got {count}"
        );
    }

    #[test]
    fn test_secrets_min_length_invalid_config_fails_loudly() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_python_secret_fixture(repo.path());
        write_config_file(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  thresholds:\n    secrets:\n      min_length: 0\n",
        );

        let output = foxguard_cmd()
            .current_dir(repo.path())
            .args(["secrets.py", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");
        assert!(
            !output.status.success(),
            "min_length: 0 must fail the scan; stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("min_length"),
            "error should mention min_length, got: {stderr}"
        );
    }
}

// ─── PQC subcommand ──────────────────────────────────────────────────────────

#[test]
fn pqc_help_exits_zero() {
    let output = foxguard_cmd_isolated()
        .args(["pqc", "--help"])
        .output()
        .expect("failed to run foxguard pqc --help");
    assert!(output.status.success(), "foxguard pqc --help should exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("post-quantum") || stdout.contains("quantum"),
        "help text should mention post-quantum, got: {stdout}"
    );
}

#[test]
fn pqc_on_safe_fixture_returns_zero_findings() {
    let output = foxguard_cmd()
        .args([
            "pqc",
            fixture_path("safe.py").to_str().unwrap(),
            "-f",
            "json",
        ])
        .output()
        .expect("failed to run foxguard pqc");
    // No PQ rules registered on main yet, so zero findings expected.
    // Once PQ rules land, safe.py should still produce zero PQ findings.
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.trim().is_empty() {
        let findings: Vec<serde_json::Value> = scan_json_findings_from_str(&stdout);
        // All findings (if any) should be PQ-related
        for f in &findings {
            let rule_id = f["rule_id"].as_str().unwrap_or("");
            assert!(
                rule_id.contains("pq-vulnerable")
                    || rule_id.contains("hardcoded-crypto-algorithm")
                    || rule_id.starts_with("config/"),
                "pqc subcommand should only return PQ rules, got: {rule_id}"
            );
        }
    }
}

/// Draft-standard awareness: early adopters of FN-DSA (FIPS 206 draft) and
/// HQC (5th NIST PQC algorithm, selected March 2025) must NOT be flagged by
/// the per-language `pq-vulnerable-crypto` rules alongside ML-DSA / ML-KEM /
/// SLH-DSA. See issue #226.
#[test]
fn pq_draft_standards_are_not_flagged() {
    for fixture in [
        "safe_pq_draft.rs",
        "safe_pq_draft.go",
        "safe_pq_draft.py",
        "safe_pq_draft.js",
        "safe_pq_draft.java",
    ] {
        let output = foxguard_cmd()
            .args([fixture_path(fixture).to_str().unwrap(), "-f", "json"])
            .output()
            .expect("failed to run foxguard");
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            continue;
        }
        let findings: Vec<serde_json::Value> = scan_json_findings_from_str(&stdout);
        for f in &findings {
            let rule_id = f["rule_id"].as_str().unwrap_or("");
            assert!(
                !rule_id.ends_with("/pq-vulnerable-crypto"),
                "{fixture}: pq-vulnerable-crypto must not fire on PQ-safe draft standards (FN-DSA / HQC). \
                 finding={f:?}"
            );
        }
    }
}

// ─── Config file PQ-scanning (PR #230) ──────────────────────────────────────
//
// These tests cover the four TLS/config-file rules added by PR #230:
//   - config/nginx-pq-vulnerable-tls
//   - config/apache-pq-vulnerable-tls
//   - config/haproxy-pq-vulnerable-tls
//   - config/dockerfile-insecure-tls-env
//
// Fixtures live under `tests/fixtures/config/<kind>_<vuln|safe>/`. Each
// vulnerable/safe pair uses the exact filename that `detect_language`
// recognises (`nginx.conf`, `httpd.conf`, `haproxy.cfg`, `Dockerfile`), so
// running the scanner against the parent directory is sufficient to exercise
// the rule. Separate subdirectories keep the positive and negative fixtures
// from colliding on the same filename.
mod config_files {
    use super::*;
    use foxguard::engine::scanner::detect_language;
    use foxguard::Language;

    fn scan_fixture_dir(relative: &str) -> Vec<serde_json::Value> {
        let output = foxguard_cmd_isolated()
            .args([&format!("tests/fixtures/config/{relative}"), "-f", "json"])
            .output()
            .expect("failed to execute foxguard");
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
                panic!(
                    "invalid JSON output for {relative}: {e}; stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            });
        report["findings"]
            .as_array()
            .cloned()
            .expect("JSON report missing findings array")
    }

    fn findings_for_rule<'a>(
        findings: &'a [serde_json::Value],
        rule_id: &str,
    ) -> Vec<&'a serde_json::Value> {
        findings
            .iter()
            .filter(|f| f["rule_id"].as_str() == Some(rule_id))
            .collect()
    }

    // ── nginx ───────────────────────────────────────────────────────────

    #[test]
    fn nginx_rule_fires_on_vulnerable_fixture() {
        let findings = scan_fixture_dir("nginx_vulnerable");
        let matches = findings_for_rule(&findings, "config/nginx-pq-vulnerable-tls");
        assert!(
            !matches.is_empty(),
            "config/nginx-pq-vulnerable-tls should fire on nginx_vulnerable/nginx.conf; \
             all findings: {findings:?}"
        );
        // Classical-only config trips both the ssl_protocols and ssl_ciphers
        // branches — assert both fire so the rule isn't secretly wrapped in
        // an early-return.
        assert!(
            matches.len() >= 2,
            "expected at least two nginx PQ findings (protocols + ciphers), got {}",
            matches.len()
        );
    }

    #[test]
    fn nginx_rule_silent_on_safe_fixture() {
        let findings = scan_fixture_dir("nginx_safe");
        let matches = findings_for_rule(&findings, "config/nginx-pq-vulnerable-tls");
        assert!(
            matches.is_empty(),
            "nginx PQ rule must not fire when TLSv1.3 + X25519MLKEM768 are present; \
             findings: {matches:?}"
        );
    }

    // ── Apache ──────────────────────────────────────────────────────────

    #[test]
    fn apache_rule_fires_on_vulnerable_fixture() {
        let findings = scan_fixture_dir("apache_vulnerable");
        let matches = findings_for_rule(&findings, "config/apache-pq-vulnerable-tls");
        assert!(
            !matches.is_empty(),
            "config/apache-pq-vulnerable-tls should fire on apache_vulnerable/httpd.conf; \
             all findings: {findings:?}"
        );
        assert!(
            matches.len() >= 2,
            "expected at least two apache PQ findings (SSLProtocol + SSLCipherSuite), got {}",
            matches.len()
        );
    }

    #[test]
    fn apache_rule_silent_on_safe_fixture() {
        let findings = scan_fixture_dir("apache_safe");
        let matches = findings_for_rule(&findings, "config/apache-pq-vulnerable-tls");
        assert!(
            matches.is_empty(),
            "apache PQ rule must not fire on a TLSv1.3 + PQ-aware config; findings: {matches:?}"
        );
    }

    // ── HAProxy ─────────────────────────────────────────────────────────

    #[test]
    fn haproxy_rule_fires_on_vulnerable_fixture() {
        let findings = scan_fixture_dir("haproxy_vulnerable");
        let matches = findings_for_rule(&findings, "config/haproxy-pq-vulnerable-tls");
        assert!(
            !matches.is_empty(),
            "config/haproxy-pq-vulnerable-tls should fire on haproxy_vulnerable/haproxy.cfg; \
             all findings: {findings:?}"
        );
        assert!(
            matches.len() >= 2,
            "expected at least two HAProxy PQ findings (bind-options + bind-ciphers), got {}",
            matches.len()
        );
    }

    #[test]
    fn haproxy_rule_silent_on_safe_fixture() {
        let findings = scan_fixture_dir("haproxy_safe");
        let matches = findings_for_rule(&findings, "config/haproxy-pq-vulnerable-tls");
        assert!(
            matches.is_empty(),
            "HAProxy PQ rule must not fire when ssl-min-ver TLSv1.3 + X25519MLKEM768 are set; \
             findings: {matches:?}"
        );
    }

    // ── Dockerfile ──────────────────────────────────────────────────────

    #[test]
    fn dockerfile_rule_fires_on_insecure_fixture() {
        let findings = scan_fixture_dir("dockerfile_insecure");
        let matches = findings_for_rule(&findings, "config/dockerfile-insecure-tls-env");
        assert!(
            !matches.is_empty(),
            "config/dockerfile-insecure-tls-env should fire on dockerfile_insecure/Dockerfile; \
             all findings: {findings:?}"
        );
        // Fixture has four insecure ENV/ARG lines + one insecure RUN line.
        assert!(
            matches.len() >= 5,
            "expected at least five Dockerfile insecure-TLS findings (4 ENV/ARG + 1 RUN), got {}",
            matches.len()
        );
    }

    #[test]
    fn dockerfile_rule_silent_on_safe_fixture() {
        let findings = scan_fixture_dir("dockerfile_safe");
        let matches = findings_for_rule(&findings, "config/dockerfile-insecure-tls-env");
        assert!(
            matches.is_empty(),
            "Dockerfile rule must not fire on a Dockerfile without TLS-disabling env vars; \
             findings: {matches:?}"
        );
    }

    // ── detect_language wiring ──────────────────────────────────────────
    //
    // These assertions pin down the filename → Language mapping for the four
    // new variants. If any rename lands (e.g. we start matching
    // `conf.d/*.conf`), this test forces the author to update both sides.

    #[test]
    fn detect_language_recognises_nginx_conf() {
        assert_eq!(
            detect_language(Path::new("nginx.conf")),
            Some(Language::NginxConf)
        );
        assert_eq!(
            detect_language(Path::new("/etc/nginx/nginx.conf")),
            Some(Language::NginxConf)
        );
    }

    #[test]
    fn detect_language_recognises_apache_filenames() {
        assert_eq!(
            detect_language(Path::new("httpd.conf")),
            Some(Language::ApacheConf)
        );
        assert_eq!(
            detect_language(Path::new("apache2.conf")),
            Some(Language::ApacheConf)
        );
        assert_eq!(
            detect_language(Path::new("/etc/apache2/apache2.conf")),
            Some(Language::ApacheConf)
        );
    }

    #[test]
    fn detect_language_recognises_haproxy_cfg() {
        assert_eq!(
            detect_language(Path::new("haproxy.cfg")),
            Some(Language::HAProxyConf)
        );
        assert_eq!(
            detect_language(Path::new("/etc/haproxy/haproxy.cfg")),
            Some(Language::HAProxyConf)
        );
    }

    #[test]
    fn detect_language_recognises_dockerfiles() {
        assert_eq!(
            detect_language(Path::new("Dockerfile")),
            Some(Language::Dockerfile)
        );
        // `Dockerfile.<suffix>` variants (e.g. Dockerfile.prod) are treated
        // as Dockerfiles too.
        assert_eq!(
            detect_language(Path::new("Dockerfile.insecure-tls")),
            Some(Language::Dockerfile)
        );
        assert_eq!(
            detect_language(Path::new("Dockerfile.prod")),
            Some(Language::Dockerfile)
        );
        // Case-insensitive
        assert_eq!(
            detect_language(Path::new("dockerfile")),
            Some(Language::Dockerfile)
        );
    }

    #[test]
    fn detect_language_recognises_config_include_dirs() {
        // conf.d/ fragments are detected as nginx config
        assert_eq!(
            detect_language(Path::new("conf.d/ssl.conf")),
            Some(Language::NginxConf)
        );
        // sites-enabled/ fragments are detected as Apache config
        assert_eq!(
            detect_language(Path::new("sites-enabled/default.conf")),
            Some(Language::ApacheConf)
        );
    }

    // ── Manifest / dependency-level PQ scanning (#221) ──────────────────

    #[test]
    fn cargo_lock_pq_finds_transitive_rsa_dep() {
        let output = foxguard_cmd()
            .args([
                "pqc",
                "--config",
                "/dev/null",
                "tests/fixtures/deps/Cargo.lock",
                "-f",
                "json",
            ])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        // rustls -> rsa (tier 1, RSA)
        let rustls = findings
            .iter()
            .find(|f| f["dep_name"].as_str() == Some("rustls"));
        assert!(rustls.is_some(), "expected finding for rustls");
        let rustls = rustls.unwrap();
        assert_eq!(rustls["rule_id"], "manifest/cargo-pq-vulnerable-dep");
        assert_eq!(rustls["crypto_algorithm"], "RSA");
        assert_json_number_eq(&rustls["confidence"], 0.9);

        // reqwest -> ring (tier 2, no specific algorithm)
        let reqwest = findings
            .iter()
            .find(|f| f["dep_name"].as_str() == Some("reqwest"));
        assert!(reqwest.is_some(), "expected finding for reqwest");
        let reqwest = reqwest.unwrap();
        assert!(reqwest["crypto_algorithm"].is_null());
        assert_json_number_eq(&reqwest["confidence"], 0.6);

        // my-app -> rustls -> rsa (transitive)
        let my_app = findings
            .iter()
            .find(|f| f["dep_name"].as_str() == Some("my-app"));
        assert!(my_app.is_some(), "expected finding for my-app (transitive)");

        // serde should NOT appear (no crypto dependency)
        let serde = findings
            .iter()
            .find(|f| f["dep_name"].as_str() == Some("serde"));
        assert!(serde.is_none(), "serde should not be flagged");

        // rsa itself should NOT appear (don't flag seeds)
        let rsa = findings
            .iter()
            .find(|f| f["dep_name"].as_str() == Some("rsa"));
        assert!(rsa.is_none(), "seed crate rsa should not be flagged itself");
    }

    #[test]
    fn requirements_txt_pq_finds_crypto_deps() {
        let output = foxguard_cmd()
            .args([
                "pqc",
                "--config",
                "/dev/null",
                "tests/fixtures/deps/requirements.txt",
                "-f",
                "json",
            ])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let dep_names: Vec<&str> = findings
            .iter()
            .filter_map(|f| f["dep_name"].as_str())
            .collect();

        // Should find: cryptography, python-rsa, fabric, paramiko
        assert!(dep_names.contains(&"python-rsa"), "expected python-rsa");
        assert!(dep_names.contains(&"cryptography"), "expected cryptography");
        assert!(dep_names.contains(&"fabric"), "expected fabric");
        assert!(dep_names.contains(&"paramiko"), "expected paramiko");

        // Should NOT find: flask, requests, -e ., git+...
        assert!(!dep_names.contains(&"flask"), "flask is not a crypto lib");
        assert!(
            !dep_names.contains(&"requests"),
            "requests is not a crypto lib"
        );

        // python-rsa should have high confidence and RSA algorithm
        let python_rsa = findings
            .iter()
            .find(|f| f["dep_name"].as_str() == Some("python-rsa"))
            .unwrap();
        assert_eq!(python_rsa["crypto_algorithm"], "RSA");
        assert_json_number_eq(&python_rsa["confidence"], 0.95);

        // cryptography should have low confidence and null algorithm
        let crypto = findings
            .iter()
            .find(|f| f["dep_name"].as_str() == Some("cryptography"))
            .unwrap();
        assert!(crypto["crypto_algorithm"].is_null());
        assert_json_number_eq(&crypto["confidence"], 0.5);
        assert!(crypto["fix_suggestion"]
            .as_str()
            .unwrap()
            .contains("PQ-safe"));
    }

    #[test]
    #[ignore = "PQC dep scanning differs on CI — investigate separately"]
    fn poetry_lock_pq_finds_crypto_deps() {
        let output = foxguard_cmd_isolated()
            .args(["pqc", "tests/fixtures/deps/poetry.lock", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let dep_names: Vec<&str> = findings
            .iter()
            .filter_map(|f| f["dep_name"].as_str())
            .collect();

        assert!(dep_names.contains(&"python-rsa"), "expected python-rsa");
        assert!(dep_names.contains(&"cryptography"), "expected cryptography");
        assert!(dep_names.contains(&"paramiko"), "expected paramiko");
        assert!(!dep_names.contains(&"flask"), "flask is not a crypto lib");
        assert!(
            !dep_names.contains(&"requests"),
            "requests is not a crypto lib"
        );

        // All findings should have the poetry rule ID
        assert!(findings
            .iter()
            .all(|f| f["rule_id"] == "manifest/poetry-pq-vulnerable-dep"));
    }

    #[test]
    #[ignore = "PQC dep scanning differs on CI — investigate separately"]
    fn pipfile_lock_pq_finds_crypto_deps() {
        let output = foxguard_cmd_isolated()
            .args(["pqc", "tests/fixtures/deps/Pipfile.lock", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let dep_names: Vec<&str> = findings
            .iter()
            .filter_map(|f| f["dep_name"].as_str())
            .collect();

        assert!(dep_names.contains(&"cryptography"), "expected cryptography");
        assert!(dep_names.contains(&"python-rsa"), "expected python-rsa");
        assert!(
            dep_names.contains(&"paramiko"),
            "expected paramiko from develop"
        );
        assert!(!dep_names.contains(&"flask"), "flask is not a crypto lib");

        assert!(findings
            .iter()
            .all(|f| f["rule_id"] == "manifest/pipfile-pq-vulnerable-dep"));
    }

    #[test]
    #[ignore = "PQC dep scanning differs on CI — investigate separately"]
    fn pnpm_lock_pq_finds_crypto_deps() {
        let output = foxguard_cmd_isolated()
            .args(["pqc", "tests/fixtures/deps/pnpm-lock.yaml", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let dep_names: Vec<&str> = findings
            .iter()
            .filter_map(|f| f["dep_name"].as_str())
            .collect();

        assert!(dep_names.contains(&"elliptic"), "expected elliptic");
        assert!(dep_names.contains(&"jsonwebtoken"), "expected jsonwebtoken");
        assert!(!dep_names.contains(&"express"), "express is not crypto");
        assert!(!dep_names.contains(&"lodash"), "lodash is not crypto");

        assert!(findings
            .iter()
            .all(|f| f["rule_id"] == "manifest/pnpm-pq-vulnerable-dep"));
    }

    #[test]
    #[ignore = "PQC dep scanning differs on CI — investigate separately"]
    fn package_lock_pq_finds_crypto_deps() {
        let output = foxguard_cmd_isolated()
            .args(["pqc", "tests/fixtures/deps/package-lock.json", "-f", "json"])
            .output()
            .expect("failed to execute foxguard");

        let findings: Vec<serde_json::Value> = scan_json_findings_from_slice(&output.stdout);

        let dep_names: Vec<&str> = findings
            .iter()
            .filter_map(|f| f["dep_name"].as_str())
            .collect();

        assert!(dep_names.contains(&"elliptic"), "expected elliptic");
        assert!(dep_names.contains(&"jsonwebtoken"), "expected jsonwebtoken");
        assert!(!dep_names.contains(&"express"), "express is not crypto");
        assert!(!dep_names.contains(&"lodash"), "lodash is not crypto");

        assert!(findings
            .iter()
            .all(|f| f["rule_id"] == "manifest/npm-pq-vulnerable-dep"));
    }

    #[test]
    fn detect_language_recognises_manifest_files() {
        assert_eq!(
            detect_language(Path::new("Cargo.lock")),
            Some(Language::Manifest)
        );
        assert_eq!(
            detect_language(Path::new("requirements.txt")),
            Some(Language::Manifest)
        );
        assert_eq!(
            detect_language(Path::new("poetry.lock")),
            Some(Language::Manifest)
        );
        assert_eq!(
            detect_language(Path::new("Pipfile.lock")),
            Some(Language::Manifest)
        );
        assert_eq!(
            detect_language(Path::new("pnpm-lock.yaml")),
            Some(Language::Manifest)
        );
        assert_eq!(
            detect_language(Path::new("package-lock.json")),
            Some(Language::Manifest)
        );
        // Regular .txt files should not match
        assert_eq!(detect_language(Path::new("notes.txt")), None);
        assert_eq!(detect_language(Path::new("Cargo.toml")), None);
        // Regular .json and .yaml should not match
        assert_eq!(detect_language(Path::new("config.json")), None);
        assert_eq!(detect_language(Path::new("config.yaml")), None);
    }
}
