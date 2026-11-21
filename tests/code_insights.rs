use foxguard::report::code_insights::{build_code_insights, Platform};
use foxguard::Finding;
use serde_json::{json, Value};

fn findings() -> Vec<Finding> {
    let mk =
        |rule: &str, sev: &str, cwe: Option<&str>, file: &str, line: usize, fix: Option<&str>| {
            serde_json::from_value::<Finding>(json!({
                "rule_id": rule, "severity": sev, "cwe": cwe,
                "description": "Untrusted input reaches a dangerous sink",
                "file": file, "line": line, "column": 1, "end_line": line,
                "end_column": 5, "snippet": "x", "fix_suggestion": fix
            }))
            .unwrap()
        };
    vec![
        mk(
            "py/sql-injection",
            "critical",
            Some("CWE-89"),
            "./app/db.py",
            12,
            Some("Use parameterized queries"),
        ),
        // Duplicate of the above by path+line+CWE, lower severity: dropped.
        mk(
            "py/sql-injection-alt",
            "medium",
            Some("CWE-89"),
            "app/db.py",
            12,
            None,
        ),
        mk(
            "js/xss",
            "high",
            Some("CWE-79"),
            "web/view.js",
            40,
            Some("Escape output"),
        ),
        mk("py/weak-hash", "low", None, "app/crypto.py", 0, None),
    ]
}

fn check(platform: Platform, recorded: &str) {
    let actual = build_code_insights(&findings(), platform);
    let expected: Value = serde_json::from_str(recorded).unwrap();
    assert_eq!(
        actual,
        expected,
        "actual:\n{}",
        serde_json::to_string_pretty(&actual).unwrap()
    );
}

#[test]
fn cloud_shape_matches_recorded_fixture() {
    check(
        Platform::Cloud,
        include_str!("fixtures/code_insights/cloud.json"),
    );
}

#[test]
fn data_center_shape_matches_recorded_fixture() {
    check(
        Platform::DataCenter,
        include_str!("fixtures/code_insights/data_center.json"),
    );
}

#[test]
fn cli_emits_code_insights_formats() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.py"), "import os\nos.system(input())\n").unwrap();
    for (fmt, key) in [
        ("code-insights", "bitbucket-cloud"),
        ("code-insights-dc", "bitbucket-data-center"),
    ] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_foxguard"))
            .args(["--format", fmt])
            .arg(dir.path())
            .output()
            .unwrap();
        let v: Value = serde_json::from_slice(&out.stdout).expect("json envelope");
        assert_eq!(v["platform"], key);
        assert!(v["report"]["title"].is_string());
    }
}
