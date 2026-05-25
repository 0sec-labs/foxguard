use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cell {
    Covered,
    Deferred(&'static str),
    NotApplicable(&'static str),
}

impl Cell {
    fn is_covered(self) -> bool {
        matches!(self, Cell::Covered)
    }

    fn note(self) -> Option<&'static str> {
        match self {
            Cell::Covered => None,
            Cell::Deferred(note) | Cell::NotApplicable(note) => Some(note),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct MatrixRow {
    language: &'static str,
    extension: &'static str,
    vulnerable_fixture: Option<&'static str>,
    safe_fixture: Option<&'static str>,
    scan_vulnerable: Cell,
    scan_safe: Cell,
    diff: Cell,
    secrets: Cell,
    terminal: Cell,
    json: Cell,
    sarif: Cell,
    cbom: Cell,
    pqc: Cell,
    taint_explain: Cell,
}

const MATRIX: &[MatrixRow] = &[
    MatrixRow {
        language: "JavaScript/TypeScript",
        extension: "js",
        vulnerable_fixture: Some("vulnerable.js"),
        safe_fixture: Some("safe.js"),
        scan_vulnerable: Cell::Covered,
        scan_safe: Cell::Covered,
        diff: Cell::Covered,
        secrets: Cell::Covered,
        terminal: Cell::Covered,
        json: Cell::Covered,
        sarif: Cell::Covered,
        cbom: Cell::Covered,
        pqc: Cell::Covered,
        taint_explain: Cell::Covered,
    },
    MatrixRow {
        language: "Python",
        extension: "py",
        vulnerable_fixture: Some("vulnerable.py"),
        safe_fixture: Some("safe.py"),
        scan_vulnerable: Cell::Covered,
        scan_safe: Cell::Covered,
        diff: Cell::Covered,
        secrets: Cell::Covered,
        terminal: Cell::Covered,
        json: Cell::Covered,
        sarif: Cell::Covered,
        cbom: Cell::Covered,
        pqc: Cell::Covered,
        taint_explain: Cell::Covered,
    },
    MatrixRow {
        language: "Go",
        extension: "go",
        vulnerable_fixture: Some("vulnerable.go"),
        safe_fixture: Some("safe.go"),
        scan_vulnerable: Cell::Covered,
        scan_safe: Cell::Covered,
        diff: Cell::Covered,
        secrets: Cell::Covered,
        terminal: Cell::Covered,
        json: Cell::Covered,
        sarif: Cell::Covered,
        cbom: Cell::Covered,
        pqc: Cell::Covered,
        taint_explain: Cell::Covered,
    },
    MatrixRow {
        language: "Ruby",
        extension: "rb",
        vulnerable_fixture: Some("vulnerable.rb"),
        safe_fixture: Some("safe.rb"),
        scan_vulnerable: Cell::Covered,
        scan_safe: Cell::Covered,
        diff: Cell::Covered,
        secrets: Cell::Covered,
        terminal: Cell::Covered,
        json: Cell::Covered,
        sarif: Cell::Covered,
        cbom: Cell::Covered,
        pqc: Cell::NotApplicable("no Ruby PQ rule is registered"),
        taint_explain: Cell::NotApplicable("Ruby has no taint engine"),
    },
    MatrixRow {
        language: "Java",
        extension: "java",
        vulnerable_fixture: Some("vulnerable.java"),
        safe_fixture: Some("safe.java"),
        scan_vulnerable: Cell::Covered,
        scan_safe: Cell::Covered,
        diff: Cell::Covered,
        secrets: Cell::Covered,
        terminal: Cell::Covered,
        json: Cell::Covered,
        sarif: Cell::Covered,
        cbom: Cell::Covered,
        pqc: Cell::Covered,
        taint_explain: Cell::NotApplicable("Java has no taint engine"),
    },
    MatrixRow {
        language: "PHP",
        extension: "php",
        vulnerable_fixture: Some("vulnerable.php"),
        safe_fixture: Some("safe.php"),
        scan_vulnerable: Cell::Covered,
        scan_safe: Cell::Covered,
        diff: Cell::Covered,
        secrets: Cell::Covered,
        terminal: Cell::Covered,
        json: Cell::Covered,
        sarif: Cell::Covered,
        cbom: Cell::Covered,
        pqc: Cell::NotApplicable("no PHP PQ rule is registered"),
        taint_explain: Cell::NotApplicable("PHP has no taint engine"),
    },
    MatrixRow {
        language: "Rust",
        extension: "rs",
        vulnerable_fixture: Some("vulnerable.rs"),
        safe_fixture: Some("safe.rs"),
        scan_vulnerable: Cell::Covered,
        scan_safe: Cell::Covered,
        diff: Cell::Covered,
        secrets: Cell::Covered,
        terminal: Cell::Covered,
        json: Cell::Covered,
        sarif: Cell::Covered,
        cbom: Cell::Covered,
        pqc: Cell::Covered,
        taint_explain: Cell::NotApplicable("Rust has no taint engine"),
    },
    MatrixRow {
        language: "C#",
        extension: "cs",
        vulnerable_fixture: Some("vulnerable.cs"),
        safe_fixture: Some("safe.cs"),
        scan_vulnerable: Cell::Covered,
        scan_safe: Cell::Covered,
        diff: Cell::Covered,
        secrets: Cell::Covered,
        terminal: Cell::Covered,
        json: Cell::Covered,
        sarif: Cell::Covered,
        cbom: Cell::Covered,
        pqc: Cell::NotApplicable("no C# PQ rule is registered"),
        taint_explain: Cell::NotApplicable("C# has no taint engine"),
    },
    MatrixRow {
        language: "Swift",
        extension: "swift",
        vulnerable_fixture: Some("vulnerable.swift"),
        safe_fixture: Some("safe.swift"),
        scan_vulnerable: Cell::Covered,
        scan_safe: Cell::Covered,
        diff: Cell::Covered,
        secrets: Cell::Covered,
        terminal: Cell::Covered,
        json: Cell::Covered,
        sarif: Cell::Covered,
        cbom: Cell::Covered,
        pqc: Cell::NotApplicable("no Swift PQ rule is registered"),
        taint_explain: Cell::NotApplicable("Swift has no taint engine"),
    },
    MatrixRow {
        language: "Kotlin",
        extension: "kt",
        vulnerable_fixture: Some("vulnerable.kt"),
        safe_fixture: Some("safe.kt"),
        scan_vulnerable: Cell::Covered,
        scan_safe: Cell::Covered,
        diff: Cell::Covered,
        secrets: Cell::Covered,
        terminal: Cell::Covered,
        json: Cell::Covered,
        sarif: Cell::Covered,
        cbom: Cell::Covered,
        pqc: Cell::NotApplicable("no Kotlin PQ rule is registered"),
        taint_explain: Cell::Covered,
    },
    MatrixRow {
        language: "C",
        extension: "c",
        vulnerable_fixture: None,
        safe_fixture: None,
        scan_vulnerable: Cell::Deferred("C built-in scan rules are not registered yet"),
        scan_safe: Cell::Deferred("C built-in scan rules are not registered yet"),
        diff: Cell::Deferred("C built-in scan rules are not registered yet"),
        secrets: Cell::Covered,
        terminal: Cell::Deferred("terminal smoke should use C once built-in rules exist"),
        json: Cell::Deferred("JSON smoke should use C once built-in rules exist"),
        sarif: Cell::Deferred("SARIF smoke should use C once built-in rules exist"),
        cbom: Cell::Deferred("CBOM smoke should use C once built-in rules exist"),
        pqc: Cell::NotApplicable("C PQ coverage is currently external-rule/kernel focused"),
        taint_explain: Cell::NotApplicable("C has no taint engine"),
    },
];

fn foxguard_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_foxguard"));
    cmd.args(["--config", "/dev/null"]);
    cmd
}

fn foxguard_cmd_isolated() -> Command {
    foxguard_cmd()
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn parse_json(stdout: &[u8]) -> Value {
    serde_json::from_slice(stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON output: {error}; stdout={}",
            String::from_utf8_lossy(stdout)
        )
    })
}

fn findings(report: &Value) -> &[Value] {
    report["findings"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("JSON report missing findings array: {report:#}"))
}

fn assert_scan_json_shape(report: &Value, expected_command: &str) {
    assert_eq!(report["schema_version"].as_str(), Some("1.0.0"));
    assert_eq!(report["scanner"]["name"].as_str(), Some("foxguard"));
    assert_eq!(
        report["scanner"]["command"].as_str(),
        Some(expected_command)
    );
    assert!(
        report["timing"]["duration_ms"].is_number(),
        "missing duration_ms in {report:#}"
    );
}

fn assert_sarif_shape(report: &Value) {
    assert_eq!(report["version"].as_str(), Some("2.1.0"));
    assert!(report["$schema"].is_string());
    assert!(report["runs"]
        .as_array()
        .is_some_and(|runs| !runs.is_empty()));
}

fn assert_cbom_shape(report: &Value) {
    assert_eq!(report["bomFormat"].as_str(), Some("CycloneDX"));
    assert_eq!(report["specVersion"].as_str(), Some("1.6"));
    assert!(report["serialNumber"]
        .as_str()
        .is_some_and(|s| s.starts_with("urn:uuid:")));
    assert_eq!(
        report["metadata"]["tools"]["components"][0]["name"].as_str(),
        Some("foxguard")
    );
}

fn run_scan_fixture(row: MatrixRow, format: &str) -> std::process::Output {
    let fixture = row
        .vulnerable_fixture
        .unwrap_or_else(|| panic!("{} has no vulnerable fixture", row.language));
    foxguard_cmd_isolated()
        .args([fixture_path(fixture).to_str().unwrap(), "-f", format])
        .output()
        .unwrap_or_else(|error| panic!("failed to run foxguard for {}: {error}", row.language))
}

fn init_repo(path: &Path) {
    let init = Command::new("git")
        .args(["init"])
        .current_dir(path)
        .output()
        .expect("failed to initialize git repo");
    assert!(init.status.success(), "git init failed: {init:?}");
}

fn commit_all(path: &Path, message: &str) {
    let add = Command::new("git")
        .args(["add", "."])
        .current_dir(path)
        .output()
        .expect("failed to git add");
    assert!(add.status.success(), "git add failed: {add:?}");

    let commit = Command::new("git")
        .args([
            "-c",
            "user.name=Foxguard Test",
            "-c",
            "user.email=foxguard@example.test",
            "commit",
            "-m",
            message,
        ])
        .current_dir(path)
        .output()
        .expect("failed to git commit");
    assert!(commit.status.success(), "git commit failed: {commit:?}");
}

fn write_secret_fixture(dir: &Path, row: MatrixRow) -> PathBuf {
    let secret = ["AKIA", "1234567890ABCDEF"].concat();
    let content = match row.extension {
        "py" | "rb" => format!("token = \"{secret}\"\n"),
        "go" => format!("package main\nconst token = \"{secret}\"\n"),
        "java" => format!("class Secret {{ String token = \"{secret}\"; }}\n"),
        "php" => format!("<?php\n$token = \"{secret}\";\n"),
        "rs" => format!("const TOKEN: &str = \"{secret}\";\n"),
        "cs" => format!("class Secret {{ string token = \"{secret}\"; }}\n"),
        "swift" => format!("let token = \"{secret}\"\n"),
        "kt" => format!("val token = \"{secret}\"\n"),
        "c" => format!("const char *token = \"{secret}\";\n"),
        _ => format!("const token = \"{secret}\";\n"),
    };
    let path = dir.join(format!("secret.{}", row.extension));
    fs::write(&path, content).expect("failed to write secret fixture");
    path
}

fn coverage_report() -> String {
    let mut report = String::new();
    for row in MATRIX {
        report.push_str(&format!("{}\n", row.language));
        for (cell_name, cell) in [
            ("scan_vulnerable", row.scan_vulnerable),
            ("scan_safe", row.scan_safe),
            ("diff", row.diff),
            ("secrets", row.secrets),
            ("terminal", row.terminal),
            ("json", row.json),
            ("sarif", row.sarif),
            ("cbom", row.cbom),
            ("pqc", row.pqc),
            ("taint_explain", row.taint_explain),
        ] {
            let status = match cell {
                Cell::Covered => "covered",
                Cell::Deferred(_) => "deferred",
                Cell::NotApplicable(_) => "n/a",
            };
            let note = cell.note().unwrap_or("");
            report.push_str(&format!("  {cell_name}: {status} {note}\n"));
        }
    }
    report
}

#[test]
fn matrix_inventory_has_all_source_languages_and_documented_gaps() {
    assert_eq!(MATRIX.len(), 11, "matrix rows:\n{}", coverage_report());

    for row in MATRIX {
        for (cell_name, cell) in [
            ("scan_vulnerable", row.scan_vulnerable),
            ("scan_safe", row.scan_safe),
            ("diff", row.diff),
            ("secrets", row.secrets),
            ("terminal", row.terminal),
            ("json", row.json),
            ("sarif", row.sarif),
            ("cbom", row.cbom),
            ("pqc", row.pqc),
            ("taint_explain", row.taint_explain),
        ] {
            if let Some(note) = cell.note() {
                assert!(
                    !note.trim().is_empty(),
                    "{} {cell_name} gap must have an audit note",
                    row.language
                );
            }
        }
    }

    eprintln!("cross-language coverage report:\n{}", coverage_report());
}

#[test]
fn scan_vulnerable_json_matrix_cells_find_issues() {
    for row in MATRIX
        .iter()
        .copied()
        .filter(|row| row.scan_vulnerable.is_covered())
    {
        let output = run_scan_fixture(row, "json");
        assert!(
            !output.status.success(),
            "{} vulnerable scan should exit non-zero",
            row.language
        );
        let report = parse_json(&output.stdout);
        assert_scan_json_shape(&report, "scan");
        assert!(
            !findings(&report).is_empty(),
            "{} vulnerable scan should emit findings",
            row.language
        );
    }
}

#[test]
fn scan_safe_json_matrix_cells_are_clean() {
    for row in MATRIX
        .iter()
        .copied()
        .filter(|row| row.scan_safe.is_covered())
    {
        let fixture = row.safe_fixture.expect("covered safe cell needs fixture");
        let output = foxguard_cmd_isolated()
            .args([fixture_path(fixture).to_str().unwrap(), "-f", "json"])
            .output()
            .unwrap_or_else(|error| {
                panic!("failed to run safe scan for {}: {error}", row.language)
            });
        assert!(
            output.status.success(),
            "{} safe scan should exit zero; stderr={}",
            row.language,
            String::from_utf8_lossy(&output.stderr)
        );
        let report = parse_json(&output.stdout);
        assert_scan_json_shape(&report, "scan");
        assert!(
            findings(&report).is_empty(),
            "{} safe scan should not emit findings",
            row.language
        );
    }
}

#[test]
fn scan_output_format_matrix_cells_are_valid() {
    for row in MATRIX
        .iter()
        .copied()
        .filter(|row| row.terminal.is_covered())
    {
        let output = run_scan_fixture(row, "terminal");
        assert!(
            !output.status.success(),
            "{} terminal scan should exit non-zero",
            row.language
        );
        assert!(
            !output.stdout.is_empty(),
            "{} terminal scan should print findings",
            row.language
        );
    }

    for row in MATRIX.iter().copied().filter(|row| row.json.is_covered()) {
        let output = run_scan_fixture(row, "json");
        let report = parse_json(&output.stdout);
        assert_scan_json_shape(&report, "scan");
    }

    for row in MATRIX.iter().copied().filter(|row| row.sarif.is_covered()) {
        let output = run_scan_fixture(row, "sarif");
        let report = parse_json(&output.stdout);
        assert_sarif_shape(&report);
    }

    for row in MATRIX.iter().copied().filter(|row| row.cbom.is_covered()) {
        let output = run_scan_fixture(row, "cbom");
        let report = parse_json(&output.stdout);
        assert_cbom_shape(&report);
    }
}

#[test]
fn diff_json_matrix_cells_report_new_findings_only() {
    for row in MATRIX.iter().copied().filter(|row| row.diff.is_covered()) {
        let safe_fixture = row
            .safe_fixture
            .expect("covered diff cell needs safe fixture");
        let vulnerable_fixture = row
            .vulnerable_fixture
            .expect("covered diff cell needs vulnerable fixture");
        let repo = TempDir::new().expect("temp repo");
        init_repo(repo.path());
        let target = repo.path().join(format!("app.{}", row.extension));
        fs::copy(fixture_path(safe_fixture), &target).expect("copy safe fixture");
        commit_all(repo.path(), "base");
        fs::copy(fixture_path(vulnerable_fixture), &target).expect("copy vulnerable fixture");

        let output = foxguard_cmd_isolated()
            .current_dir(repo.path())
            .args(["diff", "HEAD", ".", "-f", "json"])
            .output()
            .unwrap_or_else(|error| panic!("failed to run diff for {}: {error}", row.language));
        assert!(
            !output.status.success(),
            "{} diff should report new findings; stderr={}",
            row.language,
            String::from_utf8_lossy(&output.stderr)
        );
        let report = parse_json(&output.stdout);
        assert_scan_json_shape(&report, "diff");
        assert_eq!(report["target"]["diff_base"].as_str(), Some("HEAD"));
        assert!(
            !findings(&report).is_empty(),
            "{} diff should contain findings",
            row.language
        );
    }
}

#[test]
fn secrets_json_matrix_cells_find_language_string_secret() {
    for row in MATRIX
        .iter()
        .copied()
        .filter(|row| row.secrets.is_covered())
    {
        let dir = TempDir::new().expect("temp dir");
        let fixture = write_secret_fixture(dir.path(), row);
        let output = foxguard_cmd()
            .args(["secrets", fixture.to_str().unwrap(), "-f", "json"])
            .output()
            .unwrap_or_else(|error| panic!("failed to run secrets for {}: {error}", row.language));
        assert!(
            !output.status.success(),
            "{} secrets scan should exit non-zero",
            row.language
        );
        let report = parse_json(&output.stdout);
        assert_scan_json_shape(&report, "secrets");
        assert!(
            !findings(&report).is_empty(),
            "{} secrets scan should emit findings",
            row.language
        );
    }
}

#[test]
fn pqc_json_matrix_cells_emit_only_pq_findings() {
    for row in MATRIX.iter().copied().filter(|row| row.pqc.is_covered()) {
        let fixture = row
            .vulnerable_fixture
            .expect("covered pqc cell needs vulnerable fixture");
        let output = Command::new(env!("CARGO_BIN_EXE_foxguard"))
            .args(["pqc", "--config", "/dev/null", fixture_path(fixture).to_str().unwrap(), "-f", "json"])
            .output()
            .unwrap_or_else(|error| panic!("failed to run pqc for {}: {error}", row.language));
        let report = parse_json(&output.stdout);
        assert_scan_json_shape(&report, "pqc");
        assert!(
            !findings(&report).is_empty(),
            "{} pqc scan should emit PQ findings",
            row.language
        );
        for finding in findings(&report) {
            let rule_id = finding["rule_id"].as_str().unwrap_or("");
            assert!(
                rule_id.contains("pq-vulnerable")
                    || rule_id.contains("hardcoded-crypto-algorithm")
                    || rule_id.starts_with("config/")
                    || rule_id.starts_with("manifest/"),
                "{} pqc emitted non-PQ rule {rule_id}",
                row.language
            );
        }
    }
}

#[test]
fn taint_explain_matrix_cells_render_traces() {
    for (language, fixture, expected_rule) in [
        (
            "JavaScript/TypeScript",
            "vulnerable_js_taint.js",
            "js/taint-xss-innerhtml",
        ),
        (
            "Python",
            "vulnerable_py_taint.py",
            "py/taint-pickle-deserialization",
        ),
        ("Go", "vulnerable_go_taint.go", "go/taint-command-injection"),
        ("Kotlin", "vulnerable.kt", "kt/taint-sql-injection"),
    ] {
        let output = foxguard_cmd_isolated()
            .args([
                fixture_path(fixture).to_str().unwrap(),
                "--explain",
                "-f",
                "json",
            ])
            .output()
            .unwrap_or_else(|error| panic!("failed to run --explain for {language}: {error}"));
        assert!(
            !output.status.success(),
            "{language} taint explain should exit non-zero"
        );
        let report = parse_json(&output.stdout);
        let explained = findings(&report).iter().any(|finding| {
            finding["rule_id"].as_str() == Some(expected_rule)
                && finding["source_description"].is_string()
                && finding["sink_description"].is_string()
        });
        assert!(explained, "{language} should render taint trace fields");
    }

    assert!(
        MATRIX
            .iter()
            .find(|row| row.language == "Kotlin")
            .is_some_and(|row| row.taint_explain.is_covered()),
        "Kotlin taint explain should be covered by the top-level fixture"
    );
}
