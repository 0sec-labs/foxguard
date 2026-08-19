use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use foxguard::report::semgrep_migration::render_terminal;
use foxguard::rules::semgrep_compat::load_semgrep_rules;
use foxguard::rules::semgrep_readiness::{
    assess_semgrep_migration_readiness, SemgrepMigrationDisposition, SemgrepMigrationReasonCode,
    SEMGREP_MIGRATION_READINESS_SCHEMA_VERSION,
};
use tempfile::TempDir;

const FIXTURE_DIR: &str = "tests/fixtures/semgrep_migration_readiness";

fn fixture(name: &str) -> PathBuf {
    Path::new(FIXTURE_DIR).join(name)
}

fn record<'a>(
    records: &'a [foxguard::rules::semgrep_readiness::SemgrepMigrationReadinessRecord],
    source_id: &str,
) -> &'a foxguard::rules::semgrep_readiness::SemgrepMigrationReadinessRecord {
    records
        .iter()
        .find(|record| record.source_id == source_id)
        .unwrap_or_else(|| panic!("missing readiness record for {source_id}"))
}

#[test]
fn production_importer_reports_actual_emission_and_reduction_outcomes() {
    let report = assess_semgrep_migration_readiness(&fixture("pack.yml"))
        .expect("fixture pack should produce a report");

    assert_eq!(
        report.schema_version,
        SEMGREP_MIGRATION_READINESS_SCHEMA_VERSION
    );
    assert_eq!(report.records.len(), 3);

    let exact = record(&report.records, "migration/exact");
    assert_eq!(exact.language, "python");
    assert_eq!(exact.disposition, SemgrepMigrationDisposition::Exact);
    assert_eq!(exact.reason_code, SemgrepMigrationReasonCode::Exact);

    let degraded = record(&report.records, "migration/degraded");
    assert_eq!(degraded.disposition, SemgrepMigrationDisposition::Degraded);
    assert_eq!(
        degraded.reason_code,
        SemgrepMigrationReasonCode::UnsupportedPatternNotRegex
    );

    let skipped = record(&report.records, "migration/skipped");
    assert_eq!(skipped.disposition, SemgrepMigrationDisposition::Skipped);
    assert_eq!(
        skipped.reason_code,
        SemgrepMigrationReasonCode::UnsupportedLanguage
    );
}

#[test]
fn warn_skipped_pattern_not_inside_is_a_recorded_reduction() {
    let path = fixture("pattern-not-inside.yml");
    assert_eq!(load_semgrep_rules(&path).len(), 1);

    let report = assess_semgrep_migration_readiness(&path).expect("report should load");
    let outcome = record(&report.records, "reduction/pattern-not-inside");
    assert_eq!(outcome.disposition, SemgrepMigrationDisposition::Degraded);
    assert_eq!(
        outcome.reason_code,
        SemgrepMigrationReasonCode::UnsupportedConstruct
    );
}

#[test]
fn source_ordinals_keep_empty_and_duplicate_ids_independent() {
    let path = fixture("source-identity.yml");
    assert_eq!(load_semgrep_rules(&path).len(), 2);

    let report = assess_semgrep_migration_readiness(&path).expect("report should load");
    assert_eq!(report.records.len(), 4);
    for source_id in ["", "duplicate/source"] {
        let outcomes: Vec<_> = report
            .records
            .iter()
            .filter(|outcome| outcome.source_id == source_id)
            .collect();
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().any(|outcome| {
            outcome.disposition == SemgrepMigrationDisposition::Exact
                && outcome.reason_code == SemgrepMigrationReasonCode::Exact
        }));
        assert!(outcomes.iter().any(|outcome| {
            outcome.disposition == SemgrepMigrationDisposition::Skipped
                && outcome.reason_code == SemgrepMigrationReasonCode::UnsupportedLanguage
        }));
    }
    assert!(report
        .records
        .iter()
        .any(|outcome| outcome.source_id.is_empty()));
}

#[test]
fn malformed_sibling_drops_the_original_file_transaction() {
    let path = fixture("malformed-sibling.yml");
    assert!(load_semgrep_rules(&path).is_empty());

    let report = assess_semgrep_migration_readiness(&path).expect("report should load");
    assert_eq!(report.records.len(), 2);
    for source_id in ["transaction/exact-sibling", "transaction/invalid-sibling"] {
        let outcome = record(&report.records, source_id);
        assert_eq!(outcome.disposition, SemgrepMigrationDisposition::Skipped);
        assert_eq!(
            outcome.reason_code,
            SemgrepMigrationReasonCode::FileImportFailed
        );
    }
}

#[test]
fn malformed_document_is_accounted_for_once() {
    let report = assess_semgrep_migration_readiness(&fixture("invalid-document.yml"))
        .expect("report should load");
    assert_eq!(report.records.len(), 1);
    let outcome = &report.records[0];
    assert_eq!(outcome.source_id, "<invalid-document>");
    assert_eq!(outcome.disposition, SemgrepMigrationDisposition::Skipped);
    assert_eq!(
        outcome.reason_code,
        SemgrepMigrationReasonCode::InvalidDocument
    );
}

#[test]
fn explicit_files_ignore_extension_while_directories_keep_production_filtering() {
    let temp = TempDir::new().expect("temp directory");
    let extensionless = temp.path().join("rules");
    fs::write(
        &extensionless,
        "rules:\n  - id: explicit/no-extension\n    message: Explicit file\n    severity: WARNING\n    languages: [python]\n    pattern: eval(...)\n",
    )
    .expect("write extensionless rule file");

    let explicit = assess_semgrep_migration_readiness(&extensionless).expect("explicit report");
    assert_eq!(load_semgrep_rules(&extensionless).len(), 1);
    assert_eq!(explicit.records.len(), 1);
    assert_eq!(
        explicit.records[0].disposition,
        SemgrepMigrationDisposition::Exact
    );

    fs::write(
        temp.path().join("included.yml"),
        "rules:\n  - id: directory/included\n    message: Included file\n    severity: WARNING\n    languages: [python]\n    pattern: eval(...)\n",
    )
    .expect("write yaml rule file");
    assert_eq!(load_semgrep_rules(temp.path()).len(), 1);
    let directory = assess_semgrep_migration_readiness(temp.path()).expect("directory report");
    assert_eq!(directory.records.len(), 1);
    assert_eq!(directory.records[0].source_id, "directory/included");
}

#[test]
fn mode_and_id_outcomes_follow_the_production_importer() {
    let temp = TempDir::new().expect("temp directory");
    let mode_file = temp.path().join("mode.yml");
    fs::write(
        &mode_file,
        "rules:\n  - id: mode/imported\n    mode: unsupported-by-readiness\n    message: Loader behavior\n    severity: WARNING\n    languages: [python]\n    pattern: eval(...)\n",
    )
    .expect("write mode file");
    assert_eq!(load_semgrep_rules(&mode_file).len(), 1);
    let mode_report = assess_semgrep_migration_readiness(&mode_file).expect("mode report");
    assert_eq!(
        mode_report.records[0].disposition,
        SemgrepMigrationDisposition::Exact
    );

    let id_file = temp.path().join("reserved-id.yml");
    fs::write(
        &id_file,
        "rules:\n  - id: transaction/good\n    message: Good sibling\n    severity: WARNING\n    languages: [python]\n    pattern: eval(...)\n  - id: py/reserved\n    message: Reserved sibling\n    severity: WARNING\n    languages: [python]\n    pattern: eval(...)\n",
    )
    .expect("write reserved-id file");
    assert!(load_semgrep_rules(&id_file).is_empty());
    let id_report = assess_semgrep_migration_readiness(&id_file).expect("id report");
    assert_eq!(id_report.records.len(), 2);
    for outcome in &id_report.records {
        assert_eq!(outcome.disposition, SemgrepMigrationDisposition::Skipped);
        assert_eq!(
            outcome.reason_code,
            SemgrepMigrationReasonCode::FileImportFailed
        );
    }
}

#[test]
fn report_schema_and_terminal_summary_are_deterministic() {
    let first = assess_semgrep_migration_readiness(&fixture("pack.yml"))
        .expect("fixture pack should produce a report");
    let second = assess_semgrep_migration_readiness(&fixture("pack.yml"))
        .expect("fixture pack should produce a report");

    assert_eq!(
        serde_json::to_string(&first).expect("report should serialize"),
        serde_json::to_string(&second).expect("report should serialize"),
    );

    let terminal = render_terminal(&first);
    assert!(terminal.contains("Semgrep migration readiness (schema 1.0.0)"));
    assert!(terminal.contains("By language:"));
    assert!(terminal.contains("By reason:"));
    assert!(terminal.contains("unsupported-pattern-not-regex: 1"));
    assert!(terminal.contains("unsupported-language: 1"));
}

#[test]
fn versioned_json_schema_matches_report_contract() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../schemas/semgrep-migration-readiness-v1.schema.json"
    ))
    .expect("schema should be valid JSON");

    assert_eq!(
        schema["$id"],
        "https://foxguard.dev/schemas/semgrep-migration-readiness-v1.schema.json"
    );
    assert_eq!(
        schema["properties"]["schema_version"]["const"],
        SEMGREP_MIGRATION_READINESS_SCHEMA_VERSION
    );
    assert_eq!(
        schema["properties"]["records"]["items"]["properties"]["disposition"]["enum"],
        serde_json::json!(["exact", "degraded", "skipped"])
    );
}

#[test]
fn cli_emits_versioned_json_report() {
    let output = Command::new(env!("CARGO_BIN_EXE_foxguard"))
        .args([
            "semgrep-readiness",
            "tests/fixtures/semgrep_migration_readiness/pack.yml",
            "--format",
            "json",
        ])
        .output()
        .expect("foxguard should run");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CLI output should be JSON");
    assert_eq!(report["schema_version"], "1.0.0");
    assert_eq!(report["records"].as_array().map(Vec::len), Some(3));
}
