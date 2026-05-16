//! Integration tests for the CNSA 2.0 compliance module (issue #241).
//!
//! These guard two regressions the #231 review called out:
//!
//! 1. Deadlines must come from the rule itself, not substring-matching rule
//!    IDs. We therefore check every real PQ-related rule against the
//!    compliance module — if a rule is renamed without updating its
//!    `cnsa2_deadline = "..."` line, the `None` result fails the test.
//! 2. The `--cnsa2` terminal output must be opt-in. The default terminal
//!    view stays unchanged; the flag flips on the annotation line and
//!    summary block.

use std::path::{Path, PathBuf};
use std::process::Command;

fn foxguard_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_foxguard"))
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

// ── 1. Every real PQ-related rule produces a non-None deadline ────────────

/// Exact list of rule IDs that must declare a CNSA 2.0 deadline. Hard-coded
/// rather than derived from a substring match — the whole point of this
/// test is to catch rule renames. Keep in sync with `src/compliance.rs`
/// and the `impl_rule!` annotations in `src/rules/*.rs`.
const REQUIRED_CNSA2_RULES: &[&str] = &[
    "js/pq-vulnerable-crypto",
    "py/pq-vulnerable-crypto",
    "go/pq-vulnerable-crypto",
    "java/pq-vulnerable-crypto",
    "rs/pq-vulnerable-crypto",
    "js/hardcoded-crypto-algorithm",
    "py/hardcoded-crypto-algorithm",
    "java/hardcoded-crypto-algorithm",
    "config/nginx-pq-vulnerable-tls",
    "config/apache-pq-vulnerable-tls",
    "config/haproxy-pq-vulnerable-tls",
    "config/dockerfile-insecure-tls-env",
];

#[test]
fn every_declared_pq_rule_reports_a_cnsa2_deadline() {
    use foxguard::rules::RuleRegistry;

    let registry = RuleRegistry::new();
    let mut missing = Vec::new();
    for &rule_id in REQUIRED_CNSA2_RULES {
        match foxguard::compliance::deadline_for_rule_id(&registry, rule_id) {
            Some(d) if !d.is_empty() => {}
            Some(_) | None => missing.push(rule_id),
        }
    }
    assert!(
        missing.is_empty(),
        "rules missing a cnsa2_deadline annotation: {:?}",
        missing
    );
}

#[test]
fn non_pq_rules_do_not_declare_a_cnsa2_deadline() {
    // Sanity: a couple of unrelated rules must stay `None`. Guards against
    // an overly-broad macro arm accidentally bleeding the deadline into
    // every rule.
    use foxguard::rules::RuleRegistry;

    let registry = RuleRegistry::new();
    for rule_id in [
        "py/no-eval",
        "js/no-sql-injection",
        "go/no-command-injection",
    ] {
        assert!(
            foxguard::compliance::deadline_for_rule_id(&registry, rule_id).is_none(),
            "{rule_id} should not carry a CNSA 2.0 deadline"
        );
    }
}

// ── 2. End-to-end: scanning a PQ-vulnerable fixture with JSON emits the
// deadline field in every PQ finding and only in PQ findings ─────────────

fn scan_json_findings(target: &Path) -> Vec<serde_json::Value> {
    // --config /dev/null isolates the test from any developer-local
    // .foxguard.yml in CARGO_MANIFEST_DIR. Without this the test will
    // pick up the contributor's local baseline (which legitimately
    // suppresses dozens of findings in tests/fixtures/vulnerable.py
    // for self-scan hygiene) and the "non-PQ findings exist" assertion
    // below collapses to zero.
    let out = foxguard_cmd()
        .arg(target)
        .args(["--format", "json", "--config", "/dev/null"])
        .output()
        .expect("foxguard should run");
    // foxguard exits 1 when findings exist — accept non-zero exit codes.
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str::<Vec<serde_json::Value>>(&text)
        .unwrap_or_else(|e| panic!("expected JSON array of findings, got: {text}\nerror: {e}"))
}

#[test]
fn pq_fixture_emits_cnsa2_deadline_in_json() {
    // vulnerable.py contains a `rsa.generate_private_key(...)` call that
    // the py/pq-vulnerable-crypto rule fires on.
    let findings = scan_json_findings(&fixture("vulnerable.py"));
    let pq: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"].as_str() == Some("py/pq-vulnerable-crypto"))
        .collect();
    assert!(
        !pq.is_empty(),
        "expected at least one py/pq-vulnerable-crypto finding in fixture; findings: {:?}",
        findings
            .iter()
            .map(|f| f["rule_id"].clone())
            .collect::<Vec<_>>()
    );
    for f in &pq {
        assert_eq!(
            f["cnsa2_deadline"].as_str(),
            Some("2033"),
            "PQ finding must carry the CNSA 2.0 web/cloud deadline: {f:?}"
        );
    }
}

#[test]
fn non_pq_findings_in_json_have_no_cnsa2_deadline() {
    let findings = scan_json_findings(&fixture("vulnerable.py"));
    // There's always at least one non-PQ rule that fires (py/no-eval etc.).
    let has_non_pq = findings.iter().any(|f| {
        f["rule_id"]
            .as_str()
            .is_some_and(|id| !id.contains("pq-vulnerable") && !id.contains("hardcoded-crypto"))
    });
    assert!(has_non_pq, "fixture should produce non-PQ findings too");
    for f in &findings {
        let rule_id = f["rule_id"].as_str().unwrap_or("");
        if rule_id.contains("pq-vulnerable") || rule_id.contains("hardcoded-crypto") {
            continue;
        }
        let deadline = f.get("cnsa2_deadline").and_then(|v| v.as_str());
        assert!(
            deadline.is_none(),
            "non-PQ finding {rule_id} unexpectedly carries cnsa2_deadline={deadline:?}"
        );
    }
}

// ── 3. --cnsa2 flag toggles terminal output ──────────────────────────────

#[test]
fn cnsa2_flag_off_does_not_mention_cnsa_in_terminal() {
    let out = foxguard_cmd()
        .arg(fixture("vulnerable.py"))
        .output()
        .expect("foxguard should run");
    let text = String::from_utf8_lossy(&out.stdout);
    // The remediation text itself references "CNSA 2.0 / NSS:" to distinguish
    // the general-use FIPS-cat-III parameter sets from the CNSA 2.0 / NSS
    // parameter sets (issue #253). The `--cnsa2` flag controls the separate
    // *compliance annotations* — the per-finding "CNSA 2.0: migrate before
    // end of YYYY" line and the summary block. Assert on the annotation
    // markers rather than the bare substring "CNSA 2.0".
    assert!(
        !text.contains("CNSA 2.0:"),
        "default terminal output must not render the per-finding CNSA 2.0 deadline annotation; got:\n{text}"
    );
    assert!(
        !text.contains("migrate before end of"),
        "default terminal output must not render the per-finding CNSA 2.0 deadline annotation; got:\n{text}"
    );
    assert!(
        !text.contains(" at-risk ") && !text.contains(" on-track ") && !text.contains(" clean "),
        "default terminal output must not render the CNSA 2.0 summary level label; got:\n{text}"
    );
}

#[test]
fn cnsa2_flag_on_adds_deadline_annotation_and_summary() {
    let out = foxguard_cmd()
        .arg(fixture("vulnerable.py"))
        .arg("--cnsa2")
        .output()
        .expect("foxguard should run");
    let text = String::from_utf8_lossy(&out.stdout);
    // The flag renders the per-finding annotation line ("CNSA 2.0: migrate
    // before end of YYYY"). The bare substring "CNSA 2.0" now also appears
    // in remediation text regardless of the flag (see issue #253), so check
    // for the annotation-specific marker.
    assert!(
        text.contains("CNSA 2.0:") || text.contains("migrate before end of"),
        "--cnsa2 should surface the per-finding CNSA deadline annotation; got:\n{text}"
    );
    // Summary block names the migration level and per-year counts.
    assert!(
        text.contains("at-risk") || text.contains("on-track") || text.contains("clean"),
        "--cnsa2 summary should render a migration level; got:\n{text}"
    );
    // And the actual deadline year for the web/cloud class.
    assert!(
        text.contains("2033"),
        "--cnsa2 summary should name the 2033 deadline; got:\n{text}"
    );
}

#[test]
fn sarif_always_includes_cnsa2_deadline_in_properties() {
    // SARIF carries the field regardless of --cnsa2 (metadata for
    // downstream governance tooling). The key is camelCase
    // `cnsa2Deadline` per SARIF convention — not snake_case.
    let out = foxguard_cmd()
        .arg(fixture("vulnerable.py"))
        .args(["--format", "sarif"])
        .output()
        .expect("foxguard should run");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("\"cnsa2Deadline\""),
        "SARIF should expose cnsa2Deadline in properties; got:\n{text}"
    );
    assert!(
        !text.contains("\"cnsa2_deadline\":"),
        "SARIF must use camelCase cnsa2Deadline, not snake_case; got:\n{text}"
    );
}

#[test]
fn sarif_includes_dep_name_in_properties() {
    let out = foxguard_cmd()
        .arg(fixture("deps/requirements.txt"))
        .args(["--format", "sarif"])
        .output()
        .expect("foxguard should run");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("\"depName\""),
        "SARIF should expose depName in properties; got:\n{text}"
    );
}
