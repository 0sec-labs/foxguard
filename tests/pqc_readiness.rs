//! Integration tests for post-quantum algorithm detection and the migration
//! readiness scorecard (the `pq-ready-crypto` rule family + the CBOM /
//! `foxguard pqc` summary additions).
//!
//! Faithfulness gate:
//! - ML-KEM / Kyber usage is detected as **post-quantum**, tagged `PQ-READY`,
//!   and never surfaces as a vulnerability or carries a CNSA deadline.
//! - RSA still flags as quantum-vulnerable with its 2033 deadline (no
//!   regression — see also `tests/cnsa2_compliance.rs`).
//! - A hybrid TLS config (`X25519MLKEM768`) is recognised as post-quantum.
//! - The CBOM lists the PQ algorithm as a quantum-resistant asset with no
//!   attached vulnerability.
//! - The readiness summary reports correct counts on a mixed fixture.

use std::path::{Path, PathBuf};
use std::process::Command;

fn foxguard_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_foxguard"));
    cmd.args(["--config", "/dev/null"]);
    cmd
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("pq_ready")
        .join(name)
}

fn pqc_json(target: &Path) -> Vec<serde_json::Value> {
    let out = foxguard_cmd()
        .arg("pqc")
        .arg(target)
        .args(["--format", "json"])
        .output()
        .expect("foxguard pqc should run");
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("pqc JSON output should parse");
    report["findings"]
        .as_array()
        .cloned()
        .expect("JSON report missing findings array")
}

fn pqc_terminal(target: &Path) -> String {
    let out = foxguard_cmd()
        .arg("pqc")
        .arg(target)
        .output()
        .expect("foxguard pqc should run");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn rule_ids(findings: &[serde_json::Value]) -> Vec<String> {
    findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str().map(String::from))
        .collect()
}

#[test]
fn ml_kem_source_is_post_quantum_not_a_vulnerability() {
    let findings = pqc_json(&fixture("mixed.py"));
    let pq: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"].as_str() == Some("py/pq-ready-crypto"))
        .collect();
    assert!(
        !pq.is_empty(),
        "expected py/pq-ready-crypto findings; got rules: {:?}",
        rule_ids(&findings)
    );
    for f in &pq {
        // Positive inventory entry: informational, no deadline, tagged PQ-READY.
        assert_eq!(f["severity"].as_str(), Some("low"));
        assert_eq!(f["crypto_algorithm"].as_str(), Some("ML-KEM"));
        assert!(
            f.get("cnsa2_deadline").and_then(|v| v.as_str()).is_none(),
            "post-quantum finding must not carry a CNSA deadline: {f:?}"
        );
        let tags: Vec<&str> = f["tags"]
            .as_array()
            .map(|a| a.iter().filter_map(|t| t.as_str()).collect())
            .unwrap_or_default();
        assert!(tags.contains(&"PQ-READY"), "expected PQ-READY tag: {f:?}");
    }
}

#[test]
fn go_crypto_mlkem_is_detected() {
    let ids = rule_ids(&pqc_json(&fixture("mlkem.go")));
    assert!(
        ids.iter().any(|id| id == "go/pq-ready-crypto"),
        "expected go/pq-ready-crypto for `crypto/mlkem`; got {ids:?}"
    );
}

#[test]
fn cargo_lock_pq_dependency_is_detected() {
    let findings = pqc_json(&fixture("Cargo.lock"));
    let algos: Vec<&str> = findings
        .iter()
        .filter(|f| f["rule_id"].as_str() == Some("manifest/cargo-pq-ready-dep"))
        .filter_map(|f| f["crypto_algorithm"].as_str())
        .collect();
    assert!(
        algos.contains(&"ML-KEM"),
        "expected ML-KEM from `ml-kem` crate; got {algos:?}"
    );
    assert!(
        algos.contains(&"ML-DSA"),
        "expected ML-DSA from `pqcrypto-dilithium` crate; got {algos:?}"
    );
}

#[test]
fn rsa_still_flags_as_quantum_vulnerable_with_deadline() {
    let findings = pqc_json(&fixture("mixed.py"));
    let vuln: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"].as_str() == Some("py/pq-vulnerable-crypto"))
        .collect();
    assert_eq!(
        vuln.len(),
        1,
        "RSA must still flag as quantum-vulnerable; got rules {:?}",
        rule_ids(&findings)
    );
    assert_eq!(vuln[0]["cnsa2_deadline"].as_str(), Some("2033"));
}

#[test]
fn hybrid_nginx_config_is_post_quantum_ready() {
    let findings = pqc_json(&fixture("nginx-pq.conf"));
    let pq: Vec<&serde_json::Value> = findings
        .iter()
        .filter(|f| f["rule_id"].as_str() == Some("config/nginx-pq-ready-tls"))
        .collect();
    assert_eq!(
        pq.len(),
        1,
        "expected config/nginx-pq-ready-tls for X25519MLKEM768; got {:?}",
        rule_ids(&findings)
    );
    assert_eq!(pq[0]["crypto_algorithm"].as_str(), Some("X25519MLKEM768"));
}

#[test]
fn cbom_lists_pq_asset_as_quantum_resistant_without_vulnerability() {
    let out = foxguard_cmd()
        .arg("pqc")
        .arg(fixture("mixed.py"))
        .args(["--format", "cbom"])
        .output()
        .expect("foxguard pqc should run");
    let cbom: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("CBOM output should parse");

    let components = cbom["components"].as_array().expect("components array");
    let ml_kem = components
        .iter()
        .find(|c| c["name"].as_str() == Some("ML-KEM"))
        .expect("ML-KEM component present in CBOM");
    assert_eq!(ml_kem["cryptoProperties"]["assetType"], "algorithm");
    let props = ml_kem["properties"].as_array().expect("PQ props present");
    assert!(
        props
            .iter()
            .any(|p| p["name"] == "foxguard:quantum-resistant" && p["value"] == "true"),
        "ML-KEM must be marked quantum-resistant: {ml_kem:?}"
    );

    // No vulnerability entry may reference the PQ asset.
    let vulns = cbom["vulnerabilities"].as_array().expect("vulnerabilities");
    assert!(
        !vulns
            .iter()
            .any(|v| v["id"].as_str() == Some("foxguard-ml-kem")),
        "post-quantum asset must not appear as a vulnerability: {vulns:?}"
    );
    // RSA (vulnerable) must still be present as a vulnerability.
    assert!(
        vulns
            .iter()
            .any(|v| v["id"].as_str() == Some("foxguard-rsa")),
        "RSA vulnerability must remain in CBOM: {vulns:?}"
    );
}

#[test]
fn readiness_summary_reports_mixed_counts() {
    let text = pqc_terminal(&fixture("mixed.py"));
    assert!(
        text.contains("Post-quantum"),
        "pqc terminal output should include the post-quantum scorecard; got:\n{text}"
    );
    assert!(
        text.contains("1 quantum-vulnerable, 2 post-quantum"),
        "mixed fixture should report 1 vulnerable / 2 post-quantum; got:\n{text}"
    );
    assert!(
        text.contains("67% ready"),
        "mixed fixture readiness should be 67%; got:\n{text}"
    );
    assert!(
        text.contains("migration in progress"),
        "mixed fixture should read as migration in progress; got:\n{text}"
    );
}

#[test]
fn default_scan_does_not_emit_pq_ready_findings() {
    // pq-ready rules are opt-in (activated only by `foxguard pqc`). A plain
    // scan must not surface informational PQ findings — a repo using ML-KEM is
    // not "insecure" and must not fail a normal scan on that basis.
    let out = foxguard_cmd()
        .arg(fixture("mixed.py"))
        .args(["--format", "json"])
        .output()
        .expect("foxguard should run");
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("scan JSON should parse");
    let ids: Vec<String> = report["findings"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|f| f["rule_id"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !ids.iter().any(|id| id.contains("pq-ready")),
        "default scan must not run pq-ready rules; got {ids:?}"
    );
}
