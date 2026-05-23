//! Calibration tests for the Dirty Frag class rules
//! (`rules/kernel/dirty-frag-class/*.yaml`).
//!
//! Each rule has a positive fixture (must flag) and a negative fixture
//! (must NOT flag — has a dominating cow / out=0 / non-aliased SGL).
//!
//! Background:
//! - oss-security advisory 2026-05-07 (Dirty Frag, Hyunwoo Kim @v4bel)
//! - upstream ESP patch f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4
//! - pwnkit issue #263 (foxguard-first integration approach)

use foxguard::engine::codeql::parse_codeql_file;
use foxguard::engine::parser::parse_file;
use foxguard::rules::semgrep_compat::parse_semgrep_file;
use foxguard::Language;
use std::path::Path;

const RULES_DIR: &str = "rules/kernel/dirty-frag-class";
const FIXTURES_DIR: &str = "tests/fixtures/kernel/dirty-frag";

fn run_rule(rule_yaml: &str, fixture_basename: &str) -> usize {
    run_rule_at_path(rule_yaml, fixture_basename, fixture_basename)
}

fn run_rule_at_path(rule_yaml: &str, fixture_basename: &str, scan_path: &str) -> usize {
    let rules =
        parse_semgrep_file(&Path::new(RULES_DIR).join(rule_yaml)).expect("rule parses cleanly");
    assert_eq!(rules.len(), 1, "expected one rule per yaml file");

    let source =
        std::fs::read_to_string(Path::new(FIXTURES_DIR).join(fixture_basename)).expect("fixture");
    let tree = parse_file(&source, Language::C).expect("tree-sitter-c parses fixture");
    if !rules[0].applies_to_path(Path::new(scan_path)) {
        return 0;
    }
    rules[0].check(&source, &tree).len()
}

#[test]
fn skb_inplace_skcipher_no_cow_flags_vulnerable_fixture() {
    let n = run_rule(
        "skb-inplace-skcipher-no-cow.yaml",
        "skcipher_no_cow_vulnerable.c",
    );
    assert!(
        n >= 1,
        "expected positive fixture to be flagged, got {} findings",
        n
    );
}

#[test]
fn skb_inplace_skcipher_no_cow_ignores_safe_fixture() {
    let n = run_rule("skb-inplace-skcipher-no-cow.yaml", "skcipher_no_cow_safe.c");
    assert_eq!(
        n, 0,
        "expected negative fixture (skb_cow_data dominates) to be unflagged, got {} findings",
        n
    );
}

#[test]
fn skb_inplace_aead_no_cow_flags_vulnerable_fixture() {
    let n = run_rule("skb-inplace-aead-no-cow.yaml", "aead_no_cow_vulnerable.c");
    assert!(
        n >= 1,
        "expected positive fixture to be flagged, got {} findings",
        n
    );
}

#[test]
fn skb_inplace_aead_no_cow_ignores_safe_fixture() {
    let n = run_rule("skb-inplace-aead-no-cow.yaml", "aead_no_cow_safe.c");
    assert_eq!(
        n, 0,
        "expected negative fixture (skb_cow_data dominates) to be unflagged, got {} findings",
        n
    );
}

#[test]
fn scatterwalk_store_on_shared_sgl_flags_vulnerable_fixture() {
    let n = run_rule(
        "scatterwalk-store-on-shared-sgl.yaml",
        "scatterwalk_store_vulnerable.c",
    );
    assert!(
        n >= 1,
        "expected positive fixture (out=1 STORE on aliased SGL) to be flagged, got {} findings",
        n
    );
}

#[test]
fn scatterwalk_store_on_shared_sgl_ignores_safe_fixture() {
    let n = run_rule(
        "scatterwalk-store-on-shared-sgl.yaml",
        "scatterwalk_store_safe.c",
    );
    assert_eq!(
        n, 0,
        "expected negative fixture (out=0 READ, non-aliased SGL) to be unflagged, got {} findings",
        n
    );
}

// --- Tier 1 sibling-site fixtures (positive: must flag) ---

#[test]
fn skb_inplace_aead_no_cow_flags_ah_sibling_fixture() {
    let n = run_rule(
        "skb-inplace-aead-no-cow.yaml",
        "ah_aead_no_cow_vulnerable.c",
    );
    assert!(
        n >= 1,
        "expected AH-style sibling positive fixture to be flagged, got {} findings",
        n
    );
}

#[test]
fn skb_inplace_skcipher_no_cow_flags_ipcomp_sibling_fixture() {
    let n = run_rule(
        "skb-inplace-skcipher-no-cow.yaml",
        "ipcomp_skcipher_no_cow_vulnerable.c",
    );
    assert!(
        n >= 1,
        "expected IPComp-style sibling positive fixture to be flagged, got {} findings",
        n
    );
}

#[test]
fn rxrpc_verify_response_dispatch_flags_conn_event_fixture() {
    let n = run_rule_at_path(
        "rxrpc-verify-response-dispatch.yaml",
        "rxrpc_conn_event_vulnerable.c",
        "net/rxrpc/conn_event.c",
    );
    assert!(
        n >= 1,
        "expected conn_event RESPONSE dispatch fixture to be flagged, got {} findings",
        n
    );
}

// --- Tier 2 known-FP fixtures (negative: extra cow-gate names dominate) ---

#[test]
fn skb_inplace_aead_no_cow_ignores_tls_cow_fixture() {
    let n = run_rule("skb-inplace-aead-no-cow.yaml", "tls_aead_cow_safe.c");
    assert_eq!(
        n, 0,
        "expected kTLS-style cow-gate fixture (__skb_cow) to be unflagged, got {} findings",
        n
    );
}

#[test]
fn skb_inplace_skcipher_no_cow_ignores_macsec_cow_fixture() {
    let n = run_rule(
        "skb-inplace-skcipher-no-cow.yaml",
        "macsec_skcipher_cow_safe.c",
    );
    assert_eq!(
        n, 0,
        "expected MACsec-style cow-gate fixture (skb_copy_expand) to be unflagged, got {} findings",
        n
    );
}

#[test]
fn scatterwalk_store_on_shared_sgl_flags_authenc_sibling_fixture() {
    let n = run_rule(
        "scatterwalk-store-on-shared-sgl.yaml",
        "scatterwalk_authenc_store_vulnerable.c",
    );
    assert!(
        n >= 1,
        "expected authenc-style sibling positive fixture (in-place + STORE) to be flagged, got {} findings",
        n
    );
}

#[test]
fn scatterwalk_authencesn_exception_flags_confirmed_crypto_site() {
    let n = run_rule_at_path(
        "scatterwalk-store-on-shared-sgl-authencesn.yaml",
        "scatterwalk_store_vulnerable.c",
        "crypto/authencesn.c",
    );
    assert!(
        n >= 1,
        "expected authencesn exception rule to flag confirmed crypto/authencesn.c shape, got {} findings",
        n
    );
}

#[test]
fn dirty_frag_rules_ignore_crypto_template_wrapper_fixture() {
    for rule_yaml in [
        "skb-inplace-aead-no-cow.yaml",
        "skb-inplace-skcipher-no-cow.yaml",
        "scatterwalk-store-on-shared-sgl.yaml",
        "scatterwalk-store-on-shared-sgl-authencesn.yaml",
    ] {
        let n = run_rule_at_path(
            rule_yaml,
            "crypto_template_wrapper_no_skb.c",
            "crypto/gcm.c",
        );
        assert_eq!(
            n, 0,
            "expected {rule_yaml} to ignore crypto template-wrapper fixture, got {n} findings"
        );
    }
}

#[test]
fn esp_shared_frag_decrypt_guard_codeql_rule_parses() {
    let (rules, notices) =
        parse_codeql_file(&Path::new(RULES_DIR).join("esp-shared-frag-decrypt-guard-codeql.yaml"))
            .expect("CodeQL rule parses cleanly");

    assert!(
        notices.is_empty(),
        "expected no CodeQL parse notices, got {notices:?}"
    );
    assert_eq!(rules.len(), 1, "expected one CodeQL rule");
    assert_eq!(
        rules[0].id,
        "kernel/dirty-frag/esp-shared-frag-decrypt-guard-codeql"
    );
    assert_eq!(rules[0].cwe.as_deref(), Some("CWE-787"));
}

#[test]
fn scatterwalk_store_on_shared_sgl_ignores_inplace_read_fixture() {
    let n = run_rule(
        "scatterwalk-store-on-shared-sgl.yaml",
        "scatterwalk_inplace_read_safe.c",
    );
    assert_eq!(
        n, 0,
        "expected in-place + READ-back (out=0) fixture to be unflagged, got {} findings",
        n
    );
}

#[test]
fn scatterwalk_store_on_shared_sgl_flags_memcpy_to_sglist_fixture() {
    let n = run_rule(
        "scatterwalk-store-on-shared-sgl.yaml",
        "scatterwalk_memcpy_to_sglist_vulnerable.c",
    );
    assert!(
        n >= 1,
        "expected memcpy_to_sglist STORE on in-place AEAD SGL to be flagged, got {n} findings"
    );
}

#[test]
fn scatterwalk_store_on_shared_sgl_ignores_memcpy_from_sglist_fixture() {
    let n = run_rule(
        "scatterwalk-store-on-shared-sgl.yaml",
        "scatterwalk_memcpy_from_sglist_safe.c",
    );
    assert_eq!(
        n, 0,
        "expected memcpy_from_sglist READ-back on in-place AEAD SGL to be unflagged, got {n} findings"
    );
}

#[test]
fn scatterwalk_authencesn_exception_flags_memcpy_to_sglist_fixture() {
    let n = run_rule_at_path(
        "scatterwalk-store-on-shared-sgl-authencesn.yaml",
        "scatterwalk_memcpy_to_sglist_vulnerable.c",
        "crypto/authencesn.c",
    );
    assert!(
        n >= 1,
        "expected authencesn exception rule to flag memcpy_to_sglist STORE at crypto/authencesn.c, got {n} findings"
    );
}
