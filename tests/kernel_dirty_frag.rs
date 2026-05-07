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

use foxguard::engine::parser::parse_file;
use foxguard::rules::semgrep_compat::parse_semgrep_file;
use foxguard::Language;
use std::path::Path;

const RULES_DIR: &str = "rules/kernel/dirty-frag-class";
const FIXTURES_DIR: &str = "tests/fixtures/kernel/dirty-frag";

fn run_rule(rule_yaml: &str, fixture_basename: &str) -> usize {
    let rules =
        parse_semgrep_file(&Path::new(RULES_DIR).join(rule_yaml)).expect("rule parses cleanly");
    assert_eq!(rules.len(), 1, "expected one rule per yaml file");

    let source =
        std::fs::read_to_string(Path::new(FIXTURES_DIR).join(fixture_basename)).expect("fixture");
    let tree = parse_file(&source, Language::C).expect("tree-sitter-c parses fixture");
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
