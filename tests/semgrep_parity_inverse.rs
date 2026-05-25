//! Inverse-direction Semgrep parity tests (issue #377).
//!
//! The companion test file `tests/semgrep_parity.rs` proves foxguard
//! matches Semgrep on patterns Semgrep can express. That is necessary
//! but not sufficient: it does not protect the differentiation pillars
//! that motivate the product — post-quantum-vulnerable crypto detection,
//! cross-file taint, and Rust `unsafe` analysis. None of these are
//! emitted by Semgrep's default rule registry, so a single one-direction
//! parity check cannot detect a silent regression in any of them.
//!
//! Each test below pins a different pillar:
//!
//!  1. `inverse_pq_crypto_foxguard_finds_more_than_semgrep`
//!  2. `inverse_cross_file_taint_foxguard_connects_sources_to_sinks`
//!  3. `inverse_rust_unsafe_foxguard_flags_what_semgrep_ignores`
//!
//! Assertion shape (instead of the brittle `foxguard.len() > semgrep.len()`):
//!   - foxguard MUST emit at least one finding whose `rule_id` matches
//!     the expected family for the pillar.
//!   - Semgrep, run with a representative "default" ruleset, MUST NOT
//!     emit any finding whose `rule_id` matches that family.
//!
//! Tests are skipped (not failed) when the `semgrep` binary is absent
//! from the host, mirroring the convention in `tests/semgrep_parity.rs`.

mod common;

use common::semgrep_parity_harness::{
    normalize_path, semgrep_bin, skip_if_semgrep_missing, write_file,
};
use serde_json::Value;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

/// A finding normalized down to the fields the inverse tests reason
/// about. We keep `rule_id` (unlike `tests/semgrep_parity.rs`) because
/// the inverse assertions are family-scoped, not equality-scoped.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct NormalizedFinding {
    rule_id: String,
    path: String,
    line: u64,
}

fn foxguard_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_foxguard"));
    // `--config /dev/null` insulates the test from any developer-local
    // `.foxguard.yml` near CARGO_MANIFEST_DIR (the repo's own baseline
    // suppresses many findings under `tests/fixtures/` for self-scan
    // hygiene). Matches the pattern in `tests/realistic_fixtures.rs`.
    cmd.args(["--config", "/dev/null"]);
    cmd
}

fn parse_foxguard_findings(output: &[u8], repo: &Path) -> Vec<NormalizedFinding> {
    let report: Value = serde_json::from_slice(output).expect("invalid foxguard JSON output");
    let findings = report["findings"]
        .as_array()
        .cloned()
        .expect("foxguard JSON report missing findings array");
    let mut normalized = findings
        .into_iter()
        .map(|finding| NormalizedFinding {
            rule_id: finding["rule_id"]
                .as_str()
                .expect("foxguard finding missing rule_id")
                .to_string(),
            path: normalize_path(
                finding["file"]
                    .as_str()
                    .expect("foxguard finding missing file"),
                repo,
            ),
            line: finding["line"]
                .as_u64()
                .expect("foxguard finding missing line"),
        })
        .collect::<Vec<_>>();
    normalized.sort();
    normalized
}

fn parse_semgrep_findings(output: &[u8], repo: &Path) -> Vec<NormalizedFinding> {
    let payload: Value = serde_json::from_slice(output).expect("invalid semgrep JSON output");
    let results = payload["results"]
        .as_array()
        .expect("semgrep output missing results");

    let mut normalized = results
        .iter()
        .map(|finding| NormalizedFinding {
            rule_id: finding["check_id"]
                .as_str()
                .expect("semgrep finding missing check_id")
                .to_string(),
            path: normalize_path(
                finding["path"]
                    .as_str()
                    .expect("semgrep finding missing path"),
                repo,
            ),
            line: finding["start"]["line"]
                .as_u64()
                .expect("semgrep finding missing start line"),
        })
        .collect::<Vec<_>>();
    normalized.sort();
    normalized
}

/// Run foxguard with its built-in rule set enabled (the inverse tests
/// exist specifically to exercise built-in rules, so unlike
/// `tests/semgrep_parity.rs` we do NOT pass `--no-builtins`).
fn foxguard_findings(scan_target: &Path, scan_root: &Path) -> Vec<NormalizedFinding> {
    let output = foxguard_cmd()
        .args([
            scan_target.to_str().expect("non-utf8 scan target"),
            "-f",
            "json",
        ])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        output.status.success() || !output.stdout.is_empty(),
        "foxguard failed without JSON output: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    parse_foxguard_findings(&output.stdout, scan_root)
}

/// Run Semgrep against `scan_target` with a representative "default"
/// ruleset written to `rules_path`. We pass a curated YAML rather than
/// `--config auto` to keep the test hermetic (no network) while still
/// covering the kinds of rules a typical Semgrep deployment would have:
/// common injection and secret patterns. Crucially, none of these rules
/// cover the foxguard differentiation family we are about to assert on.
fn semgrep_findings_with_default_rules(
    rules_path: &Path,
    scan_target: &Path,
    scan_root: &Path,
) -> Vec<NormalizedFinding> {
    let output = Command::new(semgrep_bin())
        .args([
            "--config",
            rules_path.to_str().expect("non-utf8 rules path"),
            "--json",
            "--quiet",
            scan_target.to_str().expect("non-utf8 scan target"),
        ])
        .output()
        .expect("failed to execute semgrep");

    assert!(
        output.status.success(),
        "semgrep failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    parse_semgrep_findings(&output.stdout, scan_root)
}

// ───────────────────────────────────────────────────────────────────────────
// Pillar 1 — Post-quantum-vulnerable crypto
// ───────────────────────────────────────────────────────────────────────────

/// foxguard ships a built-in `py/pq-vulnerable-crypto` rule that flags
/// RSA / ECDSA / ECDH / DSA / Ed25519 / X25519 keygen calls so the user
/// can stage CNSA 2.0 migrations. Semgrep's default rule registry has no
/// equivalent: there is no widely-published Semgrep rule that fires on
/// `rsa.generate_private_key` or `ec.generate_private_key` purely on the
/// grounds that the algorithm is quantum-vulnerable.
///
/// Asserts:
///   - foxguard emits at least one `py/pq-vulnerable-crypto` finding.
///   - Semgrep, with representative default rules, emits zero findings
///     whose `check_id` mentions PQ / quantum.
#[test]
fn inverse_pq_crypto_foxguard_finds_more_than_semgrep() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let fixture = write_file(
        repo.path(),
        "src/keys.py",
        r#"from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

def gen_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def gen_ec():
    return ec.generate_private_key(ec.SECP256R1())

def gen_ed():
    return ed25519.Ed25519PrivateKey.generate()
"#,
    );

    // A representative "Semgrep default" Python ruleset. None of these
    // rules cover quantum-vulnerable crypto — they cover the standard
    // injection / eval patterns most teams publish.
    let semgrep_rules = write_file(
        repo.path(),
        "rules/py-defaults.yaml",
        r#"
rules:
  - id: eval-usage
    pattern-either:
      - pattern: eval(...)
      - pattern: exec(...)
    message: eval/exec usage
    severity: ERROR
    languages: [python]
  - id: sql-injection-concat
    pattern-either:
      - pattern: cursor.execute("..." + $X)
      - pattern: cur.execute("..." + $X)
    message: SQL injection via string concatenation
    severity: ERROR
    languages: [python]
  - id: hardcoded-password
    pattern-regex: '(?m)^password\s*=\s*"[^"]+"'
    message: Hardcoded password
    severity: WARNING
    languages: [python]
"#,
    );

    let foxguard = foxguard_findings(&fixture, repo.path());
    let semgrep = semgrep_findings_with_default_rules(&semgrep_rules, &fixture, repo.path());

    assert!(
        foxguard
            .iter()
            .any(|f| f.rule_id == "py/pq-vulnerable-crypto"),
        "foxguard must flag py/pq-vulnerable-crypto on RSA/ECDSA keygen; got: {foxguard:?}"
    );
    assert_eq!(
        semgrep
            .iter()
            .filter(|f| f.rule_id.contains("pq-vulnerable")
                || f.rule_id.to_ascii_lowercase().contains("quantum"))
            .count(),
        0,
        "semgrep default rules must not contain a PQ-equivalent finding; got: {semgrep:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Pillar 2 — Cross-file taint
// ───────────────────────────────────────────────────────────────────────────

/// foxguard's two-pass scanner builds per-function taint summaries (see
/// `src/rules/cross_file.rs` and `docs/taint-tracking.md`) so a tainted
/// HTTP parameter in one file can flow through a passthrough helper in
/// a second file and reach a SQL sink in a third. Semgrep's matcher is
/// per-file: it cannot connect the source in `views.py` to the sink in
/// `queries.py` no matter how the rules are written.
///
/// We reuse the existing `tests/fixtures/realistic/django_chain`
/// fixture (three-file chain: views.py → middleware.py → queries.py).
///
/// Asserts:
///   - foxguard emits at least one `py/taint-sql-injection` finding on
///     this fixture (proves the cross-file summary engine connects the
///     source to the sink).
///   - Semgrep, with the same kind of single-file SQL-injection rule a
///     team would normally publish, emits zero findings of that family.
#[test]
fn inverse_cross_file_taint_foxguard_connects_sources_to_sinks() {
    if skip_if_semgrep_missing() {
        return;
    }

    let chain = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("realistic")
        .join("django_chain");

    let rules_dir = TempDir::new().expect("failed to create temp dir");
    // A typical single-file Semgrep SQL-injection rule. It correctly
    // matches `cur.execute("..." + x)` if both the source and the sink
    // are in the same function — but in `django_chain` the source is in
    // views.py and the sink is in queries.py, so this rule cannot fire.
    let semgrep_rules = write_file(
        rules_dir.path(),
        "py-defaults.yaml",
        r#"
rules:
  - id: sql-injection-concat
    pattern-either:
      - pattern: cur.execute("..." + $X)
      - pattern: cursor.execute("..." + $X)
      - pattern: $C.execute("..." + $X)
    message: SQL injection via string concatenation
    severity: ERROR
    languages: [python]
  - id: eval-usage
    pattern: eval(...)
    message: eval used
    severity: ERROR
    languages: [python]
"#,
    );

    let foxguard = foxguard_findings(&chain, &chain);
    let semgrep = semgrep_findings_with_default_rules(&semgrep_rules, &chain, &chain);

    assert!(
        foxguard
            .iter()
            .any(|f| f.rule_id == "py/taint-sql-injection"),
        "foxguard must connect cross-file taint (views.py source → queries.py sink) \
         via py/taint-sql-injection; got: {foxguard:?}"
    );
    assert_eq!(
        semgrep
            .iter()
            .filter(|f| f.rule_id.contains("sql-injection"))
            .count(),
        0,
        "semgrep is per-file and cannot connect the cross-file chain; \
         got unexpected sql-injection finding(s): {semgrep:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Pillar 3 — Rust `unsafe` block analysis
// ───────────────────────────────────────────────────────────────────────────

/// foxguard ships built-in Rust rules `rs/unsafe-block` and
/// `rs/transmute-usage` (see `src/rules/rust_lang.rs`). Semgrep has no
/// equivalent in its default rule set — Rust support exists, but the
/// publicly-curated registry does not flag `unsafe { ... }` or
/// `std::mem::transmute` on the grounds that they bypass memory safety.
///
/// Asserts:
///   - foxguard emits at least one `rs/unsafe-block` finding AND at
///     least one `rs/transmute-usage` finding on the fixture.
///   - Semgrep, with a representative Rust default ruleset, emits zero
///     findings whose `check_id` mentions unsafe or transmute.
#[test]
fn inverse_rust_unsafe_foxguard_flags_what_semgrep_ignores() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let fixture = write_file(
        repo.path(),
        "src/lib.rs",
        r#"pub fn use_unsafe() {
    unsafe {
        let ptr = 0x1234 as *const i32;
        println!("{}", *ptr);
    }
}

pub fn use_transmute() {
    let _x: u32 = unsafe { std::mem::transmute(1.0f32) };
}
"#,
    );

    // A representative Rust ruleset a Semgrep user might publish — it
    // does NOT cover unsafe blocks or transmute, because the Semgrep
    // community registry doesn't either.
    let semgrep_rules = write_file(
        repo.path(),
        "rules/rs-defaults.yaml",
        r#"
rules:
  - id: hardcoded-password
    pattern-regex: '(?m)^\s*let\s+password\s*=\s*"[^"]+"'
    message: Hardcoded password
    severity: WARNING
    languages: [rust]
  - id: panic-in-lib
    pattern: panic!(...)
    message: panic in library code
    severity: WARNING
    languages: [rust]
"#,
    );

    let foxguard = foxguard_findings(&fixture, repo.path());
    let semgrep = semgrep_findings_with_default_rules(&semgrep_rules, &fixture, repo.path());

    assert!(
        foxguard.iter().any(|f| f.rule_id == "rs/unsafe-block"),
        "foxguard must flag rs/unsafe-block on the fixture; got: {foxguard:?}"
    );
    assert!(
        foxguard.iter().any(|f| f.rule_id == "rs/transmute-usage"),
        "foxguard must flag rs/transmute-usage on the fixture; got: {foxguard:?}"
    );
    assert_eq!(
        semgrep
            .iter()
            .filter(|f| f.rule_id.contains("unsafe") || f.rule_id.contains("transmute"))
            .count(),
        0,
        "semgrep default rules must not contain an unsafe/transmute-equivalent finding; \
         got: {semgrep:?}"
    );
}
