//! Post-quantum algorithm detection — the *migration-target* side of the PQC
//! audit.
//!
//! The `pq-vulnerable-crypto` rules detect quantum-*vulnerable* primitives
//! (RSA, ECDSA/DSA, ECDH/DH). This module detects the algorithms teams migrate
//! *to*: the NIST/FIPS post-quantum standards and the common hybrid key
//! exchanges. Findings produced here are **informational**, not
//! vulnerabilities — they are tagged [`crate::PQ_READY_TAG`], carry `Severity::Low`,
//! declare no CNSA 2.0 deadline, and never emit a CBOM vulnerability entry. A
//! repository using ML-KEM is *ahead* on migration, not insecure.
//!
//! Detection is deliberately text/token oriented (not per-language AST): the
//! recognised spellings are distinctive crate/module/package identifiers
//! (`kyber`, `mlkem`, `dilithium`, `sphincs`, `x25519mlkem768`, `liboqs`, …),
//! so a single matcher works uniformly across every source language, config,
//! and manifest the vulnerable side already covers. This mirrors how the
//! vulnerable *config* rules already recognise `X25519MLKEM768` / `MLKEM`.
//!
//! ## Authoritative identities
//!
//! - **ML-KEM** — FIPS 203 (key encapsulation), formerly CRYSTALS-Kyber.
//! - **ML-DSA** — FIPS 204 (digital signatures), formerly CRYSTALS-Dilithium.
//! - **SLH-DSA** — FIPS 205 (stateless hash-based signatures), formerly SPHINCS+.
//! - **FN-DSA** — FIPS 206 (draft; lattice signatures), formerly Falcon.
//! - **HQC** — NIST 5th selection (draft; code-based KEM), standardisation ongoing.
//! - **Hybrids** — `X25519MLKEM768` (RFC 9370 / TLS) and the earlier
//!   `X25519Kyber768` draft: classical + PQ key exchange run in combination.

use crate::rules::common::make_finding_from_offsets;
use crate::{Finding, Severity, PQ_READY_TAG};

/// A recognised post-quantum (or hybrid) cryptographic algorithm and the
/// spellings that identify it in source, config, and dependency manifests.
pub struct PqAlgorithm {
    /// Canonical NIST/FIPS name surfaced in reports and the CBOM
    /// (e.g. `"ML-KEM"`, `"X25519MLKEM768"`).
    pub canonical: &'static str,
    /// Standardisation identity (e.g. `"FIPS 203"`, `"FIPS 206 (draft)"`).
    pub standard: &'static str,
    /// Legacy / common name (e.g. `"Kyber"`), or `""` when there is none.
    pub aka: &'static str,
    /// CBOM cryptographic primitive: `"kem"`, `"signature"`, or `""` when the
    /// match is a library marker rather than a specific algorithm.
    pub primitive: &'static str,
    /// Lowercased identifier spellings. Matched with alphanumeric word
    /// boundaries so `mlkem` does not fire inside `x25519mlkem768` (the
    /// hybrid spelling wins) and `kyber` still fires inside `my_kyber_key`.
    pub spellings: &'static [&'static str],
}

/// The canonical post-quantum algorithm table.
///
/// Order matters: hybrids and multi-token spellings are listed first so that a
/// line like `x25519mlkem768` is attributed to the hybrid rather than to bare
/// `mlkem` (whose boundary check fails against the surrounding digits anyway,
/// but the ordering keeps intent explicit).
pub const PQ_ALGORITHMS: &[PqAlgorithm] = &[
    // ── Hybrids (classical + PQ key exchange) ────────────────────────────
    PqAlgorithm {
        canonical: "X25519MLKEM768",
        standard: "FIPS 203 hybrid (RFC 9370)",
        aka: "X25519 + ML-KEM-768",
        primitive: "kem",
        spellings: &[
            "x25519mlkem768",
            "x25519_mlkem768",
            "x25519-mlkem768",
            "secp256r1mlkem768",
            "x25519mlkem",
        ],
    },
    PqAlgorithm {
        canonical: "X25519Kyber768",
        standard: "FIPS 203 hybrid (pre-standard draft)",
        aka: "X25519 + Kyber-768",
        primitive: "kem",
        spellings: &[
            "x25519kyber768draft00",
            "x25519kyber768",
            "x25519_kyber768",
            "x25519-kyber768",
            "p256_kyber768",
            "p256-kyber768",
        ],
    },
    // ── FIPS 203 — ML-KEM (Kyber) ────────────────────────────────────────
    PqAlgorithm {
        canonical: "ML-KEM",
        standard: "FIPS 203",
        aka: "Kyber",
        primitive: "kem",
        spellings: &[
            "ml_kem",
            "ml-kem",
            "mlkem",
            "kyber",
            "crystals-kyber",
            "crystals_kyber",
            "fips203",
        ],
    },
    // ── FIPS 204 — ML-DSA (Dilithium) ────────────────────────────────────
    PqAlgorithm {
        canonical: "ML-DSA",
        standard: "FIPS 204",
        aka: "Dilithium",
        primitive: "signature",
        spellings: &[
            "ml_dsa",
            "ml-dsa",
            "mldsa",
            "dilithium",
            "crystals-dilithium",
            "crystals_dilithium",
            "fips204",
        ],
    },
    // ── FIPS 205 — SLH-DSA (SPHINCS+) ────────────────────────────────────
    PqAlgorithm {
        canonical: "SLH-DSA",
        standard: "FIPS 205",
        aka: "SPHINCS+",
        primitive: "signature",
        spellings: &[
            "slh_dsa",
            "slh-dsa",
            "slhdsa",
            "sphincsplus",
            "sphincs_plus",
            "sphincs+",
            "sphincs",
            "fips205",
        ],
    },
    // ── FIPS 206 (draft) — FN-DSA (Falcon) ───────────────────────────────
    PqAlgorithm {
        canonical: "FN-DSA",
        standard: "FIPS 206 (draft)",
        aka: "Falcon",
        primitive: "signature",
        // Bare "falcon" is deliberately excluded (common word); the sized
        // parameter sets and the FN-DSA name are unambiguous.
        spellings: &[
            "fn_dsa",
            "fn-dsa",
            "fndsa",
            "falcon512",
            "falcon-512",
            "falcon_512",
            "falcon1024",
            "falcon-1024",
            "falcon_1024",
        ],
    },
    // ── HQC (draft; code-based KEM) ──────────────────────────────────────
    PqAlgorithm {
        canonical: "HQC",
        standard: "NIST 5th selection (draft)",
        aka: "",
        primitive: "kem",
        spellings: &[
            "hqc-128", "hqc-192", "hqc-256", "hqc128", "hqc192", "hqc256", "hqc_128", "hqc",
        ],
    },
    // ── PQ library markers (aggregate; primitive unknown) ────────────────
    PqAlgorithm {
        canonical: "liboqs",
        standard: "Open Quantum Safe (PQC library)",
        aka: "OQS",
        primitive: "",
        spellings: &[
            "liboqs",
            "oqs-provider",
            "oqsprovider",
            "oqs_provider",
            "open-quantum-safe",
            "pqcrystals",
            "pq-crystals",
            "pqclean",
        ],
    },
];

/// A single post-quantum match located in a source buffer.
pub struct PqMatch {
    pub start_byte: usize,
    pub end_byte: usize,
    pub algo: &'static PqAlgorithm,
}

/// `true` for the identifier characters that define a token boundary.
///
/// Underscore is intentionally treated as a *separator* (not an identifier
/// char) so `kyber` still matches inside `my_kyber_key`, while `mlkem` is
/// still rejected inside `x25519mlkem768` (the preceding `9` is alphanumeric).
fn is_boundary_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// Find `needle` in `haystack_lower` with alphanumeric word boundaries.
/// Returns the byte offset of the match within the line, if any.
fn boundary_find(haystack_lower: &str, needle: &str) -> Option<usize> {
    let bytes = haystack_lower.as_bytes();
    let mut start = 0;
    while let Some(pos) = haystack_lower[start..].find(needle) {
        let idx = start + pos;
        let end = idx + needle.len();
        let before_ok = idx == 0 || !is_boundary_ident(bytes[idx - 1]);
        let after_ok = end >= bytes.len() || !is_boundary_ident(bytes[end]);
        if before_ok && after_ok {
            return Some(idx);
        }
        start = idx + needle.len().max(1);
    }
    None
}

/// `true` when a trimmed line begins with a comment marker.
///
/// Detection is a positive *usage* inventory, so prose mentions of "ML-KEM" or
/// "Kyber" in a header comment or docstring must not inflate the counts. This
/// covers whole-line comments across the languages/configs the audit scans
/// (`#`, `//`, `/*`, ` * `, `--`, `<!--`, `%`). Inline trailing comments are
/// not stripped — an acknowledged, documented limitation.
fn is_comment_line(trimmed: &str) -> bool {
    const MARKERS: &[&str] = &["#", "//", "/*", "*/", "*", "--", "<!--", "%", ";;"];
    MARKERS.iter().any(|m| trimmed.starts_with(m))
}

/// Scan a source/config/manifest buffer for post-quantum algorithm usage.
///
/// Line oriented so match positions are reportable. At most one match per
/// `(line, canonical algorithm)` pair is emitted, so `use ml_kem::{MlKem768}`
/// yields a single ML-KEM finding rather than one per spelling.
pub fn scan(source: &str) -> Vec<PqMatch> {
    let mut matches = Vec::new();
    let mut line_start = 0usize;
    for line in source.split_inclusive('\n') {
        if is_comment_line(line.trim_start()) {
            line_start += line.len();
            continue;
        }
        let lower = line.to_ascii_lowercase();
        // Track which canonicals already matched on this line to avoid
        // duplicate findings for the same algorithm.
        let mut seen: Vec<&'static str> = Vec::new();
        for algo in PQ_ALGORITHMS {
            if seen.contains(&algo.canonical) {
                continue;
            }
            for spelling in algo.spellings {
                if let Some(off) = boundary_find(&lower, spelling) {
                    matches.push(PqMatch {
                        start_byte: line_start + off,
                        end_byte: line_start + off + spelling.len(),
                        algo,
                    });
                    seen.push(algo.canonical);
                    break;
                }
            }
        }
        line_start += line.len();
    }
    matches
}

/// Build informational post-quantum-ready findings for `source`.
///
/// Every finding is tagged [`PQ_READY_TAG`], `Severity::Low`, carries the
/// canonical algorithm name in `crypto_algorithm`, and declares no CNSA 2.0
/// deadline. Callers pass their own `rule_id` so the finding attributes to the
/// language-specific rule.
pub fn pq_ready_findings(rule_id: &str, source: &str) -> Vec<Finding> {
    scan(source)
        .into_iter()
        .map(|m| {
            let aka = if m.algo.aka.is_empty() {
                String::new()
            } else {
                format!(", aka {}", m.algo.aka)
            };
            let desc = format!(
                "Post-quantum algorithm in use: {} ({}{}) — quantum-resistant; no migration required",
                m.algo.canonical, m.algo.standard, aka
            );
            let mut f = make_finding_from_offsets(
                rule_id,
                Severity::Low,
                None,
                &desc,
                source,
                m.start_byte,
                m.end_byte,
            );
            f.tags = vec![PQ_READY_TAG.to_string()];
            f.crypto_algorithm = Some(m.algo.canonical.to_string());
            f
        })
        .collect()
}

/// Look up the canonical [`PqAlgorithm`] for a canonical name, if recognised.
/// Used by the CBOM formatter to mark an asset quantum-resistant.
pub fn algorithm_by_canonical(canonical: &str) -> Option<&'static PqAlgorithm> {
    PQ_ALGORITHMS.iter().find(|a| a.canonical == canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonicals(source: &str) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = scan(source).into_iter().map(|m| m.algo.canonical).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    #[test]
    fn detects_ml_kem_spellings() {
        assert!(canonicals("use ml_kem::MlKem768;").contains(&"ML-KEM"));
        assert!(canonicals("from kyber_py.ml_kem import ML_KEM_768").contains(&"ML-KEM"));
        assert!(canonicals("import \"crypto/mlkem\"").contains(&"ML-KEM"));
        assert!(canonicals("let k = crystals_kyber::keypair();").contains(&"ML-KEM"));
    }

    #[test]
    fn detects_signature_families() {
        assert!(canonicals("dilithium.Sign(msg)").contains(&"ML-DSA"));
        assert!(canonicals("ml_dsa_65_keypair()").contains(&"ML-DSA"));
        assert!(canonicals("sphincsplus.sign()").contains(&"SLH-DSA"));
        assert!(canonicals("slh_dsa_sha2_128s()").contains(&"SLH-DSA"));
        assert!(canonicals("falcon512_keygen()").contains(&"FN-DSA"));
        assert!(canonicals("fn_dsa_sign()").contains(&"FN-DSA"));
    }

    #[test]
    fn detects_hybrids_without_double_counting_base() {
        // The hybrid spelling wins; bare ML-KEM must not also fire on the
        // same token.
        let c = canonicals("ssl_ecdh_curve X25519MLKEM768;");
        assert!(c.contains(&"X25519MLKEM768"));
        assert!(!c.contains(&"ML-KEM"));
    }

    #[test]
    fn detects_library_markers() {
        assert!(canonicals("#include <oqs/oqs.h>\nliboqs_version();").contains(&"liboqs"));
        assert!(canonicals("import pqcrystals").contains(&"liboqs"));
    }

    #[test]
    fn ignores_classical_and_unrelated_tokens() {
        // No PQ tokens: RSA/ECDSA and incidental words must not match.
        assert!(canonicals("rsa.generate_private_key()").is_empty());
        assert!(canonicals("let falcon = SpaceX::launch();").is_empty());
        assert!(canonicals("xmlkemper = parse_xml();").is_empty());
    }

    #[test]
    fn pq_ready_findings_are_informational() {
        let findings = pq_ready_findings("py/pq-ready-crypto", "from kyber_py import ml_kem\n");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(f.is_pq_ready());
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.crypto_algorithm.as_deref(), Some("ML-KEM"));
        assert!(f.cnsa2_deadline.is_none());
    }
}
