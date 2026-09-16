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

use crate::engine::scanner::comment_markers;
use crate::rules::common::make_finding_from_offsets;
use crate::{Finding, Language, Severity, PQ_READY_TAG};

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
/// Order matters: hybrids claim their byte ranges before base algorithms,
/// including spellings whose separators would otherwise admit a base match.
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
            "x25519_ml_kem_768",
            "x25519-ml-kem-768",
            "x25519_ml_kem768",
            "x25519-ml-kem768",
            "x25519_mlkem_768",
            "x25519-mlkem-768",
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
            "x25519_kyber_768",
            "x25519-kyber-768",
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
            "oqs",
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

/// Find every occurrence of `needle` with alphanumeric word boundaries.
fn boundary_matches<'a>(
    haystack_lower: &'a str,
    needle: &'a str,
) -> impl Iterator<Item = std::ops::Range<usize>> + 'a {
    let bytes = haystack_lower.as_bytes();
    haystack_lower
        .match_indices(needle)
        .filter_map(move |(start, _)| {
            let end = start + needle.len();
            let before_ok = start == 0 || !is_boundary_ident(bytes[start - 1]);
            let after_ok = end == bytes.len() || !is_boundary_ident(bytes[end]);
            (before_ok && after_ok).then_some(start..end)
        })
}

/// Exclude whole-line comment prose using the scanner's language conventions.
/// Rust attributes and C preprocessor directives are code, not hash comments.
/// C-style block-comment markers are also excluded in languages that use them.
/// Inline trailing comments are not stripped.
fn is_comment_line(trimmed: &str, language: Language) -> bool {
    let markers = comment_markers(language);
    markers.iter().any(|marker| trimmed.starts_with(marker))
        || ((markers.contains(&"//") || markers.contains(&"/*"))
            && ["/*", "*/", "*"]
                .iter()
                .any(|marker| trimmed.starts_with(marker)))
}

/// Scan a source/config/manifest buffer for post-quantum algorithm usage.
///
/// Line oriented so match positions are reportable. At most one match per
/// `(line, canonical algorithm)` pair is emitted, so `use ml_kem::{MlKem768}`
/// yields a single ML-KEM finding rather than one per spelling.
pub fn scan(source: &str, language: Language) -> Vec<PqMatch> {
    let mut matches = Vec::new();
    let mut line_start = 0usize;
    let mut lower = String::new();
    let mut claimed = Vec::new();
    for line in source.split_inclusive('\n') {
        if is_comment_line(line.trim_start(), language) {
            line_start += line.len();
            continue;
        }
        lower.clear();
        lower.push_str(line);
        lower.make_ascii_lowercase();
        claimed.clear();
        claimed.resize(line.len(), false);
        for algo in PQ_ALGORITHMS {
            let mut emitted = false;
            for spelling in algo.spellings {
                for range in boundary_matches(&lower, spelling) {
                    if claimed[range.clone()].iter().any(|&byte| byte) {
                        continue;
                    }
                    if !emitted {
                        matches.push(PqMatch {
                            start_byte: line_start + range.start,
                            end_byte: line_start + range.end,
                            algo,
                        });
                        emitted = true;
                    }
                    // Claim every occurrence, even after emitting this algorithm:
                    // a second hybrid must not leak a base-algorithm finding.
                    claimed[range].fill(true);
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
pub fn pq_ready_findings(rule_id: &str, source: &str, language: Language) -> Vec<Finding> {
    scan(source, language)
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
        let mut v: Vec<&'static str> = scan(source, Language::Rust)
            .into_iter()
            .map(|m| m.algo.canonical)
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    #[test]
    fn recognizes_bare_oqs_without_matching_unrelated_identifiers() {
        let source = "use oqs::kem::Kem;\nOQS_KEM_new(OQS_KEM_alg_bike_l1);\nliboqs_version();\nfooqs_value(); oqsish();\n";
        let matches = scan(source, Language::Rust);
        assert_eq!(
            matches
                .iter()
                .map(|m| (&source[m.start_byte..m.end_byte], m.algo.canonical))
                .collect::<Vec<_>>(),
            vec![("oqs", "liboqs"), ("OQS", "liboqs"), ("liboqs", "liboqs")]
        );
    }

    #[test]
    fn separated_hybrids_claim_every_occurrence_before_base_algorithms() {
        let source = "x25519_ml_kem_768 x25519-ml-kem-768 x25519_mlkem_768\nx25519_kyber_768 x25519-kyber-768\n";
        let matches = scan(source, Language::Rust);
        assert_eq!(
            matches.iter().map(|m| m.algo.canonical).collect::<Vec<_>>(),
            vec!["X25519MLKEM768", "X25519Kyber768"]
        );
    }

    #[test]
    fn independent_base_algorithm_after_hybrid_keeps_its_own_byte_range() {
        let source = "let café = \"x25519_ml_kem_768 ml_kem\";\n";
        let matches = scan(source, Language::Rust);
        assert_eq!(
            matches
                .iter()
                .map(|m| (m.start_byte, m.end_byte, m.algo.canonical))
                .collect::<Vec<_>>(),
            vec![
                (
                    source.find("x25519").unwrap(),
                    source.find("x25519").unwrap() + "x25519_ml_kem_768".len(),
                    "X25519MLKEM768"
                ),
                (
                    source.rfind("ml_kem").unwrap(),
                    source.rfind("ml_kem").unwrap() + "ml_kem".len(),
                    "ML-KEM"
                ),
            ]
        );
    }

    #[test]
    fn rust_attributes_are_inventory_but_hash_comment_prose_is_not() {
        let source = "#[cfg(feature = \"ml-kem\")]\n#![cfg_attr(feature = \"slh-dsa\", allow(dead_code))]\n// ML-KEM in prose\n/* ML-DSA in prose */\n";
        let findings = pq_ready_findings("rs/pq-ready-crypto", source, Language::Rust);
        assert_eq!(
            findings
                .iter()
                .map(|f| (f.line, f.crypto_algorithm.as_deref()))
                .collect::<Vec<_>>(),
            vec![(1, Some("ML-KEM")), (2, Some("SLH-DSA"))]
        );
        let comments = "#if you want ML-KEM, import ml_kem\n#[cfg(feature = \"ml-kem\")]\n";
        assert!(scan(comments, Language::Python).is_empty());
        assert!(scan(comments, Language::Bash).is_empty());
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
        let findings = pq_ready_findings(
            "py/pq-ready-crypto",
            "from kyber_py import ml_kem\n",
            Language::Python,
        );
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(f.is_pq_ready());
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.crypto_algorithm.as_deref(), Some("ML-KEM"));
        assert!(f.cnsa2_deadline.is_none());
    }
}
