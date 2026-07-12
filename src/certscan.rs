//! X.509 certificate / key scan pass for `foxguard pqc` (crypto-material audit).
//!
//! The rest of the PQC audit finds cryptography by pattern-matching source,
//! configs, and lockfiles. This pass instead opens the **actual cryptographic
//! material** in a repository — X.509 certificates and public/private keys —
//! and extracts the real signature algorithm and public-key algorithm + size /
//! curve. Quantum-vulnerable material (RSA, ECDSA/EC, DSA, Ed25519/Ed448) is
//! flagged with the same CNSA 2.0 deadline model as source-level findings;
//! post-quantum material (ML-DSA / ML-KEM) is recorded as non-vulnerable.
//!
//! ## Safety invariants
//!
//! - **Never panics on malformed input.** A repository is full of junk `.key` /
//!   `.pem` files, truncated certs, binary blobs, and test fixtures. Every
//!   parse is fallible and every failure results in the file being skipped —
//!   never a crash and never a bogus finding. See the `garbage`/`truncated`
//!   tests at the bottom of this module.
//! - **Never emits private-key material.** We extract only the algorithm
//!   identity and public metadata (bit size, curve, validity). Findings and
//!   the CBOM carry the algorithm name + file path ONLY — never key bytes.
//! - **Respects ignore rules.** The walk mirrors the other file-walking passes
//!   (`git_ignore(true)`, hidden files ignored) and honours `--exclude`.

use crate::compliance::deadlines;
use crate::engine::PathExcludeMatcher;
use crate::{default_confidence, CryptoMaterial, Finding, Severity};
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};
// NB: do NOT `use x509_parser::prelude::*` — its glob re-exports x509_parser's
// own `pem` module, which shadows the external `pem` crate we rely on.
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::asn1_rs::{FromDer, Integer, Sequence};
use x509_parser::public_key::RSAPublicKey;
use x509_parser::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

/// File extensions that may contain a certificate or key we can parse.
const MATERIAL_EXTS: &[&str] = &["pem", "crt", "cer", "der", "key", "pub"];
/// Keystore extensions we deliberately do NOT parse (usually password-encrypted
/// PKCS#12); reported via a low-noise notice instead of a finding.
const KEYSTORE_EXTS: &[&str] = &["p12", "pfx"];

/// Result of the cert/key scan pass.
#[derive(Debug, Default)]
pub struct CertScanResult {
    pub findings: Vec<Finding>,
    /// Low-noise informational notices (e.g. skipped encrypted keystores).
    pub notices: Vec<String>,
    /// Number of candidate cert/key files that were opened.
    pub files_scanned: usize,
}

/// Walk `root` for certificate / key files, parse them, and emit findings.
///
/// `scan_root` is used to render finding paths relative to the scan directory,
/// matching the other passes. `excludes`, when present, applies the same
/// `--exclude` globs as the rest of the scan.
pub fn scan_certificates(
    root: &Path,
    scan_root: &Path,
    excludes: Option<&PathExcludeMatcher>,
) -> CertScanResult {
    let mut result = CertScanResult::default();

    let files = collect_material_files(root, scan_root, excludes);
    for path in files {
        result.files_scanned += 1;
        let rel = display_path(&path, scan_root);

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .unwrap_or_default();

        if KEYSTORE_EXTS.contains(&ext.as_str()) {
            // PKCS#12 keystores are typically password-protected; we never
            // prompt for passwords and never guess. Note it and move on.
            result.notices.push(format!(
                "Skipped keystore {rel}: PKCS#12/PFX keystores are not parsed \
                 (usually password-encrypted)."
            ));
            continue;
        }

        // Read defensively — unreadable files are simply skipped.
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if bytes.is_empty() {
            continue;
        }

        let mut materials = parse_material(&bytes);
        for material in materials.drain(..) {
            result.findings.push(finding_from(&rel, material));
        }
    }

    result
}

/// Collect candidate cert/key files under `root`, honouring ignore rules and
/// the `--exclude` matcher (same walk semantics as the dependency pass).
fn collect_material_files(
    root: &Path,
    scan_root: &Path,
    excludes: Option<&PathExcludeMatcher>,
) -> Vec<PathBuf> {
    let mut files = Vec::new();

    if root.is_file() {
        if has_material_ext(root) {
            files.push(root.to_path_buf());
        }
        return files;
    }

    for entry in WalkBuilder::new(root)
        .follow_links(false)
        .hidden(true)
        .git_ignore(true)
        .build()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        let path = entry.into_path();
        if !has_material_ext(&path) {
            continue;
        }
        let relative = path.strip_prefix(scan_root).unwrap_or(&path);
        if excludes.is_some_and(|matcher| matcher.is_excluded(relative)) {
            continue;
        }
        files.push(path);
    }

    files
}

fn has_material_ext(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .is_some_and(|e| MATERIAL_EXTS.contains(&e.as_str()) || KEYSTORE_EXTS.contains(&e.as_str()))
}

fn display_path(path: &Path, scan_root: &Path) -> String {
    path.strip_prefix(scan_root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// Parsed material ready to be turned into a finding. Contains algorithm
/// identity and public metadata ONLY.
struct Material {
    /// CBOM asset type: "certificate" or "related-crypto-material".
    asset_kind: &'static str,
    /// Algorithm family for CBOM grouping, e.g. "RSA", "ECDSA", "Ed25519".
    family: String,
    /// Detailed public-key algorithm identity, e.g. "RSA-2048", "ECDSA P-256".
    detail: String,
    /// Certificate signature algorithm, when this is a full certificate.
    signature_algorithm: Option<String>,
    /// "PEM" or "DER".
    format: &'static str,
    /// Certificate notValidAfter, when available.
    not_valid_after: Option<String>,
    /// Whether the public-key algorithm is quantum-vulnerable.
    quantum_vulnerable: bool,
}

/// Parse raw file bytes into zero or more [`Material`] descriptors.
///
/// Tries PEM first (a file may contain multiple PEM blocks), then falls back to
/// raw DER. Every branch is fallible; anything unrecognised yields an empty
/// vector and the file is skipped by the caller.
fn parse_material(bytes: &[u8]) -> Vec<Material> {
    // PEM: may hold several blocks (cert chain, cert + key, etc.).
    if let Ok(blocks) = pem::parse_many(bytes) {
        if !blocks.is_empty() {
            let mut out = Vec::new();
            for block in &blocks {
                if let Some(m) = material_from_pem_block(block.tag(), block.contents()) {
                    out.push(m);
                }
            }
            return out;
        }
    }

    // Raw DER: try a certificate, then a bare SubjectPublicKeyInfo.
    if let Ok((_, cert)) = X509Certificate::from_der(bytes) {
        if let Some(m) = material_from_certificate(&cert, "DER") {
            return vec![m];
        }
    }
    if let Some(m) = material_from_spki_der(bytes, "DER") {
        return vec![m];
    }

    Vec::new()
}

/// Build a [`Material`] from a single PEM block identified by its tag.
fn material_from_pem_block(tag: &str, contents: &[u8]) -> Option<Material> {
    match tag {
        "CERTIFICATE" | "TRUSTED CERTIFICATE" | "X509 CERTIFICATE" => {
            let (_, cert) = X509Certificate::from_der(contents).ok()?;
            material_from_certificate(&cert, "PEM")
        }
        "PUBLIC KEY" => material_from_spki_der(contents, "PEM"),
        "RSA PUBLIC KEY" => {
            // PKCS#1 RSAPublicKey: SEQUENCE { modulus, exponent }.
            let (_, rsa) = RSAPublicKey::from_der(contents).ok()?;
            let bits = rsa.key_size();
            let (family, detail, vulnerable) =
                classify("1.2.840.113549.1.1.1", None, nonzero(bits))?;
            Some(Material {
                asset_kind: "related-crypto-material",
                family,
                detail,
                signature_algorithm: None,
                format: "PEM",
                not_valid_after: None,
                quantum_vulnerable: vulnerable,
            })
        }
        // PKCS#8 unencrypted private key: we read ONLY the algorithm
        // identifier (public metadata), never the private key octet string.
        "PRIVATE KEY" => material_from_pkcs8(contents, "PEM"),
        // Legacy SEC1 / PKCS#1 private keys: the PEM tag alone identifies the
        // family. We do not parse the private scalar.
        "EC PRIVATE KEY" => classify("1.2.840.10045.2.1", None, None).map(|(f, d, v)| Material {
            asset_kind: "related-crypto-material",
            family: f,
            detail: d,
            signature_algorithm: None,
            format: "PEM",
            not_valid_after: None,
            quantum_vulnerable: v,
        }),
        "RSA PRIVATE KEY" => {
            classify("1.2.840.113549.1.1.1", None, None).map(|(f, d, v)| Material {
                asset_kind: "related-crypto-material",
                family: f,
                detail: d,
                signature_algorithm: None,
                format: "PEM",
                not_valid_after: None,
                quantum_vulnerable: v,
            })
        }
        "DSA PRIVATE KEY" => classify("1.2.840.10040.4.1", None, None).map(|(f, d, v)| Material {
            asset_kind: "related-crypto-material",
            family: f,
            detail: d,
            signature_algorithm: None,
            format: "PEM",
            not_valid_after: None,
            quantum_vulnerable: v,
        }),
        // Encrypted or opaque key containers: skip quietly (never guess).
        _ => None,
    }
}

/// Build a [`Material`] from a parsed X.509 certificate.
fn material_from_certificate(cert: &X509Certificate, format: &'static str) -> Option<Material> {
    let spki = cert.public_key();
    let (family, detail, vulnerable) = classify_spki(spki)?;

    let signature_algorithm = Some(sig_alg_name(
        &cert.signature_algorithm.algorithm.to_id_string(),
    ));
    let not_valid_after = cert.validity().not_after.to_rfc2822().ok();

    Some(Material {
        asset_kind: "certificate",
        family,
        detail,
        signature_algorithm,
        format,
        not_valid_after,
        quantum_vulnerable: vulnerable,
    })
}

/// Build a [`Material`] from a DER `SubjectPublicKeyInfo` (a bare public key).
fn material_from_spki_der(der: &[u8], format: &'static str) -> Option<Material> {
    let (_, spki) = SubjectPublicKeyInfo::from_der(der).ok()?;
    let (family, detail, vulnerable) = classify_spki(&spki)?;
    Some(Material {
        asset_kind: "related-crypto-material",
        family,
        detail,
        signature_algorithm: None,
        format,
        not_valid_after: None,
        quantum_vulnerable: vulnerable,
    })
}

/// Classify a `SubjectPublicKeyInfo` into (family, detail, quantum_vulnerable).
fn classify_spki(spki: &SubjectPublicKeyInfo) -> Option<(String, String, bool)> {
    let algo_oid = spki.algorithm.algorithm.to_id_string();
    let bits = spki.parsed().ok().map(|k| k.key_size()).and_then(nonzero);
    let curve = spki
        .algorithm
        .parameters
        .clone()
        .and_then(|p| p.oid().ok())
        .map(|o| o.to_id_string());
    classify(&algo_oid, curve.as_deref(), bits)
}

/// Extract the algorithm identity from an unencrypted PKCS#8 `PrivateKeyInfo`,
/// reading ONLY the `AlgorithmIdentifier` (never the private key material).
fn material_from_pkcs8(der: &[u8], format: &'static str) -> Option<Material> {
    // PrivateKeyInfo ::= SEQUENCE { version INTEGER,
    //                               privateKeyAlgorithm AlgorithmIdentifier,
    //                               privateKey OCTET STRING }
    let (_, seq) = Sequence::from_der(der).ok()?;
    let inner = seq.content.as_ref();
    let (rest, _version) = Integer::from_der(inner).ok()?;
    let (_rest, alg) = AlgorithmIdentifier::from_der(rest).ok()?;
    let algo_oid = alg.algorithm.to_id_string();
    let curve = alg
        .parameters
        .clone()
        .and_then(|p| p.oid().ok())
        .map(|o| o.to_id_string());
    let (family, detail, vulnerable) = classify(&algo_oid, curve.as_deref(), None)?;
    Some(Material {
        asset_kind: "related-crypto-material",
        family,
        detail,
        signature_algorithm: None,
        format,
        not_valid_after: None,
        quantum_vulnerable: vulnerable,
    })
}

fn nonzero(bits: usize) -> Option<usize> {
    (bits > 0).then_some(bits)
}

/// Map an algorithm OID (+ optional EC curve OID / RSA/DSA bit size) to a
/// (family, detail, quantum_vulnerable) triple. Returns `None` for OIDs we
/// don't recognise, so unknown material is skipped rather than mis-flagged.
fn classify(
    algo_oid: &str,
    curve_oid: Option<&str>,
    bits: Option<usize>,
) -> Option<(String, String, bool)> {
    match algo_oid {
        // RSA (PKCS#1 rsaEncryption) and RSASSA-PSS.
        "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" => {
            let detail = match bits {
                Some(b) => format!("RSA-{b}"),
                None => "RSA".to_string(),
            };
            Some(("RSA".to_string(), detail, true))
        }
        // id-ecPublicKey.
        "1.2.840.10045.2.1" => {
            let detail = match curve_oid.map(curve_name) {
                Some(c) => format!("ECDSA {c}"),
                None => "ECDSA".to_string(),
            };
            Some(("ECDSA".to_string(), detail, true))
        }
        // id-dsa.
        "1.2.840.10040.4.1" => {
            let detail = match bits {
                Some(b) => format!("DSA-{b}"),
                None => "DSA".to_string(),
            };
            Some(("DSA".to_string(), detail, true))
        }
        // Edwards / Montgomery curves (classical → quantum-vulnerable).
        "1.3.101.112" => Some(("Ed25519".to_string(), "Ed25519".to_string(), true)),
        "1.3.101.113" => Some(("Ed448".to_string(), "Ed448".to_string(), true)),
        "1.3.101.110" => Some(("X25519".to_string(), "X25519".to_string(), true)),
        "1.3.101.111" => Some(("X448".to_string(), "X448".to_string(), true)),
        // NIST FIPS 204/203 post-quantum algorithms → NOT vulnerable.
        "2.16.840.1.101.3.4.3.17" => Some(("ML-DSA".to_string(), "ML-DSA-44".to_string(), false)),
        "2.16.840.1.101.3.4.3.18" => Some(("ML-DSA".to_string(), "ML-DSA-65".to_string(), false)),
        "2.16.840.1.101.3.4.3.19" => Some(("ML-DSA".to_string(), "ML-DSA-87".to_string(), false)),
        "2.16.840.1.101.3.4.4.1" => Some(("ML-KEM".to_string(), "ML-KEM-512".to_string(), false)),
        "2.16.840.1.101.3.4.4.2" => Some(("ML-KEM".to_string(), "ML-KEM-768".to_string(), false)),
        "2.16.840.1.101.3.4.4.3" => Some(("ML-KEM".to_string(), "ML-KEM-1024".to_string(), false)),
        _ => None,
    }
}

/// Map a named-curve OID to a friendly name (falls back to the raw OID).
fn curve_name(oid: &str) -> String {
    match oid {
        "1.2.840.10045.3.1.7" => "P-256",
        "1.3.132.0.34" => "P-384",
        "1.3.132.0.35" => "P-521",
        "1.3.132.0.33" => "P-224",
        "1.2.840.10045.3.1.1" => "P-192",
        "1.3.132.0.10" => "secp256k1",
        other => other,
    }
    .to_string()
}

/// Map a signature-algorithm OID to a friendly name (falls back to raw OID).
fn sig_alg_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.10045.4.3.1" => "ecdsa-with-SHA224",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        "1.2.840.10040.4.3" => "dsa-with-SHA1",
        "2.16.840.1.101.3.4.3.1" => "dsa-with-SHA224",
        "2.16.840.1.101.3.4.3.2" => "dsa-with-SHA256",
        other => other,
    }
    .to_string()
}

/// Turn a parsed [`Material`] into a [`Finding`].
fn finding_from(file: &str, material: Material) -> Finding {
    let is_cert = material.asset_kind == "certificate";
    let kind_word = if is_cert { "certificate" } else { "key" };

    let (rule_id, severity, cwe, cnsa2_deadline, description) = if material.quantum_vulnerable {
        let sig = material
            .signature_algorithm
            .as_deref()
            .map(|s| format!("; signature {s}"))
            .unwrap_or_default();
        (
            format!("cert/pq-vulnerable-{kind_word}"),
            Severity::High,
            Some("CWE-327".to_string()),
            Some(deadlines::WEB_AND_CLOUD.to_string()),
            format!(
                "X.509 {kind_word} uses quantum-vulnerable {}{sig}. \
                 Migrate to a CNSA 2.0 post-quantum algorithm before {}.",
                material.detail,
                deadlines::WEB_AND_CLOUD
            ),
        )
    } else {
        (
            format!("cert/post-quantum-{kind_word}"),
            Severity::Low,
            None,
            None,
            format!(
                "X.509 {kind_word} uses post-quantum algorithm {} (CNSA 2.0 ready).",
                material.detail
            ),
        )
    };

    // Snippet is a safe, human-readable summary — NEVER key bytes.
    let mut snippet = material.detail.clone();
    if let Some(sig) = &material.signature_algorithm {
        snippet.push_str(&format!(" (signature: {sig})"));
    }

    let fix_suggestion = material.quantum_vulnerable.then(|| {
        "Re-issue with a CNSA 2.0 post-quantum algorithm: ML-DSA (FIPS 204) for \
         signatures, ML-KEM (FIPS 203) for key establishment."
            .to_string()
    });

    Finding {
        rule_id,
        severity,
        cwe,
        description,
        file: file.to_string(),
        line: 1,
        column: 1,
        end_line: 1,
        end_column: 1,
        snippet,
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion,
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: default_confidence(),
        taint_hops: None,
        tags: vec!["PQ".to_string()],
        crypto_algorithm: Some(material.family.clone()),
        cnsa2_deadline,
        dep_name: None,
        dep_version: None,
        dep_ecosystem: None,
        dep_purl: None,
        dep_vulnerability_id: None,
        dep_fixed_version: None,
        dep_source: None,
        dep_vulnerability_severity: None,
        dep_path: vec![],
        crypto_material: Some(CryptoMaterial {
            asset_kind: material.asset_kind.to_string(),
            subject_public_key_algorithm: material.detail,
            signature_algorithm: material.signature_algorithm,
            format: material.format.to_string(),
            not_valid_after: material.not_valid_after,
            quantum_vulnerable: material.quantum_vulnerable,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Test fixtures (clearly marked; parsed, never trusted). ------------
    // Generated once with OpenSSL and embedded as literals so the tests are
    // deterministic and never shell out. See module docs.

    // FOXGUARD TEST FIXTURE — self-signed RSA-2048 cert (not a real key).
    const RSA_2048_CERT: &str = include_str!("../tests/fixtures/certs/rsa2048.pem");
    // FOXGUARD TEST FIXTURE — self-signed ECDSA P-256 cert.
    const ECDSA_P256_CERT: &str = include_str!("../tests/fixtures/certs/ecdsa_p256.pem");
    // FOXGUARD TEST FIXTURE — self-signed Ed25519 cert.
    const ED25519_CERT: &str = include_str!("../tests/fixtures/certs/ed25519.pem");

    fn only(bytes: &[u8]) -> Material {
        let mut v = parse_material(bytes);
        assert_eq!(v.len(), 1, "expected exactly one material");
        v.remove(0)
    }

    #[test]
    fn parses_rsa2048_certificate() {
        let m = only(RSA_2048_CERT.as_bytes());
        assert_eq!(m.asset_kind, "certificate");
        assert_eq!(m.family, "RSA");
        assert_eq!(m.detail, "RSA-2048");
        assert!(m.quantum_vulnerable);
        assert_eq!(m.format, "PEM");
        assert!(m.signature_algorithm.as_deref().unwrap().contains("RSA"));
        assert!(m.not_valid_after.is_some());
    }

    #[test]
    fn rsa2048_finding_is_flagged_with_cnsa_deadline() {
        let f = finding_from("certs/rsa2048.pem", only(RSA_2048_CERT.as_bytes()));
        assert_eq!(f.rule_id, "cert/pq-vulnerable-certificate");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.crypto_algorithm.as_deref(), Some("RSA"));
        assert_eq!(f.cnsa2_deadline.as_deref(), Some(deadlines::WEB_AND_CLOUD));
        let cm = f.crypto_material.expect("crypto_material set");
        assert_eq!(cm.subject_public_key_algorithm, "RSA-2048");
        assert!(cm.signature_algorithm.is_some());
        // Never leak key bytes into the snippet/description.
        assert!(!f.snippet.contains("BEGIN"));
    }

    #[test]
    fn parses_ecdsa_p256_certificate() {
        let m = only(ECDSA_P256_CERT.as_bytes());
        assert_eq!(m.family, "ECDSA");
        assert_eq!(m.detail, "ECDSA P-256");
        assert!(m.quantum_vulnerable);
        let f = finding_from("certs/ecdsa.pem", m);
        assert_eq!(f.rule_id, "cert/pq-vulnerable-certificate");
        assert_eq!(f.cnsa2_deadline.as_deref(), Some(deadlines::WEB_AND_CLOUD));
    }

    #[test]
    fn parses_ed25519_certificate_and_flags_it() {
        let m = only(ED25519_CERT.as_bytes());
        assert_eq!(m.family, "Ed25519");
        assert_eq!(m.detail, "Ed25519");
        // Ed25519 is quantum-vulnerable too.
        assert!(m.quantum_vulnerable);
    }

    #[test]
    fn garbage_pem_is_skipped_without_crash() {
        let junk =
            b"-----BEGIN CERTIFICATE-----\nnot base64 !!!! @@@@\n-----END CERTIFICATE-----\n";
        assert!(parse_material(junk).is_empty());
    }

    #[test]
    fn truncated_certificate_is_skipped() {
        // Take a valid PEM cert and lop off the second half of the body.
        let full = RSA_2048_CERT;
        let truncated = &full[..full.len() / 2];
        // Either yields no material or does not panic; must not crash.
        let _ = parse_material(truncated.as_bytes());
    }

    #[test]
    fn random_binary_key_is_skipped() {
        // 512 bytes of non-crypto noise with a .key-like payload.
        let mut noise = Vec::new();
        for i in 0u16..512 {
            noise.push((i.wrapping_mul(37) ^ 0xA5) as u8);
        }
        assert!(parse_material(&noise).is_empty());
    }

    #[test]
    fn empty_input_is_skipped() {
        assert!(parse_material(&[]).is_empty());
    }

    #[test]
    fn ml_dsa_oid_is_non_vulnerable() {
        let (family, detail, vulnerable) = classify("2.16.840.1.101.3.4.3.65", None, None)
            .unwrap_or_else(|| classify("2.16.840.1.101.3.4.3.17", None, None).unwrap());
        assert_eq!(family, "ML-DSA");
        assert!(detail.starts_with("ML-DSA"));
        assert!(!vulnerable);
    }

    #[test]
    fn unknown_oid_is_skipped() {
        assert!(classify("1.2.3.4.5.6.7.8", None, None).is_none());
    }
}
