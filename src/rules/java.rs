use std::sync::OnceLock;

use regex::Regex;

use crate::impl_rule;
use crate::rules::common::{
    hardcoded_secret_re, is_secret_value_long_enough, make_finding, make_finding_from_offsets,
    walk_tree,
};
use crate::{Language, Severity};

// ─── Static regex helpers (compiled once) ────────────────────────────────────

fn java_sql_methods_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(executeQuery|execute|createQuery|createNativeQuery)$")
            .expect("static Java SQL method regex should compile")
    })
}

fn java_weak_algo_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)"(DES|DESede|RC2|RC4|Blowfish|MD5|SHA-?1|.*ECB.*)"#)
            .expect("static Java weak crypto regex should compile")
    })
}

fn java_xxe_factory_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\(\)")
            .expect("static Java XXE factory regex should compile")
    })
}

fn java_xxe_secure_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"setFeature\s*\(|setProperty\s*\(|setAttribute\s*\(")
            .expect("static Java XXE hardening regex should compile")
    })
}

fn java_csrf_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\.csrf\(\s*\)\s*\.\s*disable\(\s*\)|csrf\s*\([^)]*\.\s*disable\(\s*\)\s*\)")
            .expect("static Java CSRF regex should compile")
    })
}

fn java_cors_wildcard_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"allowedOrigins\s*\(\s*"\*"\s*\)"#)
            .expect("static Java CORS regex should compile")
    })
}

/// Check whether any descendant of `node` is a `binary_expression` with a `+`
/// operator that involves a `string_literal`.
fn has_string_concat(node: tree_sitter::Node, src: &str) -> bool {
    if node.kind() == "binary_expression" {
        if let Some(op) = node.child_by_field_name("operator") {
            if &src[op.byte_range()] == "+" {
                // Check if either side is or contains a string_literal
                let left_has_str = node
                    .child_by_field_name("left")
                    .is_some_and(|n| contains_kind(n, "string_literal"));
                let right_has_str = node
                    .child_by_field_name("right")
                    .is_some_and(|n| contains_kind(n, "string_literal"));
                if left_has_str || right_has_str {
                    return true;
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if has_string_concat(child, src) {
            return true;
        }
    }
    false
}

fn contains_kind(node: tree_sitter::Node, kind: &str) -> bool {
    if node.kind() == kind {
        return true;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if contains_kind(child, kind) {
            return true;
        }
    }
    false
}

/// Check if a node is a literal (string_literal, number, null, boolean, etc.).
fn is_literal(node: tree_sitter::Node) -> bool {
    matches!(
        node.kind(),
        "string_literal"
            | "character_literal"
            | "decimal_integer_literal"
            | "hex_integer_literal"
            | "octal_integer_literal"
            | "binary_integer_literal"
            | "decimal_floating_point_literal"
            | "hex_floating_point_literal"
            | "true"
            | "false"
            | "null_literal"
    )
}

// ─── Rule 1: no-sql-injection ───────────────────────────────────────────────

pub struct NoSqlInjection;

impl_rule! {
    NoSqlInjection,
    id = "java/no-sql-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-89"),
    description = "Potential SQL injection via string concatenation in query method",
    language = Language::Java,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let sql_methods = java_sql_methods_re();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "method_invocation" {
                if let Some(name) = node.child_by_field_name("name") {
                    let name_text = &src[name.byte_range()];
                    if sql_methods.is_match(name_text) {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if has_string_concat(args, src) {
                                findings.push(make_finding(
                                    _self.id(),
                                    _self.severity(),
                                    _self.cwe(),
                                    "SQL query built with string concatenation — use parameterized queries or prepared statements",
                                    node,
                                    src,
                                ));
                            }
                        }
                    }
                }
            }
        });
        findings

    }
}

// ─── Rule 2: no-command-injection ───────────────────────────────────────────

pub struct NoCommandInjection;

impl_rule! {
    NoCommandInjection,
    id = "java/no-command-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-78"),
    description = "Potential command injection via Runtime.exec or ProcessBuilder with dynamic input",
    language = Language::Java,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Runtime.getRuntime().exec(variable)
            if node.kind() == "method_invocation" {
                if let Some(name) = node.child_by_field_name("name") {
                    let name_text = &src[name.byte_range()];
                    if name_text == "exec" {
                        if let Some(obj) = node.child_by_field_name("object") {
                            let obj_text = &src[obj.byte_range()];
                            if obj_text.contains("getRuntime()") || obj_text.contains("Runtime") {
                                if let Some(args) = node.child_by_field_name("arguments") {
                                    if let Some(first_arg) = args.named_child(0) {
                                        if !is_literal(first_arg) {
                                            findings.push(make_finding(
                                                _self.id(),
                                                _self.severity(),
                                                _self.cwe(),
                                                "Runtime.exec() called with dynamic argument — risk of command injection",
                                                node,
                                                src,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // new ProcessBuilder(variable)
            if node.kind() == "object_creation_expression" {
                if let Some(type_node) = node.child_by_field_name("type") {
                    let type_text = &src[type_node.byte_range()];
                    if type_text == "ProcessBuilder" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                if !is_literal(first_arg) {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        "ProcessBuilder created with dynamic argument — risk of command injection",
                                        node,
                                        src,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        });
        findings

    }
}

// ─── Rule 3: no-unsafe-deserialization ──────────────────────────────────────

pub struct NoUnsafeDeserialization;

impl_rule! {
    NoUnsafeDeserialization,
    id = "java/no-unsafe-deserialization",
    severity = Severity::Critical,
    cwe = Some("CWE-502"),
    description = "Unsafe deserialization can lead to remote code execution",
    language = Language::Java,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "method_invocation" {
                if let Some(name) = node.child_by_field_name("name") {
                    let name_text = &src[name.byte_range()];

                    // ObjectInputStream.readObject() or XMLDecoder.readObject()
                    if name_text == "readObject" {
                        if let Some(obj) = node.child_by_field_name("object") {
                            let obj_text = &src[obj.byte_range()];
                            if obj_text.contains("ObjectInputStream")
                                || obj_text.contains("XMLDecoder")
                                // Also match variable references that may be an ObjectInputStream
                                || !obj_text.contains('.')
                            {
                                findings.push(make_finding(
                                    _self.id(),
                                    _self.severity(),
                                    _self.cwe(),
                                    "readObject() on untrusted data can lead to remote code execution — use allowlist-based deserialization",
                                    node,
                                    src,
                                ));
                            }
                        }
                    }

                    // Yaml.load() (not safeLoad)
                    if name_text == "load" {
                        if let Some(obj) = node.child_by_field_name("object") {
                            let obj_text = &src[obj.byte_range()];
                            if obj_text.contains("Yaml") || obj_text.contains("yaml") {
                                findings.push(make_finding(
                                    _self.id(),
                                    _self.severity(),
                                    _self.cwe(),
                                    "Yaml.load() deserializes arbitrary objects — use Yaml.safeLoad() or a safe constructor",
                                    node,
                                    src,
                                ));
                            }
                        }
                    }
                }
            }
        });
        findings

    }
}

// ─── Rule 4: no-ssrf ───────────────────────────────────────────────────────

pub struct NoSsrf;

impl_rule! {
    NoSsrf,
    id = "java/no-ssrf",
    severity = Severity::High,
    cwe = Some("CWE-918"),
    description = "Potential SSRF via URL or RestTemplate with dynamic input",
    language = Language::Java,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // new URL(variable)
            if node.kind() == "object_creation_expression" {
                if let Some(type_node) = node.child_by_field_name("type") {
                    let type_text = &src[type_node.byte_range()];
                    if type_text == "URL" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                if !is_literal(first_arg) {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        "new URL() with dynamic argument — validate and allowlist target hosts to prevent SSRF",
                                        node,
                                        src,
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            // RestTemplate.getForObject(variable, ...)
            if node.kind() == "method_invocation" {
                if let Some(name) = node.child_by_field_name("name") {
                    let name_text = &src[name.byte_range()];
                    if name_text == "getForObject"
                        || name_text == "getForEntity"
                        || name_text == "postForObject"
                        || name_text == "postForEntity"
                        || name_text == "exchange"
                    {
                        if let Some(obj) = node.child_by_field_name("object") {
                            let obj_text = &src[obj.byte_range()];
                            if obj_text.contains("restTemplate")
                                || obj_text.contains("RestTemplate")
                                || obj_text.contains("template")
                            {
                                if let Some(args) = node.child_by_field_name("arguments") {
                                    if let Some(first_arg) = args.named_child(0) {
                                        if !is_literal(first_arg) {
                                            findings.push(make_finding(
                                                _self.id(),
                                                _self.severity(),
                                                _self.cwe(),
                                                "RestTemplate called with dynamic URL — validate and allowlist target hosts to prevent SSRF",
                                                node,
                                                src,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        findings

    }
}

// ─── Rule 5: no-path-traversal ──────────────────────────────────────────────

pub struct NoPathTraversal;

impl_rule! {
    NoPathTraversal,
    id = "java/no-path-traversal",
    severity = Severity::High,
    cwe = Some("CWE-22"),
    description = "Potential path traversal via dynamic file path",
    language = Language::Java,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // new File(variable), new FileInputStream(variable)
            if node.kind() == "object_creation_expression" {
                if let Some(type_node) = node.child_by_field_name("type") {
                    let type_text = &src[type_node.byte_range()];
                    if type_text == "File" || type_text == "FileInputStream" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                if !is_literal(first_arg) {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        &format!(
                                            "new {}() with dynamic path — sanitize input to prevent path traversal",
                                            type_text
                                        ),
                                        node,
                                        src,
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            // Paths.get(variable)
            if node.kind() == "method_invocation" {
                if let Some(name) = node.child_by_field_name("name") {
                    let name_text = &src[name.byte_range()];
                    if name_text == "get" {
                        if let Some(obj) = node.child_by_field_name("object") {
                            let obj_text = &src[obj.byte_range()];
                            if obj_text == "Paths" || obj_text == "Path" {
                                if let Some(args) = node.child_by_field_name("arguments") {
                                    if let Some(first_arg) = args.named_child(0) {
                                        if !is_literal(first_arg) {
                                            findings.push(make_finding(
                                                _self.id(),
                                                _self.severity(),
                                                _self.cwe(),
                                                "Paths.get() with dynamic path — sanitize input to prevent path traversal",
                                                node,
                                                src,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        findings

    }
}

// ─── Rule 6: no-weak-crypto ────────────────────────────────────────────────

pub struct NoWeakCrypto;

impl_rule! {
    NoWeakCrypto,
    id = "java/no-weak-crypto",
    severity = Severity::Medium,
    cwe = Some("CWE-327"),
    description = "Use of weak cryptographic algorithm",
    language = Language::Java,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let weak_algo = java_weak_algo_re();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "method_invocation" {
                if let Some(name) = node.child_by_field_name("name") {
                    let name_text = &src[name.byte_range()];
                    if name_text == "getInstance" {
                        if let Some(obj) = node.child_by_field_name("object") {
                            let obj_text = &src[obj.byte_range()];
                            if obj_text == "Cipher"
                                || obj_text == "MessageDigest"
                                || obj_text == "SecretKeyFactory"
                                || obj_text == "KeyGenerator"
                            {
                                if let Some(args) = node.child_by_field_name("arguments") {
                                    if let Some(first_arg) = args.named_child(0) {
                                        let arg_text = &src[first_arg.byte_range()];
                                        if weak_algo.is_match(arg_text) {
                                            findings.push(make_finding(
                                                _self.id(),
                                                _self.severity(),
                                                _self.cwe(),
                                                &format!(
                                                    "{}.getInstance({}) uses a weak algorithm — use AES-GCM, SHA-256, or stronger",
                                                    obj_text, arg_text
                                                ),
                                                node,
                                                src,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        findings

    }
}

// ─── Rule: pq-vulnerable-crypto ───────────────────────────────────────────

/// Classify a Java algorithm string as quantum-vulnerable.
/// Returns (algo_label, canonical_algo, default_replacement) or None if not PQ-vulnerable.
/// `canonical_algo` is the normalized CBOM algorithm name (e.g. "RSA", "ECDSA", "DH").
fn classify_java_pq_algo(algo: &str) -> Option<(&'static str, &'static str, &'static str)> {
    // Exact matches for KeyPairGenerator / KeyAgreement / KeyFactory.
    // PQ-safe algorithms (ML-KEM/ML-DSA/SLH-DSA and the draft FN-DSA / HQC
    // standards) are intentionally absent from this table and therefore skipped.
    match algo {
        "RSA" => return Some(("RSA", "RSA", "General use (FIPS category III): X25519MLKEM768 hybrid KEM (or HQC for code-based diversity, draft) for encryption, ML-DSA-65 (FIPS 204) / FN-DSA (FIPS 206, draft) with hybrid cert chains for signatures. CNSA 2.0 / NSS: ML-KEM-1024 for key establishment, ML-DSA-87 for signatures (Java JEP 527).")),
        "EC" | "ECDSA" => return Some(("ECDSA/EC", "ECDSA", "General use (FIPS category III): ML-DSA-65 (FIPS 204) or FN-DSA (FIPS 206, draft) for smaller signatures, with hybrid cert chains. CNSA 2.0 / NSS: ML-DSA-87 for signatures (Java JEP 527).")),
        "DSA" => return Some(("DSA", "DSA", "General use (FIPS category III): ML-DSA-65 (FIPS 204) or FN-DSA (FIPS 206, draft) for smaller signatures, with hybrid cert chains. CNSA 2.0 / NSS: ML-DSA-87 for signatures (Java JEP 527).")),
        "DH" | "DiffieHellman" => return Some(("DH", "DH", "General use (FIPS category III): X25519MLKEM768 hybrid KEM (FIPS 203), or HQC (code-based diversity hedge, draft) as a non-lattice alternative. CNSA 2.0 / NSS: ML-KEM-1024 for key establishment (Java JEP 527).")),
        "ECDH" => return Some(("ECDH", "ECDH", "General use (FIPS category III): X25519MLKEM768 hybrid KEM (FIPS 203), or HQC (code-based diversity hedge, draft) as a non-lattice alternative. CNSA 2.0 / NSS: ML-KEM-1024 for key establishment (Java JEP 527).")),
        "Ed25519" => return Some(("Ed25519", "Ed25519", "General use (FIPS category III): ML-DSA-65 (FIPS 204) or FN-DSA (FIPS 206, draft) for smaller signatures, with hybrid cert chains. CNSA 2.0 / NSS: ML-DSA-87 for signatures (Java JEP 527).")),
        "Ed448" => return Some(("Ed448", "Ed448", "General use (FIPS category III): ML-DSA-65 (FIPS 204) or FN-DSA (FIPS 206, draft) for smaller signatures, with hybrid cert chains. CNSA 2.0 / NSS: ML-DSA-87 for signatures (Java JEP 527).")),
        "EdDSA" => return Some(("EdDSA", "Ed25519", "General use (FIPS category III): ML-DSA-65 (FIPS 204) or FN-DSA (FIPS 206, draft) for smaller signatures, with hybrid cert chains. CNSA 2.0 / NSS: ML-DSA-87 for signatures (Java JEP 527).")),
        "X25519" => return Some(("X25519", "X25519", "General use (FIPS category III): X25519MLKEM768 hybrid KEM (FIPS 203), or HQC (code-based diversity hedge, draft). CNSA 2.0 / NSS: ML-KEM-1024 for key establishment (Java JEP 527).")),
        "X448" => return Some(("X448", "X448", "General use (FIPS category III): X25519MLKEM768 hybrid KEM (FIPS 203), or HQC (code-based diversity hedge, draft). CNSA 2.0 / NSS: ML-KEM-1024 for key establishment (Java JEP 527).")),
        "XDH" => return Some(("XDH", "X25519", "General use (FIPS category III): X25519MLKEM768 hybrid KEM (FIPS 203), or HQC (code-based diversity hedge, draft). CNSA 2.0 / NSS: ML-KEM-1024 for key establishment (Java JEP 527).")),
        _ => {}
    }
    // Non-exact matches need case-insensitive comparison
    let upper = algo.to_uppercase();
    // RSA cipher modes: "RSA/ECB/PKCS1Padding", "RSA/ECB/OAEPWithSHA-256..."
    if upper.starts_with("RSA/") || upper.starts_with("RSA_") {
        return Some(("RSA", "RSA", "General use (FIPS category III): X25519MLKEM768 hybrid KEM (or HQC for code-based diversity, draft) for encryption, ML-DSA-65 (FIPS 204) / FN-DSA (FIPS 206, draft) with hybrid cert chains for signatures. CNSA 2.0 / NSS: ML-KEM-1024 for key establishment, ML-DSA-87 for signatures (Java JEP 527)."));
    }
    // Signature combos: "SHA256withRSA", "SHA384withECDSA", "SHA256withDSA".
    // The PQ-safe exclusions below ensure future hybrid names containing the
    // substring "DSA" (e.g. "ML-DSA", "SLH-DSA", "FN-DSA") or the code-based
    // KEM "HQC" are not misclassified.
    if upper.contains("WITHRSA") {
        return Some((
            "RSA",
            "RSA",
            "General use (FIPS category III): ML-DSA-65 (FIPS 204) or FN-DSA (FIPS 206, draft) for smaller signatures, with hybrid cert chains. CNSA 2.0 / NSS: ML-DSA-87 for signatures (Java JEP 527).",
        ));
    }
    if upper.contains("WITHECDSA") {
        return Some((
            "ECDSA",
            "ECDSA",
            "General use (FIPS category III): ML-DSA-65 (FIPS 204) or FN-DSA (FIPS 206, draft) for smaller signatures, with hybrid cert chains. CNSA 2.0 / NSS: ML-DSA-87 for signatures (Java JEP 527).",
        ));
    }
    if upper.contains("WITHDSA")
        && !upper.contains("ML-DSA")
        && !upper.contains("SLH-DSA")
        && !upper.contains("FN-DSA")
        && !upper.contains("HQC")
    {
        return Some((
            "DSA",
            "DSA",
            "General use (FIPS category III): ML-DSA-65 (FIPS 204) or FN-DSA (FIPS 206, draft) for smaller signatures, with hybrid cert chains. CNSA 2.0 / NSS: ML-DSA-87 for signatures (Java JEP 527).",
        ));
    }
    None
}

pub struct PqVulnerableCrypto;

impl_rule! {
    PqVulnerableCrypto,
    id = "java/pq-vulnerable-crypto",
    severity = Severity::High,
    cwe = Some("CWE-327"),
    description = "Use of quantum-vulnerable cryptographic algorithm (RSA/EC/DSA/DH/Ed25519/X25519)",
    language = Language::Java,
    // CNSA 2.0 class: web/cloud (exclusive-use 2033).
    cnsa2_deadline = "2033",
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "method_invocation" {
                if let Some(name) = node.child_by_field_name("name") {
                    let name_text = &src[name.byte_range()];
                    if name_text == "getInstance" {
                        if let Some(obj) = node.child_by_field_name("object") {
                            let obj_text = &src[obj.byte_range()];
                            if obj_text == "KeyPairGenerator"
                                || obj_text == "KeyAgreement"
                                || obj_text == "Signature"
                                || obj_text == "Cipher"
                                || obj_text == "KeyFactory"
                            {
                                if let Some(args) = node.child_by_field_name("arguments") {
                                    if let Some(first_arg) = args.named_child(0) {
                                        let arg_text = &src[first_arg.byte_range()];
                                        let inner = arg_text.trim_matches('"');
                                        let (algo, canonical_algo, replacement) = match classify_java_pq_algo(inner) {
                                            Some(v) => v,
                                            None => return,
                                        };
                                        let replacement = if obj_text == "KeyAgreement" {
                                            "General use (FIPS category III): X25519MLKEM768 hybrid KEM (FIPS 203), or HQC (code-based diversity hedge, draft) as a non-lattice alternative. CNSA 2.0 / NSS: ML-KEM-1024 for key establishment (Java JEP 527)."
                                        } else if obj_text == "Signature" {
                                            "General use (FIPS category III): ML-DSA-65 (FIPS 204) or FN-DSA (FIPS 206, draft) for smaller signatures, with hybrid cert chains. CNSA 2.0 / NSS: ML-DSA-87 for signatures (Java JEP 527)."
                                        } else {
                                            replacement
                                        };
                                        let mut f = make_finding(
                                            _self.id(),
                                            _self.severity(),
                                            _self.cwe(),
                                            &format!(
                                                "{}.getInstance({}) uses quantum-vulnerable {} — migrate to {}",
                                                obj_text, arg_text, algo, replacement
                                            ),
                                            node,
                                            src,
                                        );
                                        f.tags = vec!["PQ".into()];
                                        f.crypto_algorithm = Some(canonical_algo.to_string());
                                        findings.push(f);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        findings

    }
}

// ─── Rule 7: no-hardcoded-secret ────────────────────────────────────────────

pub struct NoHardcodedSecret;

impl_rule! {
    NoHardcodedSecret,
    id = "java/no-hardcoded-secret",
    severity = Severity::High,
    cwe = Some("CWE-798"),
    description = "Hardcoded secret or credential detected",
    language = Language::Java,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let secret_pattern = hardcoded_secret_re();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // variable_declarator: String password = "hardcoded";
            if node.kind() == "variable_declarator" {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = &src[name_node.byte_range()];
                    if secret_pattern.is_match(name) {
                        if let Some(value) = node.child_by_field_name("value") {
                            if value.kind() == "string_literal" {
                                let val = &src[value.byte_range()];
                                let inner = val.trim_matches('"');
                                if is_secret_value_long_enough(inner) {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        &format!(
                                            "Hardcoded secret in '{}' — use environment variables or a secret manager",
                                            name
                                        ),
                                        node,
                                        src,
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            // Assignment: password = "hardcoded";
            if node.kind() == "assignment_expression" {
                if let Some(left) = node.child_by_field_name("left") {
                    let left_text = &src[left.byte_range()];
                    if secret_pattern.is_match(left_text) {
                        if let Some(right) = node.child_by_field_name("right") {
                            if right.kind() == "string_literal" {
                                let val = &src[right.byte_range()];
                                let inner = val.trim_matches('"');
                                if is_secret_value_long_enough(inner) {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        &format!(
                                            "Hardcoded secret in '{}' — use environment variables or a secret manager",
                                            left_text.trim()
                                        ),
                                        node,
                                        src,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        });
        findings

    }
}

// ─── Rule 8: no-xxe ────────────────────────────────────────────────────────

pub struct NoXxe;

impl_rule! {
    NoXxe,
    id = "java/no-xxe",
    severity = Severity::High,
    cwe = Some("CWE-611"),
    description = "XML parser created without disabling external entities (XXE)",
    language = Language::Java,
    fn check(_self, source, _tree) {

        let mut findings = Vec::new();
        let factory_pattern = java_xxe_factory_re();
        let secure_pattern = java_xxe_secure_re();

        // Simple heuristic: if a factory is created but no setFeature is called
        // in the same file, flag it.
        if factory_pattern.is_match(source) && !secure_pattern.is_match(source) {
            for matched in factory_pattern.find_iter(source) {
                findings.push(make_finding_from_offsets(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "XML parser factory created without disabling external entities — set feature to prevent XXE attacks",
                    source,
                    matched.start(),
                    matched.end(),
                ));
            }
        }
        findings

    }
}

// ─── Rule 9: spring-csrf-disabled ───────────────────────────────────────────

pub struct SpringCsrfDisabled;

impl_rule! {
    SpringCsrfDisabled,
    id = "java/spring-csrf-disabled",
    severity = Severity::High,
    cwe = Some("CWE-352"),
    description = "Spring Security CSRF protection is disabled",
    language = Language::Java,
    fn check(_self, source, _tree) {

        let mut findings = Vec::new();
        // .csrf().disable() or csrf(csrf -> csrf.disable()) or csrf(c -> c.disable())
        let csrf_pattern = java_csrf_re();

        for matched in csrf_pattern.find_iter(source) {
            findings.push(make_finding_from_offsets(
                _self.id(),
                _self.severity(),
                _self.cwe(),
                "CSRF protection is disabled — enable CSRF unless this is a stateless API with token auth",
                source,
                matched.start(),
                matched.end(),
            ));
        }
        findings

    }
}

// ─── Rule 10: no-xss ──────────────────────────────────────────────────────

pub struct NoXss;

impl_rule! {
    NoXss,
    id = "java/no-xss",
    severity = Severity::High,
    cwe = Some("CWE-79"),
    description = "Potential XSS via direct write of user input to HTTP response",
    language = Language::Java,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "method_invocation" {
                if let Some(name) = node.child_by_field_name("name") {
                    let name_text = &src[name.byte_range()];
                    if name_text == "write" || name_text == "println" || name_text == "print" {
                        if let Some(obj) = node.child_by_field_name("object") {
                            let obj_text = &src[obj.byte_range()];
                            // Match response.getWriter().write/println, out.write/println,
                            // or PrintWriter.write/println
                            if obj_text.contains("getWriter()")
                                || obj_text == "out"
                                || obj_text.contains("PrintWriter")
                                || obj_text == "writer"
                                || obj_text == "pw"
                            {
                                if let Some(args) = node.child_by_field_name("arguments") {
                                    if let Some(first_arg) = args.named_child(0) {
                                        // Flag if the argument is not a pure literal
                                        // (i.e. it's a variable, concatenation, method call, etc.)
                                        if !is_literal(first_arg)
                                            && first_arg.kind() != "string_literal"
                                        {
                                            let mut f = make_finding(
                                                _self.id(),
                                                _self.severity(),
                                                _self.cwe(),
                                                "User input written directly to HTTP response — risk of XSS",
                                                node,
                                                src,
                                            );
                                            f.fix_suggestion = Some("HTML-encode user input before writing to response: use OWASP Java Encoder or StringEscapeUtils.escapeHtml4()".to_string());
                                            findings.push(f);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        findings

    }
}

// ─── Rule 12: hardcoded-crypto-algorithm ───────────────────────────────────

pub struct HardcodedCryptoAlgorithm;

impl_rule! {
    HardcodedCryptoAlgorithm,
    id = "java/hardcoded-crypto-algorithm",
    severity = Severity::Low,
    cwe = Some("CWE-327"),
    description = "Hardcoded algorithm string in crypto API call hinders crypto agility",
    language = Language::Java,
    // CNSA 2.0 class: web/cloud (exclusive-use 2033).
    cnsa2_deadline = "2033",
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let crypto_classes = [
            "Cipher",
            "MessageDigest",
            "Signature",
            "KeyPairGenerator",
            "KeyAgreement",
            "KeyFactory",
            "SecretKeyFactory",
            "KeyGenerator",
            "Mac",
            "AlgorithmParameters",
        ];

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "method_invocation" {
                if let Some(name) = node.child_by_field_name("name") {
                    let name_text = &src[name.byte_range()];
                    if name_text == "getInstance" {
                        if let Some(obj) = node.child_by_field_name("object") {
                            let obj_text = &src[obj.byte_range()];
                            if crypto_classes.contains(&obj_text) {
                                if let Some(args) = node.child_by_field_name("arguments") {
                                    if let Some(first_arg) = args.named_child(0) {
                                        if first_arg.kind() == "string_literal" {
                                            let arg_text = &src[first_arg.byte_range()];
                                            let inner = arg_text.trim_matches('"');
                                            // Skip weak algorithms — java/no-weak-crypto owns those.
                                            let upper = inner.to_uppercase();
                                            if upper == "MD5"
                                                || upper == "SHA-1"
                                                || upper.starts_with("SHA1")
                                                || upper == "DES"
                                                || upper == "DESEDE"
                                                || upper == "RC2"
                                                || upper == "RC4"
                                                || upper == "BLOWFISH"
                                                || upper.contains("ECB")
                                            {
                                                return;
                                            }
                                            findings.push(make_finding(
                                                _self.id(),
                                                _self.severity(),
                                                _self.cwe(),
                                                &format!(
                                                    "{}.getInstance(\"{}\") uses a hardcoded algorithm — externalize to configuration for crypto agility",
                                                    obj_text, inner
                                                ),
                                                node,
                                                src,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        findings

    }
}

// ─── Rule 11: spring-cors-permissive ────────────────────────────────────────

pub struct SpringCorsPermissive;

impl_rule! {
    SpringCorsPermissive,
    id = "java/spring-cors-permissive",
    severity = Severity::Medium,
    cwe = Some("CWE-942"),
    description = "Permissive CORS configuration allows any origin",
    language = Language::Java,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        // allowedOrigins("*")
        let wildcard_pattern = java_cors_wildcard_re();
        for matched in wildcard_pattern.find_iter(source) {
            findings.push(make_finding_from_offsets(
                _self.id(),
                _self.severity(),
                _self.cwe(),
                "allowedOrigins(\"*\") permits any origin — restrict to trusted domains",
                source,
                matched.start(),
                matched.end(),
            ));
        }

        // @CrossOrigin with wildcard or no origin restriction
        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "annotation" || node.kind() == "marker_annotation" {
                let text = &src[node.byte_range()];
                if text.contains("CrossOrigin") {
                    // @CrossOrigin without arguments defaults to *, or with explicit "*"
                    if text == "@CrossOrigin"
                        || text.contains("\"*\"")
                        || text.contains("origins = \"*\"")
                    {
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            "@CrossOrigin with wildcard origin — restrict to trusted domains",
                            node,
                            src,
                        ));
                    }
                }
            }
        });
        findings

    }
}
