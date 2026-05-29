use std::sync::OnceLock;

use regex::Regex;

use crate::impl_rule;
use crate::rules::common::{
    hardcoded_secret_re, is_secret_value_long_enough, make_finding, walk_tree,
};
use crate::rules::Rule;
use crate::{Language, Severity};

// ─── Path / identifier helpers ───────────────────────────────────────────────

/// Returns the final segment of a Rust call path.
///
/// For a `call_expression` function field, the text is a scoped or simple
/// identifier such as `std::mem::transmute`, `Path::new`, or `transmute`.
/// This strips any leading path qualifiers and any trailing turbofish/generic
/// arguments, yielding the bare callee name (`transmute`, `new`, ...).
/// Used to match callees by exact identifier rather than substring, which
/// avoids flagging user helpers like `my_transmute_wrapper`.
fn last_path_segment(func_text: &str) -> &str {
    let segment = match func_text.rsplit_once("::") {
        Some((_, last)) => last,
        None => func_text,
    };
    // Drop any turbofish / generic suffix (`transmute::<T>` would already be
    // split above, but a bare `foo::<T>` keeps the `<...>` here).
    match segment.find('<') {
        Some(idx) => segment[..idx].trim(),
        None => segment.trim(),
    }
}

/// Returns the `Type::method` tail of a call path: the last two `::`-separated
/// segments joined by `::`, or the whole text if there is only one segment.
///
/// `std::path::Path::new` -> `Path::new`, `PathBuf::from` -> `PathBuf::from`,
/// `validate_path_new` -> `validate_path_new`. Lets path-traversal match the
/// constructor call exactly instead of via substring.
fn last_two_path_segments(func_text: &str) -> String {
    let trimmed = match func_text.find('<') {
        Some(idx) => func_text[..idx].trim(),
        None => func_text.trim(),
    };
    let parts: Vec<&str> = trimmed.split("::").collect();
    match parts.len() {
        0 => String::new(),
        1 => parts[0].to_string(),
        n => format!("{}::{}", parts[n - 2], parts[n - 1]),
    }
}

// ─── Static regex helpers (compiled once) ────────────────────────────────────

fn rust_sql_methods_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(query|sql_query|execute|raw_sql)\b")
            .expect("static Rust SQL method regex should compile")
    })
}

/// Returns true if a call argument node is a compile-time constant that cannot
/// carry attacker input: a string literal, or a reference to a constant
/// identifier (Rust constants are conventionally `SCREAMING_SNAKE_CASE`, e.g.
/// `Command::new(GIT_BINARY)` or `Command::new(config::GIT_BINARY)`). Dynamic
/// values (locals, function results, format! results) are not constant.
fn arg_is_constant(arg: tree_sitter::Node<'_>, src: &str) -> bool {
    match arg.kind() {
        "string_literal" => true,
        "identifier" | "scoped_identifier" => {
            let text = &src[arg.byte_range()];
            // Take the final path segment and check it is a SCREAMING_SNAKE_CASE
            // constant name (all uppercase letters, digits, or underscores, with
            // at least one letter).
            let name = last_path_segment(text);
            !name.is_empty()
                && name.chars().any(|c| c.is_ascii_alphabetic())
                && name
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        }
        _ => false,
    }
}

/// Returns true if a `format!(...)` macro body contains at least one real
/// interpolation placeholder (`{}`, `{0}`, `{name}`, ...). Escaped braces
/// (`{{` / `}}`) do not count. A `format!` with no placeholder produces a
/// constant string and cannot carry injected input, so it should not be
/// flagged as SQL injection.
fn format_has_interpolation(macro_text: &str) -> bool {
    let bytes = macro_text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            // `{{` is an escaped literal brace, not a placeholder.
            if bytes.get(i + 1) == Some(&b'{') {
                i += 2;
                continue;
            }
            return true;
        }
        i += 1;
    }
    false
}

/// Returns true if `token` appears as a leading word of any `::`-separated
/// segment of `path` (already lowercased). A "leading word" is the token at the
/// start of a segment, terminated by the end of the segment or a `_`/non-word
/// boundary — e.g. `rsa` matches the `rsa` crate or `rsa_pss`, and `ed25519`
/// matches the `ed25519_dalek` crate, but neither matches a buried occurrence
/// such as `user_ed25519_key_id` or `my_rsa_helper`.
fn crypto_token_in_path(path_lower: &str, token: &str) -> bool {
    path_lower.split("::").any(|segment| {
        let segment = segment.trim();
        match segment.strip_prefix(token) {
            // Exact segment match (e.g. `rsa`, `ecdsa`).
            Some("") => true,
            // Token is a prefix followed by a word separator (e.g.
            // `ed25519_dalek`, `rsa_pss`). The next char must not be a
            // continuation of the same word (alphanumeric), otherwise
            // `dsael` would match `dsa`. We only allow `_` as the separator
            // since these are crate/module identifiers.
            Some(rest) => rest.starts_with('_'),
            None => false,
        }
    })
}

/// If `func_text` (a call's function path) names a weak hash algorithm as one
/// of its complete `::`-separated path segments, returns the canonical
/// algorithm label ("MD5" / "SHA1"). Matching on whole segments avoids
/// substring false positives like `sha1sum_path` or `md5_is_fine_helper`.
fn weak_hash_algo_in_call(func_text: &str) -> Option<&'static str> {
    let path = match func_text.find('<') {
        Some(idx) => &func_text[..idx],
        None => func_text,
    };
    for segment in path.split("::") {
        match segment.trim() {
            "md5" | "Md5" | "MD5" => return Some("MD5"),
            "sha1" | "Sha1" | "SHA1" => return Some("SHA1"),
            _ => {}
        }
    }
    None
}

// ─── Rule 1: unsafe-block ─────────────────────────────────────────────────────

pub struct UnsafeBlock;

impl_rule! {
    UnsafeBlock,
    id = "rs/unsafe-block",
    severity = Severity::Medium,
    cwe = Some("CWE-676"),
    description = "Use of unsafe block bypasses Rust memory safety guarantees",
    language = Language::Rust,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "unsafe_block" {
                findings.push(make_finding(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "unsafe block bypasses Rust memory safety — ensure correctness is manually verified",
                    node,
                    src,
                ));
            }
        });
        findings

    }
}

// ─── Rule 2: transmute-usage ──────────────────────────────────────────────────

pub struct TransmuteUsage;

impl_rule! {
    TransmuteUsage,
    id = "rs/transmute-usage",
    severity = Severity::High,
    cwe = Some("CWE-843"),
    description = "Use of std::mem::transmute can cause type confusion and undefined behavior",
    language = Language::Rust,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    // Match only when the final call-path segment is exactly
                    // `transmute` (e.g. `std::mem::transmute`, `mem::transmute`,
                    // or a bare `transmute`). A substring check would also flag
                    // user helpers like `my_transmute_wrapper(...)`.
                    if last_path_segment(func_text) == "transmute" {
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            "std::mem::transmute can cause type confusion and undefined behavior — prefer safe casts",
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

// ─── Rule 3: no-command-injection ─────────────────────────────────────────────

pub struct NoCommandInjection;

impl_rule! {
    NoCommandInjection,
    id = "rs/no-command-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-78"),
    description = "Potential command injection via Command::new with dynamic input",
    language = Language::Rust,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    // Only match the direct Command::new call, not chained methods
                    if func_text == "Command::new"
                        || func_text == "std::process::Command::new"
                        || func_text == "process::Command::new"
                    {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let mut is_constant = false;
                            if let Some(first_arg) = args.named_child(0) {
                                is_constant = arg_is_constant(first_arg, src);
                            }
                            if !is_constant {
                                findings.push(make_finding(
                                    _self.id(),
                                    _self.severity(),
                                    _self.cwe(),
                                    "Command::new called with dynamic argument — risk of command injection",
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

// ─── Rule 4: no-sql-injection ─────────────────────────────────────────────────

pub struct NoSqlInjection;

impl_rule! {
    NoSqlInjection,
    id = "rs/no-sql-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-89"),
    description = "Potential SQL injection via format! macro in query argument",
    language = Language::Rust,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let sql_methods = rust_sql_methods_re();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if sql_methods.is_match(func_text) {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            // Check if any argument is a format! macro invocation
                            let mut arg_cursor = args.walk();
                            for arg in args.children(&mut arg_cursor) {
                                if arg.kind() == "macro_invocation" {
                                    let macro_text = &src[arg.byte_range()];
                                    // Only flag a `format!` that actually
                                    // interpolates a value. A static
                                    // `format!("SELECT 1")` with no `{}`
                                    // placeholder cannot inject anything and was
                                    // a false positive.
                                    if macro_text.starts_with("format!")
                                        && format_has_interpolation(macro_text)
                                    {
                                        findings.push(make_finding(
                                            _self.id(),
                                            _self.severity(),
                                            _self.cwe(),
                                            "SQL query built with format! macro — use parameterized queries",
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
        });
        findings

    }
}

// ─── Rule 5: no-weak-hash ────────────────────────────────────────────────────

pub struct NoWeakHash;

impl_rule! {
    NoWeakHash,
    id = "rs/no-weak-hash",
    severity = Severity::Medium,
    cwe = Some("CWE-328"),
    description = "Use of weak cryptographic hash (MD5/SHA1)",
    language = Language::Rust,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect function calls at the use site: Md5::new(), Sha1::new(),
            // md5::compute(), etc. We deliberately do NOT flag `use md5;`
            // imports — a dead/unused import is not itself a vulnerability and
            // produced false positives. The algorithm name must appear as a
            // complete `::`-separated path segment so identifiers that merely
            // contain it (e.g. a `sha1sum_path` helper) are not matched.
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if let Some(algo) = weak_hash_algo_in_call(func_text) {
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            &format!(
                                "{} is cryptographically weak — use SHA-256 or stronger",
                                algo
                            ),
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

// ─── Rule: pq-vulnerable-crypto ───────────────────────────────────────────

pub struct PqVulnerableCrypto;

impl_rule! {
    PqVulnerableCrypto,
    id = "rs/pq-vulnerable-crypto",
    severity = Severity::High,
    cwe = Some("CWE-327"),
    description = "Use of quantum-vulnerable cryptographic algorithm (RSA/ECDSA/ECDH/Ed25519/X25519)",
    language = Language::Rust,
    // CNSA 2.0 class: web/cloud (exclusive-use 2033).
    cnsa2_deadline = "2033",
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    // Only match direct calls (scoped_identifier like rsa::Foo::new),
                    // not chained method calls (field_expression like .unwrap())
                    if func.kind() != "scoped_identifier" && func.kind() != "identifier" {
                        return;
                    }
                    let func_text = &src[func.byte_range()];
                    let func_lower = func_text.to_lowercase();
                    // Skip PQ-safe algorithms. fn_dsa (FIPS 206, draft) and hqc
                    // (5th NIST selection, code-based KEM, draft std 2026) are
                    // recognised here so early adopters of those crates aren't flagged.
                    if func_lower.contains("ml_dsa")
                        || func_lower.contains("ml_kem")
                        || func_lower.contains("slh_dsa")
                        || func_lower.contains("fn_dsa")
                        || func_lower.contains("hqc")
                    {
                        return;
                    }
                    // Match the algorithm as a complete leading word of a path
                    // segment (crate/module identifier), not an arbitrary
                    // substring. This keeps `rsa::RsaPrivateKey::new` and
                    // `ed25519_dalek::SigningKey::generate` flagged while
                    // ignoring incidental matches like a `user_ed25519_key_id`
                    // identifier passed through a call path.
                    let has = |token: &str| crypto_token_in_path(&func_lower, token);
                    let (algo, canonical_algo, replacement) = if has("ed25519") {
                        ("Ed25519", "Ed25519", "General use (FIPS category III): ML-DSA-65 (FIPS 204) or FN-DSA (FIPS 206, draft) for smaller signatures, with hybrid certificate chains during transition. CNSA 2.0 / NSS: ML-DSA-87 for signatures.")
                    } else if has("x25519") {
                        ("X25519", "X25519", "General use (FIPS category III): X25519MLKEM768 hybrid KEM (FIPS 203), or HQC (code-based diversity hedge, draft) as a non-lattice alternative. CNSA 2.0 / NSS: ML-KEM-1024 for key establishment.")
                    } else if has("rsa") {
                        ("RSA", "RSA", "General use (FIPS category III): X25519MLKEM768 hybrid KEM (or HQC for code-based diversity) for encryption, ML-DSA-65 (FIPS 204) / FN-DSA (FIPS 206, draft) with hybrid cert chains for signatures. CNSA 2.0 / NSS: ML-KEM-1024 for key establishment, ML-DSA-87 for signatures.")
                    } else if has("ecdsa") {
                        ("ECDSA", "ECDSA", "General use (FIPS category III): ML-DSA-65 (FIPS 204) or FN-DSA (FIPS 206, draft) for smaller signatures, with hybrid certificate chains during transition. CNSA 2.0 / NSS: ML-DSA-87 for signatures.")
                    } else if has("p256") || has("p384") || has("p521") || has("k256") {
                        ("ECDH/ECDSA (elliptic curve)", "ECDSA", "General use (FIPS category III): X25519MLKEM768 hybrid KEM (or HQC for code-based diversity) or ML-DSA-65 (FIPS 204) / FN-DSA (FIPS 206, draft) with hybrid cert chains. CNSA 2.0 / NSS: ML-KEM-1024 for key establishment, ML-DSA-87 for signatures.")
                    } else if has("dsa") {
                        ("DSA", "DSA", "General use (FIPS category III): ML-DSA-65 (FIPS 204) or FN-DSA (FIPS 206, draft) for smaller signatures, with hybrid certificate chains during transition. CNSA 2.0 / NSS: ML-DSA-87 for signatures.")
                    } else {
                        return;
                    };
                    let mut f = make_finding(
                        _self.id(),
                        _self.severity(),
                        _self.cwe(),
                        &format!(
                            "{} is quantum-vulnerable — migrate to {}",
                            algo, replacement
                        ),
                        node,
                        src,
                    );
                    f.tags = vec!["PQ".into()];
                    f.crypto_algorithm = Some(canonical_algo.to_string());
                    findings.push(f);
                }
            }
        });
        findings

    }
}

// ─── Rule 6: no-hardcoded-secret ──────────────────────────────────────────────

pub struct NoHardcodedSecret;

impl_rule! {
    NoHardcodedSecret,
    id = "rs/no-hardcoded-secret",
    severity = Severity::High,
    cwe = Some("CWE-798"),
    description = "Hardcoded secret or credential detected",
    language = Language::Rust,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let secret_pattern = hardcoded_secret_re();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // let password = "hardcoded";
            if node.kind() == "let_declaration" {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    let name = &src[pattern.byte_range()];
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
                                            "Hardcoded secret in '{}' — use environment variables",
                                            name.trim()
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

// ─── Rule 7: tls-verify-disabled ──────────────────────────────────────────────

pub struct TlsVerifyDisabled;

impl_rule! {
    TlsVerifyDisabled,
    id = "rs/tls-verify-disabled",
    severity = Severity::High,
    cwe = Some("CWE-295"),
    description = "TLS certificate verification disabled with danger_accept_invalid_certs",
    language = Language::Rust,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text.contains("danger_accept_invalid_certs") {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                let arg_text = &src[first_arg.byte_range()];
                                if arg_text == "true" {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        "danger_accept_invalid_certs(true) disables TLS verification — prefer proper CA validation",
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

// ─── Rule 8: no-ssrf ─────────────────────────────────────────────────────────

pub struct NoSsrf;

impl_rule! {
    NoSsrf,
    id = "rs/no-ssrf",
    severity = Severity::High,
    cwe = Some("CWE-918"),
    description = "Potential SSRF via reqwest with dynamic URL",
    language = Language::Rust,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    // Require the call to be reqwest-specific:
                    //   - the free function `reqwest::get(url)`, or
                    //   - a `.get(...)`/`.post(...)` method invoked on a
                    //     `reqwest`-prefixed receiver (e.g. `reqwest::Client::new().get(url)`
                    //     or `reqwest_client.get(url)`).
                    // The previous `src.contains("reqwest")` fallback flagged any
                    // `.get()`/`.post()` in a file that merely mentioned reqwest
                    // (e.g. in a comment), producing false positives.
                    let is_reqwest_get = func_text == "reqwest::get";
                    let is_reqwest_method = (func_text.ends_with(".get")
                        || func_text.ends_with(".post"))
                        && func_text.contains("reqwest");
                    if is_reqwest_get || is_reqwest_method {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                if first_arg.kind() != "string_literal" {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        &format!(
                                            "{} called with dynamic URL — validate and allowlist target hosts to prevent SSRF",
                                            func_text
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

// ─── Rule 9: no-path-traversal ────────────────────────────────────────────────

pub struct NoPathTraversal;

impl_rule! {
    NoPathTraversal,
    id = "rs/no-path-traversal",
    severity = Severity::Medium,
    cwe = Some("CWE-22"),
    description = "Potential path traversal via Path::new or PathBuf::from with dynamic input",
    language = Language::Rust,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    // Match the constructor call exactly on its `Type::method`
                    // tail (`Path::new`, `PathBuf::from`) rather than via
                    // substring, so helpers like `validate_path_new(...)` are
                    // not flagged.
                    let tail = last_two_path_segments(func_text);
                    if tail == "Path::new" || tail == "PathBuf::from" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                if first_arg.kind() != "string_literal" {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        &format!(
                                            "{} called with dynamic path — validate input to prevent path traversal",
                                            func_text
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

// ─── Rule 10: no-unwrap-in-lib ────────────────────────────────────────────────

pub struct NoUnwrapInLib;

/// Returns true if `path` looks like Rust *library* code, where a panic from
/// `.unwrap()`/`.expect()` would abort a caller's process. Binary entry points
/// (`main.rs`, files under a `bin/`/`examples/`/`benches/` directory) and test
/// files (under a `tests/` integration-test directory, or named `*_test.rs` /
/// `*_tests.rs` / `test_*.rs`) are excluded — panicking there is conventional
/// and not a library-correctness problem.
///
/// Note: the project's own fixtures live under `tests/fixtures/`, so we only
/// treat a `tests/` component as an integration-test root when it is *not*
/// followed by a `fixtures` component. This keeps `tests/fixtures/*.rs` (the
/// scanned sample files) classified as library code.
fn is_rust_lib_path(path: &std::path::Path) -> bool {
    let file_name = path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or_default();

    // Binary / generated entry points.
    if matches!(file_name, "main.rs" | "build.rs") {
        return false;
    }
    // Test file naming conventions.
    let stem = file_name.strip_suffix(".rs").unwrap_or(file_name);
    if stem.ends_with("_test") || stem.ends_with("_tests") || stem.starts_with("test_") {
        return false;
    }

    // Directory-based binary/test/example roots.
    let components: Vec<&str> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    for (i, comp) in components.iter().enumerate() {
        match *comp {
            "bin" | "examples" | "benches" => return false,
            "tests" => {
                // Real integration-test root, but not our own
                // `tests/fixtures/` sample tree.
                let next = components.get(i + 1).copied();
                if next != Some("fixtures") {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

/// Returns true if `node` is lexically inside a `#[test]`-annotated function or
/// a `#[cfg(test)]`-annotated module/item. Unwraps in test code are acceptable.
fn is_inside_test_item(node: tree_sitter::Node<'_>, src: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(parent.kind(), "function_item" | "mod_item") {
            // Inspect attribute siblings immediately preceding this item.
            let mut sibling = parent.prev_sibling();
            while let Some(attr) = sibling {
                match attr.kind() {
                    "attribute_item" => {
                        let text = &src[attr.byte_range()];
                        if text.contains("test") {
                            return true;
                        }
                    }
                    "line_comment" | "block_comment" => {}
                    _ => break,
                }
                sibling = attr.prev_sibling();
            }
        }
        current = parent.parent();
    }
    false
}

impl Rule for NoUnwrapInLib {
    fn id(&self) -> &str {
        "rs/no-unwrap-in-lib"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-248")
    }
    fn description(&self) -> &str {
        "Use of .unwrap() or .expect() can cause panics in production"
    }
    fn language(&self) -> Language {
        Language::Rust
    }
    fn applies_to_path(&self, path: &std::path::Path) -> bool {
        is_rust_lib_path(path)
    }
    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<crate::Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text.ends_with(".unwrap") || func_text.ends_with(".expect") {
                        // Skip unwraps inside `#[test]` / `#[cfg(test)]` items.
                        if is_inside_test_item(node, src) {
                            return;
                        }
                        let method = if func_text.ends_with(".unwrap") {
                            ".unwrap()"
                        } else {
                            ".expect()"
                        };
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            &format!(
                                "{} can panic at runtime — use proper error handling with ? or match",
                                method
                            ),
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
