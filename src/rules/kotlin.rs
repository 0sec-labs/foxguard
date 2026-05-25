use std::sync::OnceLock;

use regex::Regex;

use crate::impl_rule;
use crate::rules::common::{
    hardcoded_secret_re, is_secret_value_long_enough, make_finding, make_finding_from_offsets,
    walk_tree,
};
use crate::{Finding, Language, Severity};

// ─── Static regex helpers (compiled once) ────────────────────────────────────

fn kt_sql_methods_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(executeQuery|execute|createQuery|createNativeQuery|rawQuery|execSQL)$")
            .expect("static Kotlin SQL method regex should compile")
    })
}

fn kt_weak_algo_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)"(DES|DESede|RC2|RC4|Blowfish|MD5|SHA-?1|.*ECB.*)"#)
            .expect("static Kotlin weak crypto regex should compile")
    })
}

fn kt_xxe_factory_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\(\)")
            .expect("static Kotlin XXE factory regex should compile")
    })
}

fn kt_xxe_secure_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"setFeature\s*\(|setProperty\s*\(|setAttribute\s*\(")
            .expect("static Kotlin XXE hardening regex should compile")
    })
}

fn kt_cors_wildcard_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(allowedOrigins|addAllowedOrigin)\s*\(\s*"\*"\s*\)"#)
            .expect("static Kotlin CORS regex should compile")
    })
}

/// Extract the method name from a `call_expression` node.
/// In Kotlin, method calls are: `navigation_expression` + `call_suffix`.
/// The `navigation_expression` has a `navigation_suffix` whose last
/// `simple_identifier` is the method name.
fn call_method_name<'a>(node: tree_sitter::Node<'a>, src: &'a str) -> Option<&'a str> {
    if node.kind() != "call_expression" {
        return None;
    }
    let callee = node.child(0)?;
    if callee.kind() == "navigation_expression" {
        // Last child of navigation_expression is navigation_suffix
        let nav_suffix = callee.child(callee.child_count().checked_sub(1)?)?;
        if nav_suffix.kind() == "navigation_suffix" {
            // Find simple_identifier inside navigation_suffix
            let mut cursor = nav_suffix.walk();
            for child in nav_suffix.children(&mut cursor) {
                if child.kind() == "simple_identifier" {
                    return Some(&src[child.byte_range()]);
                }
            }
        }
    }
    None
}

/// Get the object/receiver text of a `call_expression` (everything before the last `.method`).
fn call_receiver_text<'a>(node: tree_sitter::Node<'a>, src: &'a str) -> Option<&'a str> {
    if node.kind() != "call_expression" {
        return None;
    }
    let callee = node.child(0)?;
    if callee.kind() == "navigation_expression" {
        // First child is the receiver
        let receiver = callee.child(0)?;
        return Some(&src[receiver.byte_range()]);
    }
    None
}

/// Get the callee name for a constructor-style call: `ClassName(args)`.
/// In Kotlin, `File(x)` parses as `call_expression` with `simple_identifier` callee.
fn call_constructor_name<'a>(node: tree_sitter::Node<'a>, src: &'a str) -> Option<&'a str> {
    if node.kind() != "call_expression" {
        return None;
    }
    let callee = node.child(0)?;
    if callee.kind() == "simple_identifier" {
        return Some(&src[callee.byte_range()]);
    }
    None
}

/// Get the value_arguments node from a call_expression.
fn call_arguments(node: tree_sitter::Node) -> Option<tree_sitter::Node> {
    if node.kind() != "call_expression" {
        return None;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call_suffix" {
            let mut c2 = child.walk();
            for grandchild in child.children(&mut c2) {
                if grandchild.kind() == "value_arguments" {
                    return Some(grandchild);
                }
            }
        }
    }
    None
}

/// Get the first actual argument node from value_arguments.
fn first_argument(args_node: tree_sitter::Node) -> Option<tree_sitter::Node> {
    let mut cursor = args_node.walk();
    for child in args_node.children(&mut cursor) {
        if child.kind() == "value_argument" {
            // The actual expression is the child of value_argument
            return child.child(0);
        }
    }
    None
}

/// Get the Nth argument node from value_arguments.
fn nth_argument(args_node: tree_sitter::Node, n: usize) -> Option<tree_sitter::Node> {
    let mut cursor = args_node.walk();
    let mut count = 0;
    for child in args_node.children(&mut cursor) {
        if child.kind() == "value_argument" {
            if count == n {
                return child.child(0);
            }
            count += 1;
        }
    }
    None
}

/// Check if a node is a string literal.
fn is_string_literal(node: tree_sitter::Node) -> bool {
    matches!(
        node.kind(),
        "string_literal"
            | "character_literal"
            | "integer_literal"
            | "long_literal"
            | "real_literal"
            | "boolean_literal"
            | "null_literal"
    )
}

/// Check whether a node or any of its descendants contains string concatenation.
fn has_string_concat(node: tree_sitter::Node, src: &str) -> bool {
    if node.kind() == "additive_expression" {
        let text = &src[node.byte_range()];
        // Must contain a string literal and a + operator
        if text.contains('"') && text.contains('+') {
            return true;
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

// ─── Rule 1: kt/no-sql-injection ──────────────────────────────────────────

pub struct NoSqlInjection;

impl_rule! {
    NoSqlInjection,
    id = "kt/no-sql-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-89"),
    description = "Potential SQL injection via string concatenation in query method",
    language = Language::Kotlin,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let sql_methods = kt_sql_methods_re();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(name) = call_method_name(node, src) {
                    if sql_methods.is_match(name) {
                        if let Some(args) = call_arguments(node) {
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

// ─── Rule 2: kt/no-command-injection ──────────────────────────────────────

pub struct NoCommandInjection;

impl_rule! {
    NoCommandInjection,
    id = "kt/no-command-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-78"),
    description = "Potential command injection via Runtime.exec or ProcessBuilder with dynamic input",
    language = Language::Kotlin,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                // Runtime.getRuntime().exec(variable)
                if let Some(name) = call_method_name(node, src) {
                    if name == "exec" {
                        if let Some(receiver) = call_receiver_text(node, src) {
                            if receiver.contains("getRuntime") || receiver.contains("Runtime") {
                                if let Some(args) = call_arguments(node) {
                                    if let Some(first) = first_argument(args) {
                                        if !is_string_literal(first) {
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

                // ProcessBuilder(variable)
                if let Some(ctor_name) = call_constructor_name(node, src) {
                    if ctor_name == "ProcessBuilder" {
                        if let Some(args) = call_arguments(node) {
                            if let Some(first) = first_argument(args) {
                                if !is_string_literal(first) {
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

// ─── Rule 3: kt/no-unsafe-deserialization ─────────────────────────────────

pub struct NoUnsafeDeserialization;

impl_rule! {
    NoUnsafeDeserialization,
    id = "kt/no-unsafe-deserialization",
    severity = Severity::Critical,
    cwe = Some("CWE-502"),
    description = "Unsafe deserialization can lead to remote code execution",
    language = Language::Kotlin,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(name) = call_method_name(node, src) {
                    // readObject() calls
                    if name == "readObject" {
                        if let Some(receiver) = call_receiver_text(node, src) {
                            if receiver.contains("ObjectInputStream")
                                || receiver.contains("XMLDecoder")
                                || !receiver.contains('.')
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
                    if name == "load" {
                        if let Some(receiver) = call_receiver_text(node, src) {
                            if receiver.contains("Yaml") || receiver.contains("yaml") {
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

// ─── Rule 4: kt/no-ssrf ──────────────────────────────────────────────────

pub struct NoSsrf;

impl_rule! {
    NoSsrf,
    id = "kt/no-ssrf",
    severity = Severity::High,
    cwe = Some("CWE-918"),
    description = "Potential SSRF via URL or HTTP client with dynamic input",
    language = Language::Kotlin,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                // URL(variable) constructor
                if let Some(ctor_name) = call_constructor_name(node, src) {
                    if ctor_name == "URL" || ctor_name == "URI" {
                        if let Some(args) = call_arguments(node) {
                            if let Some(first) = first_argument(args) {
                                if !is_string_literal(first) {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        "URL/URI created with dynamic argument — validate and allowlist target hosts to prevent SSRF",
                                        node,
                                        src,
                                    ));
                                }
                            }
                        }
                    }
                }

                // RestTemplate or OkHttp calls
                if let Some(name) = call_method_name(node, src) {
                    if name == "getForObject"
                        || name == "getForEntity"
                        || name == "postForObject"
                        || name == "postForEntity"
                        || name == "exchange"
                    {
                        if let Some(receiver) = call_receiver_text(node, src) {
                            if receiver.contains("restTemplate")
                                || receiver.contains("RestTemplate")
                                || receiver.contains("template")
                            {
                                if let Some(args) = call_arguments(node) {
                                    if let Some(first) = first_argument(args) {
                                        if !is_string_literal(first) {
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

// ─── Rule 5: kt/no-path-traversal ────────────────────────────────────────

pub struct NoPathTraversal;

impl_rule! {
    NoPathTraversal,
    id = "kt/no-path-traversal",
    severity = Severity::High,
    cwe = Some("CWE-22"),
    description = "Potential path traversal via dynamic file path",
    language = Language::Kotlin,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                // File(variable), FileInputStream(variable)
                if let Some(ctor_name) = call_constructor_name(node, src) {
                    if ctor_name == "File" || ctor_name == "FileInputStream" {
                        if let Some(args) = call_arguments(node) {
                            if let Some(first) = first_argument(args) {
                                if !is_string_literal(first) {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        &format!(
                                            "{}() with dynamic path — sanitize input to prevent path traversal",
                                            ctor_name
                                        ),
                                        node,
                                        src,
                                    ));
                                }
                            }
                        }
                    }
                }

                // Paths.get(variable)
                if let Some(name) = call_method_name(node, src) {
                    if name == "get" {
                        if let Some(receiver) = call_receiver_text(node, src) {
                            if receiver == "Paths" || receiver == "Path" {
                                if let Some(args) = call_arguments(node) {
                                    if let Some(first) = first_argument(args) {
                                        if !is_string_literal(first) {
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

// ─── Rule 6: kt/no-weak-crypto ───────────────────────────────────────────

pub struct NoWeakCrypto;

impl_rule! {
    NoWeakCrypto,
    id = "kt/no-weak-crypto",
    severity = Severity::Medium,
    cwe = Some("CWE-327"),
    description = "Use of weak cryptographic algorithm",
    language = Language::Kotlin,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let weak_algo = kt_weak_algo_re();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(name) = call_method_name(node, src) {
                    if name == "getInstance" {
                        if let Some(receiver) = call_receiver_text(node, src) {
                            if receiver == "Cipher"
                                || receiver == "MessageDigest"
                                || receiver == "SecretKeyFactory"
                                || receiver == "KeyGenerator"
                            {
                                if let Some(args) = call_arguments(node) {
                                    if let Some(first) = first_argument(args) {
                                        let arg_text = &src[first.byte_range()];
                                        if weak_algo.is_match(arg_text) {
                                            findings.push(make_finding(
                                                _self.id(),
                                                _self.severity(),
                                                _self.cwe(),
                                                &format!(
                                                    "{}.getInstance({}) uses a weak algorithm — use AES-GCM, SHA-256, or stronger",
                                                    receiver, arg_text
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

// ─── Rule 7: kt/no-hardcoded-secret ──────────────────────────────────────

pub struct NoHardcodedSecret;

impl_rule! {
    NoHardcodedSecret,
    id = "kt/no-hardcoded-secret",
    severity = Severity::High,
    cwe = Some("CWE-798"),
    description = "Hardcoded secret or credential detected",
    language = Language::Kotlin,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let secret_pattern = hardcoded_secret_re();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // property_declaration: val password = "hardcoded"
            if node.kind() == "property_declaration" {
                // Find variable_declaration child for the name
                let mut var_name = None;
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "variable_declaration" {
                        let mut c2 = child.walk();
                        for gc in child.children(&mut c2) {
                            if gc.kind() == "simple_identifier" {
                                var_name = Some(&src[gc.byte_range()]);
                            }
                        }
                    }
                }

                if let Some(name) = var_name {
                    if secret_pattern.is_match(name) {
                        // Check if the value is a string literal
                        // The value is a direct child of property_declaration (after '=')
                        let mut c3 = node.walk();
                        for child in node.children(&mut c3) {
                            if child.kind() == "string_literal" {
                                let val = &src[child.byte_range()];
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

            // assignment: password = "hardcoded"
            if node.kind() == "assignment" {
                if let Some(left) = node.child(0) {
                    let left_text = &src[left.byte_range()];
                    if secret_pattern.is_match(left_text) {
                        // Find string_literal on the right side
                        let child_count = node.child_count();
                        if child_count >= 3 {
                            if let Some(right) = node.child(child_count - 1) {
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
            }
        });
        findings

    }
}

// ─── Rule 8: kt/no-xxe ───────────────────────────────────────────────────

pub struct NoXxe;

impl_rule! {
    NoXxe,
    id = "kt/no-xxe",
    severity = Severity::High,
    cwe = Some("CWE-611"),
    description = "XML parser created without disabling external entities (XXE)",
    language = Language::Kotlin,
    fn check(_self, source, _tree) {

        let mut findings = Vec::new();
        let factory_pattern = kt_xxe_factory_re();
        let secure_pattern = kt_xxe_secure_re();

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

// ─── Rule 9: kt/no-cors-star ─────────────────────────────────────────────

pub struct NoCorsStar;

impl_rule! {
    NoCorsStar,
    id = "kt/no-cors-star",
    severity = Severity::Medium,
    cwe = Some("CWE-942"),
    description = "Permissive CORS configuration allows any origin",
    language = Language::Kotlin,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        // allowedOrigins("*") / addAllowedOrigin("*")
        let wildcard_pattern = kt_cors_wildcard_re();
        for matched in wildcard_pattern.find_iter(source) {
            findings.push(make_finding_from_offsets(
                _self.id(),
                _self.severity(),
                _self.cwe(),
                "Wildcard CORS origin permits any domain — restrict to trusted origins",
                source,
                matched.start(),
                matched.end(),
            ));
        }

        // setHeader("Access-Control-Allow-Origin", "*")
        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(name) = call_method_name(node, src) {
                    if name == "setHeader" || name == "addHeader" || name == "header" {
                        if let Some(args) = call_arguments(node) {
                            if let Some(first) = first_argument(args) {
                                let first_text = &src[first.byte_range()];
                                if first_text.contains("Access-Control-Allow-Origin") {
                                    if let Some(second) = nth_argument(args, 1) {
                                        let second_text = &src[second.byte_range()];
                                        if second_text.contains('*') {
                                            findings.push(make_finding(
                                                _self.id(),
                                                _self.severity(),
                                                _self.cwe(),
                                                "Access-Control-Allow-Origin set to wildcard — restrict to trusted origins",
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

// ─── Rule 10: kt/no-eval ─────────────────────────────────────────────────

pub struct NoEval;

impl_rule! {
    NoEval,
    id = "kt/no-eval",
    severity = Severity::Critical,
    cwe = Some("CWE-94"),
    description = "ScriptEngine.eval can execute arbitrary code",
    language = Language::Kotlin,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(name) = call_method_name(node, src) {
                    if name == "eval" {
                        if let Some(args) = call_arguments(node) {
                            if let Some(first) = first_argument(args) {
                                if !is_string_literal(first) {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        "ScriptEngine.eval() called with dynamic argument — risk of arbitrary code execution",
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

// ═══════════════════════════════════════════════════════════════════════════
// Kotlin taint rules
// ═══════════════════════════════════════════════════════════════════════════
//
// The three `kt/taint-*-injection` rules below consume the shared taint
// engine in `crate::rules::kotlin_taint` rather than a bespoke harness.
// Each rule's `check()` looks up the rule's declarative `TaintSpec` from
// `kotlin_taint::kotlin_taint_rule_specs()`, hands it to
// `kotlin_taint::analyze_tree`, and maps returned `TaintFinding`s onto
// the project's `Finding` type — the same shape Go/JS/Python taint
// rules use. Per-rule message formatters and metadata live here; the
// engine and the shared sources/sinks live in `kotlin_taint.rs`.
//
// The scanner skips the rule's `check()` when the same rule id is
// registered as a `RegistryTaintSpec` via
// `builtin_taint_specs_for_language`, and runs the batched dispatcher
// `run_kt_taint_batched` instead. The `check()` path is kept working
// so unit tests that construct a Rule struct directly continue to
// function.

use crate::rules::common::get_source_line;
use crate::rules::kotlin_taint;

/// Per-rule metadata for Kotlin taint findings: how to format the
/// message and which fix hint to attach. Mirrors `GoTaintRuleMeta`.
struct KtTaintRuleMeta<'a> {
    rule_id: &'a str,
    severity: Severity,
    cwe: Option<&'a str>,
    fix_suggestion: Option<&'a str>,
    format_description: fn(&str, &str) -> String,
}

fn kt_taint_sql_injection_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — use parameterized queries to prevent SQL injection",
        src, sink
    )
}

fn kt_taint_command_injection_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — avoid passing untrusted input to OS commands",
        src, sink
    )
}

fn kt_taint_ssrf_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — validate and allowlist target hosts to prevent SSRF",
        src, sink
    )
}

fn kt_taint_meta(rule_id: &str) -> Option<KtTaintRuleMeta<'static>> {
    match rule_id {
        "kt/taint-sql-injection" => Some(KtTaintRuleMeta {
            rule_id: "kt/taint-sql-injection",
            severity: Severity::Critical,
            cwe: Some("CWE-89"),
            fix_suggestion: None,
            format_description: kt_taint_sql_injection_desc,
        }),
        "kt/taint-command-injection" => Some(KtTaintRuleMeta {
            rule_id: "kt/taint-command-injection",
            severity: Severity::Critical,
            cwe: Some("CWE-78"),
            fix_suggestion: None,
            format_description: kt_taint_command_injection_desc,
        }),
        "kt/taint-ssrf" => Some(KtTaintRuleMeta {
            rule_id: "kt/taint-ssrf",
            severity: Severity::High,
            cwe: Some("CWE-918"),
            fix_suggestion: None,
            format_description: kt_taint_ssrf_desc,
        }),
        _ => None,
    }
}

/// Map a single `TaintFinding` from the Kotlin engine onto a `Finding`,
/// using the rule's metadata. Preserves the field shape produced by the
/// pre-refactor bespoke harness (confidence = `default_confidence()`,
/// `taint_hops = None`, no fix suggestion, byte offsets blank).
fn map_kt_taint_finding(
    meta: &KtTaintRuleMeta<'_>,
    source: &str,
    finding: kotlin_taint::TaintFinding,
) -> Finding {
    Finding {
        rule_id: meta.rule_id.to_string(),
        severity: meta.severity,
        cwe: meta.cwe.map(|s| s.to_string()),
        description: (meta.format_description)(
            &finding.source_description,
            &finding.sink_description,
        ),
        file: String::new(),
        line: finding.sink_line,
        column: finding.sink_column,
        end_line: finding.sink_end_line,
        end_column: finding.sink_end_column,
        snippet: get_source_line(source, finding.sink_start_byte),
        source_line: if finding.source_line == 0 {
            None
        } else {
            Some(finding.source_line)
        },
        source_description: Some(finding.source_description),
        sink_line: Some(finding.sink_line),
        sink_description: Some(finding.sink_description),
        fix_suggestion: meta.fix_suggestion.map(|s| s.to_string()),
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
        tags: vec![],
        crypto_algorithm: None,
        cnsa2_deadline: None,
        dep_name: None,
    }
}

/// Run every enabled Kotlin taint rule over `tree` in a single dispatch
/// loop and return per-rule `Finding`s.
///
/// Mirrors the shape of `run_go_taint_batched` /
/// `run_py_taint_batched` / `run_js_taint_batched`. There is no
/// per-group sanitizer batching today because the three Kotlin taint
/// rules share the (empty) sanitizer set; we still iterate per rule so
/// each can attach its own message and severity.
pub fn run_kt_taint_batched(
    source: &str,
    tree: &tree_sitter::Tree,
    enabled_rule_ids: &std::collections::HashSet<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (rule_id, spec) in kotlin_taint::kotlin_taint_rule_specs() {
        if !enabled_rule_ids.contains(rule_id) {
            continue;
        }
        let Some(meta) = kt_taint_meta(rule_id) else {
            continue;
        };
        let raw = kotlin_taint::analyze_tree(tree.root_node(), source, &spec, None);
        for finding in raw {
            findings.push(map_kt_taint_finding(&meta, source, finding));
        }
    }
    findings
}

/// Run a single Kotlin taint rule over a tree. Used by the rule
/// structs' `check()` path for direct unit tests. The scanner uses
/// [`run_kt_taint_batched`] to avoid double-dispatch.
fn run_kt_taint_single(
    rule_id: &str,
    source: &str,
    tree: &tree_sitter::Tree,
    spec: &kotlin_taint::TaintSpec,
) -> Vec<Finding> {
    let Some(meta) = kt_taint_meta(rule_id) else {
        return Vec::new();
    };
    let raw = kotlin_taint::analyze_tree(tree.root_node(), source, spec, None);
    raw.into_iter()
        .map(|t| map_kt_taint_finding(&meta, source, t))
        .collect()
}

// ─── Rule 11: kt/taint-sql-injection ────────────────────────────────────

pub struct TaintSqlInjection;

impl_rule! {
    TaintSqlInjection,
    id = "kt/taint-sql-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-89"),
    description = "Untrusted input from Ktor/Spring handler reaches SQL query sink",
    language = Language::Kotlin,
    fn check(_self, source, tree) {
        let spec = kotlin_taint::kotlin_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_kt_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Rule 12: kt/taint-command-injection ────────────────────────────────

pub struct TaintCommandInjection;

impl_rule! {
    TaintCommandInjection,
    id = "kt/taint-command-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-78"),
    description = "Untrusted input from Ktor/Spring handler reaches command execution sink",
    language = Language::Kotlin,
    fn check(_self, source, tree) {
        let spec = kotlin_taint::kotlin_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_kt_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Rule 13: kt/taint-ssrf ────────────────────────────────────────────

pub struct TaintSsrf;

impl_rule! {
    TaintSsrf,
    id = "kt/taint-ssrf",
    severity = Severity::High,
    cwe = Some("CWE-918"),
    description = "Untrusted input from Ktor/Spring handler reaches HTTP/URL sink",
    language = Language::Kotlin,
    fn check(_self, source, tree) {
        let spec = kotlin_taint::kotlin_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_kt_taint_single(_self.id(), source, tree, &spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::rules::Rule;

    fn check_rule(rule: &dyn Rule, source: &str) -> Vec<Finding> {
        let tree = parse_file(source, Language::Kotlin).expect("parse failed");
        rule.check(source, &tree)
    }

    // ─── SQL Injection ────────────────────────────────────────────────────

    #[test]
    fn sql_injection_string_concat() {
        let src = r#"
fun getUser(id: String) {
    val query = "SELECT * FROM users WHERE id = " + id
    db.executeQuery(query)
    db.executeQuery("SELECT * FROM users WHERE id = " + id)
}
"#;
        let findings = check_rule(&NoSqlInjection, src);
        assert!(
            !findings.is_empty(),
            "should detect SQL injection via string concat"
        );
    }

    #[test]
    fn sql_injection_clean_parameterized() {
        let src = r#"
fun getUser(id: String) {
    val stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?")
    stmt.setString(1, id)
}
"#;
        let findings = check_rule(&NoSqlInjection, src);
        assert!(findings.is_empty(), "parameterized query should be clean");
    }

    // ─── Command Injection ────────────────────────────────────────────────

    #[test]
    fn command_injection_runtime_exec() {
        let src = r#"
fun run(cmd: String) {
    Runtime.getRuntime().exec(cmd)
}
"#;
        let findings = check_rule(&NoCommandInjection, src);
        assert!(
            !findings.is_empty(),
            "should detect Runtime.exec with variable"
        );
    }

    #[test]
    fn command_injection_process_builder() {
        let src = r#"
fun run(cmd: String) {
    ProcessBuilder(cmd).start()
}
"#;
        let findings = check_rule(&NoCommandInjection, src);
        assert!(
            !findings.is_empty(),
            "should detect ProcessBuilder with variable"
        );
    }

    #[test]
    fn command_injection_clean_literal() {
        let src = r#"
fun run() {
    Runtime.getRuntime().exec("ls -la")
}
"#;
        let findings = check_rule(&NoCommandInjection, src);
        assert!(findings.is_empty(), "literal command should be clean");
    }

    // ─── Unsafe Deserialization ───────────────────────────────────────────

    #[test]
    fn unsafe_deserialization_read_object() {
        let src = r#"
fun deserialize(stream: InputStream) {
    val ois = ObjectInputStream(stream)
    val obj = ois.readObject()
}
"#;
        let findings = check_rule(&NoUnsafeDeserialization, src);
        assert!(!findings.is_empty(), "should detect readObject");
    }

    #[test]
    fn unsafe_deserialization_clean() {
        let src = r#"
fun parse(json: String) {
    val obj = Gson().fromJson(json, MyClass::class.java)
}
"#;
        let findings = check_rule(&NoUnsafeDeserialization, src);
        assert!(findings.is_empty(), "Gson should be clean");
    }

    // ─── SSRF ─────────────────────────────────────────────────────────────

    #[test]
    fn ssrf_url_variable() {
        let src = r#"
fun fetch(userUrl: String) {
    val url = URL(userUrl)
    val conn = url.openConnection()
}
"#;
        let findings = check_rule(&NoSsrf, src);
        assert!(!findings.is_empty(), "should detect URL with variable");
    }

    #[test]
    fn ssrf_clean_literal() {
        let src = r#"
fun fetch() {
    val url = URL("https://example.com/api")
}
"#;
        let findings = check_rule(&NoSsrf, src);
        assert!(findings.is_empty(), "literal URL should be clean");
    }

    // ─── Path Traversal ──────────────────────────────────────────────────

    #[test]
    fn path_traversal_file_variable() {
        let src = r#"
fun read(userPath: String) {
    val file = File(userPath)
    file.readText()
}
"#;
        let findings = check_rule(&NoPathTraversal, src);
        assert!(!findings.is_empty(), "should detect File with variable");
    }

    #[test]
    fn path_traversal_clean_literal() {
        let src = r#"
fun read() {
    val file = File("/etc/config.txt")
}
"#;
        let findings = check_rule(&NoPathTraversal, src);
        assert!(findings.is_empty(), "literal path should be clean");
    }

    // ─── Weak Crypto ─────────────────────────────────────────────────────

    #[test]
    fn weak_crypto_md5() {
        let src = r#"
fun hash(data: String) {
    val digest = MessageDigest.getInstance("MD5")
}
"#;
        let findings = check_rule(&NoWeakCrypto, src);
        assert!(!findings.is_empty(), "should detect MD5");
    }

    #[test]
    fn weak_crypto_des() {
        let src = r#"
fun encrypt(data: String) {
    val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
}
"#;
        let findings = check_rule(&NoWeakCrypto, src);
        assert!(!findings.is_empty(), "should detect DES/ECB");
    }

    #[test]
    fn weak_crypto_clean_aes() {
        let src = r#"
fun encrypt(data: String) {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
}
"#;
        let findings = check_rule(&NoWeakCrypto, src);
        assert!(findings.is_empty(), "AES-GCM should be clean");
    }

    // ─── Hardcoded Secret ─────────────────────────────────────────────────

    #[test]
    fn hardcoded_secret_val() {
        let src = r#"
fun connect() {
    val password = "super_secret_123"
    val apiKey = "sk-1234567890abcdef"
}
"#;
        let findings = check_rule(&NoHardcodedSecret, src);
        assert!(
            findings.len() >= 2,
            "should detect hardcoded password and apiKey"
        );
    }

    #[test]
    fn hardcoded_secret_clean() {
        let src = r#"
fun connect() {
    val password = System.getenv("DB_PASSWORD")
    val username = "admin"
}
"#;
        let findings = check_rule(&NoHardcodedSecret, src);
        assert!(
            findings.is_empty(),
            "env var and non-secret should be clean"
        );
    }

    // ─── XXE ──────────────────────────────────────────────────────────────

    #[test]
    fn xxe_insecure() {
        let src = r#"
fun parse(xml: String) {
    val factory = DocumentBuilderFactory.newInstance()
    val builder = factory.newDocumentBuilder()
    val doc = builder.parse(InputSource(StringReader(xml)))
}
"#;
        let findings = check_rule(&NoXxe, src);
        assert!(!findings.is_empty(), "should detect XXE without setFeature");
    }

    #[test]
    fn xxe_clean() {
        let src = r#"
fun parse(xml: String) {
    val factory = DocumentBuilderFactory.newInstance()
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    val builder = factory.newDocumentBuilder()
}
"#;
        let findings = check_rule(&NoXxe, src);
        assert!(findings.is_empty(), "setFeature should make it clean");
    }

    // ─── CORS Star ────────────────────────────────────────────────────────

    #[test]
    fn cors_star_header() {
        let src = r#"
fun handler(response: HttpServletResponse) {
    response.setHeader("Access-Control-Allow-Origin", "*")
}
"#;
        let findings = check_rule(&NoCorsStar, src);
        assert!(!findings.is_empty(), "should detect wildcard CORS header");
    }

    #[test]
    fn cors_star_allowed_origins() {
        let src = r#"
fun cors(): CorsConfiguration {
    val config = CorsConfiguration()
    config.addAllowedOrigin("*")
    return config
}
"#;
        let findings = check_rule(&NoCorsStar, src);
        assert!(
            !findings.is_empty(),
            "should detect addAllowedOrigin(\"*\")"
        );
    }

    #[test]
    fn cors_clean() {
        let src = r#"
fun handler(response: HttpServletResponse) {
    response.setHeader("Access-Control-Allow-Origin", "https://example.com")
}
"#;
        let findings = check_rule(&NoCorsStar, src);
        assert!(findings.is_empty(), "specific origin should be clean");
    }

    // ─── Eval ─────────────────────────────────────────────────────────────

    #[test]
    fn eval_script_engine() {
        let src = r#"
fun execute(userCode: String) {
    val engine = ScriptEngineManager().getEngineByName("js")
    engine.eval(userCode)
}
"#;
        let findings = check_rule(&NoEval, src);
        assert!(
            !findings.is_empty(),
            "should detect ScriptEngine.eval with variable"
        );
    }

    #[test]
    fn eval_clean_literal() {
        let src = r#"
fun execute() {
    val engine = ScriptEngineManager().getEngineByName("js")
    engine.eval("1 + 1")
}
"#;
        let findings = check_rule(&NoEval, src);
        assert!(findings.is_empty(), "eval with literal should be clean");
    }

    // ─── Taint: SQL Injection ────────────────────────────────────────────

    #[test]
    fn taint_sql_injection_ktor_receive() {
        let src = r#"
fun Application.module() {
    routing {
        post("/users") {
            val body = call.receiveText()
            val query = "SELECT * FROM users WHERE name = '" + body + "'"
            db.executeQuery(query)
        }
    }
}
"#;
        let findings = check_rule(&TaintSqlInjection, src);
        assert!(
            !findings.is_empty(),
            "should detect tainted SQL from call.receiveText(): got {:?}",
            findings
        );
    }

    #[test]
    fn taint_sql_injection_spring_param() {
        let src = r#"
@GetMapping("/search")
fun search(@RequestParam query: String) {
    val sql = "SELECT * FROM products WHERE name = '" + query + "'"
    stmt.executeQuery(sql)
}
"#;
        let findings = check_rule(&TaintSqlInjection, src);
        assert!(
            !findings.is_empty(),
            "should detect tainted SQL from @RequestParam"
        );
    }

    #[test]
    fn taint_sql_injection_string_template() {
        let src = r#"
fun Application.module() {
    routing {
        get("/user") {
            val id = call.request.queryParameters["id"]
            val sql = "SELECT * FROM users WHERE id = ${id}"
            db.executeQuery(sql)
        }
    }
}
"#;
        let findings = check_rule(&TaintSqlInjection, src);
        assert!(
            !findings.is_empty(),
            "should detect tainted SQL via string template: got {:?}",
            findings
        );
    }

    #[test]
    fn taint_sql_injection_clean_parameterized() {
        let src = r#"
fun Application.module() {
    routing {
        get("/user") {
            val id = call.receiveText()
            val stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?")
            stmt.setString(1, id)
        }
    }
}
"#;
        let findings = check_rule(&TaintSqlInjection, src);
        assert!(
            findings.is_empty(),
            "parameterized query should not trigger taint SQL injection"
        );
    }

    // ─── Taint: Command Injection ────────────────────────────────────────

    #[test]
    fn taint_command_injection_ktor() {
        let src = r#"
fun Application.module() {
    routing {
        post("/run") {
            val cmd = call.receiveText()
            Runtime.getRuntime().exec(cmd)
        }
    }
}
"#;
        let findings = check_rule(&TaintCommandInjection, src);
        assert!(
            !findings.is_empty(),
            "should detect tainted command injection from call.receiveText()"
        );
    }

    #[test]
    fn taint_command_injection_process_builder() {
        let src = r#"
@PostMapping("/exec")
fun execute(@RequestBody input: String) {
    val args = input.split(" ")
    ProcessBuilder(args).start()
}
"#;
        let findings = check_rule(&TaintCommandInjection, src);
        assert!(
            !findings.is_empty(),
            "should detect tainted ProcessBuilder from @RequestBody"
        );
    }

    #[test]
    fn taint_command_injection_clean() {
        let src = r#"
fun Application.module() {
    routing {
        get("/status") {
            val text = call.receiveText()
            Runtime.getRuntime().exec("ls -la")
        }
    }
}
"#;
        let findings = check_rule(&TaintCommandInjection, src);
        assert!(
            findings.is_empty(),
            "literal command should not trigger taint even with source present"
        );
    }

    // ─── Taint: SSRF ─────────────────────────────────────────────────────

    #[test]
    fn taint_ssrf_ktor_url() {
        let src = r#"
fun Application.module() {
    routing {
        get("/proxy") {
            val target = call.request.queryParameters["url"]
            val url = URL(target)
            val data = url.readText()
            call.respondText(data)
        }
    }
}
"#;
        let findings = check_rule(&TaintSsrf, src);
        assert!(
            !findings.is_empty(),
            "should detect SSRF from tainted URL constructor"
        );
    }

    #[test]
    fn taint_ssrf_spring_http_client() {
        let src = r#"
@GetMapping("/fetch")
fun fetch(@RequestParam url: String) {
    val response = restTemplate.getForObject(url, String::class.java)
}
"#;
        let findings = check_rule(&TaintSsrf, src);
        assert!(
            !findings.is_empty(),
            "should detect SSRF from @RequestParam to restTemplate"
        );
    }

    #[test]
    fn taint_ssrf_clean_literal() {
        let src = r#"
fun Application.module() {
    routing {
        get("/data") {
            val input = call.receiveText()
            val url = URL("https://api.example.com/data")
            val data = url.readText()
        }
    }
}
"#;
        let findings = check_rule(&TaintSsrf, src);
        assert!(
            findings.is_empty(),
            "literal URL should not trigger taint SSRF"
        );
    }

    #[test]
    fn taint_ssrf_transitive_flow() {
        let src = r#"
fun Application.module() {
    routing {
        post("/fetch") {
            val body = call.receiveText()
            val target = body
            val endpoint = "https://internal/" + target
            val url = URL(endpoint)
        }
    }
}
"#;
        let findings = check_rule(&TaintSsrf, src);
        assert!(
            !findings.is_empty(),
            "should detect SSRF via transitive taint flow"
        );
    }
}
