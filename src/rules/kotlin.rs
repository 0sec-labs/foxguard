use crate::rules::common::{make_finding, make_finding_from_offsets, walk_tree};
use crate::rules::Rule;
use crate::{Finding, Language, Severity};
use regex::Regex;

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

impl Rule for NoSqlInjection {
    fn id(&self) -> &str {
        "kt/no-sql-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-89")
    }
    fn description(&self) -> &str {
        "Potential SQL injection via string concatenation in query method"
    }
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let sql_methods =
            Regex::new(r"^(executeQuery|execute|createQuery|createNativeQuery|rawQuery|execSQL)$")
                .unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(name) = call_method_name(node, src) {
                    if sql_methods.is_match(name) {
                        if let Some(args) = call_arguments(node) {
                            if has_string_concat(args, src) {
                                findings.push(make_finding(
                                    self.id(),
                                    self.severity(),
                                    self.cwe(),
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

impl Rule for NoCommandInjection {
    fn id(&self) -> &str {
        "kt/no-command-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-78")
    }
    fn description(&self) -> &str {
        "Potential command injection via Runtime.exec or ProcessBuilder with dynamic input"
    }
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
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
                                                self.id(),
                                                self.severity(),
                                                self.cwe(),
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
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
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

impl Rule for NoUnsafeDeserialization {
    fn id(&self) -> &str {
        "kt/no-unsafe-deserialization"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-502")
    }
    fn description(&self) -> &str {
        "Unsafe deserialization can lead to remote code execution"
    }
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
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
                                    self.id(),
                                    self.severity(),
                                    self.cwe(),
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
                                    self.id(),
                                    self.severity(),
                                    self.cwe(),
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

impl Rule for NoSsrf {
    fn id(&self) -> &str {
        "kt/no-ssrf"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-918")
    }
    fn description(&self) -> &str {
        "Potential SSRF via URL or HTTP client with dynamic input"
    }
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
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
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
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
                                                self.id(),
                                                self.severity(),
                                                self.cwe(),
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

impl Rule for NoPathTraversal {
    fn id(&self) -> &str {
        "kt/no-path-traversal"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-22")
    }
    fn description(&self) -> &str {
        "Potential path traversal via dynamic file path"
    }
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
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
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
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
                                                self.id(),
                                                self.severity(),
                                                self.cwe(),
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

impl Rule for NoWeakCrypto {
    fn id(&self) -> &str {
        "kt/no-weak-crypto"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-327")
    }
    fn description(&self) -> &str {
        "Use of weak cryptographic algorithm"
    }
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let weak_algo =
            Regex::new(r#"(?i)"(DES|DESede|RC2|RC4|Blowfish|MD5|SHA-?1|.*ECB.*)"#).unwrap();

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
                                                self.id(),
                                                self.severity(),
                                                self.cwe(),
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

impl Rule for NoHardcodedSecret {
    fn id(&self) -> &str {
        "kt/no-hardcoded-secret"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-798")
    }
    fn description(&self) -> &str {
        "Hardcoded secret or credential detected"
    }
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let secret_pattern =
            Regex::new(r"(?i)(password|secret|api_?key|apiKey|token|auth|credential|private_?key)")
                .unwrap();

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
                                if inner.len() >= 4 {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
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
                                    if inner.len() >= 4 {
                                        findings.push(make_finding(
                                            self.id(),
                                            self.severity(),
                                            self.cwe(),
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

impl Rule for NoXxe {
    fn id(&self) -> &str {
        "kt/no-xxe"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-611")
    }
    fn description(&self) -> &str {
        "XML parser created without disabling external entities (XXE)"
    }
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn check(&self, source: &str, _tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let factory_pattern = Regex::new(
            r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\(\)",
        )
        .unwrap();
        let secure_pattern =
            Regex::new(r"setFeature\s*\(|setProperty\s*\(|setAttribute\s*\(").unwrap();

        if factory_pattern.is_match(source) && !secure_pattern.is_match(source) {
            for matched in factory_pattern.find_iter(source) {
                findings.push(make_finding_from_offsets(
                    self.id(),
                    self.severity(),
                    self.cwe(),
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

impl Rule for NoCorsStar {
    fn id(&self) -> &str {
        "kt/no-cors-star"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-942")
    }
    fn description(&self) -> &str {
        "Permissive CORS configuration allows any origin"
    }
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        // allowedOrigins("*") / addAllowedOrigin("*")
        let wildcard_pattern =
            Regex::new(r#"(allowedOrigins|addAllowedOrigin)\s*\(\s*"\*"\s*\)"#).unwrap();
        for matched in wildcard_pattern.find_iter(source) {
            findings.push(make_finding_from_offsets(
                self.id(),
                self.severity(),
                self.cwe(),
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
                                                self.id(),
                                                self.severity(),
                                                self.cwe(),
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

impl Rule for NoEval {
    fn id(&self) -> &str {
        "kt/no-eval"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-94")
    }
    fn description(&self) -> &str {
        "ScriptEngine.eval can execute arbitrary code"
    }
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(name) = call_method_name(node, src) {
                    if name == "eval" {
                        if let Some(args) = call_arguments(node) {
                            if let Some(first) = first_argument(args) {
                                if !is_string_literal(first) {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
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
// Lightweight intra-procedural taint analysis for Kotlin (Ktor + Spring Boot)
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashSet;

/// Describes a taint source matched inside a function body.
struct TaintSource {
    /// Variable name the source is assigned to (if any).
    var_name: Option<String>,
    /// Human-readable description for findings.
    description: String,
    /// 1-indexed line where the source was found.
    line: usize,
}

/// Describes a taint sink match.
struct TaintSink {
    /// The sink call node (for location).
    start_byte: usize,
    end_byte: usize,
    line: usize,
    /// Human-readable description.
    description: String,
}

/// Collect Ktor/Spring Boot taint source variables inside a function body.
///
/// Recognizes:
///   - `call.receiveText()`
///   - `call.receive<T>()`
///   - `request.queryParameters[...]`
///   - `request.header(...)`
///   - `call.request.queryParameters[...]`
///   - `call.request.header(...)`
///   - Function parameters annotated with `@RequestParam`, `@RequestBody`,
///     `@PathVariable`, `@RequestHeader`
fn collect_sources(node: tree_sitter::Node, src: &str) -> Vec<TaintSource> {
    let mut sources = Vec::new();

    // 1) Walk for Ktor call.receive / request.queryParameters / request.header
    walk_tree(node, src, &mut |n, s| {
        // property_declaration or variable assignment: val x = <source>
        if n.kind() == "property_declaration" {
            let var = extract_property_var_name(n, s);
            let initializer = extract_property_initializer(n);
            if let (Some(var_name), Some(init)) = (var, initializer) {
                if let Some(desc) = classify_source_expr(init, s) {
                    sources.push(TaintSource {
                        var_name: Some(var_name),
                        description: desc,
                        line: n.start_position().row + 1,
                    });
                }
            }
        }
        // assignment: x = <source>
        if n.kind() == "assignment" {
            if let (Some(left), Some(right)) =
                (n.child(0), n.child(n.child_count().saturating_sub(1)))
            {
                let left_text = &s[left.byte_range()];
                if left.kind() == "simple_identifier" {
                    if let Some(desc) = classify_source_expr(right, s) {
                        sources.push(TaintSource {
                            var_name: Some(left_text.to_string()),
                            description: desc,
                            line: n.start_position().row + 1,
                        });
                    }
                }
            }
        }
    });

    // 2) Scan for Spring annotation-based sources on function parameters.
    // Look for function_declaration children that have parameter nodes with annotations.
    walk_tree(node, src, &mut |n, s| {
        if n.kind() == "function_declaration" {
            collect_spring_param_sources(n, s, &mut sources);
        }
    });

    sources
}

/// Classify whether a node is a taint source expression.
/// Returns a description string if it is, None otherwise.
fn classify_source_expr(node: tree_sitter::Node, src: &str) -> Option<String> {
    let text = &src[node.byte_range()];

    // call.receiveText(), call.receive<...>()
    if node.kind() == "call_expression" {
        if let Some(method) = call_method_name(node, src) {
            if method == "receiveText" || method == "receive" {
                if let Some(recv) = call_receiver_text(node, src) {
                    if recv.contains("call") {
                        return Some(format!("{}.{}()", recv, method));
                    }
                }
            }
            // request.header("...")
            if method == "header" || method == "queryParameter" {
                if let Some(recv) = call_receiver_text(node, src) {
                    if recv.contains("request") || recv.contains("call") {
                        return Some(format!("{}.{}()", recv, method));
                    }
                }
            }
        }
    }

    // request.queryParameters["x"] — indexing_expression
    if (node.kind() == "indexing_expression"
        || text.contains("queryParameters[")
        || text.contains("parameters["))
        && (text.contains("request") || text.contains("call"))
        && (text.contains("queryParameters")
            || text.contains("parameters[")
            || text.contains("header"))
    {
        return Some(text.to_string());
    }

    None
}

/// Extract the variable name from a `property_declaration`.
fn extract_property_var_name(node: tree_sitter::Node, src: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "variable_declaration" {
            let mut c2 = child.walk();
            for gc in child.children(&mut c2) {
                if gc.kind() == "simple_identifier" {
                    return Some(src[gc.byte_range()].to_string());
                }
            }
        }
    }
    None
}

/// Extract the initializer expression from a `property_declaration`.
fn extract_property_initializer(node: tree_sitter::Node) -> Option<tree_sitter::Node> {
    // The initializer comes after the `=` token.
    let count = node.child_count();
    if count < 3 {
        return None;
    }
    // Walk backwards: the initializer is the last non-trivial child.
    // Look for a child after `=`.
    let mut found_eq = false;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if found_eq && child.kind() != "=" {
            return Some(child);
        }
        if child.kind() == "=" {
            found_eq = true;
        }
    }
    None
}

/// Collect Spring annotation-based parameter sources from a function declaration.
///
/// In Kotlin's tree-sitter grammar, `function_value_parameters` children are:
///   `parameter_modifiers` (containing `@RequestParam` etc.), then `parameter`
///   (containing the name and type). They are siblings, not nested.
fn collect_spring_param_sources(
    func_node: tree_sitter::Node,
    src: &str,
    sources: &mut Vec<TaintSource>,
) {
    let spring_annotations = [
        "RequestParam",
        "RequestBody",
        "PathVariable",
        "RequestHeader",
    ];

    let mut cursor = func_node.walk();
    for child in func_node.children(&mut cursor) {
        if child.kind() == "function_value_parameters" {
            // Walk children: parameter_modifiers precedes its parameter.
            let mut c2 = child.walk();
            let children: Vec<_> = child.children(&mut c2).collect();
            let mut pending_annotation: Option<&str> = None;

            for ch in &children {
                if ch.kind() == "parameter_modifiers" {
                    let mod_text = &src[ch.byte_range()];
                    for ann in &spring_annotations {
                        if mod_text.contains(ann) {
                            pending_annotation = Some(ann);
                            break;
                        }
                    }
                } else if ch.kind() == "parameter" {
                    if let Some(ann) = pending_annotation.take() {
                        // Extract parameter name: first simple_identifier child.
                        let mut c3 = ch.walk();
                        for pc in ch.children(&mut c3) {
                            if pc.kind() == "simple_identifier" {
                                let name = &src[pc.byte_range()];
                                sources.push(TaintSource {
                                    var_name: Some(name.to_string()),
                                    description: format!("@{} parameter '{}'", ann, name),
                                    line: ch.start_position().row + 1,
                                });
                                break;
                            }
                        }
                    }
                    pending_annotation = None;
                } else {
                    // Reset on any other node (e.g., comma, parens)
                    if ch.kind() != "," && ch.kind() != "(" && ch.kind() != ")" {
                        pending_annotation = None;
                    }
                }
            }
        }
    }
}

/// Build the set of tainted variable names by starting from sources and
/// propagating through simple assignments and string concatenation.
fn build_tainted_set(
    node: tree_sitter::Node,
    src: &str,
    sources: &[TaintSource],
) -> HashSet<String> {
    let mut tainted: HashSet<String> = HashSet::new();

    // Seed with source variable names.
    for s in sources {
        if let Some(ref name) = s.var_name {
            tainted.insert(name.clone());
        }
    }

    if tainted.is_empty() {
        return tainted;
    }

    // Propagate through assignments: val y = x, val z = x + "...", val w = "..." + x
    // Do two passes to handle transitive assignments.
    for _ in 0..2 {
        walk_tree(node, src, &mut |n, s| {
            if n.kind() == "property_declaration" {
                let var = extract_property_var_name(n, s);
                let init = extract_property_initializer(n);
                if let (Some(var_name), Some(init_node)) = (var, init) {
                    if !tainted.contains(&var_name) && expr_uses_tainted(init_node, s, &tainted) {
                        tainted.insert(var_name);
                    }
                }
            }
            if n.kind() == "assignment" {
                if let (Some(left), Some(right)) =
                    (n.child(0), n.child(n.child_count().saturating_sub(1)))
                {
                    if left.kind() == "simple_identifier" {
                        let left_text = s[left.byte_range()].to_string();
                        if !tainted.contains(&left_text) && expr_uses_tainted(right, s, &tainted) {
                            tainted.insert(left_text);
                        }
                    }
                }
            }
        });
    }

    tainted
}

/// Check if an expression node references any tainted variable.
fn expr_uses_tainted(node: tree_sitter::Node, src: &str, tainted: &HashSet<String>) -> bool {
    if node.kind() == "simple_identifier" {
        let name = &src[node.byte_range()];
        return tainted.contains(name);
    }
    // String template: "...${tainted}..."
    if node.kind() == "string_literal" {
        let text = &src[node.byte_range()];
        for t in tainted {
            if text.contains(&format!("${{{}}}", t)) || text.contains(&format!("${}", t)) {
                return true;
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if expr_uses_tainted(child, src, tainted) {
            return true;
        }
    }
    false
}

/// A specification for a Kotlin taint rule.
struct KtTaintSpec {
    /// Functions to find sinks. Returns (description, start_byte, end_byte, line) tuples.
    sink_finder: fn(tree_sitter::Node, &str, &HashSet<String>) -> Vec<TaintSink>,
}

/// Run lightweight taint analysis for a Kotlin taint rule.
fn run_kt_taint(
    rule_id: &str,
    severity: Severity,
    cwe: Option<&str>,
    source: &str,
    tree: &tree_sitter::Tree,
    spec: &KtTaintSpec,
    message_fn: fn(&str, &str) -> String,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let root = tree.root_node();

    // Analyze each function body separately.
    walk_tree(root, source, &mut |node, _src| {
        if node.kind() == "function_declaration" || node.kind() == "lambda_literal" {
            // Find the function body.
            let body = find_function_body(node);
            let scope = body.unwrap_or(node);

            // Collect sources from both the function node (for Spring
            // annotations on parameters) and the body (for Ktor call.*).
            let mut sources = collect_sources(scope, source);
            // For function_declaration, also check annotations on params.
            if node.kind() == "function_declaration" {
                collect_spring_param_sources(node, source, &mut sources);
            }
            if sources.is_empty() {
                return;
            }

            let tainted = build_tainted_set(scope, source, &sources);
            if tainted.is_empty() {
                return;
            }

            let sinks = (spec.sink_finder)(scope, source, &tainted);
            for sink in sinks {
                // Find the best matching source description.
                let source_desc = sources
                    .first()
                    .map(|s| s.description.as_str())
                    .unwrap_or("user input");
                let source_line = sources.first().map(|s| s.line);

                let msg = message_fn(source_desc, &sink.description);

                let start_byte = sink.start_byte.min(source.len());
                let end_byte = sink.end_byte.min(source.len());
                let line = source[..start_byte].bytes().filter(|b| *b == b'\n').count() + 1;
                let line_start = source[..start_byte].rfind('\n').map_or(0, |idx| idx + 1);
                let column = source[line_start..start_byte].chars().count() + 1;
                let end_line = source[..end_byte].bytes().filter(|b| *b == b'\n').count() + 1;
                let end_line_start = source[..end_byte].rfind('\n').map_or(0, |idx| idx + 1);
                let end_column = source[end_line_start..end_byte].chars().count() + 1;

                findings.push(Finding {
                    rule_id: rule_id.to_string(),
                    severity,
                    cwe: cwe.map(|s| s.to_string()),
                    description: msg,
                    file: String::new(),
                    line,
                    column,
                    end_line,
                    end_column,
                    snippet: crate::rules::common::get_source_line(source, start_byte),
                    source_line,
                    source_description: Some(source_desc.to_string()),
                    sink_line: Some(sink.line),
                    sink_description: Some(sink.description.clone()),
                    fix_suggestion: None,
                });
            }
        }
    });

    findings
}

/// Find the body node of a function declaration.
#[allow(clippy::manual_find)]
fn find_function_body(func_node: tree_sitter::Node) -> Option<tree_sitter::Node> {
    let mut cursor = func_node.walk();
    for child in func_node.children(&mut cursor) {
        if child.kind() == "function_body" {
            return Some(child);
        }
    }
    None
}

// ─── Sink finders ────────────────────────────────────────────────────────

/// SQL injection sinks: executeQuery, execute, createQuery, prepareStatement, rawQuery, execSQL
/// with tainted arguments (via concat, interpolation, or direct variable).
fn find_sql_sinks(node: tree_sitter::Node, src: &str, tainted: &HashSet<String>) -> Vec<TaintSink> {
    let mut sinks = Vec::new();
    let sql_methods = [
        "executeQuery",
        "execute",
        "createQuery",
        "createNativeQuery",
        "rawQuery",
        "execSQL",
        "prepareStatement",
    ];

    walk_tree(node, src, &mut |n, s| {
        if n.kind() == "call_expression" {
            if let Some(name) = call_method_name(n, s) {
                if sql_methods.contains(&name) {
                    if let Some(args) = call_arguments(n) {
                        if expr_uses_tainted(args, s, tainted) {
                            sinks.push(TaintSink {
                                start_byte: n.start_byte(),
                                end_byte: n.end_byte(),
                                line: n.start_position().row + 1,
                                description: format!("{}() with tainted argument", name),
                            });
                        }
                    }
                }
            }
        }
    });
    sinks
}

/// Command injection sinks: Runtime.exec, ProcessBuilder with tainted args.
fn find_command_sinks(
    node: tree_sitter::Node,
    src: &str,
    tainted: &HashSet<String>,
) -> Vec<TaintSink> {
    let mut sinks = Vec::new();

    walk_tree(node, src, &mut |n, s| {
        if n.kind() == "call_expression" {
            // Runtime.getRuntime().exec(tainted)
            if let Some(name) = call_method_name(n, s) {
                if name == "exec" {
                    if let Some(receiver) = call_receiver_text(n, s) {
                        if receiver.contains("getRuntime") || receiver.contains("Runtime") {
                            if let Some(args) = call_arguments(n) {
                                if expr_uses_tainted(args, s, tainted) {
                                    sinks.push(TaintSink {
                                        start_byte: n.start_byte(),
                                        end_byte: n.end_byte(),
                                        line: n.start_position().row + 1,
                                        description: "Runtime.exec() with tainted argument"
                                            .to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // ProcessBuilder(tainted)
            if let Some(ctor) = call_constructor_name(n, s) {
                if ctor == "ProcessBuilder" {
                    if let Some(args) = call_arguments(n) {
                        if expr_uses_tainted(args, s, tainted) {
                            sinks.push(TaintSink {
                                start_byte: n.start_byte(),
                                end_byte: n.end_byte(),
                                line: n.start_position().row + 1,
                                description: "ProcessBuilder() with tainted argument".to_string(),
                            });
                        }
                    }
                }
            }
        }
    });
    sinks
}

/// SSRF sinks: URL(), HttpClient.get(), OkHttpClient calls, Fuel.get() with tainted URLs.
fn find_ssrf_sinks(
    node: tree_sitter::Node,
    src: &str,
    tainted: &HashSet<String>,
) -> Vec<TaintSink> {
    let mut sinks = Vec::new();

    walk_tree(node, src, &mut |n, s| {
        if n.kind() == "call_expression" {
            // URL(tainted), URI(tainted)
            if let Some(ctor) = call_constructor_name(n, s) {
                if ctor == "URL" || ctor == "URI" {
                    if let Some(args) = call_arguments(n) {
                        if expr_uses_tainted(args, s, tainted) {
                            sinks.push(TaintSink {
                                start_byte: n.start_byte(),
                                end_byte: n.end_byte(),
                                line: n.start_position().row + 1,
                                description: format!("{}() with tainted argument", ctor),
                            });
                        }
                    }
                }
            }

            // HttpClient/OkHttpClient/Fuel method calls: get, post, request, newCall, url
            if let Some(name) = call_method_name(n, s) {
                let http_methods = ["get", "post", "put", "delete", "request", "newCall", "url"];
                if http_methods.contains(&name) {
                    if let Some(receiver) = call_receiver_text(n, s) {
                        if receiver.contains("client")
                            || receiver.contains("Client")
                            || receiver.contains("http")
                            || receiver.contains("Http")
                            || receiver.contains("Fuel")
                            || receiver.contains("restTemplate")
                            || receiver.contains("RestTemplate")
                        {
                            if let Some(args) = call_arguments(n) {
                                if expr_uses_tainted(args, s, tainted) {
                                    sinks.push(TaintSink {
                                        start_byte: n.start_byte(),
                                        end_byte: n.end_byte(),
                                        line: n.start_position().row + 1,
                                        description: format!(
                                            "{}.{}() with tainted argument",
                                            receiver, name
                                        ),
                                    });
                                }
                            }
                        }
                    }
                }

                // RestTemplate getForObject/getForEntity/postForObject/exchange
                let rest_methods = [
                    "getForObject",
                    "getForEntity",
                    "postForObject",
                    "postForEntity",
                    "exchange",
                ];
                if rest_methods.contains(&name) {
                    if let Some(args) = call_arguments(n) {
                        if expr_uses_tainted(args, s, tainted) {
                            sinks.push(TaintSink {
                                start_byte: n.start_byte(),
                                end_byte: n.end_byte(),
                                line: n.start_position().row + 1,
                                description: format!("{}() with tainted URL", name),
                            });
                        }
                    }
                }
            }

            // Fuel.get(tainted) — Fuel is a constructor-style call
            if let Some(ctor) = call_constructor_name(n, s) {
                if ctor == "Fuel" {
                    // Check if there's a chained .get() call
                    // This is handled by the method name matching above
                }
            }
        }
    });
    sinks
}

// ─── Rule 11: kt/taint-sql-injection ────────────────────────────────────

pub struct TaintSqlInjection;

impl Rule for TaintSqlInjection {
    fn id(&self) -> &str {
        "kt/taint-sql-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-89")
    }
    fn description(&self) -> &str {
        "Untrusted input from Ktor/Spring handler reaches SQL query sink"
    }
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        run_kt_taint(
            self.id(),
            self.severity(),
            self.cwe(),
            source,
            tree,
            &KtTaintSpec {
                sink_finder: find_sql_sinks,
            },
            |src_desc, sink_desc| {
                format!(
                    "{} flows to {} — use parameterized queries to prevent SQL injection",
                    src_desc, sink_desc
                )
            },
        )
    }
}

// ─── Rule 12: kt/taint-command-injection ────────────────────────────────

pub struct TaintCommandInjection;

impl Rule for TaintCommandInjection {
    fn id(&self) -> &str {
        "kt/taint-command-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-78")
    }
    fn description(&self) -> &str {
        "Untrusted input from Ktor/Spring handler reaches command execution sink"
    }
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        run_kt_taint(
            self.id(),
            self.severity(),
            self.cwe(),
            source,
            tree,
            &KtTaintSpec {
                sink_finder: find_command_sinks,
            },
            |src_desc, sink_desc| {
                format!(
                    "{} flows to {} — avoid passing untrusted input to OS commands",
                    src_desc, sink_desc
                )
            },
        )
    }
}

// ─── Rule 13: kt/taint-ssrf ────────────────────────────────────────────

pub struct TaintSsrf;

impl Rule for TaintSsrf {
    fn id(&self) -> &str {
        "kt/taint-ssrf"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-918")
    }
    fn description(&self) -> &str {
        "Untrusted input from Ktor/Spring handler reaches HTTP/URL sink"
    }
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        run_kt_taint(
            self.id(),
            self.severity(),
            self.cwe(),
            source,
            tree,
            &KtTaintSpec {
                sink_finder: find_ssrf_sinks,
            },
            |src_desc, sink_desc| {
                format!(
                    "{} flows to {} — validate and allowlist target hosts to prevent SSRF",
                    src_desc, sink_desc
                )
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;

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
