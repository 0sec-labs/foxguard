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
}
