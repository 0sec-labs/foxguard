use crate::impl_rule;
use crate::rules::common::{make_finding, make_finding_from_offsets, walk_tree};
use crate::{Language, Severity};
use regex::Regex;

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
        let sql_methods =
            Regex::new(r"^(executeQuery|execute|createQuery|createNativeQuery)$").unwrap();

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
        let weak_algo =
            Regex::new(r#"(?i)"(DES|DESede|RC2|RC4|Blowfish|MD5|SHA-?1|.*ECB.*)"#).unwrap();

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
        let secret_pattern =
            Regex::new(r"(?i)(password|secret|api_?key|apiKey|token|auth|credential|private_?key)")
                .unwrap();

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
                                if inner.len() >= 4 {
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
                                if inner.len() >= 4 {
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
        let factory_pattern = Regex::new(
            r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\(\)",
        )
        .unwrap();
        let secure_pattern =
            Regex::new(r"setFeature\s*\(|setProperty\s*\(|setAttribute\s*\(").unwrap();

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
        let csrf_pattern = Regex::new(
            r"\.csrf\(\s*\)\s*\.\s*disable\(\s*\)|csrf\s*\([^)]*\.\s*disable\(\s*\)\s*\)",
        )
        .unwrap();

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
        let wildcard_pattern = Regex::new(r#"allowedOrigins\s*\(\s*"\*"\s*\)"#).unwrap();
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
