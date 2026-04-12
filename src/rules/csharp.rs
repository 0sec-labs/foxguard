use crate::impl_rule;
use crate::rules::common::{make_finding, walk_tree};
use crate::{Language, Severity};
use regex::Regex;

/// Check whether a subtree contains a `binary_expression` with `+` operator.
fn contains_string_concat(node: tree_sitter::Node, source: &str) -> bool {
    if node.kind() == "binary_expression" {
        if let Some(op) = node.child_by_field_name("operator") {
            let op_text = &source[op.byte_range()];
            if op_text == "+" {
                return true;
            }
        }
        // Fallback: check the text itself
        let text = &source[node.byte_range()];
        if text.contains('+') {
            return true;
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if contains_string_concat(child, source) {
            return true;
        }
    }
    false
}

/// Check whether a node is a string literal.
fn is_string_literal(node: tree_sitter::Node) -> bool {
    matches!(
        node.kind(),
        "string_literal"
            | "verbatim_string_literal"
            | "interpolated_string_expression"
            | "string_literal_expression"
    )
}

// ─── Rule 1: no-sql-injection ───────────────────────────────────────────────

pub struct NoSqlInjection;

impl_rule! {
    NoSqlInjection,
    id = "cs/no-sql-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-89"),
    description = "Potential SQL injection via string concatenation in database call",
    language = Language::CSharp,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let sql_methods = [
            "ExecuteReader",
            "ExecuteNonQuery",
            "ExecuteScalar",
            "FromSqlRaw",
        ];

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "invocation_expression" {
                let node_text = &src[node.byte_range()];
                let has_sql_method = sql_methods.iter().any(|m| node_text.contains(m));
                if has_sql_method {
                    // Check if any argument contains binary_expression with +
                    if let Some(args) = node.child_by_field_name("arguments") {
                        if contains_string_concat(args, src) {
                            findings.push(make_finding(
                                _self.id(),
                                _self.severity(),
                                _self.cwe(),
                                "SQL query built with string concatenation — use parameterized queries",
                                node,
                                src,
                            ));
                        }
                    }
                    // Also check: the expression part may carry the args
                    // Try children directly
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        if child.kind() == "argument_list" && contains_string_concat(child, src) {
                            // Avoid duplicating if already found via field name
                            if node.child_by_field_name("arguments").is_none() {
                                findings.push(make_finding(
                                    _self.id(),
                                    _self.severity(),
                                    _self.cwe(),
                                    "SQL query built with string concatenation — use parameterized queries",
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
    id = "cs/no-command-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-78"),
    description = "Potential command injection via Process.Start with dynamic argument",
    language = Language::CSharp,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "invocation_expression" {
                let node_text = &src[node.byte_range()];
                if node_text.contains("Process.Start") {
                    // Check arguments for non-literal values
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        if child.kind() == "argument_list" {
                            let mut arg_cursor = child.walk();
                            for arg in child.named_children(&mut arg_cursor) {
                                if !is_string_literal(arg) && arg.kind() != "string_literal" {
                                    // Has a non-literal argument
                                    let inner_text = &src[arg.byte_range()];
                                    // Skip if it looks like just a string literal
                                    if !inner_text.starts_with('"')
                                        && !inner_text.starts_with("@\"")
                                    {
                                        findings.push(make_finding(
                                            _self.id(),
                                            _self.severity(),
                                            _self.cwe(),
                                            "Process.Start called with dynamic argument — risk of command injection",
                                            node,
                                            src,
                                        ));
                                        return;
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

// ─── Rule 3: no-unsafe-deserialization ──────────────────────────────────────

pub struct NoUnsafeDeserialization;

impl_rule! {
    NoUnsafeDeserialization,
    id = "cs/no-unsafe-deserialization",
    severity = Severity::Critical,
    cwe = Some("CWE-502"),
    description = "Use of unsafe deserialization API",
    language = Language::CSharp,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let unsafe_patterns = ["BinaryFormatter", "JavaScriptSerializer"];

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect invocation of unsafe deserializers
            if node.kind() == "invocation_expression" {
                let node_text = &src[node.byte_range()];
                if (node_text.contains("BinaryFormatter") && node_text.contains("Deserialize"))
                    || (node_text.contains("JavaScriptSerializer")
                        && node_text.contains("Deserialize"))
                {
                    findings.push(make_finding(
                        _self.id(),
                        _self.severity(),
                        _self.cwe(),
                        "Unsafe deserialization — BinaryFormatter/JavaScriptSerializer can execute arbitrary code",
                        node,
                        src,
                    ));
                }
            }

            // Detect new BinaryFormatter() or new JavaScriptSerializer()
            if node.kind() == "object_creation_expression" {
                let node_text = &src[node.byte_range()];
                for pattern in &unsafe_patterns {
                    if node_text.contains(pattern) {
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            &format!(
                                "new {}() — this type is inherently unsafe for deserialization",
                                pattern
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

// ─── Rule 4: no-ssrf ───────────────────────────────────────────────────────

pub struct NoSsrf;

impl_rule! {
    NoSsrf,
    id = "cs/no-ssrf",
    severity = Severity::High,
    cwe = Some("CWE-918"),
    description = "Potential SSRF via HTTP request with dynamic URL",
    language = Language::CSharp,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let ssrf_methods = ["GetAsync", "PostAsync", "SendAsync", "GetStringAsync"];

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "invocation_expression" {
                let node_text = &src[node.byte_range()];

                // HttpClient methods
                let has_http_method = ssrf_methods.iter().any(|m| node_text.contains(m));
                // WebRequest.Create
                let has_webrequest = node_text.contains("WebRequest.Create");

                if has_http_method || has_webrequest {
                    // Check if the first argument is a non-literal
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        if child.kind() == "argument_list" {
                            if let Some(first_arg) = child.named_child(0) {
                                if !is_string_literal(first_arg) {
                                    let arg_text = &src[first_arg.byte_range()];
                                    if !arg_text.starts_with('"') && !arg_text.starts_with("@\"") {
                                        findings.push(make_finding(
                                            _self.id(),
                                            _self.severity(),
                                            _self.cwe(),
                                            "HTTP request with dynamic URL — validate and allowlist target hosts to prevent SSRF",
                                            node,
                                            src,
                                        ));
                                        return;
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
    id = "cs/no-path-traversal",
    severity = Severity::High,
    cwe = Some("CWE-22"),
    description = "Potential path traversal via dynamic file path",
    language = Language::CSharp,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let file_methods = [
            "File.ReadAllText",
            "File.ReadAllBytes",
            "File.Open",
            "File.OpenRead",
            "File.WriteAllText",
            "File.Delete",
            "File.Exists",
        ];

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "invocation_expression" {
                let node_text = &src[node.byte_range()];

                let has_file_method = file_methods.iter().any(|m| node_text.contains(m));
                let has_stream_reader =
                    node_text.contains("StreamReader") && node.kind() == "invocation_expression";

                if has_file_method {
                    // Check first argument is non-literal
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        if child.kind() == "argument_list" {
                            if let Some(first_arg) = child.named_child(0) {
                                if !is_string_literal(first_arg) {
                                    let arg_text = &src[first_arg.byte_range()];
                                    if !arg_text.starts_with('"') && !arg_text.starts_with("@\"") {
                                        let mut f = make_finding(
                                            _self.id(),
                                            _self.severity(),
                                            _self.cwe(),
                                            "File operation with dynamic path — validate and sanitize to prevent path traversal",
                                            node,
                                            src,
                                        );
                                        f.fix_suggestion = Some("Validate file paths with Path.GetFullPath() and ensure they don't escape the intended directory".to_string());
                                        findings.push(f);
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }

                // Avoid double-reporting; handle StreamReader separately would
                // require checking object_creation_expression, handled below.
                let _ = has_stream_reader;
            }

            // new StreamReader(userInput) / new FileStream(userInput, ...)
            if node.kind() == "object_creation_expression" {
                let node_text = &src[node.byte_range()];
                let is_stream_reader = node_text.contains("StreamReader");
                let is_file_stream = node_text.contains("FileStream");
                if is_stream_reader || is_file_stream {
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        if child.kind() == "argument_list" {
                            if let Some(first_arg) = child.named_child(0) {
                                if !is_string_literal(first_arg) {
                                    let arg_text = &src[first_arg.byte_range()];
                                    if !arg_text.starts_with('"') && !arg_text.starts_with("@\"") {
                                        let type_name = if is_stream_reader {
                                            "StreamReader"
                                        } else {
                                            "FileStream"
                                        };
                                        let mut f = make_finding(
                                            _self.id(),
                                            _self.severity(),
                                            _self.cwe(),
                                            &format!(
                                                "new {} with dynamic path — validate and sanitize to prevent path traversal",
                                                type_name
                                            ),
                                            node,
                                            src,
                                        );
                                        f.fix_suggestion = Some("Validate file paths with Path.GetFullPath() and ensure they don't escape the intended directory".to_string());
                                        findings.push(f);
                                        return;
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
    id = "cs/no-weak-crypto",
    severity = Severity::Medium,
    cwe = Some("CWE-327"),
    description = "Use of weak cryptographic algorithm",
    language = Language::CSharp,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let weak_algos = [
            ("MD5", "MD5.Create"),
            ("SHA1", "SHA1.Create"),
            ("DES", "DES.Create"),
            ("DES", "DESCryptoServiceProvider"),
            ("RC2", "RC2.Create"),
            ("RC2", "RC2CryptoServiceProvider"),
        ];

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "invocation_expression" || node.kind() == "object_creation_expression"
            {
                let node_text = &src[node.byte_range()];
                for (algo, pattern) in &weak_algos {
                    if node_text.contains(pattern) {
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            &format!("{} is cryptographically weak — use AES or SHA-256+", algo),
                            node,
                            src,
                        ));
                        return;
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
    id = "cs/no-hardcoded-secret",
    severity = Severity::High,
    cwe = Some("CWE-798"),
    description = "Hardcoded secret or credential detected",
    language = Language::CSharp,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let secret_pattern = Regex::new(
            r"(?i)(password|secret|api_?key|apikey|token|credential|private_?key|connection_?string|connectionstring)",
        )
        .unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // variable_declarator: string password = "hardcoded"
            if node.kind() == "variable_declarator" {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = &src[name_node.byte_range()];
                    if secret_pattern.is_match(name) {
                        // In C# tree-sitter, the string_literal is a direct child
                        let mut cursor = node.walk();
                        for child in node.children(&mut cursor) {
                            if child.kind() == "string_literal"
                                || child.kind() == "verbatim_string_literal"
                                || child.kind() == "interpolated_string_expression"
                            {
                                let val = &src[child.byte_range()];
                                let trimmed = val.trim_matches(|c| c == '"' || c == '@');
                                let trimmed = trimmed.trim_matches('"');
                                if trimmed.len() >= 4 {
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
                                    return;
                                }
                            }
                        }
                    }
                }
            }

            // assignment_expression: password = "hardcoded"
            if node.kind() == "assignment_expression" {
                if let Some(left) = node.child_by_field_name("left") {
                    let left_text = &src[left.byte_range()];
                    if secret_pattern.is_match(left_text) {
                        if let Some(right) = node.child_by_field_name("right") {
                            if is_string_literal(right) || right.kind() == "string_literal" {
                                let val = &src[right.byte_range()];
                                let trimmed = val.trim_matches(|c| c == '"' || c == '@');
                                let trimmed = trimmed.trim_matches('"');
                                if trimmed.len() >= 4 {
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
    id = "cs/no-xxe",
    severity = Severity::High,
    cwe = Some("CWE-611"),
    description = "Potential XXE vulnerability in XML parsing",
    language = Language::CSharp,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let has_dtd_prohibit =
            source.contains("DtdProcessing.Prohibit") || source.contains("ProhibitDtd = true");

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "invocation_expression" {
                let node_text = &src[node.byte_range()];
                if ((node_text.contains("XmlDocument") && node_text.contains("Load"))
                    || (node_text.contains("XmlReader") && node_text.contains("Create"))
                    || node_text.contains("XmlTextReader"))
                    && !has_dtd_prohibit
                {
                    findings.push(make_finding(
                        _self.id(),
                        _self.severity(),
                        _self.cwe(),
                        "XML parsing without DtdProcessing.Prohibit — vulnerable to XXE attacks",
                        node,
                        src,
                    ));
                }
            }

            // new XmlDocument() without DtdProcessing.Prohibit
            if node.kind() == "object_creation_expression" {
                let node_text = &src[node.byte_range()];
                if (node_text.contains("XmlDocument") || node_text.contains("XmlTextReader"))
                    && !has_dtd_prohibit
                {
                    findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            "XML parser created without disabling DTD processing — vulnerable to XXE attacks",
                            node,
                            src,
                        ));
                }
            }
        });
        findings

    }
}

// ─── Rule 9: no-ldap-injection ──────────────────────────────────────────────

pub struct NoLdapInjection;

impl_rule! {
    NoLdapInjection,
    id = "cs/no-ldap-injection",
    severity = Severity::High,
    cwe = Some("CWE-90"),
    description = "Potential LDAP injection via string concatenation in search filter",
    language = Language::CSharp,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // assignment_expression: searcher.Filter = "..." + userInput
            if node.kind() == "assignment_expression" {
                if let Some(left) = node.child_by_field_name("left") {
                    let left_text = &src[left.byte_range()];
                    if left_text.contains("Filter")
                        && (left_text.contains("DirectorySearcher")
                            || left_text.contains("searcher")
                            || left_text.ends_with(".Filter"))
                    {
                        if let Some(right) = node.child_by_field_name("right") {
                            if contains_string_concat(right, src) {
                                findings.push(make_finding(
                                    _self.id(),
                                    _self.severity(),
                                    _self.cwe(),
                                    "LDAP filter built with string concatenation — use parameterized filters to prevent LDAP injection",
                                    node,
                                    src,
                                ));
                            }
                        }
                    }
                }
            }

            // Also catch: new DirectorySearcher("..." + input)
            if node.kind() == "object_creation_expression" {
                let node_text = &src[node.byte_range()];
                if node_text.contains("DirectorySearcher") {
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        if child.kind() == "argument_list" && contains_string_concat(child, src) {
                            findings.push(make_finding(
                                _self.id(),
                                _self.severity(),
                                _self.cwe(),
                                "DirectorySearcher created with concatenated filter — use parameterized filters to prevent LDAP injection",
                                node,
                                src,
                            ));
                            return;
                        }
                    }
                }
            }
        });
        findings

    }
}

// ─── Rule 10: no-cors-star ─────────────────────────────────────────────────

pub struct NoCorsStar;

impl_rule! {
    NoCorsStar,
    id = "cs/no-cors-star",
    severity = Severity::Medium,
    cwe = Some("CWE-942"),
    description = "Overly permissive CORS configuration",
    language = Language::CSharp,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let cors_star = Regex::new(r#"WithOrigins\s*\(\s*"\*"\s*\)"#).unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "invocation_expression" {
                // Get the direct method name by looking at the first child
                // (the function/expression part), not the entire subtree text.
                let func_child = node.child(0);
                let func_text = func_child.map(|c| &src[c.byte_range()]).unwrap_or("");

                if func_text.ends_with("AllowAnyOrigin") || func_text.ends_with(".AllowAnyOrigin") {
                    findings.push(make_finding(
                        _self.id(),
                        _self.severity(),
                        _self.cwe(),
                        "AllowAnyOrigin() permits requests from any domain — restrict CORS origins",
                        node,
                        src,
                    ));
                } else if func_text.ends_with("WithOrigins") {
                    let node_text = &src[node.byte_range()];
                    if cors_star.is_match(node_text) {
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            "WithOrigins(\"*\") permits requests from any domain — restrict CORS origins",
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
