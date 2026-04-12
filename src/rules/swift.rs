use crate::impl_rule;
use crate::rules::common::{make_finding, make_finding_from_offsets, walk_tree};
use crate::{Language, Severity};
use regex::Regex;

// ─── Rule 1: no-hardcoded-secret ────────────────────────────────────────────

pub struct NoHardcodedSecret;

impl_rule! {
    NoHardcodedSecret,
    id = "swift/no-hardcoded-secret",
    severity = Severity::High,
    cwe = Some("CWE-798"),
    description = "Hardcoded secret or credential detected",
    language = Language::Swift,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let mut reported_lines = std::collections::HashSet::new();
        let secret_pattern =
            Regex::new(r"(?i)(password|secret|api_?key|token|auth|credential|private_?key)")
                .unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Match property declarations: let password = "hardcoded"
            // or var apiKey = "secret123"
            if node.kind() == "property_declaration" {
                // Check if the name portion matches a secret pattern
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = &src[name_node.byte_range()];
                    if secret_pattern.is_match(name) {
                        // Walk children looking for a string_literal value
                        let mut has_string_value = false;
                        let mut string_val = String::new();
                        let mut cursor = node.walk();
                        for child in node.children(&mut cursor) {
                            if child.kind() == "line_string_literal"
                                || child.kind() == "string_literal"
                            {
                                has_string_value = true;
                                string_val = src[child.byte_range()].to_string();
                            }
                        }
                        if has_string_value {
                            let inner = string_val.trim_matches('"');
                            let line = node.start_position().row;
                            if inner.len() >= 4 && reported_lines.insert(line) {
                                findings.push(make_finding(
                                    _self.id(),
                                    _self.severity(),
                                    _self.cwe(),
                                    &format!(
                                        "Hardcoded secret in '{}' — use environment variables or Keychain",
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

            // Fallback: regex-based detection for patterns like `let password = "..."`
            // that may parse differently
            if node.kind() == "value_binding_pattern" || node.kind() == "pattern" {
                let name = &src[node.byte_range()];
                if secret_pattern.is_match(name) {
                    if let Some(parent) = node.parent() {
                        let line = parent.start_position().row;
                        if reported_lines.contains(&line) {
                            return;
                        }
                        let mut cursor = parent.walk();
                        for child in parent.children(&mut cursor) {
                            if child.kind() == "line_string_literal"
                                || child.kind() == "string_literal"
                            {
                                let val = &src[child.byte_range()];
                                let inner = val.trim_matches('"');
                                if inner.len() >= 4 && reported_lines.insert(line) {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        &format!(
                                            "Hardcoded secret in '{}' — use environment variables or Keychain",
                                            name
                                        ),
                                        parent,
                                        src,
                                    ));
                                    break;
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

// ─── Rule 2: no-command-injection ───────────────────────────────────────────

pub struct NoCommandInjection;

impl_rule! {
    NoCommandInjection,
    id = "swift/no-command-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-78"),
    description = "Potential command injection via Process or NSTask with dynamic arguments",
    language = Language::Swift,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                let text = &src[node.byte_range()];
                if text.starts_with("Process(") || text.starts_with("NSTask(") {
                    findings.push(make_finding(
                        _self.id(),
                        _self.severity(),
                        _self.cwe(),
                        "Process/NSTask created — ensure arguments are not user-controlled to prevent command injection",
                        node,
                        src,
                    ));
                }
            }

            // Detect .launchPath or .arguments assignment with non-literal values
            if node.kind() == "assignment" {
                let text = &src[node.byte_range()];
                if (text.contains(".launchPath") || text.contains(".arguments"))
                    && !text.contains('"')
                {
                    findings.push(make_finding(
                        _self.id(),
                        _self.severity(),
                        _self.cwe(),
                        "Process arguments set with dynamic value — risk of command injection",
                        node,
                        src,
                    ));
                }
            }
        });
        findings

    }
}

// ─── Rule 3: no-weak-crypto ────────────────────────────────────────────────

pub struct NoWeakCrypto;

impl_rule! {
    NoWeakCrypto,
    id = "swift/no-weak-crypto",
    severity = Severity::Medium,
    cwe = Some("CWE-327"),
    description = "Use of weak cryptographic hash (MD5/SHA1)",
    language = Language::Swift,
    fn check(_self, source, _tree) {

        let mut findings = Vec::new();
        let pattern =
            Regex::new(r"\b(CC_MD5|CC_SHA1|\.md5|\.sha1|Insecure\.MD5|Insecure\.SHA1)\b").unwrap();

        for matched in pattern.find_iter(source) {
            let algo = if matched.as_str().contains("MD5") || matched.as_str().contains("md5") {
                "MD5"
            } else {
                "SHA1"
            };
            findings.push(make_finding_from_offsets(
                _self.id(),
                _self.severity(),
                _self.cwe(),
                &format!(
                    "{} is cryptographically weak — use SHA-256 or stronger",
                    algo
                ),
                source,
                matched.start(),
                matched.end(),
            ));
        }
        findings

    }
}

// ─── Rule 4: no-insecure-transport ─────────────────────────────────────────

pub struct NoInsecureTransport;

impl_rule! {
    NoInsecureTransport,
    id = "swift/no-insecure-transport",
    severity = Severity::High,
    cwe = Some("CWE-319"),
    description = "Insecure HTTP URL detected — use HTTPS instead",
    language = Language::Swift,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "line_string_literal" || node.kind() == "string_literal" {
                let text = &src[node.byte_range()];
                if text.contains("http://")
                    && !text.contains("http://localhost")
                    && !text.contains("http://127.0.0.1")
                {
                    findings.push(make_finding(
                        _self.id(),
                        _self.severity(),
                        _self.cwe(),
                        "Insecure HTTP URL — use HTTPS to protect data in transit",
                        node,
                        src,
                    ));
                }
            }
        });
        findings

    }
}

// ─── Rule 5: no-eval-js ────────────────────────────────────────────────────

pub struct NoEvalJs;

impl_rule! {
    NoEvalJs,
    id = "swift/no-eval-js",
    severity = Severity::Critical,
    cwe = Some("CWE-95"),
    description = "WKWebView evaluateJavaScript with dynamic input enables code injection",
    language = Language::Swift,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                let text = &src[node.byte_range()];
                if text.contains("evaluateJavaScript") {
                    // Check if the argument is a string literal or interpolated
                    let has_interpolation = text.contains("\\(");
                    let is_variable_arg =
                        !text.contains("evaluateJavaScript(\"") || has_interpolation;
                    if is_variable_arg {
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            "evaluateJavaScript called with dynamic input — risk of JavaScript injection in WKWebView",
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

// ─── Rule 6: no-sql-injection ──────────────────────────────────────────────

pub struct NoSqlInjection;

impl_rule! {
    NoSqlInjection,
    id = "swift/no-sql-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-89"),
    description = "Potential SQL injection via string interpolation in SQLite queries",
    language = Language::Swift,
    fn check(_self, source, _tree) {

        let mut findings = Vec::new();
        let sql_keywords =
            Regex::new(r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s").unwrap();

        // Detect SQL strings with interpolation: "SELECT ... \(variable) ..."
        let interp_string = Regex::new(r#""[^"]*\\\([^)]+\)[^"]*""#).unwrap();
        for matched in interp_string.find_iter(source) {
            let text = matched.as_str();
            if sql_keywords.is_match(text) {
                findings.push(make_finding_from_offsets(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "SQL query with string interpolation — use parameterized queries to prevent SQL injection",
                    source,
                    matched.start(),
                    matched.end(),
                ));
            }
        }

        // Detect execute/prepare calls with string concatenation
        let sql_concat = Regex::new(
            r#"(?i)(execute|prepare|sqlite3_exec)\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^)]*\+\s*"#,
        )
        .unwrap();
        for matched in sql_concat.find_iter(source) {
            findings.push(make_finding_from_offsets(
                _self.id(),
                _self.severity(),
                _self.cwe(),
                "SQL query built with string concatenation — use parameterized queries",
                source,
                matched.start(),
                matched.end(),
            ));
        }

        findings

    }
}

// ─── Rule 7: no-insecure-keychain ──────────────────────────────────────────

pub struct NoInsecureKeychain;

impl_rule! {
    NoInsecureKeychain,
    id = "swift/no-insecure-keychain",
    severity = Severity::High,
    cwe = Some("CWE-311"),
    description = "Insecure Keychain accessibility level allows access when device is locked",
    language = Language::Swift,
    fn check(_self, source, _tree) {

        let mut findings = Vec::new();
        let pattern =
            Regex::new(r"\b(kSecAttrAccessibleAlways|kSecAttrAccessibleAlwaysThisDeviceOnly)\b")
                .unwrap();

        for matched in pattern.find_iter(source) {
            findings.push(make_finding_from_offsets(
                _self.id(),
                _self.severity(),
                _self.cwe(),
                &format!(
                    "{} allows Keychain access when device is locked — use kSecAttrAccessibleWhenUnlocked",
                    matched.as_str()
                ),
                source,
                matched.start(),
                matched.end(),
            ));
        }
        findings

    }
}

// ─── Rule 8: no-tls-disabled ───────────────────────────────────────────────

pub struct NoTlsDisabled;

impl_rule! {
    NoTlsDisabled,
    id = "swift/no-tls-disabled",
    severity = Severity::High,
    cwe = Some("CWE-295"),
    description = "TLS certificate validation disabled or weakened",
    language = Language::Swift,
    fn check(_self, source, _tree) {

        let mut findings = Vec::new();

        let patterns = [
            (
                Regex::new(r"allowsExpiredCertificates\s*=\s*true").unwrap(),
                "allowsExpiredCertificates = true disables certificate expiry validation",
            ),
            (
                Regex::new(r"allowsExpiredRoots\s*=\s*true").unwrap(),
                "allowsExpiredRoots = true disables root certificate expiry validation",
            ),
            (
                Regex::new(r"\.disableEvaluation").unwrap(),
                ".disableEvaluation disables TLS server trust evaluation entirely",
            ),
        ];

        for (pattern, msg) in &patterns {
            for matched in pattern.find_iter(source) {
                findings.push(make_finding_from_offsets(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    msg,
                    source,
                    matched.start(),
                    matched.end(),
                ));
            }
        }
        findings

    }
}

// ─── Rule 9: no-path-traversal ─────────────────────────────────────────────

pub struct NoPathTraversal;

impl_rule! {
    NoPathTraversal,
    id = "swift/no-path-traversal",
    severity = Severity::High,
    cwe = Some("CWE-22"),
    description = "Potential path traversal via FileManager with dynamic path",
    language = Language::Swift,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let mut reported_lines = std::collections::HashSet::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                let text = &src[node.byte_range()];
                // Detect FileManager operations with non-literal paths
                let fm_ops = [
                    "contentsOfDirectory",
                    "createDirectory",
                    "removeItem",
                    "copyItem",
                    "moveItem",
                    "fileExists",
                    "contents(atPath",
                ];
                let has_fm_op = fm_ops.iter().any(|op| text.contains(op));
                if has_fm_op {
                    // Check if path argument is dynamic (not a string literal)
                    // Look for atPath: or path: arguments that are not string literals
                    let has_dynamic_path = (text.contains("atPath:") || text.contains("path:"))
                        && !text.contains("atPath: \"")
                        && !text.contains("path: \"");
                    if has_dynamic_path {
                        let line = node.start_position().row;
                        if reported_lines.insert(line) {
                            findings.push(make_finding(
                                _self.id(),
                                _self.severity(),
                                _self.cwe(),
                                "FileManager operation with dynamic path — validate and sanitize to prevent path traversal",
                                node,
                                src,
                            ));
                        }
                    }
                }
            }
        });

        findings

    }
}

// ─── Rule 10: no-ssrf ──────────────────────────────────────────────────────

pub struct NoSsrf;

impl_rule! {
    NoSsrf,
    id = "swift/no-ssrf",
    severity = Severity::High,
    cwe = Some("CWE-918"),
    description = "Potential SSRF via URLSession or URL with dynamic input",
    language = Language::Swift,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let mut reported_lines = std::collections::HashSet::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                let text = &src[node.byte_range()];

                // Detect URL(string: variable)
                if text.starts_with("URL(string:") || text.starts_with("URL(string :") {
                    // Check if argument is not a string literal
                    let after_colon = text.split_once(':').map(|x| x.1).unwrap_or("");
                    let trimmed = after_colon.trim();
                    if !trimmed.starts_with('"') && !trimmed.starts_with("\"") {
                        let line = node.start_position().row;
                        if reported_lines.insert(line) {
                            findings.push(make_finding(
                                _self.id(),
                                _self.severity(),
                                _self.cwe(),
                                "URL(string:) called with dynamic value — validate and allowlist target hosts to prevent SSRF",
                                node,
                                src,
                            ));
                        }
                    }
                }

                // Detect URLSession.shared.dataTask with non-literal URL
                if text.contains("dataTask") && text.contains("url") {
                    // If the URL is from a variable (not inline literal)
                    let line = node.start_position().row;
                    if !text.contains("\"http") && reported_lines.insert(line) {
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            "URLSession.dataTask called with dynamic URL — validate and allowlist target hosts to prevent SSRF",
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
