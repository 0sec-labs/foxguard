use crate::impl_rule;
use crate::rules::common::{make_finding, walk_tree};
use crate::{Language, Severity};
use regex::Regex;

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
                    if func_text.contains("transmute") {
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
                            let mut has_literal = false;
                            if let Some(first_arg) = args.named_child(0) {
                                has_literal = first_arg.kind() == "string_literal";
                            }
                            if !has_literal {
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
        let sql_methods = Regex::new(r"(?i)\b(query|sql_query|execute|raw_sql)\b").unwrap();

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
                                    if macro_text.starts_with("format!") {
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
        let weak_hash = Regex::new(r"\b(md5|sha1|Md5|Sha1|MD5|SHA1)\b").unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect use declarations: use md5::..., use sha1::...
            if node.kind() == "use_declaration" {
                let text = &src[node.byte_range()];
                if weak_hash.is_match(text) {
                    let algo =
                        if text.contains("md5") || text.contains("Md5") || text.contains("MD5") {
                            "MD5"
                        } else {
                            "SHA1"
                        };
                    findings.push(make_finding(
                        _self.id(),
                        _self.severity(),
                        _self.cwe(),
                        &format!(
                            "Import of weak hash algorithm {} — use SHA-256 or stronger",
                            algo
                        ),
                        node,
                        src,
                    ));
                }
            }

            // Detect function calls: Md5::new(), Sha1::new(), md5::compute(), etc.
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if weak_hash.is_match(func_text) {
                        let algo = if func_text.contains("md5")
                            || func_text.contains("Md5")
                            || func_text.contains("MD5")
                        {
                            "MD5"
                        } else {
                            "SHA1"
                        };
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
        let secret_pattern =
            Regex::new(r"(?i)(password|secret|api_?key|token|auth|credential|private_?key)")
                .unwrap();

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
                                if inner.len() >= 4 {
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
                    // reqwest::get(url) or .get(url) style
                    if func_text == "reqwest::get"
                        || func_text.ends_with(".get")
                        || func_text.ends_with(".post")
                    {
                        // Only flag reqwest-related calls
                        if func_text.contains("reqwest") || src.contains("reqwest") {
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
                    if func_text.contains("Path::new") || func_text.contains("PathBuf::from") {
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

impl_rule! {
    NoUnwrapInLib,
    id = "rs/no-unwrap-in-lib",
    severity = Severity::Medium,
    cwe = Some("CWE-248"),
    description = "Use of .unwrap() or .expect() can cause panics in production",
    language = Language::Rust,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text.ends_with(".unwrap") || func_text.ends_with(".expect") {
                        let method = if func_text.ends_with(".unwrap") {
                            ".unwrap()"
                        } else {
                            ".expect()"
                        };
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
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
