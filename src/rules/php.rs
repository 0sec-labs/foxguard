use crate::impl_rule;
use crate::rules::common::{make_finding, walk_tree};
use crate::{Language, Severity};
use regex::Regex;

// ─── Rule 1: no-eval ──────────────────────────────────────────────────────────

pub struct NoEval;

impl_rule! {
    NoEval,
    id = "php/no-eval",
    severity = Severity::Critical,
    cwe = Some("CWE-95"),
    description = "Use of eval() allows arbitrary code execution",
    language = Language::Php,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "function_call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "eval" {
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            "eval() allows arbitrary code execution — avoid dynamic code evaluation",
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

// ─── Rule 2: no-command-injection ─────────────────────────────────────────────

pub struct NoCommandInjection;

impl_rule! {
    NoCommandInjection,
    id = "php/no-command-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-78"),
    description = "Potential command injection via shell execution function",
    language = Language::Php,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect dangerous shell functions
            if node.kind() == "function_call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if matches!(
                        func_text,
                        "exec" | "system" | "passthru" | "shell_exec" | "popen" | "proc_open"
                    ) {
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            &format!(
                                "{}() executes shell commands — risk of command injection",
                                func_text
                            ),
                            node,
                            src,
                        ));
                    }
                }
            }

            // Detect backtick execution
            if node.kind() == "shell_command_expression" {
                findings.push(make_finding(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "Backtick operator executes shell commands — risk of command injection",
                    node,
                    src,
                ));
            }
        });
        findings

    }
}

// ─── Rule 3: no-sql-injection ─────────────────────────────────────────────────

pub struct NoSqlInjection;

impl_rule! {
    NoSqlInjection,
    id = "php/no-sql-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-89"),
    description = "Potential SQL injection via string interpolation or concatenation",
    language = Language::Php,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let sql_funcs = ["mysqli_query", "pg_query", "mysql_query"];

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect: mysqli_query($conn, "SELECT ... $var ...")
            if node.kind() == "function_call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if sql_funcs.contains(&func_text) {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let arg_text = &src[args.byte_range()];
                            if Self::has_interpolation_or_concat(args) {
                                findings.push(make_finding(
                                    _self.id(),
                                    _self.severity(),
                                    _self.cwe(),
                                    &format!(
                                        "{}() with dynamic query — use parameterized queries",
                                        func_text
                                    ),
                                    node,
                                    src,
                                ));
                            } else if arg_text.contains('$') || arg_text.contains('.') {
                                // Rough heuristic for interpolated or concatenated strings
                                findings.push(make_finding(
                                    _self.id(),
                                    _self.severity(),
                                    _self.cwe(),
                                    &format!(
                                        "{}() with dynamic query — use parameterized queries",
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

            // Detect: $stmt->query("SELECT ... $var ...")
            if node.kind() == "member_call_expression" {
                if let Some(name) = node.child_by_field_name("name") {
                    let name_text = &src[name.byte_range()];
                    if name_text == "query" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if Self::has_interpolation_or_concat(args) {
                                findings.push(make_finding(
                                    _self.id(),
                                    _self.severity(),
                                    _self.cwe(),
                                    "->query() with dynamic query — use parameterized queries",
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

impl NoSqlInjection {
    fn has_interpolation_or_concat(args_node: tree_sitter::Node) -> bool {
        let mut cursor = args_node.walk();
        for child in args_node.children(&mut cursor) {
            if child.kind() == "encapsed_string" {
                return true;
            }
            if child.kind() == "binary_expression" {
                // Check for string concatenation with .
                let mut inner = child.walk();
                for c in child.children(&mut inner) {
                    if c.kind() == "." {
                        return true;
                    }
                }
            }
            // Recurse into nested nodes
            if Self::has_interpolation_or_concat(child) {
                return true;
            }
        }
        false
    }
}

// ─── Rule 4: no-unserialize ──────────────────────────────────────────────────

pub struct NoUnserialize;

impl_rule! {
    NoUnserialize,
    id = "php/no-unserialize",
    severity = Severity::Critical,
    cwe = Some("CWE-502"),
    description = "Use of unserialize() on untrusted data can lead to object injection",
    language = Language::Php,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "function_call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "unserialize" {
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            "unserialize() on untrusted data can lead to object injection — use json_decode instead",
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

// ─── Rule 5: no-file-inclusion ───────────────────────────────────────────────

pub struct NoFileInclusion;

impl_rule! {
    NoFileInclusion,
    id = "php/no-file-inclusion",
    severity = Severity::Critical,
    cwe = Some("CWE-98"),
    description = "Dynamic file inclusion with variable argument enables remote/local file inclusion",
    language = Language::Php,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if matches!(
                node.kind(),
                "include_expression"
                    | "include_once_expression"
                    | "require_expression"
                    | "require_once_expression"
            ) {
                // Check if the argument is non-literal (contains a variable)
                let text = &src[node.byte_range()];
                let has_variable = Self::has_variable_child(node);
                if has_variable || text.contains('$') {
                    let keyword = node.kind().replace("_expression", "").replace('_', " ");
                    findings.push(make_finding(
                        _self.id(),
                        _self.severity(),
                        _self.cwe(),
                        &format!(
                            "{} with variable argument — risk of file inclusion attack",
                            keyword
                        ),
                        node,
                        src,
                    ));
                }
            }
        });
        findings

    }
}

impl NoFileInclusion {
    fn has_variable_child(node: tree_sitter::Node) -> bool {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_name" {
                return true;
            }
            if child.kind() == "encapsed_string" {
                return true;
            }
            if Self::has_variable_child(child) {
                return true;
            }
        }
        false
    }
}

// ─── Rule 6: no-weak-crypto ─────────────────────────────────────────────────

pub struct NoWeakCrypto;

impl_rule! {
    NoWeakCrypto,
    id = "php/no-weak-crypto",
    severity = Severity::Medium,
    cwe = Some("CWE-327"),
    description = "Use of weak cryptographic hash (MD5/SHA1)",
    language = Language::Php,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "function_call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "md5" || func_text == "sha1" {
                        let algo = if func_text == "md5" { "MD5" } else { "SHA1" };
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            &format!(
                                "{}() is cryptographically weak — use hash('sha256', ...) or stronger",
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

// ─── Rule 7: no-hardcoded-secret ────────────────────────────────────────────

pub struct NoHardcodedSecret;

impl_rule! {
    NoHardcodedSecret,
    id = "php/no-hardcoded-secret",
    severity = Severity::High,
    cwe = Some("CWE-798"),
    description = "Hardcoded secret or credential detected",
    language = Language::Php,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let secret_pattern = Regex::new(r"(?i)(password|secret|api_?key|token)").unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect: $password = "hardcoded";
            if node.kind() == "assignment_expression" {
                if let Some(left) = node.child_by_field_name("left") {
                    let left_text = &src[left.byte_range()];
                    if left_text.starts_with('$') && secret_pattern.is_match(left_text) {
                        if let Some(right) = node.child_by_field_name("right") {
                            if right.kind() == "string"
                                || right.kind() == "encapsed_string"
                                || right.kind() == "string_value"
                            {
                                let val = &src[right.byte_range()];
                                let inner = val.trim_matches(|c| c == '"' || c == '\'');
                                if inner.len() >= 4 {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        &format!(
                                            "Hardcoded secret in '{}' — use environment variables",
                                            left_text
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

// ─── Rule 8: no-ssrf ────────────────────────────────────────────────────────

pub struct NoSsrf;

impl_rule! {
    NoSsrf,
    id = "php/no-ssrf",
    severity = Severity::High,
    cwe = Some("CWE-918"),
    description = "Potential SSRF via file_get_contents or curl_init with variable URL",
    language = Language::Php,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "function_call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "file_get_contents" || func_text == "curl_init" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                // Flag if the argument is not a string literal
                                if first_arg.kind() != "string" {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        &format!(
                                            "{}() called with dynamic URL — validate and allowlist target hosts to prevent SSRF",
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

// ─── Rule 9: no-extract ─────────────────────────────────────────────────────

pub struct NoExtract;

impl_rule! {
    NoExtract,
    id = "php/no-extract",
    severity = Severity::High,
    cwe = Some("CWE-621"),
    description = "Use of extract() can overwrite existing variables",
    language = Language::Php,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "function_call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "extract" {
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            "extract() imports variables into the current scope — risk of variable overwrite",
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

// ─── Rule 10: no-preg-eval ──────────────────────────────────────────────────

pub struct NoPregEval;

impl_rule! {
    NoPregEval,
    id = "php/no-preg-eval",
    severity = Severity::Critical,
    cwe = Some("CWE-95"),
    description = "preg_replace with /e modifier allows arbitrary code execution",
    language = Language::Php,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let e_modifier = Regex::new(r#"['"][^'"]*/.*/[a-z]*e[a-z]*['"]"#).unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "function_call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "preg_replace" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                let arg_text = &src[first_arg.byte_range()];
                                if e_modifier.is_match(arg_text) {
                                    findings.push(make_finding(
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
                                        "preg_replace() with /e modifier executes code — use preg_replace_callback instead",
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
