use std::sync::OnceLock;

use regex::Regex;

use crate::impl_rule;
use crate::rules::common::{
    hardcoded_secret_re, is_secret_value_long_enough, make_finding, walk_tree,
};
use crate::{Language, Severity};

// ─── Static regex helpers (compiled once) ────────────────────────────────────

fn php_preg_e_modifier_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Match a PHP regex literal whose *trailing modifier flags* (the
        // characters after the final pattern delimiter) include `e`. The
        // pattern body is captured non-greedily so the final `/` is the
        // closing delimiter, and the modifier run is anchored to the end of
        // the string literal. This avoids matching an `e` that merely appears
        // inside the pattern body (e.g. `/foo/i`, `/he/`).
        Regex::new(r#"['"]/.*/[a-zA-Z]*e[a-zA-Z]*['"]$"#)
            .expect("static PHP preg_replace regex should compile")
    })
}

/// Returns `true` when an `encapsed_string` node contains *actual* variable
/// interpolation (`$var`, `${expr}`, `{$obj->prop}`), as opposed to being a
/// purely literal double-quoted string. tree-sitter-php classifies every
/// double-quoted string as an `encapsed_string`, so the node kind alone is not
/// enough to distinguish `"SELECT ... $id"` from `"SELECT ... 1"`.
fn encapsed_string_has_interpolation(node: tree_sitter::Node) -> bool {
    if node.kind() != "encapsed_string" {
        return false;
    }
    let mut cursor = node.walk();
    let interpolates = node.children(&mut cursor).any(|child| {
        matches!(
            child.kind(),
            "variable_name"
                | "dynamic_variable_name"
                | "member_access_expression"
                | "subscript_expression"
                | "nullsafe_member_access_expression"
                | "function_call_expression"
        )
    });
    interpolates
}

/// Names of PHP functions that yield values not directly controlled by the
/// HTTP request — environment lookups and configuration accessors. Used by the
/// SSRF rule to avoid flagging URLs sourced from these.
fn is_known_safe_source(func_name: &str) -> bool {
    matches!(func_name, "getenv" | "constant" | "config" | "env")
}

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
                        // Suppress when the command argument is sanitized through
                        // escapeshellarg()/escapeshellcmd() (or is a pure literal).
                        let sanitized = node
                            .child_by_field_name("arguments")
                            .and_then(|args| args.named_child(0))
                            .map(|arg| Self::command_arg_is_sanitized(arg, src))
                            .unwrap_or(false);
                        if !sanitized {
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

impl NoCommandInjection {
    /// Returns `true` when the command argument is considered sanitized:
    /// either a pure string literal with no interpolation, or an expression
    /// where every dynamic component is wrapped in `escapeshellarg()` /
    /// `escapeshellcmd()`.
    fn command_arg_is_sanitized(node: tree_sitter::Node, src: &str) -> bool {
        match node.kind() {
            // `arguments` wrap each argument in an `argument` node; unwrap it.
            "argument" => node
                .named_child(0)
                .map(|inner| Self::command_arg_is_sanitized(inner, src))
                .unwrap_or(false),

            // Plain literals carry no taint.
            "string" | "integer" | "float" | "boolean" => true,

            // Double-quoted string: safe only if it does not interpolate.
            "encapsed_string" => !encapsed_string_has_interpolation(node),

            // escapeshellarg()/escapeshellcmd() sanitize their argument.
            "function_call_expression" => node
                .child_by_field_name("function")
                .map(|f| matches!(&src[f.byte_range()], "escapeshellarg" | "escapeshellcmd"))
                .unwrap_or(false),

            // Parenthesized expression: look through it.
            "parenthesized_expression" => node
                .named_child(0)
                .map(|inner| Self::command_arg_is_sanitized(inner, src))
                .unwrap_or(false),

            // Concatenation is safe only if *both* sides are sanitized.
            "binary_expression" => {
                let lhs = node.child_by_field_name("left");
                let rhs = node.child_by_field_name("right");
                match (lhs, rhs) {
                    (Some(l), Some(r)) => {
                        Self::command_arg_is_sanitized(l, src)
                            && Self::command_arg_is_sanitized(r, src)
                    }
                    _ => false,
                }
            }

            // Anything else (bare variables, array access, etc.) is unsafe.
            _ => false,
        }
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
            // Only flag a double-quoted string when it actually interpolates a
            // variable/expression; a purely literal query string is safe.
            if child.kind() == "encapsed_string" {
                if encapsed_string_has_interpolation(child) {
                    return true;
                }
                continue;
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
            // A double-quoted string is only dangerous when it interpolates a
            // variable/expression; a literal path such as
            // `include "vendor/autoload.php"` is safe.
            if child.kind() == "encapsed_string" {
                if encapsed_string_has_interpolation(child) {
                    return true;
                }
                continue;
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
        let secret_pattern = hardcoded_secret_re();

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
                                if is_secret_value_long_enough(inner) {
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
                                // `named_child(0)` yields the wrapping `argument`
                                // node; unwrap to the actual URL expression.
                                let url_expr =
                                    first_arg.named_child(0).unwrap_or(first_arg);
                                if !Self::url_arg_is_safe(url_expr, src) {
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

impl NoSsrf {
    /// Returns `true` when the URL argument is considered safe: a string
    /// literal with no interpolation, or a value sourced from a known-safe
    /// accessor such as `getenv()`.
    fn url_arg_is_safe(node: tree_sitter::Node, src: &str) -> bool {
        match node.kind() {
            "string" => true,
            "encapsed_string" => !encapsed_string_has_interpolation(node),
            "function_call_expression" => node
                .child_by_field_name("function")
                .map(|f| is_known_safe_source(&src[f.byte_range()]))
                .unwrap_or(false),
            "parenthesized_expression" => node
                .named_child(0)
                .map(|inner| Self::url_arg_is_safe(inner, src))
                .unwrap_or(false),
            _ => false,
        }
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
        let e_modifier = php_preg_e_modifier_re();

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::rules::Rule;
    use crate::Language;

    fn run<R: Rule>(rule: &R, src: &str) -> usize {
        let tree = parse_file(src, Language::Php).expect("PHP source should parse");
        rule.check(src, &tree).len()
    }

    // ── False-positive (safe) cases — must produce ZERO findings ──────────

    #[test]
    fn literal_sql_string_not_flagged() {
        let src = r#"<?php mysqli_query($c, "SELECT * FROM users WHERE active = 1");"#;
        assert_eq!(run(&NoSqlInjection, src), 0);
    }

    #[test]
    fn literal_include_not_flagged() {
        let src = r#"<?php include "vendor/autoload.php";"#;
        assert_eq!(run(&NoFileInclusion, src), 0);
    }

    #[test]
    fn getenv_url_not_flagged() {
        let src = r#"<?php file_get_contents(getenv('SAFE_URL'));"#;
        assert_eq!(run(&NoSsrf, src), 0);
    }

    #[test]
    fn literal_url_not_flagged() {
        let src = r#"<?php file_get_contents("https://example.com/feed");"#;
        assert_eq!(run(&NoSsrf, src), 0);
    }

    #[test]
    fn escapeshell_wrapped_not_flagged() {
        let src = r#"<?php exec(escapeshellcmd($x)); system(escapeshellarg($y));"#;
        assert_eq!(run(&NoCommandInjection, src), 0);
    }

    #[test]
    fn preg_e_in_body_not_flagged() {
        let src = r#"<?php preg_replace('/foo/i', 'x', $y); preg_replace('/header/', 'x', $y);"#;
        assert_eq!(run(&NoPregEval, src), 0);
    }

    // ── True-positive cases — must STILL flag ─────────────────────────────

    #[test]
    fn interpolated_sql_still_flagged() {
        let src = r#"<?php mysqli_query($c, "SELECT * FROM users WHERE id = $id");"#;
        assert_eq!(run(&NoSqlInjection, src), 1);
    }

    #[test]
    fn variable_include_still_flagged() {
        let src = r#"<?php include $_GET['p'];"#;
        assert_eq!(run(&NoFileInclusion, src), 1);
    }

    #[test]
    fn dynamic_url_still_flagged() {
        let src = r#"<?php file_get_contents($_GET['url']);"#;
        assert_eq!(run(&NoSsrf, src), 1);
    }

    #[test]
    fn unsanitized_exec_still_flagged() {
        let src = r#"<?php exec($_GET['cmd']);"#;
        assert_eq!(run(&NoCommandInjection, src), 1);
    }

    #[test]
    fn real_preg_e_modifier_still_flagged() {
        let src = r#"<?php preg_replace('/x/e', $code);"#;
        assert_eq!(run(&NoPregEval, src), 1);
    }
}
