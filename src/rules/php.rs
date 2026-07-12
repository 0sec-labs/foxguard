use std::sync::OnceLock;

use regex::Regex;

use crate::impl_rule;
use crate::rules::common::{
    get_source_line, hardcoded_secret_re, is_secret_value_long_enough, make_finding, walk_tree,
};
use crate::rules::php_taint;
use crate::{Finding, Language, Severity};

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
    fn check_with_context(_self, source, tree, ctx) {

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
                                if is_secret_value_long_enough(inner, ctx.secret_thresholds) {
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

// ═══════════════════════════════════════════════════════════════════════════
// PHP taint rules
// ═══════════════════════════════════════════════════════════════════════════
//
// Five `php/taint-*` rules that consume the taint engine in
// `crate::rules::php_taint`. Each rule's `check()` looks up the rule's
// declarative `TaintSpec` from `php_taint::php_taint_rule_specs()`, hands
// it to `php_taint::analyze_tree`, and maps returned `TaintFinding`s onto
// the project's `Finding` type — same shape as the C taint rules.
//
// The scanner skips the rule's `check()` when the same rule id is
// registered as a `RegistryTaintSpec` via
// `builtin_taint_specs_for_language`, and runs the batched dispatcher
// `run_php_taint_batched` instead. The `check()` path is kept working
// so unit tests that construct a Rule struct directly continue to
// function.

/// Per-rule metadata for PHP taint findings.
struct PhpTaintRuleMeta<'a> {
    rule_id: &'a str,
    severity: Severity,
    cwe: Option<&'a str>,
    fix_suggestion: Option<&'a str>,
    format_description: fn(&str, &str) -> String,
}

fn php_taint_command_injection_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — avoid passing untrusted input to OS commands",
        src, sink
    )
}

fn php_taint_sql_injection_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — use prepared statements to prevent SQL injection",
        src, sink
    )
}

fn php_taint_xss_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — escape output with htmlspecialchars() before rendering",
        src, sink
    )
}

fn php_taint_file_inclusion_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — avoid dynamic include/require of user-controlled paths",
        src, sink
    )
}

fn php_taint_unsafe_deserialization_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — use json_decode() instead of unserialize() for untrusted data",
        src, sink
    )
}

fn php_taint_meta(rule_id: &str) -> Option<PhpTaintRuleMeta<'static>> {
    match rule_id {
        "php/taint-command-injection" => Some(PhpTaintRuleMeta {
            rule_id: "php/taint-command-injection",
            severity: Severity::Critical,
            cwe: Some("CWE-78"),
            fix_suggestion: Some(
                "Use escapeshellarg()/escapeshellcmd() to escape arguments, or pass an argv array to proc_open()",
            ),
            format_description: php_taint_command_injection_desc,
        }),
        "php/taint-sql-injection" => Some(PhpTaintRuleMeta {
            rule_id: "php/taint-sql-injection",
            severity: Severity::Critical,
            cwe: Some("CWE-89"),
            fix_suggestion: Some(
                "Use parameterized queries: mysqli_prepare() + mysqli_stmt_bind_param(), or PDO statements with bound parameters",
            ),
            format_description: php_taint_sql_injection_desc,
        }),
        "php/taint-xss" => Some(PhpTaintRuleMeta {
            rule_id: "php/taint-xss",
            severity: Severity::High,
            cwe: Some("CWE-79"),
            fix_suggestion: Some(
                "Escape output with htmlspecialchars($value, ENT_QUOTES, 'UTF-8') before echoing",
            ),
            format_description: php_taint_xss_desc,
        }),
        "php/taint-file-inclusion" => Some(PhpTaintRuleMeta {
            rule_id: "php/taint-file-inclusion",
            severity: Severity::Critical,
            cwe: Some("CWE-98"),
            fix_suggestion: Some(
                "Resolve include/require paths against a fixed allowlist; never include user-controlled paths",
            ),
            format_description: php_taint_file_inclusion_desc,
        }),
        "php/taint-unsafe-deserialization" => Some(PhpTaintRuleMeta {
            rule_id: "php/taint-unsafe-deserialization",
            severity: Severity::Critical,
            cwe: Some("CWE-502"),
            fix_suggestion: Some(
                "Use json_decode() for untrusted data, or call unserialize() with allowed_classes: false",
            ),
            format_description: php_taint_unsafe_deserialization_desc,
        }),
        _ => None,
    }
}

/// Map a single `TaintFinding` from the PHP engine onto a `Finding`.
fn map_php_taint_finding(
    meta: &PhpTaintRuleMeta<'_>,
    source: &str,
    finding: php_taint::TaintFinding,
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
        dep_version: None,
        dep_ecosystem: None,
        dep_purl: None,
        dep_vulnerability_id: None,
        dep_fixed_version: None,
        dep_source: None,
        dep_vulnerability_severity: None,
        dep_path: vec![],
        crypto_material: None,
    }
}

/// Run every enabled PHP taint rule over `tree` in a single dispatch.
///
/// Mirrors `run_java_taint_batched` in `java.rs`. The intra-file pass always
/// runs (each rule's `TaintSpec` is handed to `php_taint::analyze_tree` in
/// turn). A second cross-file pass runs only when pass-1 summaries and
/// same-package sibling paths are both available (i.e. a multi-file PHP scan),
/// resolving helper calls to sibling files by name (same-directory proxy).
pub fn run_php_taint_batched(
    source: &str,
    tree: &tree_sitter::Tree,
    ctx: &crate::rules::FileContext<'_>,
    enabled_rule_ids: &std::collections::HashSet<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let rule_specs = php_taint::php_taint_rule_specs();
    for (rule_id, spec) in &rule_specs {
        if !enabled_rule_ids.contains(rule_id) {
            continue;
        }
        let Some(meta) = php_taint_meta(rule_id) else {
            continue;
        };
        let raw = php_taint::analyze_tree(tree.root_node(), source, spec, None);
        for finding in raw {
            findings.push(map_php_taint_finding(&meta, source, finding));
        }
    }

    // Cross-file resolution: only when pass-1 summaries and same-package
    // sibling paths are both available (i.e. a multi-file PHP scan).
    if let (Some(summaries), Some(paths)) = (
        ctx.cross_file_summaries,
        ctx.php_same_package_paths.as_ref(),
    ) {
        let allowed: std::collections::HashSet<String> =
            enabled_rule_ids.iter().map(|id| id.to_string()).collect();
        let enabled_specs: Vec<(&str, php_taint::TaintSpec)> = rule_specs
            .iter()
            .filter(|(id, _)| enabled_rule_ids.contains(id))
            .map(|(id, spec)| (*id, spec.clone()))
            .collect();
        let cross = php_taint::CrossFileInfo {
            same_package_paths: paths,
            summaries,
            allowed_rule_ids: &allowed,
        };
        let raw = php_taint::extract_cross_file_findings(
            tree.root_node(),
            source,
            &enabled_specs,
            &cross,
        );
        for finding in raw {
            let Some(rule_id) = finding.rule_id_hint.as_deref() else {
                continue;
            };
            let Some(meta) = php_taint_meta(rule_id) else {
                continue;
            };
            findings.push(map_php_taint_finding(&meta, source, finding));
        }
    }

    findings
}

/// Run a single PHP taint rule over a tree. Used by the rule structs'
/// `check()` path for direct unit tests.
fn run_php_taint_single(
    rule_id: &str,
    source: &str,
    tree: &tree_sitter::Tree,
    spec: &php_taint::TaintSpec,
) -> Vec<Finding> {
    let Some(meta) = php_taint_meta(rule_id) else {
        return Vec::new();
    };
    let raw = php_taint::analyze_tree(tree.root_node(), source, spec, None);
    raw.into_iter()
        .map(|t| map_php_taint_finding(&meta, source, t))
        .collect()
}

// ─── Rule 1: php/taint-command-injection ────────────────────────────────────

pub struct TaintCommandInjection;

impl_rule! {
    TaintCommandInjection,
    id = "php/taint-command-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-78"),
    description = "Untrusted input flows to an OS command execution sink",
    language = Language::Php,
    fn check(_self, source, tree) {
        let spec = php_taint::php_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_php_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Rule 2: php/taint-sql-injection ────────────────────────────────────────

pub struct TaintSqlInjection;

impl_rule! {
    TaintSqlInjection,
    id = "php/taint-sql-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-89"),
    description = "Untrusted input flows to a SQL query execution sink",
    language = Language::Php,
    fn check(_self, source, tree) {
        let spec = php_taint::php_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_php_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Rule 3: php/taint-xss ─────────────────────────────────────────────────

pub struct TaintXss;

impl_rule! {
    TaintXss,
    id = "php/taint-xss",
    severity = Severity::High,
    cwe = Some("CWE-79"),
    description = "Untrusted input flows to an output sink (reflected XSS)",
    language = Language::Php,
    fn check(_self, source, tree) {
        let spec = php_taint::php_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_php_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Rule 4: php/taint-file-inclusion ───────────────────────────────────────

pub struct TaintFileInclusion;

impl_rule! {
    TaintFileInclusion,
    id = "php/taint-file-inclusion",
    severity = Severity::Critical,
    cwe = Some("CWE-98"),
    description = "Untrusted input flows to an include/require sink (LFI/RFI)",
    language = Language::Php,
    fn check(_self, source, tree) {
        let spec = php_taint::php_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_php_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Rule 5: php/taint-unsafe-deserialization ───────────────────────────────

pub struct TaintUnsafeDeserialization;

impl_rule! {
    TaintUnsafeDeserialization,
    id = "php/taint-unsafe-deserialization",
    severity = Severity::Critical,
    cwe = Some("CWE-502"),
    description = "Untrusted input flows to unserialize() (unsafe deserialization)",
    language = Language::Php,
    fn check(_self, source, tree) {
        let spec = php_taint::php_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_php_taint_single(_self.id(), source, tree, &spec)
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
