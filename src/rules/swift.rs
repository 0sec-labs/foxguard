use std::sync::OnceLock;

use regex::Regex;

use crate::impl_rule;
use crate::rules::common::{
    hardcoded_secret_re, is_secret_value_long_enough, make_finding, make_finding_from_offsets,
    walk_tree,
};
use crate::{Finding, Language, Severity};

// ─── Static regex helpers (compiled once) ────────────────────────────────────

fn swift_weak_crypto_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(CC_MD5|CC_SHA1|\.md5|\.sha1|Insecure\.MD5|Insecure\.SHA1)\b")
            .expect("static Swift weak crypto regex should compile")
    })
}

fn swift_sql_keywords_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s")
            .expect("static Swift SQL keyword regex should compile")
    })
}

fn swift_interp_string_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#""[^"]*\\\([^)]+\)[^"]*""#)
            .expect("static Swift interpolation regex should compile")
    })
}

fn swift_sql_concat_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(execute|prepare|sqlite3_exec)\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^)]*\+\s*"#,
        )
        .expect("static Swift SQL concat regex should compile")
    })
}

fn swift_keychain_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(kSecAttrAccessibleAlways|kSecAttrAccessibleAlwaysThisDeviceOnly)\b")
            .expect("static Swift keychain regex should compile")
    })
}

fn swift_tls_expired_certs_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"allowsExpiredCertificates\s*=\s*true")
            .expect("static Swift TLS regex should compile")
    })
}

fn swift_tls_expired_roots_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"allowsExpiredRoots\s*=\s*true").expect("static Swift TLS regex should compile")
    })
}

fn swift_tls_disable_eval_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\.disableEvaluation").expect("static Swift TLS regex should compile")
    })
}

// ─── Constant-folding support ────────────────────────────────────────────────
//
// Several of the dynamic-argument rules below (command injection, eval-js,
// path traversal, SSRF) used to flag any call whose argument was not an inline
// quoted string literal. That produced false positives whenever the argument
// was a `let`-bound string-literal constant declared earlier in scope, e.g.
//
//     let cmd = "/bin/ls"
//     Process().launchPath = cmd   // <- constant, not user input
//
// `swift_const_string_names` does a cheap source-level pre-pass to collect the
// names of simple `let NAME = "literal"` (and `let NAME: Type = "literal"`)
// declarations whose right-hand side is a plain, non-interpolated string
// literal. Rules can then treat references to these names as safe constants.

fn swift_const_decl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // `let NAME` or `let NAME: Type`, then `=`, then a double-quoted string
        // up to the closing quote. We reject interpolation (`\(`) afterwards.
        Regex::new(r#"(?m)\blet\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^=\n]+?)?=\s*"([^"\\]*)""#)
            .expect("static Swift const decl regex should compile")
    })
}

/// Collect names of `let`-bound, non-interpolated string-literal constants.
fn swift_const_string_names(source: &str) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    for caps in swift_const_decl_re().captures_iter(source) {
        // caps[2] is the (already interpolation-free, since `\` is excluded
        // from the body) string contents. The regex body class `[^"\\]*`
        // rejects both embedded quotes and backslashes, so `\(...)`
        // interpolation never matches here.
        if let Some(name) = caps.get(1) {
            names.insert(name.as_str().to_string());
        }
    }
    names
}

/// Extract the textual contents between the first `(` and the matching final
/// `)` of a call expression's source text. Falls back to the full text if no
/// parentheses are present. Used to feed argument text to `swift_arg_is_constant`.
fn call_args(text: &str) -> &str {
    match (text.find('('), text.rfind(')')) {
        (Some(open), Some(close)) if close > open => &text[open + 1..close],
        _ => text,
    }
}

/// Extract the value text following a labeled argument such as `atPath:` or
/// `path:`, up to the next top-level comma or the end of the call text.
/// Returns `None` if the label is not present.
fn labeled_arg_value<'a>(text: &'a str, label: &str) -> Option<&'a str> {
    let start = text.find(label)? + label.len();
    let rest = &text[start..];
    Some(first_arg(rest))
}

/// Return the first comma-separated argument from a call argument string,
/// ignoring commas nested inside parentheses or brackets. Used to isolate the
/// first positional argument (e.g. the JS string in
/// `evaluateJavaScript(script, completionHandler:)`).
fn first_arg(args: &str) -> &str {
    let mut depth = 0i32;
    for (i, c) in args.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => return &args[..i],
            _ => {}
        }
    }
    args
}

/// Given the textual contents of a call argument list (or assignment RHS),
/// decide whether every "operand" is safe: i.e. a string literal or a known
/// string constant. Returns `false` (unsafe) if the text contains string
/// interpolation, or references an identifier that is not a known constant.
///
/// This is intentionally conservative on the unsafe side: anything we cannot
/// confidently classify as a literal/constant is treated as dynamic.
fn swift_arg_is_constant(arg: &str, consts: &std::collections::HashSet<String>) -> bool {
    let trimmed = arg.trim();
    if trimmed.is_empty() {
        return true;
    }
    // Interpolation is always dynamic.
    if trimmed.contains("\\(") {
        return false;
    }
    // Split on `+` (concatenation) and `,` (array/argument elements), then
    // evaluate each operand independently. Every operand must be either an
    // inline string literal or a known string constant.
    for raw_operand in trimmed.split(['+', ',']) {
        // Strip surrounding whitespace and any leading/trailing grouping or
        // collection delimiters left over from slicing inside a larger
        // expression (e.g. `myPath)` from `removeItem(atPath: myPath)` or
        // `["-la"]` from a `process.arguments` assignment).
        let mut operand = raw_operand
            .trim()
            .trim_start_matches(['(', '[', '{'])
            .trim_end_matches([')', ']', '}'])
            .trim();
        if operand.is_empty() {
            continue;
        }
        // Strip a leading argument label (`name:`) so that
        // `arguments: [safeCmd]` is evaluated as `safeCmd`. Only strip when
        // the prefix is a plain identifier followed by a colon (not `::` and
        // not part of a string literal).
        if let Some((label, rest)) = operand.split_once(':') {
            if !label.is_empty()
                && label.chars().all(|c| c.is_alphanumeric() || c == '_')
                && !rest.starts_with(':')
            {
                operand = rest
                    .trim()
                    .trim_start_matches(['(', '[', '{'])
                    .trim_end_matches([')', ']', '}'])
                    .trim();
            }
        }
        if operand.is_empty() {
            continue;
        }
        // Inline string literal operand.
        if operand.starts_with('"') {
            continue;
        }
        // Bare identifier operand — safe only if it is a known constant.
        let ident: String = operand
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !ident.is_empty() && operand.len() == ident.len() && consts.contains(&ident) {
            continue;
        }
        return false;
    }
    true
}

// ─── Rule 1: no-hardcoded-secret ────────────────────────────────────────────

pub struct NoHardcodedSecret;

impl_rule! {
    NoHardcodedSecret,
    id = "swift/no-hardcoded-secret",
    severity = Severity::High,
    cwe = Some("CWE-798"),
    description = "Hardcoded secret or credential detected",
    language = Language::Swift,
    fn check_with_context(_self, source, tree, ctx) {

        let mut findings = Vec::new();
        let mut reported_lines = std::collections::HashSet::new();
        let secret_pattern = hardcoded_secret_re();

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
                            if is_secret_value_long_enough(inner, ctx.secret_thresholds)
                                && reported_lines.insert(line)
                            {
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
                                if is_secret_value_long_enough(inner, ctx.secret_thresholds)
                                    && reported_lines.insert(line)
                                {
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
        let consts = swift_const_string_names(source);

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                let text = &src[node.byte_range()];
                if text.starts_with("Process(") || text.starts_with("NSTask(") {
                    // A bare constructor (`Process()`) or one whose arguments are
                    // all string literals / known constants is not, by itself,
                    // command injection. Only flag when an argument is dynamic
                    // (interpolation, concatenation with a non-constant, or a
                    // bare non-constant identifier).
                    let args = call_args(text);
                    if !swift_arg_is_constant(args, &consts) {
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
                            "Process/NSTask created with dynamic arguments — ensure arguments are not user-controlled to prevent command injection",
                            node,
                            src,
                        ));
                    }
                }
            }

            // Detect .launchPath or .arguments assignment with non-literal values
            if node.kind() == "assignment" {
                let text = &src[node.byte_range()];
                if text.contains(".launchPath") || text.contains(".arguments") {
                    // The RHS is what matters: flag only if it is dynamic and
                    // not a known string constant.
                    let rhs = text.split_once('=').map(|x| x.1).unwrap_or(text);
                    if !swift_arg_is_constant(rhs, &consts) {
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
        let pattern = swift_weak_crypto_re();

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
        let consts = swift_const_string_names(source);

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                let text = &src[node.byte_range()];
                if text.contains("evaluateJavaScript") {
                    // Extract the argument(s) to evaluateJavaScript(...) and flag
                    // only when dynamic: interpolation, concatenation with a
                    // non-constant, or a bare non-constant identifier. An inline
                    // literal or a known string constant is safe.
                    let args = first_arg(call_args(text));
                    let is_variable_arg = !swift_arg_is_constant(args, &consts);
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
        let sql_keywords = swift_sql_keywords_re();

        // Detect SQL strings with interpolation: "SELECT ... \(variable) ..."
        let interp_string = swift_interp_string_re();
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
        let sql_concat = swift_sql_concat_re();
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
        let pattern = swift_keychain_re();

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

        let patterns: [(&Regex, &str); 3] = [
            (
                swift_tls_expired_certs_re(),
                "allowsExpiredCertificates = true disables certificate expiry validation",
            ),
            (
                swift_tls_expired_roots_re(),
                "allowsExpiredRoots = true disables root certificate expiry validation",
            ),
            (
                swift_tls_disable_eval_re(),
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
        let consts = swift_const_string_names(source);

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
                    // Check the value passed to atPath:/path:. It is dynamic
                    // only if it is neither an inline literal nor a known
                    // string constant.
                    let path_value = labeled_arg_value(text, "atPath:")
                        .or_else(|| labeled_arg_value(text, "path:"));
                    let has_dynamic_path = match path_value {
                        Some(v) => !swift_arg_is_constant(v, &consts),
                        None => false,
                    };
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
        let consts = swift_const_string_names(source);

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                let text = &src[node.byte_range()];

                // Detect URL(string: variable)
                if text.starts_with("URL(string:") || text.starts_with("URL(string :") {
                    // The string: value is dynamic only if it is neither an
                    // inline literal nor a known string constant.
                    let value = text.split_once(':').map(|x| x.1).unwrap_or("");
                    if !swift_arg_is_constant(first_arg(value), &consts) {
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
                    // Dynamic unless an inline http literal or a known string
                    // constant is referenced in the call.
                    let line = node.start_position().row;
                    let mentions_const = consts.iter().any(|c| {
                        // word-boundary-ish containment check
                        text.split(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
                            .any(|w| w == c)
                    });
                    if !text.contains("\"http") && !mentions_const && reported_lines.insert(line) {
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

// ═══════════════════════════════════════════════════════════════════════════
// Swift taint rules
// ═══════════════════════════════════════════════════════════════════════════
//
// The `swift/taint-*` rules below consume the shared taint engine in
// `crate::rules::swift_taint` rather than a bespoke harness. Each rule's
// `check()` looks up the rule's declarative `TaintSpec` from
// `swift_taint::swift_taint_rule_specs()`, hands it to
// `swift_taint::analyze_tree`, and maps returned `TaintFinding`s onto the
// project's `Finding` type — the same shape the Kotlin/C/Go/JS/Python taint
// rules use. Per-rule message formatters and metadata live here; the engine
// and the shared sources/sinks live in `swift_taint.rs`.
//
// The Swift engine recognises a single source shape — a dynamically
// constructed string (interpolation or concatenation with a non-literal
// operand) — flowing into a dangerous call. See `swift_taint.rs` for the
// honest scope notes.
//
// The scanner skips the rule's `check()` when the same rule id is registered
// as a `RegistryTaintSpec` via `builtin_taint_specs_for_language`, and runs
// the batched dispatcher `run_swift_taint_batched` instead. The `check()`
// path is kept working so unit tests that construct a Rule struct directly
// continue to function.

use crate::rules::common::get_source_line;
use crate::rules::swift_taint;

/// Per-rule metadata for Swift taint findings: how to format the message and
/// which fix hint to attach. Mirrors `KtTaintRuleMeta`.
struct SwiftTaintRuleMeta<'a> {
    rule_id: &'a str,
    severity: Severity,
    cwe: Option<&'a str>,
    fix_suggestion: Option<&'a str>,
    format_description: fn(&str, &str) -> String,
}

fn swift_taint_sql_injection_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — use parameterized queries (sqlite3_bind_*) to prevent SQL injection",
        src, sink
    )
}

fn swift_taint_command_injection_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — avoid passing untrusted input to OS commands",
        src, sink
    )
}

fn swift_taint_js_injection_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — sanitize or JSON-encode untrusted input before evaluating it in a web view",
        src, sink
    )
}

fn swift_taint_nsexpression_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — never build an NSExpression format string from untrusted input",
        src, sink
    )
}

fn swift_taint_meta(rule_id: &str) -> Option<SwiftTaintRuleMeta<'static>> {
    match rule_id {
        "swift/taint-sql-injection" => Some(SwiftTaintRuleMeta {
            rule_id: "swift/taint-sql-injection",
            severity: Severity::Critical,
            cwe: Some("CWE-89"),
            fix_suggestion: None,
            format_description: swift_taint_sql_injection_desc,
        }),
        "swift/taint-command-injection" => Some(SwiftTaintRuleMeta {
            rule_id: "swift/taint-command-injection",
            severity: Severity::Critical,
            cwe: Some("CWE-78"),
            fix_suggestion: None,
            format_description: swift_taint_command_injection_desc,
        }),
        "swift/taint-js-injection" => Some(SwiftTaintRuleMeta {
            rule_id: "swift/taint-js-injection",
            severity: Severity::High,
            cwe: Some("CWE-79"),
            fix_suggestion: None,
            format_description: swift_taint_js_injection_desc,
        }),
        "swift/taint-nsexpression-injection" => Some(SwiftTaintRuleMeta {
            rule_id: "swift/taint-nsexpression-injection",
            severity: Severity::High,
            cwe: Some("CWE-95"),
            fix_suggestion: None,
            format_description: swift_taint_nsexpression_desc,
        }),
        _ => None,
    }
}

/// Map a single `TaintFinding` from the Swift engine onto a `Finding`, using
/// the rule's metadata. Mirrors `map_kt_taint_finding`.
fn map_swift_taint_finding(
    meta: &SwiftTaintRuleMeta<'_>,
    source: &str,
    finding: swift_taint::TaintFinding,
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

/// Run every enabled Swift taint rule over `tree` in a single dispatch loop
/// and return per-rule `Finding`s. Mirrors `run_kt_taint_batched`.
pub fn run_swift_taint_batched(
    source: &str,
    tree: &tree_sitter::Tree,
    enabled_rule_ids: &std::collections::HashSet<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (rule_id, spec) in swift_taint::swift_taint_rule_specs() {
        if !enabled_rule_ids.contains(rule_id) {
            continue;
        }
        let Some(meta) = swift_taint_meta(rule_id) else {
            continue;
        };
        let raw = swift_taint::analyze_tree(tree.root_node(), source, &spec, None);
        for finding in raw {
            findings.push(map_swift_taint_finding(&meta, source, finding));
        }
    }
    findings
}

/// Run a single Swift taint rule over a tree. Used by the rule structs'
/// `check()` path for direct unit tests. The scanner uses
/// [`run_swift_taint_batched`] to avoid double-dispatch.
fn run_swift_taint_single(
    rule_id: &str,
    source: &str,
    tree: &tree_sitter::Tree,
    spec: &swift_taint::TaintSpec,
) -> Vec<Finding> {
    let Some(meta) = swift_taint_meta(rule_id) else {
        return Vec::new();
    };
    let raw = swift_taint::analyze_tree(tree.root_node(), source, spec, None);
    raw.into_iter()
        .map(|t| map_swift_taint_finding(&meta, source, t))
        .collect()
}

// ─── Swift taint rule: swift/taint-sql-injection ────────────────────────────

pub struct TaintSqlInjection;

impl_rule! {
    TaintSqlInjection,
    id = "swift/taint-sql-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-89"),
    description = "Dynamically constructed string reaches a SQLite query sink",
    language = Language::Swift,
    fn check(_self, source, tree) {
        let spec = swift_taint::swift_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_swift_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Swift taint rule: swift/taint-command-injection ────────────────────────

pub struct TaintCommandInjection;

impl_rule! {
    TaintCommandInjection,
    id = "swift/taint-command-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-78"),
    description = "Dynamically constructed string reaches an OS command sink",
    language = Language::Swift,
    fn check(_self, source, tree) {
        let spec = swift_taint::swift_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_swift_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Swift taint rule: swift/taint-js-injection ─────────────────────────────

pub struct TaintJsInjection;

impl_rule! {
    TaintJsInjection,
    id = "swift/taint-js-injection",
    severity = Severity::High,
    cwe = Some("CWE-79"),
    description = "Dynamically constructed string reaches WKWebView.evaluateJavaScript",
    language = Language::Swift,
    fn check(_self, source, tree) {
        let spec = swift_taint::swift_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_swift_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Swift taint rule: swift/taint-nsexpression-injection ───────────────────

pub struct TaintNsexpressionInjection;

impl_rule! {
    TaintNsexpressionInjection,
    id = "swift/taint-nsexpression-injection",
    severity = Severity::High,
    cwe = Some("CWE-95"),
    description = "Dynamically constructed string reaches NSExpression(format:)",
    language = Language::Swift,
    fn check(_self, source, tree) {
        let spec = swift_taint::swift_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_swift_taint_single(_self.id(), source, tree, &spec)
    }
}
