use std::sync::OnceLock;

use regex::Regex;

use crate::impl_rule;
use crate::rules::common::{
    csharp_hardcoded_secret_re, is_secret_value_long_enough, make_finding, walk_tree,
};
use crate::{Language, Severity};

// ─── Static regex helpers (compiled once) ────────────────────────────────────

fn cs_cors_star_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"WithOrigins\s*\(\s*"\*"\s*\)"#).expect("static C# CORS regex should compile")
    })
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

/// Check whether a `binary_expression` subtree forms a `+` concatenation that
/// has at least one non-literal operand. All-literal concatenations (e.g.
/// `"a" + "b"`) are considered safe and return `false`.
///
/// This walks the tree looking for a `+` `binary_expression`. For the first one
/// found, it flattens the chain of `+` operands and returns `true` only if at
/// least one operand is **not** a string literal (i.e. an identifier, member
/// access, invocation, etc.). It recurses into children otherwise.
fn is_tainting_string_concat(
    node: tree_sitter::Node,
    root: tree_sitter::Node,
    source: &str,
) -> bool {
    if node.kind() == "binary_expression" {
        if let Some(op) = node.child_by_field_name("operator") {
            if &source[op.byte_range()] == "+" {
                // Flatten the `+` chain and inspect operands.
                let mut operands = Vec::new();
                collect_concat_operands(node, source, &mut operands);
                let has_non_literal = operands
                    .iter()
                    .any(|operand| !is_literal_operand(*operand, root, source));
                if has_non_literal {
                    return true;
                }
                // All-literal concat: this particular `+` is safe. Do not
                // recurse into its (literal) children — but a sibling subtree
                // elsewhere may still taint, so fall through to recursion.
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if is_tainting_string_concat(child, root, source) {
            return true;
        }
    }
    false
}

/// Recursively flatten the operands of a `+` `binary_expression` chain.
fn collect_concat_operands<'a>(
    node: tree_sitter::Node<'a>,
    source: &str,
    out: &mut Vec<tree_sitter::Node<'a>>,
) {
    if node.kind() == "binary_expression" {
        if let Some(op) = node.child_by_field_name("operator") {
            if &source[op.byte_range()] == "+" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    collect_concat_operands(left, source, out);
                    collect_concat_operands(right, source, out);
                    return;
                }
            }
        }
    }
    out.push(node);
}

/// Whether an operand of a concatenation is a compile-time constant string:
/// either a string literal directly, or an identifier that resolves to a
/// `const` / string-literal declaration in scope.
fn is_literal_operand(node: tree_sitter::Node, root: tree_sitter::Node, source: &str) -> bool {
    // Unwrap parenthesized expressions.
    let mut n = node;
    while n.kind() == "parenthesized_expression" {
        match n.named_child(0) {
            Some(inner) => n = inner,
            None => break,
        }
    }
    if is_string_literal(n) {
        return true;
    }
    if n.kind() == "identifier" {
        let name = &source[n.byte_range()];
        return identifier_is_const_string(name, n, root, source);
    }
    false
}

/// Recursively collect every `variable_declarator` node whose declared name
/// equals `name`. Preserves the tree's lifetime (unlike the `walk_tree`
/// callback, which restricts node lifetimes to the closure body).
fn collect_declarators_named<'a>(
    node: tree_sitter::Node<'a>,
    name: &str,
    source: &'a str,
    out: &mut Vec<tree_sitter::Node<'a>>,
) {
    if node.kind() == "variable_declarator" {
        if let Some(name_node) = node.child_by_field_name("name") {
            if &source[name_node.byte_range()] == name {
                out.push(node);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_declarators_named(child, name, source, out);
    }
}

/// Find the nearest enclosing local scope (a `block`) for `node`, falling back
/// to the method/constructor/accessor body, then to the root. This lets us
/// resolve a local identifier within its own method without colliding with
/// same-named locals declared in sibling methods.
fn enclosing_scope<'a>(node: tree_sitter::Node<'a>) -> tree_sitter::Node<'a> {
    let mut cur = node;
    while let Some(parent) = cur.parent() {
        if matches!(
            parent.kind(),
            "block"
                | "method_declaration"
                | "constructor_declaration"
                | "accessor_declaration"
                | "local_function_statement"
        ) {
            return parent;
        }
        cur = parent;
    }
    cur
}

/// Resolve a single in-scope declaration of `name` relative to a use site.
///
/// First searches the use site's nearest enclosing method/block scope. If that
/// finds exactly one declaration, returns it. Otherwise (e.g. the identifier is
/// a class-level `const` field) it searches the whole tree from `root` and
/// returns the declaration only if there is exactly one globally — this is the
/// conservative path for fields. Returns `None` on ambiguity or absence.
fn resolve_single_declarator<'a>(
    name: &str,
    use_site: tree_sitter::Node<'a>,
    root: tree_sitter::Node<'a>,
    source: &'a str,
) -> Option<tree_sitter::Node<'a>> {
    let scope = enclosing_scope(use_site);
    let mut local: Vec<tree_sitter::Node> = Vec::new();
    collect_declarators_named(scope, name, source, &mut local);
    if local.len() == 1 {
        return Some(local[0]);
    }
    if !local.is_empty() {
        // Multiple declarations in the same scope — ambiguous, bail.
        return None;
    }
    // Not a local: fall back to a unique whole-tree match (covers fields).
    let mut global: Vec<tree_sitter::Node> = Vec::new();
    collect_declarators_named(root, name, source, &mut global);
    if global.len() == 1 {
        Some(global[0])
    } else {
        None
    }
}

/// Whether `name` resolves to a single declaration whose initializer is a
/// string literal (covers `const string X = "..."` and `string x = "..."`).
fn identifier_is_const_string(
    name: &str,
    use_site: tree_sitter::Node,
    root: tree_sitter::Node,
    source: &str,
) -> bool {
    resolve_single_declarator(name, use_site, root, source)
        .and_then(declarator_initializer)
        .map(is_string_literal)
        .unwrap_or(false)
}

/// Extract the initializer expression node of a `variable_declarator`.
fn declarator_initializer(decl: tree_sitter::Node) -> Option<tree_sitter::Node> {
    let mut init: Option<tree_sitter::Node> = None;
    let mut cursor = decl.walk();
    for child in decl.children(&mut cursor) {
        match child.kind() {
            "equals_value_clause" => {
                init = child.named_child(0);
            }
            "identifier" | "=" => {}
            _ => {
                if init.is_none() && child.is_named() {
                    init = Some(child);
                }
            }
        }
    }
    init
}

/// Names of helper methods that, when invoked, are treated as making their
/// result safe (validated / sanitized / allowlisted). The text is expected to
/// be a call expression like `Validate(x)`, `this.Sanitize(x)`,
/// `helper.AllowlistUrl(x)`.
fn is_sanitizer_call_text(text: &str) -> bool {
    let t = text.trim();
    // Must actually be a call.
    if !t.contains('(') {
        return false;
    }
    // The invoked method name is the identifier immediately before the `(`,
    // i.e. the last `.`-separated segment of the callee.
    let callee = t.split('(').next().unwrap_or(t);
    let method = callee.rsplit('.').next().unwrap_or(callee).trim();
    let lower = method.to_ascii_lowercase();
    lower.starts_with("validate") || lower.starts_with("sanitize") || lower.starts_with("allowlist")
}

/// Whether the text of an initializer/expression is a safe path-building call:
/// `Path.Combine(...)`, `Path.GetFullPath(...)`, or `Path.Join(...)`.
fn is_safe_path_call_text(text: &str) -> bool {
    let t = text.trim_start();
    t.starts_with("Path.Combine") || t.starts_with("Path.GetFullPath") || t.starts_with("Path.Join")
}

/// Given an `argument` node that is (or wraps) a single identifier, find the
/// identifier name. Returns `None` if the argument is not a plain identifier.
fn argument_identifier_name<'a>(arg: tree_sitter::Node<'a>, source: &'a str) -> Option<&'a str> {
    let mut n = arg;
    // `argument` node may wrap the expression.
    if n.kind() == "argument" {
        n = n.named_child(0)?;
    }
    while n.kind() == "parenthesized_expression" {
        n = n.named_child(0)?;
    }
    if n.kind() == "identifier" {
        Some(&source[n.byte_range()])
    } else {
        None
    }
}

/// Trace whether an identifier resolves to a value that is safe for a
/// command / path / URL sink. Searches the tree for a single declaration of
/// `name` and inspects its initializer. Returns `true` when the value is
/// known-safe (string literal, `const`, safe `Path.*` call, or sanitizer call).
///
/// Conservative: if there is no declaration, multiple declarations, or the
/// initializer is anything else, returns `false` (still flag).
fn identifier_is_safe(
    name: &str,
    use_site: tree_sitter::Node,
    root: tree_sitter::Node,
    source: &str,
) -> bool {
    let decl = match resolve_single_declarator(name, use_site, root, source) {
        Some(d) => d,
        None => return false,
    };

    let init = match declarator_initializer(decl) {
        Some(i) => i,
        None => return false,
    };

    if is_string_literal(init) {
        return true;
    }

    let init_text = &source[init.byte_range()];

    is_safe_path_call_text(init_text) || is_sanitizer_call_text(init_text)
}

/// Resolve an `argument` node for a sink: returns `true` if the argument is a
/// string literal, or an identifier that traces to a safe value.
fn sink_argument_is_safe(arg: tree_sitter::Node, root: tree_sitter::Node, source: &str) -> bool {
    // Unwrap `argument` wrapper for literal check.
    let mut inner = arg;
    if inner.kind() == "argument" {
        if let Some(c) = inner.named_child(0) {
            inner = c;
        }
    }
    if is_string_literal(inner) {
        return true;
    }
    let arg_text = &source[inner.byte_range()];
    if arg_text.starts_with('"') || arg_text.starts_with("@\"") || arg_text.starts_with("$\"") {
        return true;
    }
    if is_safe_path_call_text(arg_text) || is_sanitizer_call_text(arg_text) {
        return true;
    }
    if let Some(name) = argument_identifier_name(arg, source) {
        if identifier_is_safe(name, arg, root, source) {
            return true;
        }
    }
    false
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

        let root = tree.root_node();
        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "invocation_expression" {
                let node_text = &src[node.byte_range()];
                let has_sql_method = sql_methods.iter().any(|m| node_text.contains(m));
                if has_sql_method {
                    // Check if any argument contains a tainting binary_expression with +
                    if let Some(args) = node.child_by_field_name("arguments") {
                        if is_tainting_string_concat(args, root, src) {
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
                        if child.kind() == "argument_list" && is_tainting_string_concat(child, root, src) {
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
                    let root = tree.root_node();
                    // Check arguments for non-literal, non-safe values
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        if child.kind() == "argument_list" {
                            let mut arg_cursor = child.walk();
                            for arg in child.named_children(&mut arg_cursor) {
                                if !sink_argument_is_safe(arg, root, src) {
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
                    let root = tree.root_node();
                    // Check if the first argument is a non-literal, non-safe value
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        if child.kind() == "argument_list" {
                            if let Some(first_arg) = child.named_child(0) {
                                if !sink_argument_is_safe(first_arg, root, src) {
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
                    let root = tree.root_node();
                    // Check first argument is non-literal and non-safe
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        if child.kind() == "argument_list" {
                            if let Some(first_arg) = child.named_child(0) {
                                if !sink_argument_is_safe(first_arg, root, src) {
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
                    let root = tree.root_node();
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        if child.kind() == "argument_list" {
                            if let Some(first_arg) = child.named_child(0) {
                                if !sink_argument_is_safe(first_arg, root, src) {
                                    {
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
        let secret_pattern = csharp_hardcoded_secret_re();

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
                                if is_secret_value_long_enough(trimmed) {
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
                                if is_secret_value_long_enough(trimmed) {
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
        // Treat the file as hardened against XXE if it disables DTD processing
        // (`DtdProcessing.Prohibit` / `ProhibitDtd = true`) or nulls out the
        // entity resolver (`XmlResolver = null`). Same-instance tracking is left
        // as follow-up; this remains file-scoped but no longer ignores the
        // `XmlResolver = null` hardening pattern.
        let resolver_nulled = {
            // Match `XmlResolver` followed by `=` and `null`, tolerating
            // whitespace (e.g. `XmlResolver = null`, `XmlResolver=null`).
            source.contains("XmlResolver")
                && source
                    .split("XmlResolver")
                    .skip(1)
                    .any(|after| {
                        let trimmed = after.trim_start();
                        let rest = trimmed.strip_prefix('=').map(|r| r.trim_start());
                        matches!(rest, Some(r) if r.starts_with("null"))
                    })
        };
        let has_dtd_prohibit = source.contains("DtdProcessing.Prohibit")
            || source.contains("ProhibitDtd = true")
            || resolver_nulled;

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
        let root = tree.root_node();

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
                            if is_tainting_string_concat(right, root, src) {
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
                        if child.kind() == "argument_list" && is_tainting_string_concat(child, root, src) {
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
        let cors_star = cs_cors_star_re();

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
