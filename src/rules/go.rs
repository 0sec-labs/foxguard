use crate::rules::go_taint::{
    self, go_taint_sources, GoImportAliases, NodeMatcher as GoNodeMatcher, TaintSpec as GoTaintSpec,
};
use crate::rules::{FileContext, Rule};
use crate::{Finding, Language, Severity};
use regex::Regex;

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn get_source_line(source: &str, byte_offset: usize) -> String {
    let start = source[..byte_offset].rfind('\n').map_or(0, |p| p + 1);
    let end = source[byte_offset..]
        .find('\n')
        .map_or(source.len(), |p| byte_offset + p);
    source[start..end].to_string()
}

fn walk_tree(
    node: tree_sitter::Node,
    source: &str,
    callback: &mut dyn FnMut(tree_sitter::Node, &str),
) {
    callback(node, source);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_tree(child, source, callback);
    }
}

fn make_finding(
    rule_id: &str,
    severity: Severity,
    cwe: Option<&str>,
    description: &str,
    node: tree_sitter::Node,
    source: &str,
) -> Finding {
    let start = node.start_position();
    let end = node.end_position();
    Finding {
        rule_id: rule_id.to_string(),
        severity,
        cwe: cwe.map(|s| s.to_string()),
        description: description.to_string(),
        file: String::new(),
        line: start.row + 1,
        column: start.column + 1,
        end_line: end.row + 1,
        end_column: end.column + 1,
        snippet: get_source_line(source, node.start_byte()),
    }
}

fn make_finding_from_offsets(
    rule_id: &str,
    severity: Severity,
    cwe: Option<&str>,
    description: &str,
    source: &str,
    start_byte: usize,
    end_byte: usize,
) -> Finding {
    let line = source[..start_byte].bytes().filter(|b| *b == b'\n').count() + 1;
    let line_start = source[..start_byte].rfind('\n').map_or(0, |idx| idx + 1);
    let column = source[line_start..start_byte].chars().count() + 1;

    let end_line = source[..end_byte].bytes().filter(|b| *b == b'\n').count() + 1;
    let end_line_start = source[..end_byte].rfind('\n').map_or(0, |idx| idx + 1);
    let end_column = source[end_line_start..end_byte].chars().count() + 1;

    Finding {
        rule_id: rule_id.to_string(),
        severity,
        cwe: cwe.map(|s| s.to_string()),
        description: description.to_string(),
        file: String::new(),
        line,
        column,
        end_line,
        end_column,
        snippet: get_source_line(source, start_byte),
    }
}

// ─── Rule 1: no-sql-injection ───────────────────────────────────────────────

pub struct NoSqlInjection;

impl Rule for NoSqlInjection {
    fn id(&self) -> &str {
        "go/no-sql-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-89")
    }
    fn description(&self) -> &str {
        "Potential SQL injection via string concatenation or fmt.Sprintf"
    }
    fn language(&self) -> Language {
        Language::Go
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let sql_pattern =
            Regex::new(r"(?i)(SELECT\s+.{0,40}\s+FROM|INSERT\s+INTO|UPDATE\s+.{0,40}\s+SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|CREATE\s+TABLE|EXEC\s+)").unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect: "SELECT ... WHERE id = " + userId (binary_expression with +)
            if node.kind() == "binary_expression" {
                let text = &src[node.byte_range()];
                if text.contains('+') {
                    // Check if left child is a string with SQL
                    if let Some(left) = node.child_by_field_name("left") {
                        if left.kind() == "interpreted_string_literal"
                            || left.kind() == "raw_string_literal"
                        {
                            let left_text = &src[left.byte_range()];
                            if sql_pattern.is_match(left_text) {
                                findings.push(make_finding(
                                    self.id(),
                                    self.severity(),
                                    self.cwe(),
                                    "SQL query built with string concatenation — use parameterized queries",
                                    node,
                                    src,
                                ));
                            }
                        }
                    }
                }
            }

            // Detect: fmt.Sprintf("SELECT ... WHERE id = %s", userId)
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "fmt.Sprintf" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                if first_arg.kind() == "interpreted_string_literal"
                                    || first_arg.kind() == "raw_string_literal"
                                {
                                    let arg_text = &src[first_arg.byte_range()];
                                    if sql_pattern.is_match(arg_text) {
                                        findings.push(make_finding(
                                            self.id(),
                                            self.severity(),
                                            self.cwe(),
                                            "SQL query built with fmt.Sprintf — use parameterized queries",
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

// ─── Rule 2: no-command-injection ───────────────────────────────────────────

pub struct NoCommandInjection;

impl Rule for NoCommandInjection {
    fn id(&self) -> &str {
        "go/no-command-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-78")
    }
    fn description(&self) -> &str {
        "Potential command injection via exec.Command with dynamic input"
    }
    fn language(&self) -> Language {
        Language::Go
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "exec.Command" || func_text == "exec.CommandContext" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                // Flag if the first argument is not a string literal
                                if first_arg.kind() != "interpreted_string_literal"
                                    && first_arg.kind() != "raw_string_literal"
                                {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        "exec.Command called with dynamic argument — risk of command injection",
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

// ─── Rule 3: no-hardcoded-secret ────────────────────────────────────────────

pub struct NoHardcodedSecret;

impl Rule for NoHardcodedSecret {
    fn id(&self) -> &str {
        "go/no-hardcoded-secret"
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
        Language::Go
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let secret_pattern =
            Regex::new(r"(?i)(password|secret|api_?key|token|auth|credential|private_?key)")
                .unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Short variable declaration: password := "hardcoded"
            if node.kind() == "short_var_declaration" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    let left_text = &src[left.byte_range()];
                    if secret_pattern.is_match(left_text) {
                        // Check if right side is a string literal
                        // right is an expression_list, check its first child
                        let value_node = right.named_child(0).unwrap_or(right);
                        if value_node.kind() == "interpreted_string_literal"
                            || value_node.kind() == "raw_string_literal"
                        {
                            let val = &src[value_node.byte_range()];
                            let inner = val.trim_matches(|c| c == '"' || c == '`');
                            if inner.len() >= 4 {
                                findings.push(make_finding(
                                    self.id(),
                                    self.severity(),
                                    self.cwe(),
                                    &format!(
                                        "Hardcoded secret in '{}' — use environment variables",
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

            // var declaration: var password = "hardcoded"
            if node.kind() == "var_spec" {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = &src[name_node.byte_range()];
                    if secret_pattern.is_match(name) {
                        if let Some(value) = node.child_by_field_name("value") {
                            let value_node = value.named_child(0).unwrap_or(value);
                            if value_node.kind() == "interpreted_string_literal"
                                || value_node.kind() == "raw_string_literal"
                            {
                                let val = &src[value_node.byte_range()];
                                let inner = val.trim_matches(|c| c == '"' || c == '`');
                                if inner.len() >= 4 {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        &format!(
                                            "Hardcoded secret in '{}' — use environment variables",
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

            // const declaration: const apiKey = "hardcoded"
            if node.kind() == "const_spec" {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = &src[name_node.byte_range()];
                    if secret_pattern.is_match(name) {
                        if let Some(value) = node.child_by_field_name("value") {
                            let value_node = value.named_child(0).unwrap_or(value);
                            if value_node.kind() == "interpreted_string_literal"
                                || value_node.kind() == "raw_string_literal"
                            {
                                let val = &src[value_node.byte_range()];
                                let inner = val.trim_matches(|c| c == '"' || c == '`');
                                if inner.len() >= 4 {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        &format!(
                                            "Hardcoded secret in '{}' — use environment variables",
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
        });
        findings
    }
}

// ─── Rule 4: no-weak-crypto ────────────────────────────────────────────────

pub struct NoWeakCrypto;

impl Rule for NoWeakCrypto {
    fn id(&self) -> &str {
        "go/no-weak-crypto"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-327")
    }
    fn description(&self) -> &str {
        "Use of weak cryptographic hash (MD5/SHA1)"
    }
    fn language(&self) -> Language {
        Language::Go
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect: md5.New(), md5.Sum(), sha1.New(), sha1.Sum()
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "md5.New"
                        || func_text == "md5.Sum"
                        || func_text == "sha1.New"
                        || func_text == "sha1.Sum"
                    {
                        let algo = if func_text.starts_with("md5") {
                            "MD5"
                        } else {
                            "SHA1"
                        };
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
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

            // Detect import of "crypto/md5" or "crypto/sha1"
            if node.kind() == "import_spec" {
                if let Some(path) = node.child_by_field_name("path") {
                    let path_text = &src[path.byte_range()];
                    if path_text == "\"crypto/md5\"" || path_text == "\"crypto/sha1\"" {
                        let algo = if path_text.contains("md5") {
                            "MD5"
                        } else {
                            "SHA1"
                        };
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            &format!(
                                "Import of weak crypto package {} — use crypto/sha256 or stronger",
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

// ─── Rule 5: gin-no-trusted-proxies ────────────────────────────────────────

pub struct GinNoTrustedProxies;

impl Rule for GinNoTrustedProxies {
    fn id(&self) -> &str {
        "go/gin-no-trusted-proxies"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-346")
    }
    fn description(&self) -> &str {
        "Gin engine created without SetTrustedProxies configuration"
    }
    fn language(&self) -> Language {
        Language::Go
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        // Check if gin.Default() or gin.New() is called
        let has_gin_init = source.contains("gin.Default()") || source.contains("gin.New()");
        let has_trusted_proxies = source.contains("SetTrustedProxies");

        if has_gin_init && !has_trusted_proxies {
            walk_tree(tree.root_node(), source, &mut |node, src| {
                if node.kind() == "call_expression" {
                    if let Some(func) = node.child_by_field_name("function") {
                        let func_text = &src[func.byte_range()];
                        if func_text == "gin.Default" || func_text == "gin.New" {
                            findings.push(make_finding(
                                self.id(),
                                self.severity(),
                                self.cwe(),
                                &format!(
                                    "{}() called without SetTrustedProxies — configure trusted proxies to prevent IP spoofing",
                                    func_text
                                ),
                                node,
                                src,
                            ));
                        }
                    }
                }
            });
        }
        findings
    }
}

// ─── Rule 6: net-http-no-timeout ──────────────────────────────────────────

pub struct NetHttpNoTimeout;

impl Rule for NetHttpNoTimeout {
    fn id(&self) -> &str {
        "go/net-http-no-timeout"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-400")
    }
    fn description(&self) -> &str {
        "http.ListenAndServe without timeout configuration enables slowloris attacks"
    }
    fn language(&self) -> Language {
        Language::Go
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "http.ListenAndServe" || func_text == "http.ListenAndServeTLS" {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            &format!(
                                "{} used without timeout — use http.Server with ReadTimeout/WriteTimeout to prevent slowloris",
                                func_text
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

// ─── Rule 7: no-ssrf ───────────────────────────────────────────────────────

pub struct NoSsrf;

impl Rule for NoSsrf {
    fn id(&self) -> &str {
        "go/no-ssrf"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-918")
    }
    fn description(&self) -> &str {
        "Potential SSRF via http.Get/http.Post with variable URL"
    }
    fn language(&self) -> Language {
        Language::Go
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "http.Get"
                        || func_text == "http.Post"
                        || func_text == "http.Head"
                        || func_text == "http.PostForm"
                        || func_text == "http.NewRequest"
                        || func_text == "http.NewRequestWithContext"
                    {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let url_arg = if func_text == "http.NewRequest" {
                                args.named_child(1)
                            } else if func_text == "http.NewRequestWithContext" {
                                args.named_child(2)
                            } else {
                                args.named_child(0)
                            };

                            if let Some(first_arg) = url_arg {
                                // Flag if URL arg is not a string literal
                                if first_arg.kind() != "interpreted_string_literal"
                                    && first_arg.kind() != "raw_string_literal"
                                {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
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
        });
        findings
    }
}

// ─── Rule 8: insecure-tls-skip-verify ──────────────────────────────────────

pub struct InsecureTlsSkipVerify;

impl Rule for InsecureTlsSkipVerify {
    fn id(&self) -> &str {
        "go/insecure-tls-skip-verify"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-295")
    }
    fn description(&self) -> &str {
        "TLS certificate verification disabled with InsecureSkipVerify"
    }
    fn language(&self) -> Language {
        Language::Go
    }

    fn check(&self, source: &str, _tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let pattern = Regex::new(r"InsecureSkipVerify\s*:\s*true").unwrap();

        for matched in pattern.find_iter(source) {
            findings.push(make_finding_from_offsets(
                self.id(),
                self.severity(),
                self.cwe(),
                "InsecureSkipVerify: true disables TLS certificate verification — prefer proper CA validation",
                source,
                matched.start(),
                matched.end(),
            ));
        }

        findings
    }
}

// ─── Taint rules ───────────────────────────────────────────────────────────
//
// These rules consume the intraprocedural taint engine in
// `go_taint`. They coexist with the conservative `go/no-*`
// counterparts above: the conservative rule fires on any dynamic
// argument at the sink, the taint rule only fires when the argument
// is provably reachable from a known untrusted source within the
// same function / file. Higher precision, lower recall.
//
// Shared sources live in `go_taint::go_taint_sources()`; each rule
// only declares its own sinks.

/// Build a `Call` sink matcher where the canonical path is reused as
/// the sink description — shorthand used by the specs below.
fn go_call_sink(canonical: &str) -> GoNodeMatcher {
    GoNodeMatcher::Call {
        canonical: canonical.into(),
        description: canonical.into(),
    }
}

#[allow(clippy::too_many_arguments)]
fn map_go_taint_findings(
    rule_id: &str,
    severity: Severity,
    cwe: Option<&str>,
    source: &str,
    tree: &tree_sitter::Tree,
    ctx: &FileContext<'_>,
    spec: &GoTaintSpec,
    format_description: impl Fn(&str, &str) -> String,
) -> Vec<Finding> {
    // If the scanner never built a per-file Go alias table (e.g.
    // rules are invoked without FileContext), fall back to building
    // one locally so the rule still works.
    let local_aliases: Option<GoImportAliases> = if ctx.go_aliases.is_none() {
        Some(GoImportAliases::from_tree(source, tree))
    } else {
        None
    };
    let aliases: Option<&GoImportAliases> = ctx.go_aliases.or(local_aliases.as_ref());
    let raw = go_taint::analyze_tree(tree.root_node(), source, spec, aliases);
    raw.into_iter()
        .map(|t| Finding {
            rule_id: rule_id.to_string(),
            severity,
            cwe: cwe.map(|s| s.to_string()),
            description: format_description(&t.source_description, &t.sink_description),
            file: String::new(),
            line: t.sink_line,
            column: t.sink_column,
            end_line: t.sink_end_line,
            end_column: t.sink_end_column,
            snippet: get_source_line(source, t.sink_start_byte),
        })
        .collect()
}

// ─── Rule: taint-command-injection ─────────────────────────────────────────

pub struct TaintCommandInjection;

impl TaintCommandInjection {
    fn spec() -> GoTaintSpec {
        GoTaintSpec {
            sources: go_taint_sources(),
            sinks: vec![
                go_call_sink("exec.Command"),
                go_call_sink("exec.CommandContext"),
            ],
            sanitizers: vec![],
        }
    }
}

impl Rule for TaintCommandInjection {
    fn id(&self) -> &str {
        "go/taint-command-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-78")
    }
    fn description(&self) -> &str {
        "Untrusted input reaches os/exec command execution sink"
    }
    fn language(&self) -> Language {
        Language::Go
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        map_go_taint_findings(
            self.id(),
            self.severity(),
            self.cwe(),
            source,
            tree,
            ctx,
            &Self::spec(),
            |src, sink| {
                format!(
                    "{} reaches {} — untrusted input can inject OS commands",
                    src, sink
                )
            },
        )
    }
}

// ─── Rule: taint-sql-injection ─────────────────────────────────────────────

pub struct TaintSqlInjection;

impl TaintSqlInjection {
    fn spec() -> GoTaintSpec {
        // Go DB execute APIs live on many receiver names
        // (`db`, `conn`, `tx`, `stmt`…). Use `MethodName` matchers so
        // any `.Query(...)`, `.Exec(...)`, `.QueryRow(...)` call with
        // tainted input fires, regardless of the bound variable name.
        // This matches the approach `py/taint-sql-injection` uses.
        GoTaintSpec {
            sources: go_taint_sources(),
            sinks: vec![
                GoNodeMatcher::MethodName {
                    method: "Query".into(),
                    description: "db/tx/stmt.Query".into(),
                },
                GoNodeMatcher::MethodName {
                    method: "QueryContext".into(),
                    description: "db/tx/stmt.QueryContext".into(),
                },
                GoNodeMatcher::MethodName {
                    method: "QueryRow".into(),
                    description: "db/tx/stmt.QueryRow".into(),
                },
                GoNodeMatcher::MethodName {
                    method: "QueryRowContext".into(),
                    description: "db/tx/stmt.QueryRowContext".into(),
                },
                GoNodeMatcher::MethodName {
                    method: "Exec".into(),
                    description: "db/tx/stmt.Exec".into(),
                },
                GoNodeMatcher::MethodName {
                    method: "ExecContext".into(),
                    description: "db/tx/stmt.ExecContext".into(),
                },
                GoNodeMatcher::MethodName {
                    method: "Raw".into(),
                    description: "gorm.DB.Raw".into(),
                },
            ],
            sanitizers: vec![],
        }
    }
}

impl Rule for TaintSqlInjection {
    fn id(&self) -> &str {
        "go/taint-sql-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-89")
    }
    fn description(&self) -> &str {
        "Untrusted input reaches database Query/Exec sink"
    }
    fn language(&self) -> Language {
        Language::Go
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        map_go_taint_findings(
            self.id(),
            self.severity(),
            self.cwe(),
            source,
            tree,
            ctx,
            &Self::spec(),
            |src, sink| format!("{} reaches {} — untrusted input can inject SQL", src, sink),
        )
    }
}

// ─── Rule: taint-ssrf ──────────────────────────────────────────────────────

pub struct TaintSsrf;

impl TaintSsrf {
    fn spec() -> GoTaintSpec {
        GoTaintSpec {
            sources: go_taint_sources(),
            sinks: vec![
                go_call_sink("http.Get"),
                go_call_sink("http.Post"),
                go_call_sink("http.PostForm"),
                go_call_sink("http.NewRequest"),
                go_call_sink("http.NewRequestWithContext"),
                go_call_sink("http.Head"),
            ],
            sanitizers: vec![],
        }
    }
}

impl Rule for TaintSsrf {
    fn id(&self) -> &str {
        "go/taint-ssrf"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-918")
    }
    fn description(&self) -> &str {
        "Untrusted input reaches outbound net/http sink (potential SSRF)"
    }
    fn language(&self) -> Language {
        Language::Go
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        map_go_taint_findings(
            self.id(),
            self.severity(),
            self.cwe(),
            source,
            tree,
            ctx,
            &Self::spec(),
            |src, sink| {
                format!(
                    "{} reaches {} — untrusted input can drive server-side request forgery",
                    src, sink
                )
            },
        )
    }
}
