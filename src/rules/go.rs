use crate::impl_rule;
use crate::rules::common::AliasTable;
use crate::rules::common::{get_source_line, make_finding, make_finding_from_offsets, walk_tree};
use crate::rules::go_taint::{
    self, go_aliases_from_tree, go_taint_sources, NodeMatcher as GoNodeMatcher,
    TaintSpec as GoTaintSpec,
};
use crate::rules::FileContext;
use crate::{Finding, Language, Severity};
use regex::Regex;

// ─── Rule 1: no-sql-injection ───────────────────────────────────────────────

pub struct NoSqlInjection;

impl_rule! {
    NoSqlInjection,
    id = "go/no-sql-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-89"),
    description = "Potential SQL injection via string concatenation or fmt.Sprintf",
    language = Language::Go,
    fn check(_self, source, tree) {

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
                                            _self.id(),
                                            _self.severity(),
                                            _self.cwe(),
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

impl_rule! {
    NoCommandInjection,
    id = "go/no-command-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-78"),
    description = "Potential command injection via exec.Command with dynamic input",
    language = Language::Go,
    fn check(_self, source, tree) {

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
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
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

impl_rule! {
    NoHardcodedSecret,
    id = "go/no-hardcoded-secret",
    severity = Severity::High,
    cwe = Some("CWE-798"),
    description = "Hardcoded secret or credential detected",
    language = Language::Go,
    fn check(_self, source, tree) {

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
                                    _self.id(),
                                    _self.severity(),
                                    _self.cwe(),
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
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
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
                                        _self.id(),
                                        _self.severity(),
                                        _self.cwe(),
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

impl_rule! {
    NoWeakCrypto,
    id = "go/no-weak-crypto",
    severity = Severity::Medium,
    cwe = Some("CWE-327"),
    description = "Use of weak cryptographic hash (MD5/SHA1)",
    language = Language::Go,
    fn check(_self, source, tree) {

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
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
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

impl_rule! {
    GinNoTrustedProxies,
    id = "go/gin-no-trusted-proxies",
    severity = Severity::Medium,
    cwe = Some("CWE-346"),
    description = "Gin engine created without SetTrustedProxies configuration",
    language = Language::Go,
    fn check(_self, source, tree) {

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
                                _self.id(),
                                _self.severity(),
                                _self.cwe(),
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

impl_rule! {
    NetHttpNoTimeout,
    id = "go/net-http-no-timeout",
    severity = Severity::Medium,
    cwe = Some("CWE-400"),
    description = "http.ListenAndServe without timeout configuration enables slowloris attacks",
    language = Language::Go,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "http.ListenAndServe" || func_text == "http.ListenAndServeTLS" {
                        findings.push(make_finding(
                            _self.id(),
                            _self.severity(),
                            _self.cwe(),
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

impl_rule! {
    NoSsrf,
    id = "go/no-ssrf",
    severity = Severity::High,
    cwe = Some("CWE-918"),
    description = "Potential SSRF via http.Get/http.Post with variable URL",
    language = Language::Go,
    fn check(_self, source, tree) {

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
        });
        findings

    }
}

// ─── Rule 8: insecure-tls-skip-verify ──────────────────────────────────────

pub struct InsecureTlsSkipVerify;

impl_rule! {
    InsecureTlsSkipVerify,
    id = "go/insecure-tls-skip-verify",
    severity = Severity::High,
    cwe = Some("CWE-295"),
    description = "TLS certificate verification disabled with InsecureSkipVerify",
    language = Language::Go,
    fn check(_self, source, _tree) {

        let mut findings = Vec::new();
        let pattern = Regex::new(r"InsecureSkipVerify\s*:\s*true").unwrap();

        for matched in pattern.find_iter(source) {
            findings.push(make_finding_from_offsets(
                _self.id(),
                _self.severity(),
                _self.cwe(),
                "InsecureSkipVerify: true disables TLS certificate verification — prefer proper CA validation",
                source,
                matched.start(),
                matched.end(),
            ));
        }

        findings

    }
}

// ─── Rule 9: no-unsafe-deserialization ─────────────────────────────────────

pub struct NoUnsafeDeserialization;

impl_rule! {
    NoUnsafeDeserialization,
    id = "go/no-unsafe-deserialization",
    severity = Severity::High,
    cwe = Some("CWE-502"),
    description = "Unsafe deserialization via gob or yaml.Unmarshal into interface{}/any",
    language = Language::Go,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "call_expression" {
                return;
            }

            let Some(func) = node.child_by_field_name("function") else {
                return;
            };
            let func_text = &src[func.byte_range()];

            // Flag gob.NewDecoder()
            if func_text == "gob.NewDecoder" {
                findings.push(make_finding(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "Use JSON instead of gob for untrusted input. Unmarshal into concrete types, not interface{}.",
                    node,
                    src,
                ));
                return;
            }

            // Flag yaml.Unmarshal into interface{} or any
            if func_text == "yaml.Unmarshal" {
                let call_text = &src[node.byte_range()];
                if call_text.contains("interface{}") || call_text.contains("any") {
                    findings.push(make_finding(
                        _self.id(),
                        _self.severity(),
                        _self.cwe(),
                        "Use JSON instead of gob for untrusted input. Unmarshal into concrete types, not interface{}.",
                        node,
                        src,
                    ));
                }
            }
        });

        findings

    }
}

// ─── Rule 10: jwt-no-verify ───────────────────────────────────────────────

pub struct JwtNoVerify;

impl_rule! {
    JwtNoVerify,
    id = "go/jwt-no-verify",
    severity = Severity::Critical,
    cwe = Some("CWE-347"),
    description = "JWT parsed without signature verification",
    language = Language::Go,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "call_expression" {
                return;
            }

            let Some(func) = node.child_by_field_name("function") else {
                return;
            };
            let func_text = &src[func.byte_range()];

            // Flag jwt.ParseUnverified
            if func_text == "jwt.ParseUnverified" {
                findings.push(make_finding(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "JWT parsed without verification — use jwt.Parse with a proper key function",
                    node,
                    src,
                ));
                return;
            }

            // Flag jwt.Parse with nil key function
            if func_text == "jwt.Parse" || func_text == "jwt.ParseWithClaims" {
                if let Some(args) = node.child_by_field_name("arguments") {
                    // Key function is the second argument for jwt.Parse,
                    // third for jwt.ParseWithClaims
                    let key_fn_idx = if func_text == "jwt.ParseWithClaims" {
                        2
                    } else {
                        1
                    };
                    if let Some(key_fn_arg) = args.named_child(key_fn_idx) {
                        let key_fn_text = &src[key_fn_arg.byte_range()];
                        if key_fn_text == "nil" {
                            findings.push(make_finding(
                                _self.id(),
                                _self.severity(),
                                _self.cwe(),
                                "JWT parsed with nil key function — provide a proper key validation function",
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

// ─── Rule 11: jwt-hardcoded-secret ────────────────────────────────────────

pub struct JwtHardcodedSecret;

impl_rule! {
    JwtHardcodedSecret,
    id = "go/jwt-hardcoded-secret",
    severity = Severity::High,
    cwe = Some("CWE-798"),
    description = "JWT key function uses a hardcoded secret",
    language = Language::Go,
    fn check(_self, source, tree) {

        let mut findings = Vec::new();
        let hardcoded_byte_re = Regex::new(r#"\[\]byte\(\s*"[^"]{4,}"\s*\)"#).unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() != "call_expression" {
                return;
            }

            let Some(func) = node.child_by_field_name("function") else {
                return;
            };
            let func_text = &src[func.byte_range()];

            if func_text != "jwt.Parse"
                && func_text != "jwt.ParseWithClaims"
                && func_text != "jwt.NewWithClaims"
            {
                return;
            }

            let node_text = &src[node.byte_range()];
            if hardcoded_byte_re.is_match(node_text) {
                findings.push(make_finding(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "JWT secret is hardcoded — load signing keys from environment or a secrets manager",
                    node,
                    src,
                ));
            }
        });

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

struct GoTaintRuleMeta<'a> {
    rule_id: &'a str,
    severity: Severity,
    cwe: Option<&'a str>,
    fix_suggestion: Option<&'a str>,
}

fn map_go_taint_findings(
    meta: &GoTaintRuleMeta<'_>,
    source: &str,
    tree: &tree_sitter::Tree,
    ctx: &FileContext<'_>,
    spec: &GoTaintSpec,
    format_description: impl Fn(&str, &str) -> String,
) -> Vec<Finding> {
    // If the scanner never built a per-file Go alias table (e.g.
    // rules are invoked without FileContext), fall back to building
    // one locally so the rule still works.
    let local_aliases: Option<AliasTable> = if ctx.go_aliases.is_none() {
        Some(go_aliases_from_tree(source, tree))
    } else {
        None
    };
    let aliases: Option<&AliasTable> = ctx.go_aliases.or(local_aliases.as_ref());

    // Build cross-file info if both summaries and same-package paths are available.
    let cross_file_info = match (ctx.cross_file_summaries, ctx.go_same_package_paths.as_ref()) {
        (Some(summaries), Some(paths)) => Some(go_taint::CrossFileInfo {
            same_package_paths: paths,
            summaries,
            rule_filter: go_taint::RuleFilter::Single(meta.rule_id),
        }),
        _ => None,
    };
    let raw = go_taint::analyze_tree_with_cross_file(
        tree.root_node(),
        source,
        spec,
        aliases,
        cross_file_info.as_ref(),
    );
    raw.into_iter()
        .map(|t| Finding {
            rule_id: meta.rule_id.to_string(),
            severity: meta.severity,
            cwe: meta.cwe.map(|s| s.to_string()),
            description: format_description(&t.source_description, &t.sink_description),
            file: String::new(),
            line: t.sink_line,
            column: t.sink_column,
            end_line: t.sink_end_line,
            end_column: t.sink_end_column,
            snippet: get_source_line(source, t.sink_start_byte),
            source_line: Some(t.source_line),
            source_description: Some(t.source_description),
            sink_line: Some(t.sink_line),
            sink_description: Some(t.sink_description),
            fix_suggestion: meta.fix_suggestion.map(|s| s.to_string()),
            sink_start_byte: Some(t.sink_start_byte),
            sink_end_byte: Some(t.sink_end_byte),
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

impl_rule! {
    TaintCommandInjection,
    id = "go/taint-command-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-78"),
    description = "Untrusted input reaches os/exec command execution sink",
    language = Language::Go,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = GoTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some("Go has no standard shell-escape function. Pass arguments as separate elements to `exec.Command(name, arg1, arg2)` instead of building a shell string — this avoids shell interpretation entirely"),
        };
        map_go_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can inject OS commands",
                src, sink
            )
        })

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

impl_rule! {
    TaintSqlInjection,
    id = "go/taint-sql-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-89"),
    description = "Untrusted input reaches database Query/Exec sink",
    language = Language::Go,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = GoTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some("Use parameterized queries: `db.Query(\"SELECT * FROM users WHERE name = $1\", name)`"),
        };
        map_go_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!("{} reaches {} — untrusted input can inject SQL", src, sink)
        })

    }
}

// ─── Rule: taint-ssti ─────────────────────────────────────────────────────

pub struct TaintSsti;

impl TaintSsti {
    fn spec() -> GoTaintSpec {
        GoTaintSpec {
            sources: go_taint_sources(),
            sinks: vec![
                GoNodeMatcher::MethodName {
                    method: "Parse".into(),
                    description: "template.Parse".into(),
                },
                go_call_sink("template.Must"),
                go_call_sink("template.New"),
            ],
            sanitizers: vec![],
        }
    }
}

impl_rule! {
    TaintSsti,
    id = "go/taint-ssti",
    severity = Severity::Critical,
    cwe = Some("CWE-1336"),
    description = "Untrusted input reaches template parsing sink (potential SSTI)",
    language = Language::Go,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = GoTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some("Use pre-defined template files with template.ParseFiles() instead of parsing user-controlled template strings"),
        };
        map_go_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can inject server-side templates",
                src, sink
            )
        })

    }
}

// ─── Rule: taint-xpath-injection ──────────────────────────────────────────

pub struct TaintXpathInjection;

impl TaintXpathInjection {
    fn spec() -> GoTaintSpec {
        GoTaintSpec {
            sources: go_taint_sources(),
            sinks: vec![
                go_call_sink("xmlpath.Compile"),
                go_call_sink("xpath.Compile"),
                go_call_sink("xmlquery.QueryAll"),
                go_call_sink("xmlquery.Query"),
                go_call_sink("htmlquery.QueryAll"),
            ],
            sanitizers: vec![],
        }
    }
}

impl_rule! {
    TaintXpathInjection,
    id = "go/taint-xpath-injection",
    severity = Severity::High,
    cwe = Some("CWE-643"),
    description = "Untrusted input reaches XPath query sink (potential XPath injection)",
    language = Language::Go,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = GoTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some(
                "Validate and sanitize user input before building XPath expressions",
            ),
        };
        map_go_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can inject XPath queries",
                src, sink
            )
        })

    }
}

// ─── Rule: taint-ldap-injection ───────────────────────────────────────────

pub struct TaintLdapInjection;

impl TaintLdapInjection {
    fn spec() -> GoTaintSpec {
        GoTaintSpec {
            sources: go_taint_sources(),
            sinks: vec![
                go_call_sink("ldap.NewSearchRequest"),
                go_call_sink("ldap.SearchRequest"),
                go_call_sink("conn.Search"),
                go_call_sink("client.Search"),
                go_call_sink("l.Search"),
            ],
            sanitizers: vec![],
        }
    }
}

impl_rule! {
    TaintLdapInjection,
    id = "go/taint-ldap-injection",
    severity = Severity::High,
    cwe = Some("CWE-90"),
    description = "Untrusted input reaches LDAP search sink (potential LDAP injection)",
    language = Language::Go,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = GoTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some("Use ldap.EscapeFilter() to sanitize user input before building LDAP filter strings"),
        };
        map_go_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can inject LDAP queries",
                src, sink
            )
        })

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

impl_rule! {
    TaintSsrf,
    id = "go/taint-ssrf",
    severity = Severity::High,
    cwe = Some("CWE-918"),
    description = "Untrusted input reaches outbound net/http sink (potential SSRF)",
    language = Language::Go,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = GoTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some(
                "Validate URLs against an allowlist of permitted hosts before making requests",
            ),
        };
        map_go_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can drive server-side request forgery",
                src, sink
            )
        })

    }
}

// ─── Rule: taint-log-injection ────────────────────────────────────────────

pub struct TaintLogInjection;

impl TaintLogInjection {
    fn spec() -> GoTaintSpec {
        GoTaintSpec {
            sources: go_taint_sources(),
            sinks: vec![
                go_call_sink("log.Printf"),
                go_call_sink("log.Println"),
                go_call_sink("log.Print"),
                go_call_sink("log.Fatalf"),
                go_call_sink("fmt.Printf"),
            ],
            sanitizers: vec![],
        }
    }
}

impl_rule! {
    TaintLogInjection,
    id = "go/taint-log-injection",
    severity = Severity::Medium,
    cwe = Some("CWE-117"),
    description = "Untrusted input reaches a logging sink — possible log injection",
    language = Language::Go,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = GoTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some(
                "Sanitize user input before logging — strip newlines and control characters",
            ),
        };
        map_go_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can forge log entries",
                src, sink
            )
        })

    }
}

// ─── Rule: taint-nosql-injection ────────────────────────────────────────

pub struct TaintNosqlInjection;

impl TaintNosqlInjection {
    fn spec() -> GoTaintSpec {
        GoTaintSpec {
            sources: go_taint_sources(),
            sinks: vec![
                // Use specific Call matchers for .Find() to avoid matching
                // regexp.Find() and other non-MongoDB uses (issue #141).
                GoNodeMatcher::Call {
                    canonical: "collection.Find".into(),
                    description: "MongoDB collection.Find()".into(),
                },
                GoNodeMatcher::Call {
                    canonical: "db.Find".into(),
                    description: "MongoDB db.Find()".into(),
                },
                GoNodeMatcher::MethodName {
                    method: "FindOne".into(),
                    description: "collection.FindOne".into(),
                },
                GoNodeMatcher::MethodName {
                    method: "UpdateOne".into(),
                    description: "collection.UpdateOne".into(),
                },
                GoNodeMatcher::MethodName {
                    method: "UpdateMany".into(),
                    description: "collection.UpdateMany".into(),
                },
                GoNodeMatcher::MethodName {
                    method: "DeleteOne".into(),
                    description: "collection.DeleteOne".into(),
                },
                GoNodeMatcher::MethodName {
                    method: "DeleteMany".into(),
                    description: "collection.DeleteMany".into(),
                },
                GoNodeMatcher::MethodName {
                    method: "Aggregate".into(),
                    description: "collection.Aggregate".into(),
                },
                GoNodeMatcher::MethodName {
                    method: "CountDocuments".into(),
                    description: "collection.CountDocuments".into(),
                },
            ],
            sanitizers: vec![],
        }
    }
}

impl_rule! {
    TaintNosqlInjection,
    id = "go/taint-nosql-injection",
    severity = Severity::High,
    cwe = Some("CWE-943"),
    description = "Untrusted input reaches a MongoDB query sink — possible NoSQL injection",
    language = Language::Go,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = GoTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some(
                "Validate and sanitize user input before building MongoDB queries.",
            ),
        };
        map_go_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can inject NoSQL operators",
                src, sink
            )
        })

    }
}

// ─── Rule: taint-path-traversal ──────────────────────────────────────────

pub struct TaintPathTraversal;

impl TaintPathTraversal {
    fn spec() -> GoTaintSpec {
        GoTaintSpec {
            sources: go_taint_sources(),
            sinks: vec![
                go_call_sink("os.Open"),
                go_call_sink("os.OpenFile"),
                go_call_sink("os.ReadFile"),
                go_call_sink("os.WriteFile"),
                go_call_sink("os.Remove"),
                go_call_sink("os.Stat"),
                go_call_sink("os.MkdirAll"),
                go_call_sink("filepath.Join"),
                go_call_sink("ioutil.ReadFile"),
                go_call_sink("ioutil.WriteFile"),
                GoNodeMatcher::MethodName {
                    method: "Open".into(),
                    description: "http.Dir.Open".into(),
                },
                GoNodeMatcher::MethodName {
                    method: "Create".into(),
                    description: "os.Create".into(),
                },
                GoNodeMatcher::MethodName {
                    method: "ReadFile".into(),
                    description: "afero.ReadFile".into(),
                },
                GoNodeMatcher::MethodName {
                    method: "WriteFile".into(),
                    description: "afero.WriteFile".into(),
                },
            ],
            sanitizers: vec![go_call_sink("filepath.Clean"), go_call_sink("filepath.Abs")],
        }
    }
}

impl_rule! {
    TaintPathTraversal,
    id = "go/taint-path-traversal",
    severity = Severity::High,
    cwe = Some("CWE-22"),
    description = "Untrusted input reaches a filesystem path sink — possible path traversal",
    language = Language::Go,
    fn check_with_context(_self, source, tree, ctx) {

        let meta = GoTaintRuleMeta {
            rule_id: _self.id(),
            severity: _self.severity(),
            cwe: _self.cwe(),
            fix_suggestion: Some(
                "Validate file paths with filepath.Clean() and ensure they don't escape the intended directory",
            ),
        };
        map_go_taint_findings(&meta, source, tree, ctx, &Self::spec(), |src, sink| {
            format!(
                "{} reaches {} — untrusted input can traverse the filesystem",
                src, sink
            )
        })

    }
}

/// All Go taint rule IDs paired with their specs.
///
/// Used by the scanner's pass 1 to extract cross-file summaries: each
/// rule's sinks are tested against function bodies with synthetic
/// per-parameter sources.
pub fn go_taint_rule_specs() -> Vec<(&'static str, GoTaintSpec)> {
    vec![
        ("go/taint-command-injection", TaintCommandInjection::spec()),
        ("go/taint-sql-injection", TaintSqlInjection::spec()),
        ("go/taint-ssti", TaintSsti::spec()),
        ("go/taint-xpath-injection", TaintXpathInjection::spec()),
        ("go/taint-ldap-injection", TaintLdapInjection::spec()),
        ("go/taint-ssrf", TaintSsrf::spec()),
        ("go/taint-log-injection", TaintLogInjection::spec()),
        ("go/taint-nosql-injection", TaintNosqlInjection::spec()),
        ("go/taint-path-traversal", TaintPathTraversal::spec()),
    ]
}

/// Per-rule metadata used by the batched Go taint runner to shape
/// findings (severity, CWE, fix hint, description formatter).
struct GoTaintRuleDispatch {
    meta: GoTaintRuleMeta<'static>,
    format_description: fn(&str, &str) -> String,
}

fn go_taint_command_injection_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted input can inject OS commands")
}
fn go_taint_sql_injection_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted input can inject SQL")
}
fn go_taint_ssti_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted input can inject server-side templates")
}
fn go_taint_xpath_injection_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted input can inject XPath queries")
}
fn go_taint_ldap_injection_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted input can inject LDAP queries")
}
fn go_taint_ssrf_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted input can drive server-side request forgery")
}
fn go_taint_log_injection_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted input can forge log entries")
}
fn go_taint_nosql_injection_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted input can inject NoSQL operators")
}
fn go_taint_path_traversal_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted input can traverse the filesystem")
}

fn go_taint_rule_dispatch_table() -> Vec<GoTaintRuleDispatch> {
    vec![
        GoTaintRuleDispatch {
            meta: GoTaintRuleMeta {
                rule_id: "go/taint-command-injection",
                severity: Severity::Critical,
                cwe: Some("CWE-78"),
                fix_suggestion: Some("Go has no standard shell-escape function. Pass arguments as separate elements to `exec.Command(name, arg1, arg2)` instead of building a shell string — this avoids shell interpretation entirely"),
            },
            format_description: go_taint_command_injection_desc,
        },
        GoTaintRuleDispatch {
            meta: GoTaintRuleMeta {
                rule_id: "go/taint-sql-injection",
                severity: Severity::Critical,
                cwe: Some("CWE-89"),
                fix_suggestion: Some("Use parameterized queries: `db.Query(\"SELECT * FROM users WHERE name = $1\", name)`"),
            },
            format_description: go_taint_sql_injection_desc,
        },
        GoTaintRuleDispatch {
            meta: GoTaintRuleMeta {
                rule_id: "go/taint-ssti",
                severity: Severity::Critical,
                cwe: Some("CWE-1336"),
                fix_suggestion: Some("Use pre-defined template files with template.ParseFiles() instead of parsing user-controlled template strings"),
            },
            format_description: go_taint_ssti_desc,
        },
        GoTaintRuleDispatch {
            meta: GoTaintRuleMeta {
                rule_id: "go/taint-xpath-injection",
                severity: Severity::High,
                cwe: Some("CWE-643"),
                fix_suggestion: Some("Validate and sanitize user input before building XPath expressions"),
            },
            format_description: go_taint_xpath_injection_desc,
        },
        GoTaintRuleDispatch {
            meta: GoTaintRuleMeta {
                rule_id: "go/taint-ldap-injection",
                severity: Severity::High,
                cwe: Some("CWE-90"),
                fix_suggestion: Some("Use ldap.EscapeFilter() to sanitize user input before building LDAP filter strings"),
            },
            format_description: go_taint_ldap_injection_desc,
        },
        GoTaintRuleDispatch {
            meta: GoTaintRuleMeta {
                rule_id: "go/taint-ssrf",
                severity: Severity::High,
                cwe: Some("CWE-918"),
                fix_suggestion: Some("Validate URLs against an allowlist of permitted hosts before making requests"),
            },
            format_description: go_taint_ssrf_desc,
        },
        GoTaintRuleDispatch {
            meta: GoTaintRuleMeta {
                rule_id: "go/taint-log-injection",
                severity: Severity::Medium,
                cwe: Some("CWE-117"),
                fix_suggestion: Some("Sanitize user input before logging — strip newlines and control characters"),
            },
            format_description: go_taint_log_injection_desc,
        },
        GoTaintRuleDispatch {
            meta: GoTaintRuleMeta {
                rule_id: "go/taint-nosql-injection",
                severity: Severity::High,
                cwe: Some("CWE-943"),
                fix_suggestion: Some("Validate and sanitize user input before building MongoDB queries."),
            },
            format_description: go_taint_nosql_injection_desc,
        },
        GoTaintRuleDispatch {
            meta: GoTaintRuleMeta {
                rule_id: "go/taint-path-traversal",
                severity: Severity::High,
                cwe: Some("CWE-22"),
                fix_suggestion: Some("Validate file paths with filepath.Clean() and ensure they don't escape the intended directory"),
            },
            format_description: go_taint_path_traversal_desc,
        },
    ]
}

/// Returns `true` if `rule_id` is one of the built-in Go taint rules
/// handled by [`run_go_taint_batched`]. The scanner uses this to avoid
/// running those rules individually in the per-rule loop.
pub fn is_go_taint_rule_id(rule_id: &str) -> bool {
    rule_id.starts_with("go/taint-")
}

/// Run every built-in Go taint rule over `tree` in a single batched
/// pass, returning per-rule [`Finding`]s.
///
/// This replaces the historical code path where each of the nine Go
/// taint rules called [`go_taint::analyze_tree_with_cross_file`]
/// individually — which recomputed rule-agnostic Pass 1 summaries and
/// re-walked every function body once per rule.
///
/// Rules are grouped by their sanitizer profile so that rules sharing
/// the same sanitizers collapse into a single AST walk. The default
/// ruleset has two groups (no-sanitizer × 8 rules, path-traversal × 1
/// rule), which means 2 walks per file instead of 9.
pub fn run_go_taint_batched(
    source: &str,
    tree: &tree_sitter::Tree,
    ctx: &FileContext<'_>,
    enabled_rule_ids: &std::collections::HashSet<&str>,
) -> Vec<Finding> {
    // Resolve aliases (prefer the one from FileContext).
    let local_aliases: Option<AliasTable> = if ctx.go_aliases.is_none() {
        Some(go_aliases_from_tree(source, tree))
    } else {
        None
    };
    let aliases: Option<&AliasTable> = ctx.go_aliases.or(local_aliases.as_ref());

    let dispatch = go_taint_rule_dispatch_table();
    let rule_specs = go_taint_rule_specs();

    // Only include rules the caller actually registered.
    let rules: Vec<go_taint::BatchedRule<'_>> = rule_specs
        .iter()
        .filter(|(id, _)| enabled_rule_ids.contains(id))
        .map(|(id, spec)| go_taint::BatchedRule { rule_id: id, spec })
        .collect();

    if rules.is_empty() {
        return Vec::new();
    }

    let cross_file_info = match (ctx.cross_file_summaries, ctx.go_same_package_paths.as_ref()) {
        (Some(summaries), Some(paths)) => Some(go_taint::CrossFileInfoBatched {
            same_package_paths: paths,
            summaries,
        }),
        _ => None,
    };

    let raw = go_taint::analyze_tree_batched(
        tree.root_node(),
        source,
        &rules,
        aliases,
        cross_file_info.as_ref(),
    );

    raw.into_iter()
        .filter_map(|(rule_id, t)| {
            let d = dispatch.iter().find(|d| d.meta.rule_id == rule_id)?;
            Some(Finding {
                rule_id: d.meta.rule_id.to_string(),
                severity: d.meta.severity,
                cwe: d.meta.cwe.map(|s| s.to_string()),
                description: (d.format_description)(&t.source_description, &t.sink_description),
                file: String::new(),
                line: t.sink_line,
                column: t.sink_column,
                end_line: t.sink_end_line,
                end_column: t.sink_end_column,
                snippet: get_source_line(source, t.sink_start_byte),
                source_line: Some(t.source_line),
                source_description: Some(t.source_description),
                sink_line: Some(t.sink_line),
                sink_description: Some(t.sink_description),
                fix_suggestion: d.meta.fix_suggestion.map(|s| s.to_string()),
                sink_start_byte: Some(t.sink_start_byte),
                sink_end_byte: Some(t.sink_end_byte),
            })
        })
        .collect()
}
