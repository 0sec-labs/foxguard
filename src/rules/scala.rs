//! First-party Scala taint rules.
//!
//! Two `scala/taint-*` rules consume the intraprocedural taint engine in
//! [`crate::rules::scala_taint`]. Each rule's `check()` looks up its
//! declarative [`scala_taint::TaintSpec`] from
//! [`scala_taint::scala_taint_rule_specs`], hands it to
//! [`scala_taint::analyze_tree`], and maps the returned
//! [`scala_taint::TaintFinding`]s onto the project's [`Finding`] type — the
//! same shape as the C#/Bash taint rules.
//!
//! Scala is intra-file only (no cross-file pass), so the scanner drives it
//! through the `run_scala_taint` adapter registered in the intra-file section
//! of `TAINT_DISPATCH`. The scanner skips a rule's `check()` when its id is
//! registered as a `RegistryTaintSpec` via `builtin_taint_specs_for_language`,
//! running the batched dispatcher [`run_scala_taint_batched`] instead. The
//! `check()` path is kept working so unit tests that construct a Rule struct
//! directly continue to function.

use crate::impl_rule;
use crate::rules::common::{confidence_for_hops, get_source_line};
use crate::rules::scala_taint;
use crate::{Finding, Language, Severity};

// ─── Per-rule metadata ───────────────────────────────────────────────────────

/// Per-rule metadata for Scala taint findings.
struct ScalaTaintRuleMeta<'a> {
    rule_id: &'a str,
    severity: Severity,
    cwe: Option<&'a str>,
    fix_suggestion: Option<&'a str>,
    format_description: fn(&str, &str) -> String,
}

fn scala_taint_sql_injection_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted request input can inject SQL")
}

fn scala_taint_command_injection_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted request input can inject OS commands")
}

fn scala_taint_xss_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted input reaches an HTML output sink (XSS)")
}

fn scala_taint_path_traversal_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted request input can traverse to an arbitrary path")
}

fn scala_taint_ssrf_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted request input can redirect the request to an arbitrary host")
}

fn scala_taint_meta(rule_id: &str) -> Option<ScalaTaintRuleMeta<'static>> {
    match rule_id {
        "scala/taint-sql-injection" => Some(ScalaTaintRuleMeta {
            rule_id: "scala/taint-sql-injection",
            severity: Severity::Critical,
            cwe: Some("CWE-89"),
            fix_suggestion: Some(
                "Use a parameterized PreparedStatement (or a query builder) instead of concatenating request input into SQL",
            ),
            format_description: scala_taint_sql_injection_desc,
        }),
        "scala/taint-command-injection" => Some(ScalaTaintRuleMeta {
            rule_id: "scala/taint-command-injection",
            severity: Severity::Critical,
            cwe: Some("CWE-78"),
            fix_suggestion: Some(
                "Avoid invoking shell commands with request-controlled data; pass a fixed executable and a validated argument sequence",
            ),
            format_description: scala_taint_command_injection_desc,
        }),
        "scala/taint-xss" => Some(ScalaTaintRuleMeta {
            rule_id: "scala/taint-xss",
            severity: Severity::High,
            cwe: Some("CWE-79"),
            fix_suggestion: Some(
                "HTML-escape untrusted values before rendering them; avoid wrapping request input in Html(...) which bypasses Play's auto-escaping",
            ),
            format_description: scala_taint_xss_desc,
        }),
        "scala/taint-path-traversal" => Some(ScalaTaintRuleMeta {
            rule_id: "scala/taint-path-traversal",
            severity: Severity::High,
            cwe: Some("CWE-22"),
            fix_suggestion: Some(
                "Validate request input against an allowlist and resolve it under a fixed base directory before opening a file (Source.fromFile / Paths.get)",
            ),
            format_description: scala_taint_path_traversal_desc,
        }),
        "scala/taint-ssrf" => Some(ScalaTaintRuleMeta {
            rule_id: "scala/taint-ssrf",
            severity: Severity::High,
            cwe: Some("CWE-918"),
            fix_suggestion: Some(
                "Do not build URLs from request input; validate the host against an allowlist of trusted endpoints before calling Source.fromURL / WSClient.url",
            ),
            format_description: scala_taint_ssrf_desc,
        }),
        _ => None,
    }
}

/// Map a single `TaintFinding` from the Scala engine onto a `Finding`.
fn map_scala_taint_finding(
    meta: &ScalaTaintRuleMeta<'_>,
    source: &str,
    finding: scala_taint::TaintFinding,
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
        source_line: Some(finding.source_line),
        source_description: Some(finding.source_description),
        sink_line: Some(finding.sink_line),
        sink_description: Some(finding.sink_description),
        fix_suggestion: meta.fix_suggestion.map(|s| s.to_string()),
        sink_start_byte: Some(finding.sink_start_byte),
        sink_end_byte: Some(finding.sink_end_byte),
        confidence: confidence_for_hops(finding.hops),
        taint_hops: Some(finding.hops),
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

/// Run every enabled Scala taint rule over `tree` in a single dispatch.
///
/// Scala is intra-file only, so — unlike the C#/Java batched runners — there is
/// no cross-file resolution pass. Mirrors `run_bash_taint_batched` in `bash.rs`.
pub fn run_scala_taint_batched(
    source: &str,
    tree: &tree_sitter::Tree,
    enabled_rule_ids: &std::collections::HashSet<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (rule_id, spec) in scala_taint::scala_taint_rule_specs() {
        if !enabled_rule_ids.contains(rule_id) {
            continue;
        }
        let Some(meta) = scala_taint_meta(rule_id) else {
            continue;
        };
        let raw = scala_taint::analyze_tree(tree.root_node(), source, &spec, None);
        for finding in raw {
            findings.push(map_scala_taint_finding(&meta, source, finding));
        }
    }
    findings
}

/// Run a single Scala taint rule over a tree. Used by the rule structs'
/// `check()` path for direct unit tests.
fn run_scala_taint_single(
    rule_id: &str,
    source: &str,
    tree: &tree_sitter::Tree,
    spec: &scala_taint::TaintSpec,
) -> Vec<Finding> {
    let Some(meta) = scala_taint_meta(rule_id) else {
        return Vec::new();
    };
    let raw = scala_taint::analyze_tree(tree.root_node(), source, spec, None);
    raw.into_iter()
        .map(|finding| map_scala_taint_finding(&meta, source, finding))
        .collect()
}

// ─── Rule 1: scala/taint-sql-injection ──────────────────────────────────────

pub struct TaintSqlInjection;

impl_rule! {
    TaintSqlInjection,
    id = "scala/taint-sql-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-89"),
    description = "Untrusted request input reaches a SQL query sink",
    language = Language::Scala,
    fn check(_self, source, tree) {
        let spec = scala_taint::scala_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_scala_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Rule 2: scala/taint-command-injection ──────────────────────────────────

pub struct TaintCommandInjection;

impl_rule! {
    TaintCommandInjection,
    id = "scala/taint-command-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-78"),
    description = "Untrusted request input reaches a command execution sink",
    language = Language::Scala,
    fn check(_self, source, tree) {
        let spec = scala_taint::scala_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_scala_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Rule 3: scala/taint-xss ────────────────────────────────────────────────

pub struct TaintXss;

impl_rule! {
    TaintXss,
    id = "scala/taint-xss",
    severity = Severity::High,
    cwe = Some("CWE-79"),
    description = "Untrusted request input reaches an HTML output sink",
    language = Language::Scala,
    fn check(_self, source, tree) {
        let spec = scala_taint::scala_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_scala_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Rule 4: scala/taint-path-traversal ─────────────────────────────────────

pub struct TaintPathTraversal;

impl_rule! {
    TaintPathTraversal,
    id = "scala/taint-path-traversal",
    severity = Severity::High,
    cwe = Some("CWE-22"),
    description = "Untrusted request input reaches a file-open sink (path traversal)",
    language = Language::Scala,
    fn check(_self, source, tree) {
        let spec = scala_taint::scala_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_scala_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Rule 5: scala/taint-ssrf ───────────────────────────────────────────────

pub struct TaintSsrf;

impl_rule! {
    TaintSsrf,
    id = "scala/taint-ssrf",
    severity = Severity::High,
    cwe = Some("CWE-918"),
    description = "Untrusted request input reaches a URL-fetch sink (SSRF)",
    language = Language::Scala,
    fn check(_self, source, tree) {
        let spec = scala_taint::scala_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_scala_taint_single(_self.id(), source, tree, &spec)
    }
}
