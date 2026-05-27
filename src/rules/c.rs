use crate::impl_rule;
use crate::rules::c_taint;
use crate::rules::common::get_source_line;
use crate::{Finding, Language, Severity};

// ═══════════════════════════════════════════════════════════════════════════
// C taint rules
// ═══════════════════════════════════════════════════════════════════════════
//
// Four `c/taint-*` rules that consume the taint engine in
// `crate::rules::c_taint`. Each rule's `check()` looks up the rule's
// declarative `TaintSpec` from `c_taint::c_taint_rule_specs()`, hands
// it to `c_taint::analyze_tree`, and maps returned `TaintFinding`s onto
// the project's `Finding` type — same shape as Kotlin taint rules.
//
// The scanner skips the rule's `check()` when the same rule id is
// registered as a `RegistryTaintSpec` via
// `builtin_taint_specs_for_language`, and runs the batched dispatcher
// `run_c_taint_batched` instead. The `check()` path is kept working
// so unit tests that construct a Rule struct directly continue to
// function.

/// Per-rule metadata for C taint findings.
struct CTaintRuleMeta<'a> {
    rule_id: &'a str,
    severity: Severity,
    cwe: Option<&'a str>,
    fix_suggestion: Option<&'a str>,
    format_description: fn(&str, &str) -> String,
}

fn c_taint_format_string_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — use a format string literal (e.g. printf(\"%s\", input))",
        src, sink
    )
}

fn c_taint_command_injection_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — avoid passing untrusted input to OS commands",
        src, sink
    )
}

fn c_taint_buffer_overflow_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — use bounds-checked alternatives (strlcpy, snprintf)",
        src, sink
    )
}

fn c_taint_sql_injection_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — use parameterized queries to prevent SQL injection",
        src, sink
    )
}

fn c_taint_meta(rule_id: &str) -> Option<CTaintRuleMeta<'static>> {
    match rule_id {
        "c/taint-format-string" => Some(CTaintRuleMeta {
            rule_id: "c/taint-format-string",
            severity: Severity::Critical,
            cwe: Some("CWE-134"),
            fix_suggestion: Some(
                "Use a literal format string: printf(\"%s\", input) instead of printf(input)",
            ),
            format_description: c_taint_format_string_desc,
        }),
        "c/taint-command-injection" => Some(CTaintRuleMeta {
            rule_id: "c/taint-command-injection",
            severity: Severity::Critical,
            cwe: Some("CWE-78"),
            fix_suggestion: None,
            format_description: c_taint_command_injection_desc,
        }),
        "c/taint-buffer-overflow" => Some(CTaintRuleMeta {
            rule_id: "c/taint-buffer-overflow",
            severity: Severity::High,
            cwe: Some("CWE-120"),
            fix_suggestion: Some("Use bounds-checked alternatives: strlcpy, strncpy, snprintf"),
            format_description: c_taint_buffer_overflow_desc,
        }),
        "c/taint-sql-injection" => Some(CTaintRuleMeta {
            rule_id: "c/taint-sql-injection",
            severity: Severity::Critical,
            cwe: Some("CWE-89"),
            fix_suggestion: Some("Use parameterized queries: sqlite3_prepare_v2 + sqlite3_bind_*"),
            format_description: c_taint_sql_injection_desc,
        }),
        _ => None,
    }
}

/// Map a single `TaintFinding` from the C engine onto a `Finding`.
fn map_c_taint_finding(
    meta: &CTaintRuleMeta<'_>,
    source: &str,
    finding: c_taint::TaintFinding,
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
    }
}

/// Run every enabled C taint rule over `tree` in a single dispatch.
///
/// Mirrors `run_kt_taint_batched` in `kotlin.rs`.
pub fn run_c_taint_batched(
    source: &str,
    tree: &tree_sitter::Tree,
    enabled_rule_ids: &std::collections::HashSet<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (rule_id, spec) in c_taint::c_taint_rule_specs() {
        if !enabled_rule_ids.contains(rule_id) {
            continue;
        }
        let Some(meta) = c_taint_meta(rule_id) else {
            continue;
        };
        let raw = c_taint::analyze_tree(tree.root_node(), source, &spec, None);
        for finding in raw {
            findings.push(map_c_taint_finding(&meta, source, finding));
        }
    }
    findings
}

/// Run a single C taint rule over a tree. Used by the rule structs'
/// `check()` path for direct unit tests.
fn run_c_taint_single(
    rule_id: &str,
    source: &str,
    tree: &tree_sitter::Tree,
    spec: &c_taint::TaintSpec,
) -> Vec<Finding> {
    let Some(meta) = c_taint_meta(rule_id) else {
        return Vec::new();
    };
    let raw = c_taint::analyze_tree(tree.root_node(), source, spec, None);
    raw.into_iter()
        .map(|t| map_c_taint_finding(&meta, source, t))
        .collect()
}

// ─── Rule 1: c/taint-format-string ─────────────────────────────────────────

pub struct TaintFormatString;

impl_rule! {
    TaintFormatString,
    id = "c/taint-format-string",
    severity = Severity::Critical,
    cwe = Some("CWE-134"),
    description = "Untrusted input used as format string argument",
    language = Language::C,
    fn check(_self, source, tree) {
        let spec = c_taint::c_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_c_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Rule 2: c/taint-command-injection ─────────────────────────────────────

pub struct TaintCommandInjection;

impl_rule! {
    TaintCommandInjection,
    id = "c/taint-command-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-78"),
    description = "Untrusted input flows to command execution sink",
    language = Language::C,
    fn check(_self, source, tree) {
        let spec = c_taint::c_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_c_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Rule 3: c/taint-buffer-overflow ───────────────────────────────────────

pub struct TaintBufferOverflow;

impl_rule! {
    TaintBufferOverflow,
    id = "c/taint-buffer-overflow",
    severity = Severity::High,
    cwe = Some("CWE-120"),
    description = "Untrusted input flows to buffer operation without bounds checking",
    language = Language::C,
    fn check(_self, source, tree) {
        let spec = c_taint::c_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_c_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Rule 4: c/taint-sql-injection ─────────────────────────────────────────

pub struct TaintSqlInjection;

impl_rule! {
    TaintSqlInjection,
    id = "c/taint-sql-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-89"),
    description = "Untrusted input flows to SQL query execution sink",
    language = Language::C,
    fn check(_self, source, tree) {
        let spec = c_taint::c_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_c_taint_single(_self.id(), source, tree, &spec)
    }
}
