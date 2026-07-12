//! First-party Apex (Salesforce) taint rules.
//!
//! A single `apex/taint-soql-injection` rule consumes the taint engine in
//! [`crate::rules::apex_taint`]. The rule's `check()` looks up its declarative
//! [`apex_taint::TaintSpec`] from [`apex_taint::apex_taint_rule_specs`], hands
//! it to [`apex_taint::analyze_tree`], and maps the returned
//! [`apex_taint::TaintFinding`]s onto the project's [`Finding`] type — the same
//! shape as the C#/Bash taint rules.
//!
//! The scanner skips the rule's `check()` when the rule id is registered as a
//! `RegistryTaintSpec` via `builtin_taint_specs_for_language`, running the
//! batched dispatcher [`run_apex_taint_batched`] instead. The `check()` path is
//! kept working so unit tests that construct the Rule struct directly continue
//! to function.

use crate::impl_rule;
use crate::rules::apex_taint;
use crate::rules::common::{confidence_for_hops, get_source_line};
use crate::{Finding, Language, Severity};

// ─── Per-rule metadata ───────────────────────────────────────────────────────

/// Per-rule metadata for Apex taint findings.
struct ApexTaintRuleMeta<'a> {
    rule_id: &'a str,
    severity: Severity,
    cwe: Option<&'a str>,
    fix_suggestion: Option<&'a str>,
    format_description: fn(&str, &str) -> String,
}

fn apex_taint_soql_injection_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted input can inject SOQL")
}

fn apex_taint_sosl_injection_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted input can inject SOSL")
}

fn apex_taint_meta(rule_id: &str) -> Option<ApexTaintRuleMeta<'static>> {
    match rule_id {
        "apex/taint-soql-injection" => Some(ApexTaintRuleMeta {
            rule_id: "apex/taint-soql-injection",
            severity: Severity::Critical,
            cwe: Some("CWE-943"),
            fix_suggestion: Some(
                "Use static SOQL with bind variables, or escape untrusted input with String.escapeSingleQuotes() before building a dynamic query",
            ),
            format_description: apex_taint_soql_injection_desc,
        }),
        "apex/taint-sosl-injection" => Some(ApexTaintRuleMeta {
            rule_id: "apex/taint-sosl-injection",
            severity: Severity::Critical,
            cwe: Some("CWE-943"),
            fix_suggestion: Some(
                "Use a static SOSL FIND clause, or escape untrusted input with String.escapeSingleQuotes() before building a dynamic Search.query()",
            ),
            format_description: apex_taint_sosl_injection_desc,
        }),
        _ => None,
    }
}

/// Map a single `TaintFinding` from the Apex engine onto a `Finding`.
fn map_apex_taint_finding(
    meta: &ApexTaintRuleMeta<'_>,
    source: &str,
    finding: apex_taint::TaintFinding,
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

/// Run every enabled Apex taint rule over `tree` in a single dispatch.
///
/// Mirrors `run_bash_taint_batched` in `bash.rs`. Apex taint is intra-file only.
pub fn run_apex_taint_batched(
    source: &str,
    tree: &tree_sitter::Tree,
    enabled_rule_ids: &std::collections::HashSet<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (rule_id, spec) in apex_taint::apex_taint_rule_specs() {
        if !enabled_rule_ids.contains(rule_id) {
            continue;
        }
        let Some(meta) = apex_taint_meta(rule_id) else {
            continue;
        };
        let raw = apex_taint::analyze_tree(tree.root_node(), source, &spec, None);
        for finding in raw {
            findings.push(map_apex_taint_finding(&meta, source, finding));
        }
    }
    findings
}

/// Run a single Apex taint rule over a tree. Used by the rule struct's
/// `check()` path for direct unit tests.
fn run_apex_taint_single(
    rule_id: &str,
    source: &str,
    tree: &tree_sitter::Tree,
    spec: &apex_taint::TaintSpec,
) -> Vec<Finding> {
    let Some(meta) = apex_taint_meta(rule_id) else {
        return Vec::new();
    };
    let raw = apex_taint::analyze_tree(tree.root_node(), source, spec, None);
    raw.into_iter()
        .map(|finding| map_apex_taint_finding(&meta, source, finding))
        .collect()
}

// ─── Rule: apex/taint-soql-injection ────────────────────────────────────────

pub struct TaintSoqlInjection;

impl_rule! {
    TaintSoqlInjection,
    id = "apex/taint-soql-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-943"),
    description = "Untrusted input reaches a dynamic SOQL query sink",
    language = Language::Apex,
    fn check(_self, source, tree) {
        let spec = apex_taint::apex_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_apex_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Rule: apex/taint-sosl-injection ────────────────────────────────────────

pub struct TaintSoslInjection;

impl_rule! {
    TaintSoslInjection,
    id = "apex/taint-sosl-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-943"),
    description = "Untrusted input reaches a dynamic SOSL query sink",
    language = Language::Apex,
    fn check(_self, source, tree) {
        let spec = apex_taint::apex_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_apex_taint_single(_self.id(), source, tree, &spec)
    }
}
