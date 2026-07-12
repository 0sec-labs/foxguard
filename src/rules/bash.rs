//! First-party Bash/shell taint rules.
//!
//! A single `bash/taint-command-injection` rule consumes the taint engine in
//! [`crate::rules::bash_taint`]. The rule's `check()` looks up its declarative
//! [`bash_taint::TaintSpec`] from [`bash_taint::bash_taint_rule_specs`], hands
//! it to [`bash_taint::analyze_tree`], and maps the returned
//! [`bash_taint::TaintFinding`]s onto the project's [`Finding`] type — the same
//! shape as the C#/Java taint rules.
//!
//! The scanner skips the rule's `check()` when the rule id is registered as a
//! `RegistryTaintSpec` via `builtin_taint_specs_for_language`, running the
//! batched dispatcher [`run_bash_taint_batched`] instead. The `check()` path is
//! kept working so unit tests that construct the Rule struct directly continue
//! to function.

use crate::impl_rule;
use crate::rules::bash_taint;
use crate::rules::common::{confidence_for_hops, get_source_line};
use crate::{Finding, Language, Severity};

// ─── Per-rule metadata ───────────────────────────────────────────────────────

/// Per-rule metadata for Bash taint findings.
struct BashTaintRuleMeta<'a> {
    rule_id: &'a str,
    severity: Severity,
    cwe: Option<&'a str>,
    fix_suggestion: Option<&'a str>,
    format_description: fn(&str, &str) -> String,
}

fn bash_taint_command_injection_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted shell input can inject OS commands")
}

fn bash_taint_path_traversal_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted shell input can traverse to an arbitrary path")
}

fn bash_taint_ssrf_desc(src: &str, sink: &str) -> String {
    format!("{src} reaches {sink} — untrusted shell input can redirect the request to an arbitrary host")
}

fn bash_taint_meta(rule_id: &str) -> Option<BashTaintRuleMeta<'static>> {
    match rule_id {
        "bash/taint-command-injection" => Some(BashTaintRuleMeta {
            rule_id: "bash/taint-command-injection",
            severity: Severity::Critical,
            cwe: Some("CWE-78"),
            fix_suggestion: Some(
                "Do not pass untrusted input to eval/bash -c/sh -c/source; validate against an allowlist or shell-quote with printf %q",
            ),
            format_description: bash_taint_command_injection_desc,
        }),
        "bash/taint-path-traversal" => Some(BashTaintRuleMeta {
            rule_id: "bash/taint-path-traversal",
            severity: Severity::High,
            cwe: Some("CWE-22"),
            fix_suggestion: Some(
                "Validate untrusted input against an allowlist and resolve it under a fixed base directory before passing it to file commands (cat/rm/cp/mv/...)",
            ),
            format_description: bash_taint_path_traversal_desc,
        }),
        "bash/taint-ssrf" => Some(BashTaintRuleMeta {
            rule_id: "bash/taint-ssrf",
            severity: Severity::High,
            cwe: Some("CWE-918"),
            fix_suggestion: Some(
                "Do not build curl/wget URLs from untrusted input; validate the host against an allowlist of trusted endpoints",
            ),
            format_description: bash_taint_ssrf_desc,
        }),
        _ => None,
    }
}

/// Map a single `TaintFinding` from the Bash engine onto a `Finding`.
fn map_bash_taint_finding(
    meta: &BashTaintRuleMeta<'_>,
    source: &str,
    finding: bash_taint::TaintFinding,
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

/// Run every enabled Bash taint rule over `tree` in a single dispatch.
///
/// Mirrors `run_csharp_taint_batched` in `csharp.rs`.
pub fn run_bash_taint_batched(
    source: &str,
    tree: &tree_sitter::Tree,
    enabled_rule_ids: &std::collections::HashSet<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (rule_id, spec) in bash_taint::bash_taint_rule_specs() {
        if !enabled_rule_ids.contains(rule_id) {
            continue;
        }
        let Some(meta) = bash_taint_meta(rule_id) else {
            continue;
        };
        let raw = bash_taint::analyze_tree(tree.root_node(), source, &spec, None);
        for finding in raw {
            findings.push(map_bash_taint_finding(&meta, source, finding));
        }
    }
    findings
}

/// Run a single Bash taint rule over a tree. Used by the rule struct's
/// `check()` path for direct unit tests.
fn run_bash_taint_single(
    rule_id: &str,
    source: &str,
    tree: &tree_sitter::Tree,
    spec: &bash_taint::TaintSpec,
) -> Vec<Finding> {
    let Some(meta) = bash_taint_meta(rule_id) else {
        return Vec::new();
    };
    let raw = bash_taint::analyze_tree(tree.root_node(), source, spec, None);
    raw.into_iter()
        .map(|finding| map_bash_taint_finding(&meta, source, finding))
        .collect()
}

// ─── Rule: bash/taint-command-injection ─────────────────────────────────────

pub struct TaintCommandInjection;

impl_rule! {
    TaintCommandInjection,
    id = "bash/taint-command-injection",
    severity = Severity::Critical,
    cwe = Some("CWE-78"),
    description = "Untrusted shell input reaches a command execution sink",
    language = Language::Bash,
    fn check(_self, source, tree) {
        let spec = bash_taint::bash_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_bash_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Rule: bash/taint-path-traversal ────────────────────────────────────────

pub struct TaintPathTraversal;

impl_rule! {
    TaintPathTraversal,
    id = "bash/taint-path-traversal",
    severity = Severity::High,
    cwe = Some("CWE-22"),
    description = "Untrusted shell input reaches a file-operation sink (path traversal)",
    language = Language::Bash,
    fn check(_self, source, tree) {
        let spec = bash_taint::bash_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_bash_taint_single(_self.id(), source, tree, &spec)
    }
}

// ─── Rule: bash/taint-ssrf ──────────────────────────────────────────────────

pub struct TaintSsrf;

impl_rule! {
    TaintSsrf,
    id = "bash/taint-ssrf",
    severity = Severity::High,
    cwe = Some("CWE-918"),
    description = "Untrusted shell input reaches a curl/wget URL sink (SSRF)",
    language = Language::Bash,
    fn check(_self, source, tree) {
        let spec = bash_taint::bash_taint_rule_specs()
            .into_iter()
            .find(|(id, _)| *id == _self.id())
            .map(|(_, spec)| spec)
            .unwrap_or_default();
        run_bash_taint_single(_self.id(), source, tree, &spec)
    }
}
