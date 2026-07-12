use crate::impl_rule;
use crate::rules::common::get_source_line;
use crate::rules::solidity_taint;
use crate::{Finding, Language, Severity};

// ═══════════════════════════════════════════════════════════════════════════
// Solidity taint rules
// ═══════════════════════════════════════════════════════════════════════════
//
// Three `solidity/taint-*` rules that consume the intraprocedural taint engine
// in `crate::rules::solidity_taint`. Each rule's `check()` looks up the rule's
// declarative `TaintSpec` from `solidity_taint::solidity_taint_rule_specs()`,
// hands it to `solidity_taint::analyze_tree`, and maps returned
// `TaintFinding`s onto the project's `Finding` type — the same shape as the
// C and Kotlin taint rules.
//
// The scanner skips the rule's `check()` when the same rule id is registered
// as a `RegistryTaintSpec` via `builtin_taint_specs_for_language`, and runs
// the batched dispatcher `run_solidity_taint_batched` instead. The `check()`
// path is kept working so unit tests that construct a Rule struct directly
// continue to function.

/// Per-rule metadata for Solidity taint findings.
struct SolidityTaintRuleMeta<'a> {
    rule_id: &'a str,
    severity: Severity,
    cwe: Option<&'a str>,
    fix_suggestion: Option<&'a str>,
    format_description: fn(&str, &str) -> String,
}

fn solidity_taint_delegatecall_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — delegatecall to an attacker-controlled address runs arbitrary code in this contract's context",
        src, sink
    )
}

fn solidity_taint_selfdestruct_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — guard self-destruction behind an access-control check",
        src, sink
    )
}

fn solidity_taint_unchecked_call_desc(src: &str, sink: &str) -> String {
    format!(
        "{} flows to {} — calling an attacker-controlled address enables reentrancy and fund theft",
        src, sink
    )
}

fn solidity_taint_meta(rule_id: &str) -> Option<SolidityTaintRuleMeta<'static>> {
    match rule_id {
        "solidity/taint-arbitrary-delegatecall" => Some(SolidityTaintRuleMeta {
            rule_id: "solidity/taint-arbitrary-delegatecall",
            severity: Severity::Critical,
            cwe: Some("CWE-829"),
            fix_suggestion: Some(
                "Restrict delegatecall targets to a hard-coded allowlist of trusted implementations",
            ),
            format_description: solidity_taint_delegatecall_desc,
        }),
        "solidity/taint-unprotected-selfdestruct" => Some(SolidityTaintRuleMeta {
            rule_id: "solidity/taint-unprotected-selfdestruct",
            severity: Severity::Critical,
            cwe: Some("CWE-284"),
            fix_suggestion: Some(
                "Gate selfdestruct behind an owner/role check (e.g. an onlyOwner modifier)",
            ),
            format_description: solidity_taint_selfdestruct_desc,
        }),
        "solidity/taint-unchecked-call" => Some(SolidityTaintRuleMeta {
            rule_id: "solidity/taint-unchecked-call",
            severity: Severity::High,
            cwe: Some("CWE-829"),
            fix_suggestion: Some(
                "Validate/allowlist the target address and follow the checks-effects-interactions pattern",
            ),
            format_description: solidity_taint_unchecked_call_desc,
        }),
        _ => None,
    }
}

/// Map a single `TaintFinding` from the Solidity engine onto a `Finding`.
fn map_solidity_taint_finding(
    meta: &SolidityTaintRuleMeta<'_>,
    source: &str,
    finding: solidity_taint::TaintFinding,
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

/// Run every enabled Solidity taint rule over `tree` in a single dispatch.
///
/// Mirrors `run_c_taint_batched` in `c.rs` / `run_kt_taint_batched` in
/// `kotlin.rs`. The Solidity engine is intra-function only with no cross-file
/// work, so there is no Pass 1 summary phase.
pub fn run_solidity_taint_batched(
    source: &str,
    tree: &tree_sitter::Tree,
    enabled_rule_ids: &std::collections::HashSet<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (rule_id, spec) in solidity_taint::solidity_taint_rule_specs() {
        if !enabled_rule_ids.contains(rule_id) {
            continue;
        }
        let Some(meta) = solidity_taint_meta(rule_id) else {
            continue;
        };
        let raw = solidity_taint::analyze_tree(tree.root_node(), source, &spec, None);
        for finding in raw {
            findings.push(map_solidity_taint_finding(&meta, source, finding));
        }
    }
    findings
}

/// Run a single Solidity taint rule over a tree. Used by the rule structs'
/// `check()` path for direct unit tests; the scanner uses
/// [`run_solidity_taint_batched`] to avoid double-dispatch.
fn run_solidity_taint_single(
    rule_id: &str,
    source: &str,
    tree: &tree_sitter::Tree,
    spec: &solidity_taint::TaintSpec,
) -> Vec<Finding> {
    let Some(meta) = solidity_taint_meta(rule_id) else {
        return Vec::new();
    };
    let raw = solidity_taint::analyze_tree(tree.root_node(), source, spec, None);
    raw.into_iter()
        .map(|t| map_solidity_taint_finding(&meta, source, t))
        .collect()
}

fn spec_for(rule_id: &str) -> solidity_taint::TaintSpec {
    solidity_taint::solidity_taint_rule_specs()
        .into_iter()
        .find(|(id, _)| *id == rule_id)
        .map(|(_, spec)| spec)
        .unwrap_or_default()
}

// ─── Rule 1: solidity/taint-arbitrary-delegatecall ──────────────────────────

pub struct TaintArbitraryDelegatecall;

impl_rule! {
    TaintArbitraryDelegatecall,
    id = "solidity/taint-arbitrary-delegatecall",
    severity = Severity::Critical,
    cwe = Some("CWE-829"),
    description = "Attacker-controlled address reaches delegatecall/callcode (arbitrary code execution)",
    language = Language::Solidity,
    fn check(_self, source, tree) {
        run_solidity_taint_single(_self.id(), source, tree, &spec_for(_self.id()))
    }
}

// ─── Rule 2: solidity/taint-unprotected-selfdestruct ────────────────────────

pub struct TaintUnprotectedSelfdestruct;

impl_rule! {
    TaintUnprotectedSelfdestruct,
    id = "solidity/taint-unprotected-selfdestruct",
    severity = Severity::Critical,
    cwe = Some("CWE-284"),
    description = "Attacker-controlled recipient reaches selfdestruct/suicide without an access-control guard",
    language = Language::Solidity,
    fn check(_self, source, tree) {
        run_solidity_taint_single(_self.id(), source, tree, &spec_for(_self.id()))
    }
}

// ─── Rule 3: solidity/taint-unchecked-call ──────────────────────────────────

pub struct TaintUncheckedCall;

impl_rule! {
    TaintUncheckedCall,
    id = "solidity/taint-unchecked-call",
    severity = Severity::High,
    cwe = Some("CWE-829"),
    description = "Attacker-controlled address reaches a low-level .call() (reentrancy / fund theft)",
    language = Language::Solidity,
    fn check(_self, source, tree) {
        run_solidity_taint_single(_self.id(), source, tree, &spec_for(_self.id()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;

    fn scan(rule_id: &str, src: &str) -> Vec<Finding> {
        let tree = parse_file(src, Language::Solidity).expect("solidity should parse");
        run_solidity_taint_single(rule_id, src, &tree, &spec_for(rule_id))
    }

    #[test]
    fn delegatecall_to_param_fires() {
        let src = r#"
contract C {
  function run(address target, bytes data) public {
    target.delegatecall(data);
  }
}
"#;
        let f = scan("solidity/taint-arbitrary-delegatecall", src);
        assert_eq!(f.len(), 1, "expected one finding, got {:?}", f);
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn selfdestruct_of_param_fires() {
        let src = r#"
contract C {
  function kill(address payable target) public {
    selfdestruct(target);
  }
}
"#;
        let f = scan("solidity/taint-unprotected-selfdestruct", src);
        assert_eq!(f.len(), 1, "expected one finding, got {:?}", f);
    }

    #[test]
    fn low_level_call_to_param_fires() {
        let src = r#"
contract C {
  function fwd(address target, bytes data) public {
    target.call(data);
  }
}
"#;
        let f = scan("solidity/taint-unchecked-call", src);
        assert_eq!(f.len(), 1, "expected one finding, got {:?}", f);
    }

    #[test]
    fn delegatecall_to_constant_no_finding() {
        let src = r#"
contract C {
  function run(bytes data) public {
    address(this).delegatecall(data);
  }
}
"#;
        let f = scan("solidity/taint-arbitrary-delegatecall", src);
        assert!(f.is_empty(), "constant receiver must not fire, got {:?}", f);
    }
}
