//! Intraprocedural, flow-insensitive taint analysis for Apex (Salesforce).
//!
//! # Scope
//!
//! Mirrors the other language engines (`java_taint`, `solidity_taint`):
//!
//! - **Per method.** Each `method_declaration` / `constructor_declaration`
//!   body is analyzed independently; taint does not cross method boundaries.
//! - **Per file.** No cross-file analysis.
//! - **Flow-insensitive.** Statements are processed in source order; a clean
//!   reassignment clears a name.
//!
//! Apex's tree-sitter grammar (`tree-sitter-sfapex`) closely resembles Java:
//! the node vocabulary and field names are nearly identical.
//!
//! # Apex grammar node kinds used here (tree-sitter-sfapex)
//!
//! - `method_declaration` / `constructor_declaration` — fields: `name`,
//!   `parameters` (a `formal_parameters` node), `body` (a `block`).
//! - `formal_parameters` → repeated `formal_parameter` children, each with a
//!   `type` and a `name` `identifier`.
//! - `local_variable_declaration` → `declarator` (`variable_declarator` with
//!   fields `name` and `value`).
//! - `assignment_expression` — fields `left`, `right`.
//! - `method_invocation` — fields `object` (receiver), `name`, `arguments`
//!   (an `argument_list`).
//!
//! # Matcher interpretation
//!
//! The Semgrep bridge compiles the Apex taint rules to:
//!
//! - A **source** [`NodeMatcher::ParamName`] whose name is the any-parameter
//!   wildcard (compiled from a `$M(..., String $P, ...) { ... }` +
//!   `focus-metavariable: $P` source block). Every parameter of the enclosing
//!   method is seeded as tainted — matching Semgrep's any-parameter semantics.
//! - A **source** [`NodeMatcher::Call`] (`ApexPage.getCurrentPage` …) matched
//!   against a call whose resolved callee equals it (request-parameter reads).
//! - A **sink** [`NodeMatcher::Call`] (`Database.query`, `req.setHeader`)
//!   matched against a call whose receiver/name resolve to it AND a tainted
//!   value flows into its argument list.
//! - A **sanitizer** [`NodeMatcher::Call`] (`String.escapeSingleQuotes`) that
//!   produces a clean value.

use crate::rules::common::{walk_tree, AliasTable};
use crate::rules::taint_engine::{node_text, walk_scope_nodes as walk_taint_scope_nodes};
pub use crate::rules::taint_engine::{NodeMatcher, TaintFinding, TaintSpec};
use std::collections::HashMap;
use tree_sitter::Node;

#[derive(Clone, Debug)]
struct TaintInfo {
    description: String,
    line: usize,
    hops: u8,
}

#[derive(Default)]
struct TaintState {
    tainted: HashMap<String, TaintInfo>,
}

impl TaintState {
    fn taint(&mut self, name: String, info: TaintInfo) {
        self.tainted.insert(name, info);
    }

    fn clear(&mut self, name: &str) {
        self.tainted.remove(name);
    }

    fn info(&self, name: &str) -> Option<&TaintInfo> {
        self.tainted.get(name)
    }
}

// ─── Built-in specs ──────────────────────────────────────────────────────────

/// All Apex taint rule IDs paired with their specs.
pub fn apex_taint_rule_specs() -> Vec<(&'static str, TaintSpec)> {
    vec![
        ("apex/taint-soql-injection", soql_injection_spec()),
        ("apex/taint-sosl-injection", sosl_injection_spec()),
    ]
}

/// Shared sources for Apex taint rules — untrusted request inputs.
///
/// Two source shapes the engine actually fires on (verified empirically on the
/// tree-sitter-sfapex grammar):
///
/// * `ParamName` wildcard — every method / constructor parameter is seeded as
///   tainted at scope entry. Apex controller and `@AuraEnabled` / REST methods
///   receive their untrusted input as parameters, so any parameter reaching a
///   dynamic SOQL sink is a classic SOQL-injection vector.
/// * `Call` — request-parameter reads. `ApexPages.currentPage().getParameters()
///   .get('x')` is the Visualforce page-parameter accessor; the outer call is a
///   `.get(...)` whose receiver text contains `getParameters()`, so a canonical
///   of `getParameters.get` matches it (and only it — a bare `Map.get` has no
///   `getParameters` receiver).
pub fn apex_taint_sources() -> Vec<NodeMatcher> {
    vec![
        NodeMatcher::ParamName {
            names: vec![crate::rules::taint_engine::ANY_PARAM_WILDCARD.into()],
            description: "untrusted method parameter".into(),
        },
        // Visualforce page parameter: ApexPages.currentPage().getParameters().get('id')
        NodeMatcher::Call {
            canonical: "getParameters.get".into(),
            description: "ApexPages page parameter".into(),
        },
    ]
}

/// Shared sanitizers for Apex taint rules. `String.escapeSingleQuotes` escapes
/// single quotes in a string, neutralizing SOQL/SOSL injection, so a value
/// derived from it is treated as clean.
pub fn apex_taint_sanitizers() -> Vec<NodeMatcher> {
    vec![NodeMatcher::Call {
        canonical: "String.escapeSingleQuotes".into(),
        description: "String.escapeSingleQuotes()".into(),
    }]
}

/// Dynamic-SOQL sinks: a tainted value flowing into one of these executes an
/// attacker-controlled query (SOQL injection — the signature Apex vulnerability).
pub fn apex_taint_sinks() -> Vec<NodeMatcher> {
    vec![
        NodeMatcher::Call {
            canonical: "Database.query".into(),
            description: "Database.query() (dynamic SOQL)".into(),
        },
        NodeMatcher::Call {
            canonical: "Database.countQuery".into(),
            description: "Database.countQuery() (dynamic SOQL)".into(),
        },
        NodeMatcher::Call {
            canonical: "Database.getQueryLocator".into(),
            description: "Database.getQueryLocator() (dynamic SOQL)".into(),
        },
    ]
}

fn soql_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: apex_taint_sources(),
        sinks: apex_taint_sinks(),
        sanitizers: apex_taint_sanitizers(),
    }
}

/// Dynamic-SOSL sinks: `Search.query(sosl)` executes an attacker-controlled
/// full-text search string (SOSL injection — the SOSL analogue of SOQL
/// injection, CWE-943). `String.escapeSingleQuotes` neutralizes it, so it is
/// carried as the shared sanitizer.
pub fn apex_taint_sosl_sinks() -> Vec<NodeMatcher> {
    vec![NodeMatcher::Call {
        canonical: "Search.query".into(),
        description: "Search.query() (dynamic SOSL)".into(),
    }]
}

fn sosl_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: apex_taint_sources(),
        sinks: apex_taint_sosl_sinks(),
        sanitizers: apex_taint_sanitizers(),
    }
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Run the Apex taint engine over every method / constructor inside `root`,
/// returning one [`TaintFinding`] per source→sink flow.
pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    _aliases: Option<&AliasTable>,
) -> Vec<TaintFinding> {
    let mut findings = Vec::new();
    walk_tree(root, source, &mut |node, src| {
        if is_scope_node(node.kind()) {
            analyze_scope(node, src, spec, &mut findings);
        }
    });
    findings
}

// ─── Per-scope analysis ──────────────────────────────────────────────────────

fn analyze_scope(
    scope_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    out: &mut Vec<TaintFinding>,
) {
    let body = find_scope_body(scope_node).unwrap_or(scope_node);
    let mut state = TaintState::default();
    collect_param_sources(scope_node, source, spec, &mut state);

    // A few fixed passes cover the common `source -> local -> derived -> sink`
    // chain without a full fixed-point loop.
    for _ in 0..3 {
        propagate_assignments(body, source, spec, &mut state);
    }
    find_sinks(body, source, spec, &state, out);
}

fn collect_param_sources(
    scope_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &mut TaintState,
) {
    let mut bare_names: Vec<&str> = Vec::new();
    // `$`-prefixed name (the any-parameter wildcard) is compiled from a Semgrep
    // `$M(..., $P, ...) { ... }` + `focus-metavariable: $P` source block: seed
    // *every* parameter of the enclosing method.
    let mut wildcard = false;
    for matcher in &spec.sources {
        if let NodeMatcher::ParamName { names, .. } = matcher {
            for name in names {
                if name == crate::rules::taint_engine::ANY_PARAM_WILDCARD || name.starts_with('$') {
                    wildcard = true;
                } else {
                    bare_names.push(name.as_str());
                }
            }
        }
    }

    for node in scope_parameter_nodes(scope_node) {
        let Some(name) = formal_parameter_name(node, source) else {
            continue;
        };
        if bare_names.contains(&name) || wildcard {
            state.taint(
                name.to_string(),
                TaintInfo {
                    description: format!("untrusted parameter '{name}'"),
                    line: node.start_position().row + 1,
                    hops: 0,
                },
            );
        }
    }
}

fn propagate_assignments(scope: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    walk_scope_nodes(scope, source, &mut |node, src| {
        if node.kind() == "variable_declarator" {
            let Some(name_node) = node.child_by_field_name("name") else {
                return;
            };
            let name = node_text(name_node, src).to_string();
            let Some(value) = node.child_by_field_name("value") else {
                return;
            };
            match expression_taint(value, src, spec, state) {
                Some(info) => state.taint(name, bump_hops(info)),
                None => state.clear(&name),
            }
        }

        if node.kind() == "assignment_expression" {
            let Some(left) = node.child_by_field_name("left") else {
                return;
            };
            let Some(name) = assignment_target_name(left, src) else {
                return;
            };
            let Some(right) = node.child_by_field_name("right") else {
                return;
            };
            match expression_taint(right, src, spec, state) {
                Some(info) => state.taint(name.to_string(), bump_hops(info)),
                None => state.clear(name),
            }
        }
    });
}

fn find_sinks(
    scope: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
    out: &mut Vec<TaintFinding>,
) {
    walk_scope_nodes(scope, source, &mut |node, src| {
        if node.kind() != "method_invocation" {
            return;
        }
        let Some(sink_description) = match_sink(node, src, spec) else {
            return;
        };
        if let Some(info) = sink_argument_taint(node, src, spec, state) {
            out.push(taint_finding_for_node(node, info, sink_description));
        }
    });
}

// ─── Taint evaluation ────────────────────────────────────────────────────────

fn expression_taint(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
) -> Option<TaintInfo> {
    let text = node_text(node, source);
    if let Some(info) = state.info(text) {
        return Some(info.clone());
    }

    if node.kind() == "identifier" {
        return state.info(text).cloned();
    }

    // A sanitizer call (`String.escapeSingleQuotes(...)`) produces a clean
    // value regardless of its arguments.
    if is_sanitizer_call(node, source, spec) {
        return None;
    }

    // A call that is itself a taint source (`ApexPage.getCurrentPage()....get`).
    if let Some(description) = classify_source_expr(node, source, spec) {
        return Some(TaintInfo {
            description,
            line: node.start_position().row + 1,
            hops: 0,
        });
    }

    // Member call on a tainted receiver propagates taint.
    if node.kind() == "method_invocation" {
        if let Some(receiver) = node.child_by_field_name("object") {
            if let Some(info) = expression_taint(receiver, source, spec, state) {
                return Some(bump_hops(info));
            }
        }
    }

    // Taint flows from any tainted argument.
    if let Some(args) = call_arguments(node) {
        if let Some(info) = expression_taint(args, source, spec, state) {
            return Some(bump_hops(info));
        }
    }

    // Generic: descend (covers `binary_expression` string concatenation,
    // `argument_list`, etc.).
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(info) = expression_taint(child, source, spec, state) {
            return Some(info);
        }
    }
    None
}

fn classify_source_expr(node: Node<'_>, source: &str, spec: &TaintSpec) -> Option<String> {
    if node.kind() != "method_invocation" {
        return None;
    }
    spec.sources.iter().find_map(|matcher| match matcher {
        NodeMatcher::Call {
            canonical,
            description,
        } if call_matches_canonical(node, source, canonical) => Some(description.clone()),
        _ => None,
    })
}

fn is_sanitizer_call(node: Node<'_>, source: &str, spec: &TaintSpec) -> bool {
    spec.sanitizers
        .iter()
        .any(|matcher| matcher_matches_call(matcher, node, source))
}

fn match_sink(node: Node<'_>, source: &str, spec: &TaintSpec) -> Option<String> {
    spec.sinks.iter().find_map(|matcher| {
        if matcher_matches_call(matcher, node, source) {
            Some(matcher.description().to_string())
        } else {
            None
        }
    })
}

fn matcher_matches_call(matcher: &NodeMatcher, node: Node<'_>, source: &str) -> bool {
    if node.kind() != "method_invocation" {
        return false;
    }
    match matcher {
        NodeMatcher::MethodName { method, .. } => {
            call_method_name(node, source).is_some_and(|actual| actual == method)
        }
        NodeMatcher::Call { canonical, .. } => call_matches_canonical(node, source, canonical),
        _ => false,
    }
}

/// Match a `method_invocation` against a Semgrep dotted callee `canonical`.
///
/// `Database.query` → receiver `Database`, method `query`. A bare canonical
/// (`query`) matches any receiver with that method name.
fn call_matches_canonical(node: Node<'_>, source: &str, canonical: &str) -> bool {
    let Some(method) = call_method_name(node, source) else {
        return false;
    };
    match canonical.rsplit_once('.') {
        Some((expected_receiver, expected_method)) => {
            if method != expected_method {
                return false;
            }
            let Some(receiver) = call_receiver_text(node, source) else {
                return false;
            };
            let receiver_lower = receiver.to_ascii_lowercase();
            receiver_lower.contains(&expected_receiver.to_ascii_lowercase())
        }
        None => method == canonical,
    }
}

fn sink_argument_taint(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
) -> Option<TaintInfo> {
    call_arguments(node).and_then(|args| expression_taint(args, source, spec, state))
}

fn bump_hops(mut info: TaintInfo) -> TaintInfo {
    info.hops = info.hops.saturating_add(1);
    info
}

fn taint_finding_for_node(
    node: Node<'_>,
    source_info: TaintInfo,
    sink_description: String,
) -> TaintFinding {
    let start = node.start_position();
    let end = node.end_position();
    TaintFinding {
        sink_start_byte: node.start_byte(),
        sink_end_byte: node.end_byte(),
        sink_line: start.row + 1,
        sink_column: start.column + 1,
        sink_end_line: end.row + 1,
        sink_end_column: end.column + 1,
        source_description: source_info.description,
        sink_description,
        source_line: source_info.line,
        source_range: None,
        rule_id_hint: None,
        hops: source_info.hops.max(1),
    }
}

// ─── AST helpers ─────────────────────────────────────────────────────────────

fn walk_scope_nodes(scope: Node<'_>, source: &str, visitor: &mut impl FnMut(Node<'_>, &str)) {
    walk_taint_scope_nodes(scope, source, is_scope_node, visitor);
}

fn is_scope_node(kind: &str) -> bool {
    matches!(kind, "method_declaration" | "constructor_declaration")
}

fn scope_parameter_nodes<'a>(scope_node: Node<'a>) -> Vec<Node<'a>> {
    if let Some(parameters) = scope_node.child_by_field_name("parameters") {
        return direct_formal_parameters(parameters);
    }
    let mut params = Vec::new();
    let mut cursor = scope_node.walk();
    for child in scope_node.children(&mut cursor) {
        match child.kind() {
            "formal_parameter" => params.push(child),
            "formal_parameters" => params.extend(direct_formal_parameters(child)),
            _ => {}
        }
    }
    params
}

fn direct_formal_parameters<'a>(parameters: Node<'a>) -> Vec<Node<'a>> {
    let mut params = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.children(&mut cursor) {
        if child.kind() == "formal_parameter" {
            params.push(child);
        }
    }
    params
}

fn find_scope_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body").or_else(|| {
        let mut cursor = node.walk();
        let body = node
            .children(&mut cursor)
            .find(|child| child.kind() == "block");
        body
    })
}

fn call_method_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "method_invocation" {
        return None;
    }
    node.child_by_field_name("name")
        .map(|name| node_text(name, source))
}

fn call_receiver_text<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "method_invocation" {
        return None;
    }
    node.child_by_field_name("object")
        .map(|object| node_text(object, source))
}

fn call_arguments(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "method_invocation" {
        return None;
    }
    node.child_by_field_name("arguments")
}

fn assignment_target_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    match node.kind() {
        "identifier" | "field_access" => Some(node_text(node, source)),
        _ => None,
    }
}

fn formal_parameter_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    if let Some(name) = node.child_by_field_name("name") {
        return Some(node_text(name, source));
    }
    let mut last_identifier = None;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" {
            last_identifier = Some(node_text(child, source));
        }
    }
    last_identifier
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::Language;

    fn run(src: &str, spec: &TaintSpec) -> Vec<TaintFinding> {
        let tree = parse_file(src, Language::Apex).expect("apex parse");
        analyze_tree(tree.root_node(), src, spec, None)
    }

    fn wildcard_source() -> NodeMatcher {
        NodeMatcher::ParamName {
            names: vec![crate::rules::taint_engine::ANY_PARAM_WILDCARD.into()],
            description: "untrusted function parameter".into(),
        }
    }

    fn soql_spec() -> TaintSpec {
        TaintSpec {
            sources: vec![wildcard_source()],
            sinks: vec![NodeMatcher::Call {
                canonical: "Database.query".into(),
                description: "Database.query()".into(),
            }],
            sanitizers: vec![NodeMatcher::Call {
                canonical: "String.escapeSingleQuotes".into(),
                description: "String.escapeSingleQuotes()".into(),
            }],
        }
    }

    #[test]
    fn soql_injection_from_param_fires() {
        let src = r#"
public class C {
    public void m(String p) {
        List<Account> a = Database.query(p);
    }
}
"#;
        let f = run(src, &soql_spec());
        assert_eq!(f.len(), 1, "tainted Database.query must fire, got {:?}", f);
        assert!(f[0].sink_description.contains("Database.query"));
    }

    #[test]
    fn soql_injection_transitive_concat_fires() {
        let src = r#"
public class C {
    public void m(String p) {
        String q = 'SELECT Id FROM Account WHERE Name = ' + p;
        List<Account> a = Database.query(q);
    }
}
"#;
        let f = run(src, &soql_spec());
        assert_eq!(
            f.len(),
            1,
            "transitive SOQL injection must fire, got {:?}",
            f
        );
    }

    #[test]
    fn soql_injection_sanitized_no_finding() {
        let src = r#"
public class C {
    public void m(String p) {
        String q = String.escapeSingleQuotes(p);
        List<Account> a = Database.query(q);
    }
}
"#;
        let f = run(src, &soql_spec());
        assert_eq!(f.len(), 0, "escaped param must not fire, got {:?}", f);
    }

    #[test]
    fn soql_injection_literal_no_finding() {
        let src = r#"
public class C {
    public void m(String p) {
        List<Account> a = Database.query('SELECT Id FROM Account');
    }
}
"#;
        let f = run(src, &soql_spec());
        assert_eq!(f.len(), 0, "literal query must not fire, got {:?}", f);
    }
}
