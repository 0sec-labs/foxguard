//! Intraprocedural, flow-insensitive taint analysis for Swift.
//!
//! # Scope
//!
//! Mirrors the other language engines (`java_taint`, `solidity_taint`):
//!
//! - **Per function.** Each `function_declaration` body is analyzed
//!   independently; taint does not cross function boundaries.
//! - **Per file.** No cross-file analysis.
//! - **Flow-insensitive.** Statements are processed in source order; a clean
//!   reassignment clears a name.
//!
//! # Swift grammar node kinds used here (tree-sitter-swift)
//!
//! - `function_declaration` — field `body` (a `function_body`).
//! - `property_declaration` — field `name` (a `pattern` wrapping a
//!   `simple_identifier`) and field `value` (the initializer expression).
//! - `assignment` — fields `target` / `result`.
//! - `line_string_literal` — a `"..."` string; a child `interpolation`
//!   (`interpolated_expression`) marks a `"...\(expr)..."` interpolation.
//! - `additive_expression` — fields `lhs`, `rhs` (a `+` concatenation).
//! - `call_expression` — child `simple_identifier` (the callee) plus a
//!   `call_suffix` → `value_arguments` → repeated `value_argument` (field
//!   `value`).
//!
//! # Matcher interpretation
//!
//! The Semgrep bridge compiles the Swift `swift-potential-sqlite-injection`
//! rule to:
//!
//! - A **source** [`NodeMatcher::ParamName`] carrying the
//!   [`STRING_CONSTRUCTION_SENTINEL`] name — compiled from the rule's
//!   string-interpolation / string-concatenation source patterns
//!   (`"...\($X)..."`, `$SQL = "..." + $X`, `$SQL = $X + "..."`). The engine
//!   treats any *string built by interpolation or by concatenation with a
//!   non-literal operand* as a (low-confidence) tainted value, matching the
//!   rule's intent of flagging dynamically-assembled SQL strings.
//! - A **sink** [`NodeMatcher::Call`] (`sqlite3_exec`, `sqlite3_prepare_v2`)
//!   matched against a call whose callee equals it AND a tainted value flows
//!   into its argument list.

use crate::rules::common::{walk_tree, AliasTable};
use crate::rules::taint_engine::{node_text, walk_scope_nodes as walk_taint_scope_nodes};
pub use crate::rules::taint_engine::{NodeMatcher, TaintFinding, TaintSpec};
use std::collections::HashMap;
use tree_sitter::Node;

/// Sentinel `ParamName` source name the bridge uses to encode the Swift
/// "string built by interpolation/concatenation" source shape. No real Swift
/// identifier can equal it, so it is only interpreted by this engine's
/// string-construction recognition (never as a literal variable name).
pub const STRING_CONSTRUCTION_SENTINEL: &str = "$<swift-string-construction>";

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

// ─── Public API ──────────────────────────────────────────────────────────────

/// Run the Swift taint engine over every function inside `root`, returning one
/// [`TaintFinding`] per source→sink flow.
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

// ─── Built-in specs ──────────────────────────────────────────────────────────
//
// # What the Swift engine can actually prove
//
// `analyze_tree` recognises exactly ONE source shape: a string built by
// interpolation (`"...\(x)..."`) or by concatenation with a non-literal
// operand (`"lit" + x`). It carries that shape as the
// [`STRING_CONSTRUCTION_SENTINEL`] `ParamName` source. The engine does NOT
// model framework request objects, function parameters, or any other taint
// source — there is no `match_source` for `Call`/`Attribute`/identifier
// sources in `expression_taint`. Every shipped Swift taint rule therefore
// shares the same single source and differs only in its sink set: "a
// dynamically-assembled string flows into a dangerous call".
//
// Sinks are matched by `match_sink` against `call_expression` callees only,
// via [`NodeMatcher::Call`] (callee name equals `canonical`) or
// [`NodeMatcher::MethodName`] (final `.method` segment equals `method`).
// Member-assignment sinks (`process.arguments = …`) are NOT call nodes and
// are intentionally absent — the engine would not fire on them.
//
// Sanitizers are inert for Swift: `expression_taint` never consults
// `spec.sanitizers`, so [`swift_taint_sanitizers`] returns an empty set
// rather than advertising sanitization the engine does not perform.

/// All Swift taint rule IDs paired with their specs.
///
/// Mirrors `kotlin_taint_rule_specs()` / `c_taint_rule_specs()`. Consumed by
/// [`crate::rules::builtin_taint_specs_for_language`] so the rules show up as
/// `RegistryTaintSpec` entries the same way the other languages do.
pub fn swift_taint_rule_specs() -> Vec<(&'static str, TaintSpec)> {
    vec![
        ("swift/taint-sql-injection", sql_injection_spec()),
        ("swift/taint-command-injection", command_injection_spec()),
        ("swift/taint-js-injection", js_injection_spec()),
        ("swift/taint-nsexpression-injection", nsexpression_spec()),
    ]
}

/// The single Swift taint source: a dynamically-constructed string
/// (interpolation or concatenation with a non-literal operand), encoded with
/// the [`STRING_CONSTRUCTION_SENTINEL`] the engine interprets specially.
pub fn swift_taint_sources() -> Vec<NodeMatcher> {
    vec![NodeMatcher::ParamName {
        names: vec![STRING_CONSTRUCTION_SENTINEL.into()],
        description: "dynamically constructed string".into(),
    }]
}

/// The union of every Swift taint sink across all rules. Provided as a
/// companion accessor to [`swift_taint_sources`] / [`swift_taint_sanitizers`];
/// individual rules carry their own focused sink subset via the specs above.
pub fn swift_taint_sinks() -> Vec<NodeMatcher> {
    let mut sinks = sql_injection_spec().sinks;
    sinks.extend(command_injection_spec().sinks);
    sinks.extend(js_injection_spec().sinks);
    sinks.extend(nsexpression_spec().sinks);
    sinks
}

/// Sanitizers for Swift taint rules.
///
/// The Swift engine is source-shape based and never consults
/// `spec.sanitizers` in `expression_taint`, so there is nothing to declare.
/// Returns an empty set deliberately (no false advertising of sanitization).
pub fn swift_taint_sanitizers() -> Vec<NodeMatcher> {
    Vec::new()
}

fn sql_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: swift_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "sqlite3_exec".into(),
                description: "sqlite3_exec() with tainted query (SQL injection)".into(),
            },
            NodeMatcher::Call {
                canonical: "sqlite3_prepare_v2".into(),
                description: "sqlite3_prepare_v2() with tainted query (SQL injection)".into(),
            },
            NodeMatcher::Call {
                canonical: "sqlite3_prepare".into(),
                description: "sqlite3_prepare() with tainted query (SQL injection)".into(),
            },
            NodeMatcher::Call {
                canonical: "sqlite3_prepare_v3".into(),
                description: "sqlite3_prepare_v3() with tainted query (SQL injection)".into(),
            },
        ],
        sanitizers: swift_taint_sanitizers(),
    }
}

fn command_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: swift_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "system".into(),
                description: "system() with tainted command (command injection)".into(),
            },
            NodeMatcher::Call {
                canonical: "popen".into(),
                description: "popen() with tainted command (command injection)".into(),
            },
            NodeMatcher::MethodName {
                method: "launchedProcess".into(),
                description: "Process.launchedProcess() with tainted argument (command injection)"
                    .into(),
            },
        ],
        sanitizers: swift_taint_sanitizers(),
    }
}

fn js_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: swift_taint_sources(),
        sinks: vec![NodeMatcher::MethodName {
            method: "evaluateJavaScript".into(),
            description: "WKWebView.evaluateJavaScript() with tainted script (JS injection)".into(),
        }],
        sanitizers: swift_taint_sanitizers(),
    }
}

fn nsexpression_spec() -> TaintSpec {
    TaintSpec {
        sources: swift_taint_sources(),
        sinks: vec![NodeMatcher::Call {
            canonical: "NSExpression".into(),
            description: "NSExpression(format:) with tainted format (expression injection)".into(),
        }],
        sanitizers: swift_taint_sanitizers(),
    }
}

// ─── Per-scope analysis ──────────────────────────────────────────────────────

fn analyze_scope(scope: Node<'_>, source: &str, spec: &TaintSpec, out: &mut Vec<TaintFinding>) {
    let body = find_scope_body(scope).unwrap_or(scope);
    let mut state = TaintState::default();

    for _ in 0..3 {
        propagate_assignments(body, source, spec, &mut state);
    }
    find_sinks(body, source, spec, &state, out);
}

fn propagate_assignments(scope: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    walk_scope_nodes(scope, source, &mut |node, src| match node.kind() {
        "property_declaration" => {
            let Some(name) = property_name(node, src) else {
                return;
            };
            let Some(value) = node.child_by_field_name("value") else {
                return;
            };
            match expression_taint(value, src, spec, state) {
                Some(info) => state.taint(name.to_string(), bump_hops(info)),
                None => state.clear(name),
            }
        }
        "assignment" => {
            let Some(target) = node.child_by_field_name("target") else {
                return;
            };
            let Some(name) = assignment_target_name(target, src) else {
                return;
            };
            let Some(result) = node.child_by_field_name("result") else {
                return;
            };
            match expression_taint(result, src, spec, state) {
                Some(info) => state.taint(name.to_string(), bump_hops(info)),
                None => state.clear(name),
            }
        }
        _ => {}
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
        if node.kind() != "call_expression" {
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
    // Known-tainted local.
    let text = node_text(node, source);
    if let Some(info) = state.info(text) {
        return Some(info.clone());
    }

    if node.kind() == "simple_identifier" {
        return state.info(text).cloned();
    }

    // Source shape: a string built by interpolation or by concatenation with a
    // non-literal operand.
    if source_wants_string_construction(spec) {
        if let Some(desc) = string_construction_taint(node) {
            return Some(TaintInfo {
                description: desc,
                line: node.start_position().row + 1,
                hops: 0,
            });
        }
    }

    // `additive_expression`: tainted if either operand is tainted.
    if node.kind() == "additive_expression" {
        for field in ["lhs", "rhs"] {
            if let Some(op) = node.child_by_field_name(field) {
                if let Some(info) = expression_taint(op, source, spec, state) {
                    return Some(info);
                }
            }
        }
        return None;
    }

    // Generic: descend into children (covers parenthesized expressions, etc.).
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(info) = expression_taint(child, source, spec, state) {
            return Some(info);
        }
    }
    None
}

/// True when the spec carries the string-construction sentinel source.
fn source_wants_string_construction(spec: &TaintSpec) -> bool {
    spec.sources.iter().any(|m| {
        matches!(m, NodeMatcher::ParamName { names, .. }
            if names.iter().any(|n| n == STRING_CONSTRUCTION_SENTINEL))
    })
}

/// Returns a description if `node` is a string built by interpolation
/// (`"...\(expr)..."`) or by concatenation with a non-literal operand
/// (`"lit" + x`, `x + "lit"`).
fn string_construction_taint(node: Node<'_>) -> Option<String> {
    match node.kind() {
        "line_string_literal" | "multi_line_string_literal" => {
            if has_interpolation(node) {
                Some("dynamically interpolated string".to_string())
            } else {
                None
            }
        }
        "additive_expression" => {
            let lhs = node.child_by_field_name("lhs");
            let rhs = node.child_by_field_name("rhs");
            let (Some(lhs), Some(rhs)) = (lhs, rhs) else {
                return None;
            };
            // A concatenation is a "constructed string" source when one operand
            // is a string literal and the other is NOT a string literal (i.e. a
            // dynamic value flows into the string).
            let lhs_str = is_string_literal(lhs.kind());
            let rhs_str = is_string_literal(rhs.kind());
            if lhs_str != rhs_str {
                Some("dynamically concatenated string".to_string())
            } else if lhs_str && rhs_str {
                None
            } else {
                // Neither operand is a literal: recurse to find a nested
                // constructed string (e.g. `("a" + x) + y`).
                string_construction_taint(lhs).or_else(|| string_construction_taint(rhs))
            }
        }
        _ => None,
    }
}

fn is_string_literal(kind: &str) -> bool {
    matches!(kind, "line_string_literal" | "multi_line_string_literal")
}

/// True when a string-literal node contains an `interpolation` child.
fn has_interpolation(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    let found = node
        .children(&mut cursor)
        .any(|c| c.kind() == "interpolation" || c.kind() == "interpolated_expression");
    found
}

fn match_sink(node: Node<'_>, source: &str, spec: &TaintSpec) -> Option<String> {
    let callee = call_callee_name(node, source)?;
    spec.sinks.iter().find_map(|matcher| match matcher {
        NodeMatcher::Call { canonical, .. } if canonical == callee => {
            Some(matcher.description().to_string())
        }
        NodeMatcher::MethodName { method, .. } if method == callee => {
            Some(matcher.description().to_string())
        }
        _ => None,
    })
}

fn sink_argument_taint(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
) -> Option<TaintInfo> {
    let args = call_value_arguments(node)?;
    let mut cursor = args.walk();
    for arg in args.children(&mut cursor) {
        if arg.kind() != "value_argument" {
            continue;
        }
        let target = arg.child_by_field_name("value").unwrap_or(arg);
        if let Some(info) = expression_taint(target, source, spec, state) {
            return Some(info);
        }
    }
    None
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
    matches!(
        kind,
        "function_declaration" | "init_declaration" | "deinit_declaration"
    )
}

fn find_scope_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body").or_else(|| {
        let mut cursor = node.walk();
        let body = node
            .children(&mut cursor)
            .find(|child| child.kind() == "function_body");
        body
    })
}

fn property_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    let name = node.child_by_field_name("name")?;
    // `name` is a `pattern` wrapping a `simple_identifier`.
    if let Some(id) = name.child_by_field_name("bound_identifier") {
        return Some(node_text(id, source));
    }
    let mut cursor = name.walk();
    for child in name.children(&mut cursor) {
        if child.kind() == "simple_identifier" {
            return Some(node_text(child, source));
        }
    }
    if name.kind() == "simple_identifier" {
        return Some(node_text(name, source));
    }
    None
}

fn assignment_target_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    match node.kind() {
        "simple_identifier" => Some(node_text(node, source)),
        _ => {
            // `directly_assignable_expression` wraps a `simple_identifier`.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "simple_identifier" {
                    return Some(node_text(child, source));
                }
            }
            None
        }
    }
}

fn call_callee_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "call_expression" {
        return None;
    }
    // The callee is the first named child before the `call_suffix`.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "simple_identifier" => return Some(node_text(child, source)),
            "navigation_expression" => {
                // `a.b.method(...)` — take the final navigation suffix name.
                return navigation_final_name(child, source);
            }
            "call_suffix" => break,
            _ => {}
        }
    }
    None
}

fn navigation_final_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    let mut last = None;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "navigation_suffix" {
            let mut sc = child.walk();
            for sub in child.children(&mut sc) {
                if sub.kind() == "simple_identifier" {
                    last = Some(node_text(sub, source));
                }
            }
        }
    }
    last
}

fn call_value_arguments(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call_suffix" {
            let mut sc = child.walk();
            for sub in child.children(&mut sc) {
                if sub.kind() == "value_arguments" {
                    return Some(sub);
                }
            }
        }
        if child.kind() == "value_arguments" {
            return Some(child);
        }
    }
    None
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::Language;

    fn run(src: &str, spec: &TaintSpec) -> Vec<TaintFinding> {
        let tree = parse_file(src, Language::Swift).expect("swift parse");
        analyze_tree(tree.root_node(), src, spec, None)
    }

    fn sqlite_spec() -> TaintSpec {
        TaintSpec {
            sources: vec![NodeMatcher::ParamName {
                names: vec![STRING_CONSTRUCTION_SENTINEL.into()],
                description: "dynamically constructed SQL string".into(),
            }],
            sinks: vec![
                NodeMatcher::Call {
                    canonical: "sqlite3_exec".into(),
                    description: "sqlite3_exec()".into(),
                },
                NodeMatcher::Call {
                    canonical: "sqlite3_prepare_v2".into(),
                    description: "sqlite3_prepare_v2()".into(),
                },
            ],
            sanitizers: vec![],
        }
    }

    #[test]
    fn interpolated_string_into_exec_fires() {
        let src = r#"
func handler(input: String) {
    let q = "SELECT * FROM t WHERE n = \(input)"
    sqlite3_exec(db, q, nil, nil, nil)
}
"#;
        let f = run(src, &sqlite_spec());
        assert_eq!(f.len(), 1, "interpolated SQL must fire, got {:?}", f);
        assert!(f[0].sink_description.contains("sqlite3_exec"));
    }

    #[test]
    fn concatenated_string_into_prepare_fires() {
        let src = r#"
func handler(input: String) {
    let q = "SELECT " + input
    sqlite3_prepare_v2(db, q, -1, stmt, nil)
}
"#;
        let f = run(src, &sqlite_spec());
        assert_eq!(f.len(), 1, "concatenated SQL must fire, got {:?}", f);
    }

    #[test]
    fn inline_interpolation_into_exec_fires() {
        let src = r#"
func handler(input: String) {
    sqlite3_exec(db, "SELECT \(input)", nil, nil, nil)
}
"#;
        let f = run(src, &sqlite_spec());
        assert_eq!(f.len(), 1, "inline interpolated SQL must fire, got {:?}", f);
    }

    #[test]
    fn literal_string_into_exec_no_finding() {
        let src = r#"
func handler(input: String) {
    let q = "SELECT * FROM t"
    sqlite3_exec(db, q, nil, nil, nil)
}
"#;
        let f = run(src, &sqlite_spec());
        assert_eq!(f.len(), 0, "literal SQL must not fire, got {:?}", f);
    }
}
