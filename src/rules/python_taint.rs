//! Intraprocedural, flow-insensitive taint analysis for Python.
//!
//! # Scope
//!
//! The engine walks a single function body in source order and reports
//! every sink call whose arguments are reachable from a configured source.
//! It is deliberately small:
//!
//! - **Per function.** No cross-function analysis. Each function is analyzed
//!   independently; taint does not cross call boundaries.
//! - **Per file.** No cross-file analysis. Callers of helper functions in
//!   other modules are on their own.
//! - **Flow-insensitive.** Statements are processed in source order. When a
//!   variable is reassigned to a non-tainted expression the old taint is
//!   dropped, but control flow is not modeled — taint observed in one branch
//!   of an `if` is treated as taint in the fall-through. Over-approximation
//!   is the whole point.
//! - **No container sensitivity.** `d["key"]` is tainted if `d` is tainted.
//!   Individual keys are not tracked.
//! - **No attribute propagation beyond one level.** `x.y` is tainted if `x`
//!   is tainted, but taint does not persist on `x.y` as a distinct name.
//! - **Sanitizers collapse to "clean".** When a call whose callee matches a
//!   [`TaintSpec::sanitizers`] entry is applied to a tainted value, the
//!   result is treated as clean — the engine does not track a separate
//!   "sanitized" state the way Semgrep's `mode: taint` does.
//!
//! Everything the engine knows about *which* patterns are sources, sinks, or
//! sanitizers is expressed declaratively via [`TaintSpec`] — nothing is
//! hardcoded about Flask, pickle, or any other library. The POC ships one
//! built-in rule as the first consumer; future rules (including
//! Semgrep-compatible `mode: taint` YAML) will plug into the same API.

use crate::rules::python_aliases::ImportAliases;
use std::collections::HashMap;
use tree_sitter::{Node, TreeCursor};

// ─── Public API ───────────────────────────────────────────────────────────

/// A pattern that matches an AST node for the purposes of taint analysis.
///
/// Kept intentionally narrow so that the YAML bridge in the follow-up PR
/// has a finite target to compile into. Every match returns a short human
/// description that is propagated to findings so the report can say
/// *why* something was tainted.
#[derive(Debug, Clone)]
pub enum NodeMatcher {
    /// Match an attribute access like `request.data` or `request.form`.
    ///
    /// The match is conservative: it triggers whenever the *leftmost*
    /// identifier in a dotted chain equals `root` and the *final* attribute
    /// segment equals `field`. This catches both `request.data` and
    /// `flask.request.data`-style forms after alias resolution, without
    /// over-fitting to a specific depth.
    Attribute {
        root: String,
        field: String,
        description: String,
    },

    /// Match a function or method call by its canonical dotted callee
    /// path, after resolution through the per-file import alias table.
    ///
    /// Example: `canonical: "request.get_json"` matches `request.get_json()`,
    /// `req.get_json()` where `req` is an alias for `request`, and
    /// `from flask import request; request.get_json()`.
    Call {
        canonical: String,
        description: String,
    },

    /// Match any use of a function parameter whose name is in this list.
    ///
    /// Useful for marking `request`-typed parameters as implicit sources:
    /// `def handler(request): pickle.loads(request.data)` flags without
    /// requiring an explicit assignment from a known source.
    ParamName {
        names: Vec<String>,
        description: String,
    },

    /// Match any method call whose final attribute name equals `method`,
    /// regardless of receiver. Useful for sinks like `cursor.execute`,
    /// `connection.execute`, `db.execute`, etc., where the receiver can be
    /// any DB-like object and enumerating every plausible name is
    /// impractical. Only meaningful as a *sink* matcher; the source path
    /// ignores it.
    MethodName { method: String, description: String },
}

impl NodeMatcher {
    /// Short human description used in findings.
    pub fn description(&self) -> &str {
        match self {
            NodeMatcher::Attribute { description, .. } => description,
            NodeMatcher::Call { description, .. } => description,
            NodeMatcher::ParamName { description, .. } => description,
            NodeMatcher::MethodName { description, .. } => description,
        }
    }
}

/// Declarative taint specification consumed by the engine. Each rule that
/// wants to use taint analysis builds one of these and passes it to
/// [`analyze_function`].
#[derive(Debug, Clone, Default)]
pub struct TaintSpec {
    pub sources: Vec<NodeMatcher>,
    pub sinks: Vec<NodeMatcher>,
    /// Calls whose callee matches one of these matchers are treated as
    /// producing a clean value, even if their arguments were tainted. See
    /// the module-level docs for the collapsed-to-clean semantics.
    pub sanitizers: Vec<NodeMatcher>,
}

/// A single source→sink flow reported by the engine.
#[derive(Debug, Clone)]
pub struct TaintFinding {
    /// Byte range of the sink node within the source string.
    pub sink_start_byte: usize,
    pub sink_end_byte: usize,
    /// 1-indexed line of the sink.
    pub sink_line: usize,
    /// 1-indexed column of the sink.
    pub sink_column: usize,
    pub sink_end_line: usize,
    pub sink_end_column: usize,
    /// Description of the source matcher that tainted this flow.
    pub source_description: String,
    /// Description of the sink matcher that flagged this flow.
    pub sink_description: String,
}

/// Return-taint summary for a single function. Keyed by the function's
/// simple name (class/nesting are ignored for v1). The value is `Some`
/// description if any `return` statement in the function returns a
/// tainted expression, `None` otherwise.
///
/// Function-name collisions (e.g. a nested `def helper` inside an outer
/// function when another top-level `def helper` exists) are resolved
/// last-write-wins, which is a known v1 limitation.
pub type ReturnSummary = HashMap<String, Option<String>>;

/// Run the taint engine over every function definition inside `root` and
/// return one [`TaintFinding`] per source→sink flow discovered.
///
/// The root can be a whole file tree. The engine finds every
/// `function_definition` inside it (including nested ones) and analyzes
/// each independently.
///
/// Internally this runs in two passes:
///
/// 1. **Pass 1 — return summaries.** Every function in the file is walked
///    and its `return` expressions are classified as tainted / clean
///    using the same `expression_taint` logic that pass 2 uses. The
///    difference is that pass 1 has an *empty* return summary, so calls
///    to local helpers fall through to default behavior. This gives one
///    level of interprocedural propagation: a direct helper whose body
///    reads a source will be summarized as tainted, but a helper that
///    itself calls another helper will not (the deeper chain is missed).
///    Documented limitation for v1.
///
/// 2. **Pass 2 — analysis with summaries.** Re-analyze each function with
///    the pass-1 summary available. A call to a bare local helper whose
///    summary says "tainted" now makes the call result tainted, so the
///    caller's local bindings and sink arguments propagate correctly.
pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&ImportAliases>,
) -> Vec<TaintFinding> {
    // Pass 1: build return summaries using an empty summary map so that
    // calls to local helpers inside helper bodies fall through to the
    // default behavior. This is the one-level interprocedural limit.
    let empty_summary = ReturnSummary::new();
    let mut summaries = ReturnSummary::new();
    collect_function_defs(root, &mut |func_node| {
        let (name, ret_taint) =
            summarize_function(func_node, source, spec, aliases, &empty_summary);
        if let Some(name) = name {
            // Last-write-wins on name collisions (v1 limitation).
            summaries.insert(name, ret_taint);
        }
    });

    // Pass 2: full analysis with the summary map available.
    let mut findings = Vec::new();
    collect_function_defs(root, &mut |func_node| {
        analyze_function(func_node, source, spec, aliases, &summaries, &mut findings);
    });
    findings
}

/// Pass-1 walker: compute a function's return-taint summary by scanning
/// its body with the same state machinery used in pass 2, then inspecting
/// every `return_statement` that appears inside it (excluding nested
/// function bodies, which have their own summary).
fn summarize_function(
    func_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&ImportAliases>,
    summaries: &ReturnSummary,
) -> (Option<String>, Option<String>) {
    let name = func_node
        .child_by_field_name("name")
        .map(|n| node_text(n, source).to_string());

    let mut state = TaintState::default();
    if let Some(params) = func_node.child_by_field_name("parameters") {
        seed_param_sources(params, source, spec, &mut state);
    }
    let Some(body) = func_node.child_by_field_name("body") else {
        return (name, None);
    };

    let mut return_taint: Option<String> = None;
    // Reuse the normal walker but throw away sink findings — we only want
    // to update the taint state and inspect return statements.
    let mut scratch: Vec<TaintFinding> = Vec::new();
    walk_body_for_summary(
        body,
        source,
        spec,
        aliases,
        &mut state,
        &mut scratch,
        summaries,
        &mut return_taint,
    );
    (name, return_taint)
}

#[allow(clippy::too_many_arguments)]
fn walk_body_for_summary(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&ImportAliases>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
    summaries: &ReturnSummary,
    return_taint: &mut Option<String>,
) {
    // Don't descend into nested function definitions — their own returns
    // belong to their own summary.
    if node.kind() == "function_definition" {
        return;
    }

    if node.kind() == "assignment" {
        handle_assignment(node, source, spec, aliases, state, summaries);
    }
    if node.kind() == "call" {
        handle_call(node, source, spec, aliases, state, findings, summaries);
    }
    if node.kind() == "return_statement" && return_taint.is_none() {
        // The return's argument is the first named child, if any.
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some(desc) = expression_taint(child, source, spec, aliases, state, summaries) {
                *return_taint = Some(desc);
                break;
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_body_for_summary(
            child,
            source,
            spec,
            aliases,
            state,
            findings,
            summaries,
            return_taint,
        );
    }
}

// ─── Internals ────────────────────────────────────────────────────────────

fn collect_function_defs<'tree, F>(node: Node<'tree>, visit: &mut F)
where
    F: FnMut(Node<'tree>),
{
    if node.kind() == "function_definition" {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_function_defs(child, visit);
    }
}

/// State maintained while walking a single function body. Maps local
/// identifier names to a description of the source that tainted them.
#[derive(Default)]
struct TaintState {
    tainted: HashMap<String, String>,
}

impl TaintState {
    fn taint(&mut self, name: String, description: String) {
        self.tainted.insert(name, description);
    }

    fn clear(&mut self, name: &str) {
        self.tainted.remove(name);
    }

    fn describe(&self, name: &str) -> Option<&str> {
        self.tainted.get(name).map(String::as_str)
    }
}

fn analyze_function(
    func_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&ImportAliases>,
    summaries: &ReturnSummary,
    findings: &mut Vec<TaintFinding>,
) {
    let mut state = TaintState::default();

    // Seed the state with any parameters marked as implicit sources.
    if let Some(params) = func_node.child_by_field_name("parameters") {
        seed_param_sources(params, source, spec, &mut state);
    }

    // Walk the body in source order, updating taint state at assignments
    // and reporting flows at sink calls.
    let Some(body) = func_node.child_by_field_name("body") else {
        return;
    };
    walk_body(body, source, spec, aliases, &mut state, findings, summaries);
}

fn seed_param_sources(params: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        let param_name = match child.kind() {
            "identifier" => node_text(child, source),
            "typed_parameter" | "default_parameter" | "typed_default_parameter" => {
                // Drill to the first identifier inside.
                let mut inner_cursor = child.walk();
                let mut found: Option<&str> = None;
                for inner in child.children(&mut inner_cursor) {
                    if inner.kind() == "identifier" {
                        found = Some(node_text(inner, source));
                        break;
                    }
                }
                match found {
                    Some(n) => n,
                    None => continue,
                }
            }
            _ => continue,
        };

        for matcher in &spec.sources {
            if let NodeMatcher::ParamName { names, description } = matcher {
                if names.iter().any(|n| n == param_name) {
                    state.taint(param_name.to_string(), description.clone());
                    break;
                }
            }
        }
    }
}

fn walk_body(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&ImportAliases>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
    summaries: &ReturnSummary,
) {
    // Nested function definitions have their own scope. Skip them — they'll
    // be picked up independently by analyze_tree.
    if node.kind() == "function_definition" {
        return;
    }

    if node.kind() == "assignment" {
        handle_assignment(node, source, spec, aliases, state, summaries);
    }

    if node.kind() == "call" {
        handle_call(node, source, spec, aliases, state, findings, summaries);
    }

    // Tree-sitter's cursor walks in document order, which is exactly the
    // "process statements in source order, unioning taint across branches"
    // semantics the POC wants.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_body(child, source, spec, aliases, state, findings, summaries);
    }
}

fn handle_assignment(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&ImportAliases>,
    state: &mut TaintState,
    summaries: &ReturnSummary,
) {
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };

    // Simple identifier LHS: the common case.
    if left.kind() == "identifier" {
        let lhs_name = node_text(left, source).to_string();
        if let Some(desc) = expression_taint(right, source, spec, aliases, state, summaries) {
            state.taint(lhs_name, desc);
        } else {
            // Reassignment with a clean RHS kills any previous taint on LHS.
            state.clear(&lhs_name);
        }
        return;
    }

    // Tuple/list destructuring LHS: `a, b = ...` or `[a, b] = ...`.
    // Tree-sitter-python uses `pattern_list` for bare `a, b`, and
    // `tuple_pattern` / `list_pattern` for parenthesized/bracketed forms.
    // We walk the LHS targets and pair them with RHS elements when the
    // RHS is also a tuple/list literal of the same arity. Otherwise we
    // fall back to conservative semantics: if the RHS is tainted at all,
    // taint every LHS target (we lack type info to pick the slot).
    if is_destructuring_pattern(left) {
        let lhs_targets = collect_destructuring_targets(left, source);
        if lhs_targets.is_empty() {
            return;
        }

        if let Some(rhs_elems) = tuple_like_elements(right) {
            if rhs_elems.len() == lhs_targets.len() {
                for (target, rhs) in lhs_targets.iter().zip(rhs_elems.iter()) {
                    if let Some(desc) =
                        expression_taint(*rhs, source, spec, aliases, state, summaries)
                    {
                        state.taint(target.clone(), desc);
                    } else {
                        state.clear(target);
                    }
                }
                return;
            }
        }

        // Arity mismatch or opaque RHS: apply conservative semantics.
        if let Some(desc) = expression_taint(right, source, spec, aliases, state, summaries) {
            for target in &lhs_targets {
                state.taint(target.clone(), desc.clone());
            }
        } else {
            for target in &lhs_targets {
                state.clear(target);
            }
        }
    }
}

fn is_destructuring_pattern(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "pattern_list" | "tuple_pattern" | "list_pattern"
    )
}

/// Collect the identifier names that are direct targets of a destructuring
/// LHS. Nested patterns (`(a, (b, c)) = ...`) recurse; non-identifier
/// targets like `obj.attr` or `d[k]` are skipped because the engine only
/// tracks plain names in its taint state.
fn collect_destructuring_targets(node: Node<'_>, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "identifier" => out.push(node_text(child, source).to_string()),
            "pattern_list" | "tuple_pattern" | "list_pattern" => {
                out.extend(collect_destructuring_targets(child, source));
            }
            // `*rest` captures in unpacking: tree-sitter-python wraps the
            // inner name in a list_splat_pattern.
            "list_splat_pattern" => {
                let mut inner = child.walk();
                for c in child.named_children(&mut inner) {
                    if c.kind() == "identifier" {
                        out.push(node_text(c, source).to_string());
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// If `node` is a tuple/list literal or an `expression_list`, return its
/// element nodes in order. Otherwise return `None`.
fn tuple_like_elements<'tree>(node: Node<'tree>) -> Option<Vec<Node<'tree>>> {
    match node.kind() {
        "expression_list" | "tuple" | "list" => {
            let mut cursor = node.walk();
            let elems: Vec<Node<'tree>> = node.named_children(&mut cursor).collect();
            Some(elems)
        }
        _ => None,
    }
}

fn handle_call(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&ImportAliases>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
    summaries: &ReturnSummary,
) {
    let Some(func) = node.child_by_field_name("function") else {
        return;
    };
    let callee_text = node_text(func, source);
    let resolved = match aliases {
        Some(a) => a.resolve(callee_text).into_owned(),
        None => callee_text.to_string(),
    };

    // The final attribute segment of the callee, used by `MethodName`
    // sink matching. For `cursor.execute` this is `"execute"`; for a bare
    // `eval` it's `"eval"`.
    let final_segment = resolved.rsplit('.').next().unwrap_or(resolved.as_str());

    // Is this a sink?
    let sink_desc = spec.sinks.iter().find_map(|m| match m {
        NodeMatcher::Call {
            canonical,
            description,
        } if *canonical == resolved => Some(description.clone()),
        NodeMatcher::MethodName {
            method,
            description,
        } if method == final_segment => Some(description.clone()),
        _ => None,
    });
    let Some(sink_desc) = sink_desc else {
        return;
    };

    // Check each argument for taint.
    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    let mut cursor = args.walk();
    for arg in args.named_children(&mut cursor) {
        if let Some(source_desc) = expression_taint(arg, source, spec, aliases, state, summaries) {
            let start = node.start_position();
            let end = node.end_position();
            findings.push(TaintFinding {
                sink_start_byte: node.start_byte(),
                sink_end_byte: node.end_byte(),
                sink_line: start.row + 1,
                sink_column: start.column + 1,
                sink_end_line: end.row + 1,
                sink_end_column: end.column + 1,
                source_description: source_desc,
                sink_description: sink_desc.clone(),
            });
            // One finding per sink call is enough — don't double-report
            // when multiple args are tainted.
            break;
        }
    }
}

/// Returns the source description if `expr` evaluates to (or references) a
/// tainted value, otherwise `None`.
fn expression_taint(
    expr: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&ImportAliases>,
    state: &TaintState,
    summaries: &ReturnSummary,
) -> Option<String> {
    // Direct source match on this expression.
    if let Some(desc) = match_source(expr, source, spec, aliases) {
        return Some(desc);
    }

    // Tainted identifier reference.
    if expr.kind() == "identifier" {
        let name = node_text(expr, source);
        if let Some(desc) = state.describe(name) {
            return Some(desc.to_string());
        }
    }

    // Tainted attribute access on a tainted root (x.y where x is tainted).
    if expr.kind() == "attribute" {
        if let Some(object) = expr.child_by_field_name("object") {
            if object.kind() == "identifier" {
                let name = node_text(object, source);
                if let Some(desc) = state.describe(name) {
                    return Some(desc.to_string());
                }
            }
        }
    }

    // Tainted subscript (d[k] where d is tainted — no key sensitivity).
    // Recurse into the subject so that nested subscript chains like
    // `request.json["a"]["b"]` propagate taint: if any link in the chain
    // (or its root) is tainted, the whole chain is. This also naturally
    // handles attribute-then-subscript (`request.form["x"]`) and
    // identifier roots via the recursive call.
    if expr.kind() == "subscript" {
        if let Some(value) = expr.child_by_field_name("value") {
            if let Some(desc) = expression_taint(value, source, spec, aliases, state, summaries) {
                return Some(desc);
            }
        }
    }

    // Recurse one level for wrapping expressions (e.g. `bytes(request.data)`),
    // so the taint survives trivial type conversions without requiring
    // full interprocedural tracking.
    //
    // BUT: if the callee matches a configured sanitizer, the result is
    // clean regardless of whether any argument was tainted. This is the
    // "collapse to clean" semantics documented at the top of the module.
    if expr.kind() == "call" {
        if is_sanitizer_call(expr, source, spec, aliases) {
            return None;
        }
        if let Some(args) = expr.child_by_field_name("arguments") {
            let mut cursor = args.walk();
            for arg in args.named_children(&mut cursor) {
                if let Some(desc) = expression_taint(arg, source, spec, aliases, state, summaries) {
                    return Some(desc);
                }
            }
        }

        // Same-file interprocedural v1: a bare identifier callee whose
        // name matches a function in the return-summary map propagates
        // the summary's taint description as the call's result. The
        // description is decorated with "(via <callee>)" so findings
        // show the helper chain. Only bare identifiers are considered —
        // attribute calls like `self.helper()` or `obj.method()` need
        // different semantics and are out of scope for v1.
        if let Some(func) = expr.child_by_field_name("function") {
            if func.kind() == "identifier" {
                let callee = node_text(func, source);
                if let Some(Some(desc)) = summaries.get(callee) {
                    return Some(format!("{desc} (via {callee})"));
                }
            }
        }
    }

    None
}

/// Returns `true` if `call_node` is a call whose callee matches any of the
/// configured sanitizer matchers in `spec`. Only `NodeMatcher::Call` entries
/// are meaningful as sanitizers today; other kinds are ignored.
fn is_sanitizer_call(
    call_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&ImportAliases>,
) -> bool {
    if call_node.kind() != "call" {
        return false;
    }
    let Some(func) = call_node.child_by_field_name("function") else {
        return false;
    };
    let callee_text = node_text(func, source);
    let resolved: std::borrow::Cow<'_, str> = match aliases {
        Some(a) => a.resolve(callee_text),
        None => std::borrow::Cow::Borrowed(callee_text),
    };
    for matcher in &spec.sanitizers {
        if let NodeMatcher::Call { canonical, .. } = matcher {
            if callee_text == canonical.as_str() || resolved.as_ref() == canonical.as_str() {
                return true;
            }
        }
    }
    false
}

fn match_source(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&ImportAliases>,
) -> Option<String> {
    for matcher in &spec.sources {
        match matcher {
            NodeMatcher::Attribute {
                root,
                field,
                description,
            } => {
                if node.kind() != "attribute" {
                    continue;
                }
                let Some(final_attr) = node.child_by_field_name("attribute") else {
                    continue;
                };
                if node_text(final_attr, source) != field.as_str() {
                    continue;
                }
                let Some(raw_root) = leftmost_identifier(node, source) else {
                    continue;
                };
                // Match against both the raw leftmost identifier (e.g.
                // `request` from `from flask import request`) and its
                // alias-resolved canonical (e.g. `flask.request`). This lets
                // one spec cover both imported and parameter-introduced
                // `request` names without requiring callers to duplicate
                // their source list.
                if raw_root == root.as_str() {
                    return Some(description.clone());
                }
                if let Some(a) = aliases {
                    if a.resolve(raw_root).as_ref() == root.as_str() {
                        return Some(description.clone());
                    }
                }
            }
            NodeMatcher::Call {
                canonical,
                description,
            } => {
                if node.kind() != "call" {
                    continue;
                }
                let Some(func) = node.child_by_field_name("function") else {
                    continue;
                };
                let callee_text = node_text(func, source);
                if callee_text == canonical.as_str() {
                    return Some(description.clone());
                }
                if let Some(a) = aliases {
                    if a.resolve(callee_text).as_ref() == canonical.as_str() {
                        return Some(description.clone());
                    }
                }
            }
            NodeMatcher::ParamName { .. } => {
                // ParamName matchers are applied when seeding the state
                // from the function's parameter list, not when walking
                // expressions.
            }
            NodeMatcher::MethodName { .. } => {
                // MethodName is a sink-only matcher. Ignore in source
                // matching — sources match on precise callee shapes.
            }
        }
    }
    None
}

/// Canonical set of untrusted-input sources for Python web handlers.
///
/// Shared across every `py/taint-*` rule so that "what counts as
/// untrusted" is defined once and stays consistent. Currently covers
/// Flask-style `request.*` access plus handler parameters named
/// `request`. Django is intentionally out of scope for the first batch
/// of taint rules.
pub fn python_taint_sources() -> Vec<NodeMatcher> {
    vec![
        NodeMatcher::Attribute {
            root: "request".into(),
            field: "data".into(),
            description: "flask.request.data".into(),
        },
        NodeMatcher::Attribute {
            root: "request".into(),
            field: "form".into(),
            description: "flask.request.form".into(),
        },
        NodeMatcher::Attribute {
            root: "request".into(),
            field: "args".into(),
            description: "flask.request.args".into(),
        },
        NodeMatcher::Attribute {
            root: "request".into(),
            field: "values".into(),
            description: "flask.request.values".into(),
        },
        NodeMatcher::Attribute {
            root: "request".into(),
            field: "json".into(),
            description: "flask.request.json".into(),
        },
        NodeMatcher::Attribute {
            root: "request".into(),
            field: "files".into(),
            description: "flask.request.files".into(),
        },
        NodeMatcher::Attribute {
            root: "request".into(),
            field: "cookies".into(),
            description: "flask.request.cookies".into(),
        },
        NodeMatcher::Call {
            canonical: "request.get_data".into(),
            description: "flask.request.get_data()".into(),
        },
        NodeMatcher::Call {
            canonical: "request.get_json".into(),
            description: "flask.request.get_json()".into(),
        },
        NodeMatcher::ParamName {
            names: vec!["request".into()],
            description: "untrusted request parameter".into(),
        },
    ]
}

/// Walk an attribute chain leftward and return the leftmost identifier text.
/// For `request.form.get`, returns `"request"`. For `x.y`, returns `"x"`.
/// Returns `None` if the leftmost node is not a simple identifier.
fn leftmost_identifier<'a>(mut node: Node<'_>, source: &'a str) -> Option<&'a str> {
    loop {
        match node.kind() {
            "identifier" => return Some(node_text(node, source)),
            "attribute" => {
                node = node.child_by_field_name("object")?;
            }
            _ => return None,
        }
    }
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

#[allow(dead_code)]
fn debug_tree(node: Node<'_>, depth: usize) {
    let mut cursor: TreeCursor = node.walk();
    for _ in 0..depth {
        eprint!("  ");
    }
    eprintln!("{}", node.kind());
    for child in node.children(&mut cursor) {
        debug_tree(child, depth + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::Language;

    fn spec_pickle_from_request() -> TaintSpec {
        TaintSpec {
            sources: vec![
                NodeMatcher::Attribute {
                    root: "request".into(),
                    field: "data".into(),
                    description: "flask.request.data".into(),
                },
                NodeMatcher::Attribute {
                    root: "request".into(),
                    field: "form".into(),
                    description: "flask.request.form".into(),
                },
                NodeMatcher::Attribute {
                    root: "request".into(),
                    field: "args".into(),
                    description: "flask.request.args".into(),
                },
                NodeMatcher::Call {
                    canonical: "request.get_json".into(),
                    description: "flask.request.get_json()".into(),
                },
                NodeMatcher::ParamName {
                    names: vec!["request".into()],
                    description: "function parameter named request".into(),
                },
            ],
            sinks: vec![
                NodeMatcher::Call {
                    canonical: "pickle.loads".into(),
                    description: "pickle.loads".into(),
                },
                NodeMatcher::Call {
                    canonical: "pickle.load".into(),
                    description: "pickle.load".into(),
                },
            ],
            sanitizers: vec![],
        }
    }

    fn run(source: &str) -> Vec<TaintFinding> {
        let tree = parse_file(source, Language::Python).expect("parse");
        let aliases = ImportAliases::from_tree(source, &tree);
        analyze_tree(
            tree.root_node(),
            source,
            &spec_pickle_from_request(),
            Some(&aliases),
        )
    }

    #[test]
    fn direct_flow_request_data_to_pickle_loads() {
        let src = r#"
import pickle
from flask import request

def handler():
    data = request.data
    return pickle.loads(data)
"#;
        let f = run(src);
        assert_eq!(f.len(), 1);
        assert!(f[0].source_description.contains("request.data"));
        assert_eq!(f[0].sink_description, "pickle.loads");
    }

    #[test]
    fn chained_assignment_propagates_taint() {
        let src = r#"
import pickle
from flask import request

def handler():
    a = request.form
    b = a
    c = b
    return pickle.loads(c)
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn reassignment_to_literal_kills_taint() {
        let src = r#"
import pickle
from flask import request

def handler():
    data = request.data
    data = b"static"
    return pickle.loads(data)
"#;
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn taint_survives_branch_over_approximation() {
        // Flow-insensitive: taint observed in one branch persists into the
        // fall-through. The POC deliberately over-approximates.
        let src = r#"
import pickle
from flask import request

def handler(cond):
    if cond:
        data = request.data
    return pickle.loads(data)
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn function_parameter_named_request_is_tainted() {
        let src = r#"
import pickle

def handler(request):
    return pickle.loads(request.data)
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn nested_function_has_independent_taint() {
        // The outer function taints `data`, but the inner function never
        // sees it — each function body is analyzed independently.
        let src = r#"
import pickle
from flask import request

def outer():
    data = request.data
    def inner():
        return pickle.loads(data)
    return inner
"#;
        // outer() has no sink call; inner() has a sink call on `data`
        // which is not in its own scope, so zero findings.
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn no_source_no_finding() {
        let src = r#"
import pickle

def handler():
    data = b"trusted"
    return pickle.loads(data)
"#;
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn source_call_get_json_flows_to_sink() {
        let src = r#"
import pickle
from flask import request

def handler():
    payload = request.get_json()
    return pickle.loads(payload)
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn direct_source_as_sink_argument_without_intermediate() {
        let src = r#"
import pickle
from flask import request

def handler():
    return pickle.loads(request.data)
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn subscript_on_tainted_root_is_tainted() {
        let src = r#"
import pickle
from flask import request

def handler():
    form = request.form
    return pickle.loads(form["payload"])
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn wrapping_call_preserves_taint() {
        let src = r#"
import pickle
from flask import request

def handler():
    return pickle.loads(bytes(request.data))
"#;
        assert_eq!(run(src).len(), 1);
    }

    fn spec_pickle_with_html_escape_sanitizer() -> TaintSpec {
        let mut spec = spec_pickle_from_request();
        spec.sanitizers = vec![NodeMatcher::Call {
            canonical: "html.escape".into(),
            description: "html.escape".into(),
        }];
        spec
    }

    fn run_with(source: &str, spec: &TaintSpec) -> Vec<TaintFinding> {
        let tree = parse_file(source, Language::Python).expect("parse");
        let aliases = ImportAliases::from_tree(source, &tree);
        analyze_tree(tree.root_node(), source, spec, Some(&aliases))
    }

    #[test]
    fn sanitizer_call_kills_taint() {
        let src = r#"
import pickle
import html
from flask import request

def handler():
    raw = request.data
    clean = html.escape(raw)
    return pickle.loads(clean)
"#;
        assert_eq!(
            run_with(src, &spec_pickle_with_html_escape_sanitizer()).len(),
            0
        );
    }

    #[test]
    fn sanitizer_bypassed_still_flows() {
        // html.escape is applied to `raw` and stored in `escaped`, but the
        // sink reads the still-tainted `raw`. Must still fire.
        let src = r#"
import pickle
import html
from flask import request

def handler():
    raw = request.data
    escaped = html.escape(raw)
    return pickle.loads(raw)
"#;
        assert_eq!(
            run_with(src, &spec_pickle_with_html_escape_sanitizer()).len(),
            1
        );
    }

    #[test]
    fn non_sanitizer_wrapping_call_preserves_taint() {
        // bytes() is not listed as a sanitizer, so the wrapping-call rule
        // still applies and taint survives.
        let src = r#"
import pickle
from flask import request

def handler():
    data = bytes(request.data)
    return pickle.loads(data)
"#;
        assert_eq!(
            run_with(src, &spec_pickle_with_html_escape_sanitizer()).len(),
            1
        );
    }

    #[test]
    fn sanitizer_result_assigned_to_new_variable() {
        // The assignment `data = html.escape(request.args["q"])` must not
        // add `data` to the taint set.
        let src = r#"
import pickle
import html
from flask import request

def handler():
    data = html.escape(request.args["q"])
    return pickle.loads(data)
"#;
        assert_eq!(
            run_with(src, &spec_pickle_with_html_escape_sanitizer()).len(),
            0
        );
    }

    #[test]
    fn multiple_sanitizers_in_spec() {
        let mut spec = spec_pickle_from_request();
        spec.sanitizers = vec![
            NodeMatcher::Call {
                canonical: "html.escape".into(),
                description: "html.escape".into(),
            },
            NodeMatcher::Call {
                canonical: "shlex.quote".into(),
                description: "shlex.quote".into(),
            },
        ];

        let src_escape = r#"
import pickle
import html
from flask import request

def handler():
    return pickle.loads(html.escape(request.data))
"#;
        let src_quote = r#"
import pickle
import shlex
from flask import request

def handler():
    return pickle.loads(shlex.quote(request.data))
"#;
        let src_neither = r#"
import pickle
from flask import request

def handler():
    return pickle.loads(urllib.parse.quote(request.data))
"#;
        assert_eq!(run_with(src_escape, &spec).len(), 0);
        assert_eq!(run_with(src_quote, &spec).len(), 0);
        assert_eq!(run_with(src_neither, &spec).len(), 1);
    }

    #[test]
    fn nested_subscript_propagates_through_chain() {
        // `request.form["a"]["b"]["c"]` must be tainted: the innermost
        // subject `request.form` is a source, and every outer subscript
        // preserves taint regardless of the keys.
        let src = r#"
import pickle
from flask import request

def handler():
    return pickle.loads(request.form["a"]["b"]["c"])
"#;
        let f = run(src);
        assert_eq!(f.len(), 1);
        assert!(f[0].source_description.contains("request.form"));
    }

    #[test]
    fn tuple_unpack_literal_rhs_taints_matching_element() {
        // `a, b = request.args["a"], request.args["b"]`: both a and b are
        // tainted because each RHS element is a subscript on a source.
        // The sink reads `a`, so we should see exactly one finding.
        let src = r#"
import pickle
from flask import request

def handler():
    a, b = request.args["a"], request.args["b"]
    return pickle.loads(a)
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn tuple_unpack_literal_rhs_leaves_clean_element_clean() {
        // Precise pairing: only the first element of the RHS is tainted,
        // the sink reads `b` which pairs with the clean literal, so the
        // taint rule must stay silent.
        let src = r#"
import pickle
from flask import request

def handler():
    a, b = request.args["a"], b"static"
    return pickle.loads(b)
"#;
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn tuple_unpack_tainted_rhs_conservatively_taints_all_targets() {
        // When the RHS is a single opaque expression we can't know which
        // slot is tainted without type info, so both targets are tainted.
        let src = r#"
import pickle
from flask import request

def handler():
    a, b = request.get_json()
    return pickle.loads(b)
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn list_unpack_similar_to_tuple_unpack() {
        // `[a, b] = ...` should behave the same as `a, b = ...`.
        let src = r#"
import pickle
from flask import request

def handler():
    [a, b] = [request.args["a"], b"static"]
    return pickle.loads(a)
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn interprocedural_tainted_return_propagates_to_caller() {
        let src = r#"
import pickle
from flask import request

def get_user_input():
    return request.data

def handler():
    data = get_user_input()
    return pickle.loads(data)
"#;
        let f = run(src);
        assert_eq!(f.len(), 1);
        assert!(f[0].source_description.contains("get_user_input"));
        assert!(f[0].source_description.contains("request.data"));
    }

    #[test]
    fn interprocedural_clean_return_does_not_fire() {
        let src = r#"
import pickle

def literal_helper():
    return b"static"

def handler():
    return pickle.loads(literal_helper())
"#;
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn interprocedural_late_definition_still_found() {
        // Helper defined *below* the caller: pass 1 collects summaries
        // for every function in the file before pass 2 runs, so the
        // order of definitions does not matter.
        let src = r#"
import pickle
from flask import request

def handler():
    data = helper()
    return pickle.loads(data)

def helper():
    return request.data
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn multi_hop_chain_is_out_of_scope_v1() {
        // Two-hop chain: `middle()` calls `source()`. Pass 1 evaluates
        // each helper with an empty summary, so `middle`'s return (which
        // calls `source`) is seen as clean. Documented v1 limitation —
        // the test pins the behavior so a future upgrade breaking it is
        // a deliberate decision.
        let src = r#"
import pickle
from flask import request

def source():
    return request.data

def middle():
    return source()

def handler():
    return pickle.loads(middle())
"#;
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn interprocedural_direct_call_as_sink_argument() {
        let src = r#"
import pickle
from flask import request

def get_user_input():
    return request.data

def handler():
    return pickle.loads(get_user_input())
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn alias_resolution_through_import_table() {
        // import pickle as p; p.loads(...) must still be recognized as the
        // pickle.loads sink when the alias table is supplied.
        let src = r#"
import pickle as p
from flask import request

def handler():
    return p.loads(request.data)
"#;
        assert_eq!(run(src).len(), 1);
    }
}
