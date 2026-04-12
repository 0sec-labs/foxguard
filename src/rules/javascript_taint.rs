//! Intraprocedural, flow-insensitive taint analysis for JavaScript/TypeScript.
//!
//! Ported from `python_taint.rs` as part of issue #18. The surface mirrors
//! the Python engine intentionally — `TaintSpec`, `NodeMatcher`,
//! `TaintFinding`, and `analyze_tree` have identical shapes so a future
//! refactor that extracts the language-agnostic core is cheap. For now we
//! keep two engines so each grammar's quirks stay local.
//!
//! # Scope (same as Python)
//!
//! - **Per function.** Each `function_declaration`, `function_expression`,
//!   `arrow_function`, and `method_definition` body is analyzed independently.
//! - **Per file.** No cross-file analysis.
//! - **Flow-insensitive.** Statements are processed in source order; a
//!   reassignment with a clean RHS clears the target's taint.
//! - **No container sensitivity.** `x["k"]` is tainted when `x` is tainted.
//! - **One level of attribute propagation.** `req.body` is tainted when `req`
//!   is tainted. `req.body.name` is tainted when `req` is tainted.
//! - **One level of wrapping-call propagation.** `String(tainted)` stays
//!   tainted unless the callee is in `sanitizers`.
//! - **Template-literal propagation.** Any `template_string` with an
//!   interpolation whose expression is tainted is itself tainted.
//! - **Sanitizers collapse to "clean".**
//!
//! Everything specific to a library is expressed declaratively via `TaintSpec`.

use super::common::AliasTable;
use std::borrow::Cow;
use std::collections::HashMap;
use tree_sitter::{Node, Tree};

// ─── Public API ───────────────────────────────────────────────────────────

/// A pattern that matches an AST node for taint analysis.
///
/// Surface matches `python_taint::NodeMatcher` exactly so both engines can
/// share a YAML bridge later.
#[derive(Debug, Clone)]
pub enum NodeMatcher {
    /// Match a member-expression access like `req.body` or `request.query`.
    ///
    /// Triggers whenever the *leftmost* identifier in a chain equals `root`
    /// and the *final* property segment equals `field`.
    Attribute {
        root: String,
        field: String,
        description: String,
    },

    /// Match a call whose callee resolves (raw or via the alias table) to
    /// `canonical`.
    Call {
        canonical: String,
        description: String,
    },

    /// Match any use of a function parameter whose name is in this list.
    /// Used to mark Express-style handlers `(req, res) => {...}` as having
    /// `req` pre-tainted without an explicit source assignment.
    ParamName {
        names: Vec<String>,
        description: String,
    },

    /// Match any method call whose final property name equals `method`,
    /// regardless of receiver. Only meaningful as a sink matcher.
    MethodName { method: String, description: String },

    /// Match an assignment where the LHS is a member expression whose
    /// property name equals `field`. JS-specific: covers the
    /// `element.innerHTML = tainted` pattern, which is not a call and so
    /// cannot be expressed as `Call`.
    MemberAssign { field: String, description: String },
}

impl NodeMatcher {
    pub fn description(&self) -> &str {
        match self {
            NodeMatcher::Attribute { description, .. } => description,
            NodeMatcher::Call { description, .. } => description,
            NodeMatcher::ParamName { description, .. } => description,
            NodeMatcher::MethodName { description, .. } => description,
            NodeMatcher::MemberAssign { description, .. } => description,
        }
    }
}

/// Declarative taint specification consumed by the engine.
#[derive(Debug, Clone, Default)]
pub struct TaintSpec {
    pub sources: Vec<NodeMatcher>,
    pub sinks: Vec<NodeMatcher>,
    pub sanitizers: Vec<NodeMatcher>,
}

/// A single source→sink flow reported by the engine.
#[derive(Debug, Clone)]
pub struct TaintFinding {
    pub sink_start_byte: usize,
    pub sink_end_byte: usize,
    pub sink_line: usize,
    pub sink_column: usize,
    pub sink_end_line: usize,
    pub sink_end_column: usize,
    pub source_description: String,
    pub sink_description: String,
    /// 1-indexed line where the taint source was introduced.
    pub source_line: usize,
}

/// Return-taint summary map keyed by a function's simple name. Mirrors
/// `python_taint::ReturnSummary`. Only top-level `function_declaration`s
/// and arrow/function-expression helpers assigned to a `const`/`let`/
/// `var` identifier are collected — instance methods and object-literal
/// methods are out of scope for v1 because they live on objects with
/// different call semantics. Function-name collisions are resolved
/// last-write-wins (known v1 limitation).
pub type ReturnSummary = HashMap<String, Option<String>>;

/// Bundles the read-only context that every internal walker needs,
/// replacing the repeated `(source, spec, aliases, summaries)` tuple.
struct AnalysisContext<'a> {
    source: &'a str,
    spec: &'a TaintSpec,
    aliases: Option<&'a AliasTable>,
    summaries: &'a ReturnSummary,
}

/// Run the taint engine over every function/method body inside `root` and
/// return one `TaintFinding` per source→sink flow.
///
/// Runs two passes per file. Pass 1 builds the return-taint summary for
/// every eligible function in the file. Pass 2 re-analyzes each scope
/// with that summary available so bare helper calls propagate their
/// return taint into the caller. See `python_taint::analyze_tree` for
/// the full design; the JS engine mirrors it.
pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&AliasTable>,
) -> Vec<TaintFinding> {
    let empty_summary = ReturnSummary::new();
    let mut summaries = ReturnSummary::new();
    let pass1_ctx = AnalysisContext {
        source,
        spec,
        aliases,
        summaries: &empty_summary,
    };
    collect_summary_targets(root, source, &mut |name, func_node| {
        let ret = summarize_function(func_node, &pass1_ctx);
        summaries.insert(name, ret);
    });

    let ctx = AnalysisContext {
        source,
        spec,
        aliases,
        summaries: &summaries,
    };
    let mut findings = Vec::new();
    collect_function_scopes(root, &mut |func_node| {
        analyze_function(func_node, &ctx, &mut findings);
    });
    findings
}

/// Walk `root` and invoke `visit(name, body_node)` for every function
/// whose simple name we can recover: top-level `function_declaration`s
/// and `const foo = (...) => {...}` / `const foo = function(...) {...}`
/// variable declarators with an arrow-function or function-expression
/// initializer. Nested definitions inside other function scopes are NOT
/// descended into for v1 — their summaries would rarely be useful and
/// instance-method / class-method handling is explicitly out of scope.
fn collect_summary_targets<'tree, F>(node: Node<'tree>, source: &str, visit: &mut F)
where
    F: FnMut(String, Node<'tree>),
{
    // Function declarations: record by name, don't descend into their
    // body (nested helpers are out of scope for v1 summaries).
    if matches!(
        node.kind(),
        "function_declaration" | "generator_function_declaration"
    ) {
        if let Some(name) = node.child_by_field_name("name") {
            visit(node_text(name, source).to_string(), node);
        }
        return;
    }
    // `const foo = (...) => ...` / `const foo = function(...) {...}`
    if node.kind() == "variable_declarator" {
        if let (Some(name), Some(value)) = (
            node.child_by_field_name("name"),
            node.child_by_field_name("value"),
        ) {
            if name.kind() == "identifier"
                && matches!(value.kind(), "arrow_function" | "function_expression")
            {
                visit(node_text(name, source).to_string(), value);
                return;
            }
        }
    }
    // Otherwise recurse, but don't descend into *other* function scopes:
    // nested-scope helpers are out of scope for v1.
    if is_function_scope(node.kind()) {
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_summary_targets(child, source, visit);
    }
}

/// Pass-1 walker: compute the return-taint summary for a single function
/// scope. Walks the body with the normal state machinery but throws away
/// sink findings and records the first tainted return expression it sees.
fn summarize_function(func_node: Node<'_>, ctx: &AnalysisContext<'_>) -> Option<String> {
    let mut state = TaintState::default();
    if let Some(params) = func_node.child_by_field_name("parameters") {
        seed_param_sources(params, ctx.source, ctx.spec, &mut state);
    }
    if let Some(single) = func_node.child_by_field_name("parameter") {
        if single.kind() == "identifier" {
            let name = node_text(single, ctx.source);
            for matcher in &ctx.spec.sources {
                if let NodeMatcher::ParamName { names, description } = matcher {
                    if names.iter().any(|n| n == name) {
                        let line = single.start_position().row + 1;
                        state.taint(name.to_string(), description.clone(), line);
                        break;
                    }
                }
            }
        }
    }
    let body = func_node.child_by_field_name("body")?;

    // Arrow-function concise body (`() => expr`): the body field holds
    // the expression directly rather than a `statement_block`, and there
    // is no `return_statement` node to visit. Evaluate taint on it up
    // front so the summary still reflects the implicit return.
    if func_node.kind() == "arrow_function" && body.kind() != "statement_block" {
        return expression_taint(body, ctx, &state).map(|(desc, _line)| desc);
    }

    let mut scratch: Vec<TaintFinding> = Vec::new();
    let mut return_taint: Option<String> = None;
    walk_body_for_summary(body, ctx, &mut state, &mut scratch, &mut return_taint);
    return_taint
}

fn walk_body_for_summary(
    node: Node<'_>,
    ctx: &AnalysisContext<'_>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
    return_taint: &mut Option<String>,
) {
    if is_function_scope(node.kind()) {
        return;
    }

    match node.kind() {
        "variable_declarator" => {
            handle_variable_declarator(node, ctx, state);
        }
        "assignment_expression" => {
            handle_assignment(node, ctx, state, findings);
        }
        "call_expression" => {
            handle_call(node, ctx, state, findings);
        }
        "return_statement" => {
            if return_taint.is_none() {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if let Some((desc, _line)) = expression_taint(child, ctx, state) {
                        *return_taint = Some(desc);
                        break;
                    }
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_body_for_summary(child, ctx, state, findings, return_taint);
    }
}

// ─── Per-file import alias table ──────────────────────────────────────────

/// Per-file JavaScript/TypeScript import alias table.
///
/// Build a JavaScript/TypeScript import alias table from a parsed tree.
///
/// Maps a local identifier (as it appears in the source) to its canonical
/// dotted path. Handles the common forms:
///
/// - `import { loads } from "pickle"`      -> `loads` -> `pickle.loads`
/// - `import { loads as d } from "pickle"` -> `d`     -> `pickle.loads`
/// - `import foo from "bar"`               -> `foo`   -> `bar` (default)
/// - `import * as ns from "mod"`           -> `ns`    -> `mod`
/// - `const pk = require("pickle")`        -> `pk`    -> `pickle`
/// - `const { loads } = require("pickle")` -> `loads` -> `pickle.loads`
/// - `const { loads: l2 } = require("pickle")` -> `l2` -> `pickle.loads`
///
/// File-scope only; function-local rebindings are not tracked. Dynamic
/// forms (`import("mod")`) are out of scope.
pub fn js_aliases_from_tree(source: &str, tree: &Tree) -> AliasTable {
    let mut aliases = AliasTable::new();
    js_walk_for_imports(&mut aliases, tree.root_node(), source);
    aliases
}

fn js_walk_for_imports(aliases: &mut AliasTable, node: Node<'_>, source: &str) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "import_statement" => js_collect_import(aliases, child, source),
            "lexical_declaration" | "variable_declaration" => {
                js_collect_require_decl(aliases, child, source);
            }
            // Recurse into top-level blocks/conditionals but stop at
            // function bodies — alias resolution there is out of scope.
            "program" | "statement_block" | "if_statement" | "try_statement"
            | "labeled_statement" | "export_statement" => {
                js_walk_for_imports(aliases, child, source);
            }
            _ => {}
        }
    }
}

fn js_collect_import(aliases: &mut AliasTable, node: Node<'_>, source: &str) {
    // import_statement has a `source` field holding a `string` with an
    // inner `string_fragment` that carries the module specifier.
    let Some(src_node) = node.child_by_field_name("source") else {
        return;
    };
    let module = string_literal_text(src_node, source);
    if module.is_empty() {
        return;
    }

    // The import clause is the unnamed child between `import` and `from`.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "import_clause" {
            continue;
        }
        let mut inner = child.walk();
        for spec in child.children(&mut inner) {
            match spec.kind() {
                // `import foo from "bar"` — default import.
                "identifier" => {
                    let local = node_text(spec, source).to_string();
                    aliases.insert(local, module.clone());
                }
                // `import * as ns from "mod"` — namespace import.
                "namespace_import" => {
                    let mut ns_cursor = spec.walk();
                    for c in spec.children(&mut ns_cursor) {
                        if c.kind() == "identifier" {
                            let local = node_text(c, source).to_string();
                            aliases.insert(local, module.clone());
                        }
                    }
                }
                // `import { a, b as c } from "mod"` — named imports.
                "named_imports" => {
                    let mut n_cursor = spec.walk();
                    for isp in spec.children(&mut n_cursor) {
                        if isp.kind() != "import_specifier" {
                            continue;
                        }
                        let name = isp
                            .child_by_field_name("name")
                            .map(|n| node_text(n, source).to_string());
                        let alias = isp
                            .child_by_field_name("alias")
                            .map(|n| node_text(n, source).to_string());
                        if let Some(real) = name {
                            let canonical = format!("{}.{}", module, real);
                            let local = alias.unwrap_or(real);
                            aliases.insert(local, canonical);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn js_collect_require_decl(aliases: &mut AliasTable, node: Node<'_>, source: &str) {
    // Walk each variable_declarator under the decl.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }
        let Some(value) = child.child_by_field_name("value") else {
            continue;
        };
        // Match `require("mod")` on the RHS.
        let Some(module) = require_call_module(value, source) else {
            continue;
        };
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        match name_node.kind() {
            "identifier" => {
                // `const pk = require("pickle")` -> pk -> pickle
                let local = node_text(name_node, source).to_string();
                aliases.insert(local, module);
            }
            "object_pattern" => {
                // `const { loads, dumps: d } = require("pickle")`
                let mut p_cursor = name_node.walk();
                for p in name_node.children(&mut p_cursor) {
                    match p.kind() {
                        "shorthand_property_identifier_pattern" => {
                            let local = node_text(p, source).to_string();
                            let canonical = format!("{}.{}", module, local);
                            aliases.insert(local, canonical);
                        }
                        "pair_pattern" => {
                            let key = p
                                .child_by_field_name("key")
                                .map(|n| node_text(n, source).to_string());
                            let value = p
                                .child_by_field_name("value")
                                .map(|n| node_text(n, source).to_string());
                            if let (Some(key), Some(value)) = (key, value) {
                                let canonical = format!("{}.{}", module, key);
                                aliases.insert(value, canonical);
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

/// If `expr` is a `require("...")` call expression, return the module name.
fn require_call_module(expr: Node<'_>, source: &str) -> Option<String> {
    if expr.kind() != "call_expression" {
        return None;
    }
    let func = expr.child_by_field_name("function")?;
    if func.kind() != "identifier" || node_text(func, source) != "require" {
        return None;
    }
    let args = expr.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    for arg in args.named_children(&mut cursor) {
        if arg.kind() == "string" {
            return Some(string_literal_text(arg, source));
        }
    }
    None
}

/// Extract the textual content of a `string` literal node (without the
/// surrounding quotes), using its `string_fragment` child.
fn string_literal_text(node: Node<'_>, source: &str) -> String {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "string_fragment" {
            return node_text(child, source).to_string();
        }
    }
    // Empty-string literal has no fragment child — fall back to trimming.
    let raw = node_text(node, source);
    raw.trim_matches(|c: char| c == '"' || c == '\'' || c == '`')
        .to_string()
}

// ─── Internals ────────────────────────────────────────────────────────────

/// Node kinds that introduce a fresh taint scope (a function body).
fn is_function_scope(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "method_definition"
            | "generator_function"
            | "generator_function_declaration"
    )
}

fn collect_function_scopes<'tree, F>(node: Node<'tree>, visit: &mut F)
where
    F: FnMut(Node<'tree>),
{
    if is_function_scope(node.kind()) {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_function_scopes(child, visit);
    }
}

#[derive(Clone, Debug)]
struct TaintInfo {
    description: String,
    line: usize,
}

#[derive(Default)]
struct TaintState {
    tainted: HashMap<String, TaintInfo>,
}

impl TaintState {
    fn taint(&mut self, name: String, description: String, line: usize) {
        self.tainted.insert(name, TaintInfo { description, line });
    }

    fn clear(&mut self, name: &str) {
        self.tainted.remove(name);
    }

    fn info(&self, name: &str) -> Option<&TaintInfo> {
        self.tainted.get(name)
    }
}

fn analyze_function(
    func_node: Node<'_>,
    ctx: &AnalysisContext<'_>,
    findings: &mut Vec<TaintFinding>,
) {
    let mut state = TaintState::default();

    if let Some(params) = func_node.child_by_field_name("parameters") {
        seed_param_sources(params, ctx.source, ctx.spec, &mut state);
    }
    // Arrow functions with a single bare parameter have `parameter` instead
    // of `parameters` (e.g. `x => x + 1`). tree-sitter-javascript actually
    // wraps it in `formal_parameters` when there is a paren, but a bare
    // identifier parameter is an `identifier` child field-named `parameter`.
    if let Some(single) = func_node.child_by_field_name("parameter") {
        if single.kind() == "identifier" {
            let name = node_text(single, ctx.source);
            let line = single.start_position().row + 1;
            for matcher in &ctx.spec.sources {
                if let NodeMatcher::ParamName { names, description } = matcher {
                    if names.iter().any(|n| n == name) {
                        state.taint(name.to_string(), description.clone(), line);
                        break;
                    }
                }
            }
        }
    }

    let Some(body) = func_node.child_by_field_name("body") else {
        return;
    };
    walk_body(body, ctx, &mut state, findings);
}

fn seed_param_sources(params: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        let param_name = match child.kind() {
            "identifier" => node_text(child, source),
            // `function f(x = 1)` — tree-sitter-javascript wraps the name in
            // an `assignment_pattern` with `left`/`right` fields.
            "assignment_pattern" => {
                let Some(left) = child.child_by_field_name("left") else {
                    continue;
                };
                if left.kind() != "identifier" {
                    continue;
                }
                node_text(left, source)
            }
            // Rest params `...rest`
            "rest_pattern" => {
                let mut inner = child.walk();
                let mut found: Option<&str> = None;
                for c in child.named_children(&mut inner) {
                    if c.kind() == "identifier" {
                        found = Some(node_text(c, source));
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
                    let line = child.start_position().row + 1;
                    state.taint(param_name.to_string(), description.clone(), line);
                    break;
                }
            }
        }
    }
}

fn walk_body(
    node: Node<'_>,
    ctx: &AnalysisContext<'_>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    // Nested function scopes have their own taint state — skip them; they'll
    // be picked up independently by analyze_tree.
    if is_function_scope(node.kind()) {
        return;
    }

    match node.kind() {
        "variable_declarator" => handle_variable_declarator(node, ctx, state),
        "assignment_expression" => handle_assignment(node, ctx, state, findings),
        "call_expression" => handle_call(node, ctx, state, findings),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_body(child, ctx, state, findings);
    }
}

fn handle_variable_declarator(node: Node<'_>, ctx: &AnalysisContext<'_>, state: &mut TaintState) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let Some(value) = node.child_by_field_name("value") else {
        // Bare `let x;` with no initializer — nothing to do.
        return;
    };

    if name.kind() == "identifier" {
        let lhs = node_text(name, ctx.source).to_string();
        if let Some((desc, src_line)) = expression_taint(value, ctx, state) {
            state.taint(lhs, desc, src_line);
        } else {
            state.clear(&lhs);
        }
        return;
    }

    // Destructuring: `const { a } = req.body` or `const [a, b] = arr`.
    // Conservative semantics: if the RHS is tainted at all, taint every
    // bound name. We do not attempt per-slot pairing for JS because
    // destructuring shapes are more varied than Python's tuple unpack.
    if matches!(name.kind(), "object_pattern" | "array_pattern") {
        let targets = collect_destructuring_targets(name, ctx.source);
        if let Some((desc, src_line)) = expression_taint(value, ctx, state) {
            for t in &targets {
                state.taint(t.clone(), desc.clone(), src_line);
            }
        } else {
            for t in &targets {
                state.clear(t);
            }
        }
    }
}

fn collect_destructuring_targets(node: Node<'_>, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "identifier" | "shorthand_property_identifier_pattern" => {
                out.push(node_text(child, source).to_string());
            }
            "pair_pattern" => {
                if let Some(v) = child.child_by_field_name("value") {
                    if v.kind() == "identifier" {
                        out.push(node_text(v, source).to_string());
                    } else if matches!(v.kind(), "object_pattern" | "array_pattern") {
                        out.extend(collect_destructuring_targets(v, source));
                    }
                }
            }
            "object_pattern" | "array_pattern" => {
                out.extend(collect_destructuring_targets(child, source));
            }
            "rest_pattern" => {
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

fn handle_assignment(
    node: Node<'_>,
    ctx: &AnalysisContext<'_>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };

    // Check MemberAssign sinks first: `el.innerHTML = tainted`.
    if left.kind() == "member_expression" {
        if let Some(prop) = left.child_by_field_name("property") {
            let prop_name = node_text(prop, ctx.source);
            if let Some(sink_desc) = ctx.spec.sinks.iter().find_map(|m| match m {
                NodeMatcher::MemberAssign { field, description } if field == prop_name => {
                    Some(description.clone())
                }
                _ => None,
            }) {
                if let Some((src_desc, src_line)) = expression_taint(right, ctx, state) {
                    let start = node.start_position();
                    let end = node.end_position();
                    findings.push(TaintFinding {
                        sink_start_byte: node.start_byte(),
                        sink_end_byte: node.end_byte(),
                        sink_line: start.row + 1,
                        sink_column: start.column + 1,
                        sink_end_line: end.row + 1,
                        sink_end_column: end.column + 1,
                        source_description: src_desc,
                        sink_description: sink_desc,
                        source_line: src_line,
                    });
                }
            }
        }
        // Member-expression LHS: no local name to taint.
        return;
    }

    if left.kind() == "identifier" {
        let lhs = node_text(left, ctx.source).to_string();
        if let Some((desc, src_line)) = expression_taint(right, ctx, state) {
            state.taint(lhs, desc, src_line);
        } else {
            state.clear(&lhs);
        }
        return;
    }

    // Destructuring LHS: `({ a } = req.body)` or `[a, b] = arr`.
    if matches!(left.kind(), "object_pattern" | "array_pattern") {
        let targets = collect_destructuring_targets(left, ctx.source);
        if let Some((desc, src_line)) = expression_taint(right, ctx, state) {
            for t in &targets {
                state.taint(t.clone(), desc.clone(), src_line);
            }
        } else {
            for t in &targets {
                state.clear(t);
            }
        }
    }
}

fn handle_call(
    node: Node<'_>,
    ctx: &AnalysisContext<'_>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    let Some(func) = node.child_by_field_name("function") else {
        return;
    };
    let callee_text = node_text(func, ctx.source);
    let resolved: Cow<'_, str> = match ctx.aliases {
        Some(a) => a.resolve(callee_text),
        None => Cow::Borrowed(callee_text),
    };
    let final_segment = resolved.rsplit('.').next().unwrap_or(resolved.as_ref());

    let sink_desc = ctx.spec.sinks.iter().find_map(|m| match m {
        NodeMatcher::Call {
            canonical,
            description,
        } if canonical.as_str() == resolved.as_ref() => Some(description.clone()),
        NodeMatcher::MethodName {
            method,
            description,
        } if method == final_segment => Some(description.clone()),
        _ => None,
    });
    let Some(sink_desc) = sink_desc else {
        return;
    };

    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    let mut cursor = args.walk();
    for arg in args.named_children(&mut cursor) {
        if let Some((source_desc, src_line)) = expression_taint(arg, ctx, state) {
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
                source_line: src_line,
            });
            break;
        }
    }
}

fn expression_taint(
    expr: Node<'_>,
    ctx: &AnalysisContext<'_>,
    state: &TaintState,
) -> Option<(String, usize)> {
    let expr_line = expr.start_position().row + 1;

    // Direct source match on this expression.
    if let Some(desc) = match_source(expr, ctx.source, ctx.spec, ctx.aliases) {
        return Some((desc, expr_line));
    }

    // Tainted identifier reference.
    if expr.kind() == "identifier" {
        let name = node_text(expr, ctx.source);
        if let Some(info) = state.info(name) {
            return Some((info.description.clone(), info.line));
        }
    }

    // Tainted member-expression root: `x.y` where `x` is tainted.
    if expr.kind() == "member_expression" {
        if let Some(object) = expr.child_by_field_name("object") {
            if let Some(result) = expression_taint(object, ctx, state) {
                return Some(result);
            }
        }
    }

    // Tainted subscript: `x[k]` where `x` is tainted (no key sensitivity).
    if expr.kind() == "subscript_expression" {
        if let Some(object) = expr.child_by_field_name("object") {
            if let Some(result) = expression_taint(object, ctx, state) {
                return Some(result);
            }
        }
    }

    // Template literals propagate taint through any interpolation whose
    // inner expression is tainted: `` `foo ${x}` `` is tainted when `x` is.
    if expr.kind() == "template_string" {
        let mut cursor = expr.walk();
        for child in expr.children(&mut cursor) {
            if child.kind() == "template_substitution" {
                let mut inner = child.walk();
                for inner_child in child.named_children(&mut inner) {
                    if let Some(result) = expression_taint(inner_child, ctx, state) {
                        return Some(result);
                    }
                }
            }
        }
    }

    // Binary plus (string concat): `"x" + tainted` is tainted.
    if expr.kind() == "binary_expression" {
        let mut cursor = expr.walk();
        for child in expr.named_children(&mut cursor) {
            if let Some(result) = expression_taint(child, ctx, state) {
                return Some(result);
            }
        }
    }

    // Parenthesized / unary / sequence wrappers: recurse into children.
    if matches!(
        expr.kind(),
        "parenthesized_expression" | "unary_expression" | "sequence_expression"
    ) {
        let mut cursor = expr.walk();
        for child in expr.named_children(&mut cursor) {
            if let Some(result) = expression_taint(child, ctx, state) {
                return Some(result);
            }
        }
    }

    // Wrapping call: `String(tainted)` / `bytes(tainted)`. Sanitizers short
    // circuit this and collapse to clean.
    if expr.kind() == "call_expression" {
        if is_sanitizer_call(expr, ctx.source, ctx.spec, ctx.aliases) {
            return None;
        }
        if let Some(args) = expr.child_by_field_name("arguments") {
            let mut cursor = args.walk();
            for arg in args.named_children(&mut cursor) {
                if let Some(result) = expression_taint(arg, ctx, state) {
                    return Some(result);
                }
            }
        }

        // Method-call propagation on a tainted root: `x.foo(...)` is
        // tainted when the receiver `x` (or any member/subscript chain
        // rooted at a tainted value) is tainted. Conservative: tainted-in
        // → tainted-out, mirroring the wrapping-call rule. Method calls
        // on literal receivers (e.g. `"foo".toUpperCase()`) are NOT
        // tainted because the recursive `expression_taint` on the object
        // returns None for a bare string literal.
        if let Some(func) = expr.child_by_field_name("function") {
            if func.kind() == "member_expression" {
                if let Some(object) = func.child_by_field_name("object") {
                    if let Some(result) = expression_taint(object, ctx, state) {
                        return Some(result);
                    }
                }
            }
        }

        // Same-file interprocedural v1: a bare identifier callee whose
        // name is in the return-summary map propagates the summary's
        // taint description through the call result. Method calls
        // (`obj.helper()`) are out of scope for v1.
        if let Some(func) = expr.child_by_field_name("function") {
            if func.kind() == "identifier" {
                let callee = node_text(func, ctx.source);
                if let Some(Some(desc)) = ctx.summaries.get(callee) {
                    return Some((format!("{desc} (via {callee})"), expr_line));
                }
            }
        }
    }

    None
}

fn is_sanitizer_call(
    call_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&AliasTable>,
) -> bool {
    if call_node.kind() != "call_expression" {
        return false;
    }
    let Some(func) = call_node.child_by_field_name("function") else {
        return false;
    };
    let callee_text = node_text(func, source);
    let resolved: Cow<'_, str> = match aliases {
        Some(a) => a.resolve(callee_text),
        None => Cow::Borrowed(callee_text),
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
    aliases: Option<&AliasTable>,
) -> Option<String> {
    for matcher in &spec.sources {
        match matcher {
            NodeMatcher::Attribute {
                root,
                field,
                description,
            } => {
                if node.kind() != "member_expression" {
                    continue;
                }
                let Some(prop) = node.child_by_field_name("property") else {
                    continue;
                };
                if node_text(prop, source) != field.as_str() {
                    continue;
                }
                let Some(raw_root) = leftmost_identifier(node, source) else {
                    continue;
                };
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
                if node.kind() != "call_expression" {
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
                // Seeded at function entry, not matched on expressions.
            }
            NodeMatcher::MethodName { .. } | NodeMatcher::MemberAssign { .. } => {
                // Sink-only matchers.
            }
        }
    }
    None
}

/// Canonical set of untrusted-input sources for JavaScript/TypeScript web
/// handlers. Organized by framework; add new sources to the matching
/// section and keep the layout stable so future contributors know where
/// their entries belong.
///
/// Frameworks covered today:
/// 1. Generic handler parameters (`req`, `request`) — Express / Fastify /
///    Next.js App Router share this convention.
/// 2. Express-style `req.*` / `request.*` attribute access.
/// 3. Next.js App Router (`request.nextUrl.*`, `request.cookies.*`).
/// 4. Hono (`c.req.*` call / attribute patterns — `c` is intentionally
///    NOT added as a `ParamName` matcher because single-letter locals
///    named `c` are extremely common in generic JS and would explode
///    false positives).
/// 5. Fastify — largely overlaps with Express sources above; no new
///    matchers needed today, but future Fastify-only fields go here.
/// 6. SvelteKit (`event.request`, `event.params`, `event.url`). `event`
///    is intentionally NOT a `ParamName` matcher — browser DOM event
///    handlers use the same name and would flood false positives.
/// 7. Deno (`Deno.args`, `Deno.env.get`).
///
/// Several method-call sources (`request.headers.get(...)`,
/// `request.cookies.get(...)`, `request.formData()`, `request.json()`)
/// require the engine to propagate taint from a method-call *receiver*
/// into the call expression's result. That is tracked as issue #27 and
/// is not expressible with the `NodeMatcher` variants today. Once #27
/// lands, those patterns will fire automatically for any handler whose
/// parameter is already seeded as `request` / `req` — no new matchers
/// required here.
pub fn javascript_taint_sources() -> Vec<NodeMatcher> {
    vec![
        // ─── 1. Generic handler parameters ────────────────────────────
        NodeMatcher::ParamName {
            names: vec!["req".into(), "request".into()],
            description: "untrusted request parameter".into(),
        },
        // ─── 2. Express / general `req.*` and `request.*` ────────────
        NodeMatcher::Attribute {
            root: "req".into(),
            field: "body".into(),
            description: "req.body".into(),
        },
        NodeMatcher::Attribute {
            root: "req".into(),
            field: "query".into(),
            description: "req.query".into(),
        },
        NodeMatcher::Attribute {
            root: "req".into(),
            field: "params".into(),
            description: "req.params".into(),
        },
        NodeMatcher::Attribute {
            root: "req".into(),
            field: "headers".into(),
            description: "req.headers".into(),
        },
        NodeMatcher::Attribute {
            root: "req".into(),
            field: "cookies".into(),
            description: "req.cookies".into(),
        },
        NodeMatcher::Attribute {
            root: "request".into(),
            field: "body".into(),
            description: "request.body".into(),
        },
        NodeMatcher::Attribute {
            root: "request".into(),
            field: "query".into(),
            description: "request.query".into(),
        },
        NodeMatcher::Attribute {
            root: "request".into(),
            field: "params".into(),
            description: "request.params".into(),
        },
        NodeMatcher::Attribute {
            root: "request".into(),
            field: "headers".into(),
            description: "request.headers".into(),
        },
        NodeMatcher::Attribute {
            root: "request".into(),
            field: "cookies".into(),
            description: "request.cookies".into(),
        },
        // ─── 3. Next.js App Router ───────────────────────────────────
        // `request.nextUrl` exposes a parsed URL — `.searchParams`,
        // `.pathname`, `.href` are all untrusted when `request` is the
        // handler input. `request.cookies` overlaps with Express above.
        // Method-call variants (`request.headers.get`, `request.json`,
        // `request.formData`, `request.cookies.get`) depend on issue
        // #27 — see the header comment above.
        NodeMatcher::Attribute {
            root: "request".into(),
            field: "nextUrl".into(),
            description: "Next.js request.nextUrl".into(),
        },
        // ─── 4. Hono ─────────────────────────────────────────────────
        // Hono handlers receive a context `c` whose `c.req` is the
        // untrusted request. Direct `c.req` attribute access is covered
        // by the `Attribute` matcher below; the most common call forms
        // are enumerated explicitly so the engine picks them up even
        // though `c` is never seeded via `ParamName` (see header
        // comment for the rationale).
        NodeMatcher::Attribute {
            root: "c".into(),
            field: "req".into(),
            description: "Hono c.req".into(),
        },
        NodeMatcher::Call {
            canonical: "c.req.query".into(),
            description: "Hono c.req.query()".into(),
        },
        NodeMatcher::Call {
            canonical: "c.req.param".into(),
            description: "Hono c.req.param()".into(),
        },
        NodeMatcher::Call {
            canonical: "c.req.header".into(),
            description: "Hono c.req.header()".into(),
        },
        NodeMatcher::Call {
            canonical: "c.req.json".into(),
            description: "Hono c.req.json()".into(),
        },
        NodeMatcher::Call {
            canonical: "c.req.formData".into(),
            description: "Hono c.req.formData()".into(),
        },
        NodeMatcher::Call {
            canonical: "c.req.parseBody".into(),
            description: "Hono c.req.parseBody()".into(),
        },
        // ─── 5. Fastify ──────────────────────────────────────────────
        // Fastify uses the same `request.body` / `.query` / `.params` /
        // `.headers` / `.cookies` surface as Express, so the section 2
        // matchers already cover it. Add Fastify-specific fields here
        // if any ever diverge.
        // ─── 6. SvelteKit ────────────────────────────────────────────
        // `event` is intentionally NOT a `ParamName` matcher — DOM
        // event handlers use the same name. Rely on explicit
        // attribute paths from the request event object.
        NodeMatcher::Attribute {
            root: "event".into(),
            field: "request".into(),
            description: "SvelteKit event.request".into(),
        },
        NodeMatcher::Attribute {
            root: "event".into(),
            field: "params".into(),
            description: "SvelteKit event.params".into(),
        },
        NodeMatcher::Attribute {
            root: "event".into(),
            field: "url".into(),
            description: "SvelteKit event.url".into(),
        },
        // ─── 7. Deno ─────────────────────────────────────────────────
        NodeMatcher::Attribute {
            root: "Deno".into(),
            field: "args".into(),
            description: "Deno.args".into(),
        },
        NodeMatcher::Call {
            canonical: "Deno.env.get".into(),
            description: "Deno.env.get()".into(),
        },
    ]
}

/// Walk a member-expression chain leftward and return the leftmost
/// identifier text. For `req.body.name`, returns `"req"`. For `x.y`,
/// returns `"x"`.
fn leftmost_identifier<'a>(mut node: Node<'_>, source: &'a str) -> Option<&'a str> {
    loop {
        match node.kind() {
            "identifier" => return Some(node_text(node, source)),
            "member_expression" => {
                node = node.child_by_field_name("object")?;
            }
            "subscript_expression" => {
                node = node.child_by_field_name("object")?;
            }
            _ => return None,
        }
    }
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::Language;

    fn spec_innerhtml_from_req() -> TaintSpec {
        TaintSpec {
            sources: javascript_taint_sources(),
            sinks: vec![
                NodeMatcher::MemberAssign {
                    field: "innerHTML".into(),
                    description: "innerHTML assignment".into(),
                },
                NodeMatcher::MemberAssign {
                    field: "outerHTML".into(),
                    description: "outerHTML assignment".into(),
                },
                NodeMatcher::Call {
                    canonical: "document.write".into(),
                    description: "document.write".into(),
                },
            ],
            sanitizers: vec![],
        }
    }

    fn run(source: &str) -> Vec<TaintFinding> {
        let tree = parse_file(source, Language::JavaScript).expect("parse");
        let aliases = js_aliases_from_tree(source, &tree);
        analyze_tree(
            tree.root_node(),
            source,
            &spec_innerhtml_from_req(),
            Some(&aliases),
        )
    }

    #[test]
    fn direct_flow_req_body_to_innerhtml() {
        let src = r#"
function handler(req) {
    document.getElementById("x").innerHTML = req.body;
}
"#;
        let f = run(src);
        assert_eq!(f.len(), 1);
        assert!(f[0].source_description.contains("req.body"));
        assert_eq!(f[0].sink_description, "innerHTML assignment");
    }

    #[test]
    fn express_param_source_is_implicit() {
        // No explicit `req.body` access: the handler uses the bare `req`
        // parameter, which is tainted via ParamName.
        let src = r#"
app.get("/", function(req, res) {
    document.write(req);
});
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn express_param_source_via_field_access() {
        let src = r#"
app.get("/", function(req, res) {
    document.write(req.body.title);
});
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn template_literal_propagates_taint() {
        let src = r#"
function handler(req) {
    const el = document.getElementById("x");
    el.innerHTML = `<p>${req.body.name}</p>`;
}
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn reassignment_to_literal_kills_taint() {
        let src = r#"
function handler(req) {
    let data = req.body.data;
    data = "clean";
    document.write(data);
}
"#;
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn subscript_on_tainted_root_is_tainted() {
        let src = r#"
function handler(req) {
    document.write(req.body["payload"]);
}
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn one_hop_assignment_propagates() {
        let src = r#"
function handler(req) {
    const name = req.query.name;
    document.getElementById("x").innerHTML = name;
}
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn alias_chain_propagates() {
        let src = r#"
function handler(req) {
    const data = req.body.data;
    const moreData = data;
    document.write(moreData);
}
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn no_source_no_finding() {
        let src = r#"
function handler() {
    const x = "static";
    document.write(x);
    document.getElementById("a").innerHTML = "<p>hi</p>";
}
"#;
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn nested_function_has_independent_taint() {
        let src = r#"
function outer(req) {
    const data = req.body;
    function inner() {
        document.write(data);
    }
    return inner;
}
"#;
        // `outer` has no sink call; `inner` sees no source because `data`
        // is not in its local taint state.
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn arrow_function_body_is_analyzed() {
        let src = r#"
const handler = (req, res) => {
    document.write(req.body.x);
};
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn alias_resolution_through_import_table() {
        // `const { loads } = require("pickle"); loads(x)` must resolve to
        // `pickle.loads` — verified via a spec that uses Call sink matching.
        let src = r#"
const { loads } = require("pickle");
function handler(req) {
    loads(req.body);
}
"#;
        let spec = TaintSpec {
            sources: javascript_taint_sources(),
            sinks: vec![NodeMatcher::Call {
                canonical: "pickle.loads".into(),
                description: "pickle.loads".into(),
            }],
            sanitizers: vec![],
        };
        let tree = parse_file(src, Language::JavaScript).expect("parse");
        let aliases = js_aliases_from_tree(src, &tree);
        let findings = analyze_tree(tree.root_node(), src, &spec, Some(&aliases));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn alias_import_star_as_namespace() {
        let src = r#"
import * as pickle from "pickle";
function handler(req) {
    pickle.loads(req.body);
}
"#;
        let spec = TaintSpec {
            sources: javascript_taint_sources(),
            sinks: vec![NodeMatcher::Call {
                canonical: "pickle.loads".into(),
                description: "pickle.loads".into(),
            }],
            sanitizers: vec![],
        };
        let tree = parse_file(src, Language::JavaScript).expect("parse");
        let aliases = js_aliases_from_tree(src, &tree);
        let findings = analyze_tree(tree.root_node(), src, &spec, Some(&aliases));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn require_default_binding_resolves() {
        let src = r#"const pk = require("pickle");"#;
        let tree = parse_file(src, Language::JavaScript).expect("parse");
        let a = js_aliases_from_tree(src, &tree);
        assert_eq!(a.get("pk"), Some("pickle"));
        assert_eq!(a.resolve("pk.loads"), "pickle.loads");
    }

    #[test]
    fn named_import_with_alias_resolves() {
        let src = r#"import { loads as l2 } from "pickle";"#;
        let tree = parse_file(src, Language::JavaScript).expect("parse");
        let a = js_aliases_from_tree(src, &tree);
        assert_eq!(a.get("l2"), Some("pickle.loads"));
    }

    #[test]
    fn string_concat_propagates_taint() {
        let src = r#"
function handler(req) {
    document.write("<h1>" + req.body.title + "</h1>");
}
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn interprocedural_tainted_return_propagates_to_caller() {
        // Use a module-scoped `req` so the caller's argument list is clean
        // and the only path to taint in the caller is via the helper's
        // return summary.
        let src = r#"
function getUserInput() {
    return req.body;
}

function handler() {
    const data = getUserInput();
    document.write(data);
}
"#;
        let f = run(src);
        assert_eq!(f.len(), 1);
        assert!(f[0].source_description.contains("getUserInput"));
    }

    #[test]
    fn interprocedural_clean_return_does_not_fire() {
        let src = r#"
function cleanHelper() {
    return "static";
}

function handler() {
    document.write(cleanHelper());
}
"#;
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn interprocedural_late_definition_still_found() {
        let src = r#"
function handler() {
    const data = helper();
    document.write(data);
}

function helper() {
    return req.body;
}
"#;
        let f = run(src);
        assert_eq!(f.len(), 1);
        assert!(f[0].source_description.contains("helper"));
    }

    #[test]
    fn multi_hop_chain_is_out_of_scope_v1() {
        // Two-hop chain: `middle` calls `sourceFn`. Pass 1 uses an empty
        // summary, so `middle`'s return is seen as clean. Documented
        // v1 limitation — the test pins the behavior. The handler has
        // no tainted argument (no `req` param or access), so the only
        // path to taint would be a working multi-hop summary.
        let src = r#"
function sourceFn() {
    return req.body;
}

function middle() {
    return sourceFn();
}

function handler() {
    document.write(middle());
}
"#;
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn interprocedural_arrow_function_helper_propagates() {
        // Arrow-function helper with concise body assigned to a const.
        let src = r#"
const getInput = () => req.body;

function handler() {
    document.write(getInput());
}
"#;
        let f = run(src);
        assert_eq!(f.len(), 1);
        assert!(f[0].source_description.contains("getInput"));
    }

    #[test]
    fn interprocedural_arrow_function_block_body_propagates() {
        let src = r#"
const getInput = () => { return req.body; };

function handler() {
    const data = getInput();
    document.write(data);
}
"#;
        let f = run(src);
        assert_eq!(f.len(), 1);
        assert!(f[0].source_description.contains("getInput"));
    }

    #[test]
    fn method_call_on_tainted_source_propagates() {
        // `req.body.get("x")` — receiver `req.body` is a source, method
        // call result must carry the taint into the sink.
        let src = r#"
function handler(req) {
    const data = req.body.get("x");
    document.write(data);
}
"#;
        let f = run(src);
        assert_eq!(f.len(), 1);
        assert!(f[0].source_description.contains("req.body"));
    }

    #[test]
    fn method_call_with_args_still_tainted() {
        let src = r#"
function handler(req) {
    const data = req.body.get("x", "default");
    document.write(data);
}
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn chained_method_calls_preserve_taint() {
        let src = r#"
function handler(req) {
    const data = req.body.get("x").trim().toUpperCase();
    document.write(data);
}
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn to_string_on_tainted_value_is_tainted() {
        let src = r#"
function handler(req) {
    const data = req.body.toString();
    document.write(data);
}
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn sanitizer_call_kills_taint() {
        let mut spec = spec_innerhtml_from_req();
        spec.sanitizers = vec![NodeMatcher::Call {
            canonical: "escapeHtml".into(),
            description: "escapeHtml".into(),
        }];
        let src = r#"
function handler(req) {
    const raw = req.body;
    const clean = escapeHtml(raw);
    document.write(clean);
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("parse");
        let aliases = js_aliases_from_tree(src, &tree);
        assert_eq!(
            analyze_tree(tree.root_node(), src, &spec, Some(&aliases)).len(),
            0
        );
    }
}
