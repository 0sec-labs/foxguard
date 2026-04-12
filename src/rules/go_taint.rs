//! Intraprocedural, flow-insensitive taint analysis for Go.
//!
//! Ported from `python_taint.rs` / `javascript_taint.rs` as part of
//! issue #31. The surface mirrors the Python/JS engines intentionally
//! — `TaintSpec`, `NodeMatcher`, `TaintFinding`, and `analyze_tree` have
//! identical shapes so a future refactor that extracts the
//! language-agnostic core is cheap. For now we keep three engines so
//! each grammar's quirks stay local.
//!
//! # Scope (same as Python/JS)
//!
//! - **Per function / method / closure.** Each `function_declaration`,
//!   `method_declaration`, and `func_literal` (closure / anonymous
//!   function) body is analyzed independently.
//! - **Per file.** No cross-file analysis.
//! - **Flow-insensitive.** Statements are processed in source order; a
//!   reassignment with a clean RHS clears the target's taint.
//! - **One level of selector/subscript propagation.** `c.Query("x")`
//!   and `m["k"]` propagate taint whenever the root is tainted.
//! - **One level of wrapping-call propagation.** `string(tainted)`,
//!   `fmt.Sprintf("%s", tainted)` stay tainted unless the callee is in
//!   `sanitizers`.
//! - **Binary `+` (string concat) propagates taint** — mirrors the JS
//!   engine.
//! - **Method-call propagation on tainted receivers** — `x.foo()` is
//!   tainted when `x` is.
//! - **Same-file interprocedural return propagation.** Pass 1 records a
//!   return-taint summary per function / method simple name; pass 2
//!   re-analyzes using the summary. Method names collide with bare
//!   functions: last-write-wins (documented v1 limitation).
//! - **Multi-return destructuring** — `a, b := f()`: if `f`'s summary
//!   slot is tainted, all bound names are tainted.
//!
//! Everything specific to a library is expressed declaratively via
//! `TaintSpec`.

use std::borrow::Cow;
use std::collections::HashMap;
use tree_sitter::{Node, Tree, TreeCursor};

// ─── Public API ───────────────────────────────────────────────────────────

/// A pattern that matches an AST node for taint analysis.
///
/// Surface matches `python_taint::NodeMatcher` / `javascript_taint::NodeMatcher`
/// exactly so all three engines can share a YAML bridge later.
#[derive(Debug, Clone)]
pub enum NodeMatcher {
    /// Match a selector-expression access like `r.URL` or `c.Request`.
    ///
    /// Triggers whenever the *leftmost* identifier in a chain equals
    /// `root` and the *final* field segment equals `field`.
    Attribute {
        root: String,
        field: String,
        description: String,
    },

    /// Match a call whose callee resolves (raw or via the alias table)
    /// to `canonical`.
    Call {
        canonical: String,
        description: String,
    },

    /// Match any use of a function parameter whose name is in this
    /// list. Used to mark `func handler(w http.ResponseWriter, r *http.Request)`
    /// as having `r` pre-tainted without an explicit source access.
    ParamName {
        names: Vec<String>,
        description: String,
    },

    /// Match any method call whose final field name equals `method`,
    /// regardless of receiver. Only meaningful as a sink matcher. Used
    /// by the SQL injection rule so `db.Query`, `tx.Query`, `stmt.Query`,
    /// `conn.QueryContext` all fire uniformly without listing every
    /// plausible receiver.
    MethodName { method: String, description: String },
}

impl NodeMatcher {
    pub fn description(&self) -> &str {
        match self {
            NodeMatcher::Attribute { description, .. } => description,
            NodeMatcher::Call { description, .. } => description,
            NodeMatcher::ParamName { description, .. } => description,
            NodeMatcher::MethodName { description, .. } => description,
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
}

/// Return-taint summary map keyed by a function / method simple name.
/// Mirrors `python_taint::ReturnSummary`.
///
/// Methods are keyed by their bare name (ignoring the receiver type),
/// which means a file that defines both `func foo()` and
/// `func (r *Foo) foo()` will last-write-wins. Documented as a known
/// v1 limitation.
pub type ReturnSummary = HashMap<String, Option<String>>;

/// Run the taint engine over every function/method body inside `root`
/// and return one `TaintFinding` per source→sink flow.
///
/// Runs two passes per file. Pass 1 builds the return-taint summary
/// for every eligible function / method in the file. Pass 2
/// re-analyzes each scope with that summary available.
pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&GoImportAliases>,
) -> Vec<TaintFinding> {
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

    let mut findings = Vec::new();
    collect_function_defs(root, &mut |func_node| {
        analyze_function(func_node, source, spec, aliases, &summaries, &mut findings);
    });
    findings
}

// ─── Per-file import alias table ──────────────────────────────────────────

/// Per-file Go import alias table.
///
/// Maps a local package identifier to its canonical import path's
/// last segment — the default name users reference in call sites.
///
/// Handles:
///
/// - `import "fmt"`              → `fmt`  → `fmt`
/// - `import f "fmt"`            → `f`    → `fmt`
/// - `import "net/http"`         → `http` → `http`
/// - `import net "net/http"`     → `net`  → `http`
/// - Grouped imports inside `import ( ... )` blocks.
///
/// Out of scope for v1 (documented):
///
/// - `import . "fmt"`  — dot imports make names unqualified, rare.
/// - `import _ "foo"`  — side-effect imports introduce no names.
///
/// File-scope only; function-local rebindings are not tracked.
#[derive(Debug, Default, Clone)]
pub struct GoImportAliases {
    /// Local alias → canonical short package name (e.g. `net` → `http`).
    map: HashMap<String, String>,
}

impl GoImportAliases {
    pub fn from_tree(source: &str, tree: &Tree) -> Self {
        let mut aliases = Self::default();
        let root = tree.root_node();
        let mut cursor = root.walk();
        for child in root.children(&mut cursor) {
            if child.kind() == "import_declaration" {
                aliases.collect_import_decl(child, source);
            }
        }
        aliases
    }

    fn collect_import_decl(&mut self, node: Node<'_>, source: &str) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            match child.kind() {
                "import_spec" => self.collect_import_spec(child, source),
                "import_spec_list" => {
                    let mut inner = child.walk();
                    for spec in child.children(&mut inner) {
                        if spec.kind() == "import_spec" {
                            self.collect_import_spec(spec, source);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn collect_import_spec(&mut self, node: Node<'_>, source: &str) {
        let Some(path_node) = node.child_by_field_name("path") else {
            return;
        };
        let raw = node_text(path_node, source);
        let path = raw.trim_matches(|c: char| c == '"' || c == '`');
        if path.is_empty() {
            return;
        }
        // Canonical: last segment of the import path, e.g. `net/http` → `http`.
        let canonical = path.rsplit('/').next().unwrap_or(path).to_string();

        let name_node = node.child_by_field_name("name");
        match name_node.map(|n| n.kind()) {
            // `import . "fmt"` — out of scope; record nothing.
            Some("dot") => {}
            // `import _ "foo"` — out of scope; record nothing.
            Some("blank_identifier") => {}
            // `import f "fmt"` — local alias `f` → canonical `fmt`.
            Some("package_identifier") => {
                let local = node_text(name_node.unwrap(), source).to_string();
                self.map.insert(local, canonical);
            }
            // Plain `import "fmt"` — the local name is the canonical.
            _ => {
                self.map.insert(canonical.clone(), canonical);
            }
        }
    }

    /// Resolve a call-site callee text back to its canonical dotted
    /// path. `f.Println` → `fmt.Println` when `f` is aliased to `fmt`.
    pub fn resolve<'a>(&'a self, callee: &'a str) -> Cow<'a, str> {
        if let Some((head, tail)) = callee.split_once('.') {
            if let Some(canonical_root) = self.map.get(head) {
                if canonical_root == head {
                    return Cow::Borrowed(callee);
                }
                return Cow::Owned(format!("{}.{}", canonical_root, tail));
            }
            return Cow::Borrowed(callee);
        }
        if let Some(canonical) = self.map.get(callee) {
            return Cow::Borrowed(canonical.as_str());
        }
        Cow::Borrowed(callee)
    }

    #[cfg(test)]
    pub fn get(&self, local: &str) -> Option<&str> {
        self.map.get(local).map(String::as_str)
    }
}

// ─── Internals ────────────────────────────────────────────────────────────

/// Walk `root` and visit every function/method declaration **and**
/// every `func_literal` (closure / anonymous function). Named
/// declarations and closures both get independent taint analysis.
/// We recurse into function bodies so that closures nested inside
/// call arguments (e.g. `r.GET("/path", func(c *gin.Context) { … })`)
/// are discovered.
fn collect_function_defs<'tree, F>(node: Node<'tree>, visit: &mut F)
where
    F: FnMut(Node<'tree>),
{
    if matches!(
        node.kind(),
        "function_declaration" | "method_declaration" | "func_literal"
    ) {
        visit(node);
        // Continue recursing: the body may contain nested func_literals
        // (closures passed as arguments, goroutines, etc.) that also
        // need independent analysis.
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_function_defs(child, visit);
    }
}

/// Extract a function / method simple name. For `method_declaration`
/// the name is a `field_identifier`; for `function_declaration` it's
/// an `identifier`.
fn function_simple_name<'a>(func_node: Node<'_>, source: &'a str) -> Option<&'a str> {
    func_node
        .child_by_field_name("name")
        .map(|n| node_text(n, source))
}

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

/// Pass-1 walker: compute a function/method's return-taint summary.
fn summarize_function(
    func_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&GoImportAliases>,
    summaries: &ReturnSummary,
) -> (Option<String>, Option<String>) {
    let name = function_simple_name(func_node, source).map(|s| s.to_string());

    let mut state = TaintState::default();
    if let Some(params) = func_node.child_by_field_name("parameters") {
        seed_param_sources(params, source, spec, &mut state);
    }
    let Some(body) = func_node.child_by_field_name("body") else {
        return (name, None);
    };

    let mut return_taint: Option<String> = None;
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
    aliases: Option<&GoImportAliases>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
    summaries: &ReturnSummary,
    return_taint: &mut Option<String>,
) {
    // Don't descend into nested function literals / closures — their
    // own returns belong to their own summary. Each closure gets its
    // own independent analysis via `collect_function_defs`.
    if node.kind() == "func_literal" {
        return;
    }

    match node.kind() {
        "short_var_declaration" => {
            handle_short_var_declaration(node, source, spec, aliases, state, summaries);
        }
        "var_spec" => {
            handle_var_spec(node, source, spec, aliases, state, summaries);
        }
        "assignment_statement" => {
            handle_assignment(node, source, spec, aliases, state, findings, summaries);
        }
        "call_expression" => {
            handle_call(node, source, spec, aliases, state, findings, summaries);
        }
        "return_statement" => {
            if return_taint.is_none() {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    // return statement children are expression_list(s).
                    if child.kind() == "expression_list" {
                        let mut inner = child.walk();
                        for expr in child.named_children(&mut inner) {
                            if let Some(desc) =
                                expression_taint(expr, source, spec, aliases, state, summaries)
                            {
                                *return_taint = Some(desc);
                                break;
                            }
                        }
                    } else if let Some(desc) =
                        expression_taint(child, source, spec, aliases, state, summaries)
                    {
                        *return_taint = Some(desc);
                    }
                    if return_taint.is_some() {
                        break;
                    }
                }
            }
        }
        _ => {}
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

fn analyze_function(
    func_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&GoImportAliases>,
    summaries: &ReturnSummary,
    findings: &mut Vec<TaintFinding>,
) {
    let mut state = TaintState::default();

    if let Some(params) = func_node.child_by_field_name("parameters") {
        seed_param_sources(params, source, spec, &mut state);
    }

    let Some(body) = func_node.child_by_field_name("body") else {
        return;
    };
    walk_body(body, source, spec, aliases, &mut state, findings, summaries);
}

fn seed_param_sources(params: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        if !matches!(
            child.kind(),
            "parameter_declaration" | "variadic_parameter_declaration"
        ) {
            continue;
        }
        // parameter_declaration has multiple `name` field children.
        // `parameter_declaration.name` is an identifier but there may
        // be several per declaration (`a, b int`).
        let mut name_cursor = child.walk();
        for inner in child.children(&mut name_cursor) {
            if inner.kind() != "identifier" {
                continue;
            }
            let param_name = node_text(inner, source);
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
}

fn walk_body(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&GoImportAliases>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
    summaries: &ReturnSummary,
) {
    // Nested function literal / closure — skip. Each closure gets its
    // own independent analysis via `collect_function_defs`, so we must
    // not walk into its body here (that would mix taint states).
    if node.kind() == "func_literal" {
        return;
    }

    match node.kind() {
        "short_var_declaration" => {
            handle_short_var_declaration(node, source, spec, aliases, state, summaries);
        }
        "var_spec" => {
            handle_var_spec(node, source, spec, aliases, state, summaries);
        }
        "assignment_statement" => {
            handle_assignment(node, source, spec, aliases, state, findings, summaries);
        }
        "call_expression" => {
            handle_call(node, source, spec, aliases, state, findings, summaries);
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_body(child, source, spec, aliases, state, findings, summaries);
    }
}

/// Collect identifiers from an `expression_list` that are plain
/// identifier targets (e.g. LHS of `a, b := f()`). Non-identifier
/// targets (selector/index) are skipped because the state only tracks
/// bare names.
fn collect_identifier_targets<'a>(list: Node<'_>, source: &'a str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut cursor = list.walk();
    for child in list.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            out.push(node_text(child, source));
        }
    }
    out
}

/// Collect expression nodes from an `expression_list`.
fn collect_expression_list<'tree>(list: Node<'tree>) -> Vec<Node<'tree>> {
    let mut out = Vec::new();
    let mut cursor = list.walk();
    for child in list.named_children(&mut cursor) {
        out.push(child);
    }
    out
}

/// Handle `a := ...`, `a, b := ...`, `a, b := f()`.
fn handle_short_var_declaration(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&GoImportAliases>,
    state: &mut TaintState,
    summaries: &ReturnSummary,
) {
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    propagate_multi_assign(left, right, source, spec, aliases, state, summaries);
}

/// Handle `var x = ...`, `var x, y = f()`, `var x T = ...`.
fn handle_var_spec(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&GoImportAliases>,
    state: &mut TaintState,
    summaries: &ReturnSummary,
) {
    // var_spec has multiple `name` fields and an optional `value`
    // expression_list.
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };

    // Collect the name identifiers from the var_spec directly.
    let mut lhs_names: Vec<&str> = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" {
            lhs_names.push(node_text(child, source));
        }
    }
    if lhs_names.is_empty() {
        return;
    }

    // `value` is an expression_list. Pair it with LHS names.
    let rhs_exprs = collect_expression_list(value);
    apply_multi_assign_semantics(
        &lhs_names, &rhs_exprs, source, spec, aliases, state, summaries,
    );
}

/// Handle `x = ...`, `x, y = ...`, `x += ...`.
fn handle_assignment(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&GoImportAliases>,
    state: &mut TaintState,
    _findings: &mut Vec<TaintFinding>,
    summaries: &ReturnSummary,
) {
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    propagate_multi_assign(left, right, source, spec, aliases, state, summaries);
}

fn propagate_multi_assign(
    left: Node<'_>,
    right: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&GoImportAliases>,
    state: &mut TaintState,
    summaries: &ReturnSummary,
) {
    // Both sides are `expression_list`s in tree-sitter-go.
    let lhs_names = if left.kind() == "expression_list" {
        collect_identifier_targets(left, source)
    } else {
        return;
    };
    if lhs_names.is_empty() {
        return;
    }
    let rhs_exprs = if right.kind() == "expression_list" {
        collect_expression_list(right)
    } else {
        vec![right]
    };
    apply_multi_assign_semantics(
        &lhs_names, &rhs_exprs, source, spec, aliases, state, summaries,
    );
}

/// Shared LHS/RHS pairing semantics for short_var_declaration,
/// var_spec, and assignment_statement.
///
/// - If RHS and LHS arity match, pair element-wise.
/// - Otherwise, if RHS is a single expression (typical multi-return
///   call like `a, b := f()`), evaluate that expression's taint and
///   broadcast to every LHS name. This is the conservative
///   multi-return destructuring policy documented in the module header.
fn apply_multi_assign_semantics(
    lhs_names: &[&str],
    rhs_exprs: &[Node<'_>],
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&GoImportAliases>,
    state: &mut TaintState,
    summaries: &ReturnSummary,
) {
    if lhs_names.len() == rhs_exprs.len() {
        // Collect desc first to avoid borrow conflicts.
        let descs: Vec<Option<String>> = rhs_exprs
            .iter()
            .map(|rhs| expression_taint(*rhs, source, spec, aliases, state, summaries))
            .collect();
        for (name, desc) in lhs_names.iter().zip(descs.into_iter()) {
            match desc {
                Some(d) => state.taint((*name).to_string(), d),
                None => state.clear(name),
            }
        }
        return;
    }

    // Conservative broadcast: if *any* RHS expression is tainted, taint
    // every LHS name; otherwise clear them all.
    let mut broadcast: Option<String> = None;
    for rhs in rhs_exprs {
        if let Some(d) = expression_taint(*rhs, source, spec, aliases, state, summaries) {
            broadcast = Some(d);
            break;
        }
    }
    match broadcast {
        Some(desc) => {
            for name in lhs_names {
                state.taint((*name).to_string(), desc.clone());
            }
        }
        None => {
            for name in lhs_names {
                state.clear(name);
            }
        }
    }
}

/// Resolve a `call_expression`'s callee into a canonical text. Handles
/// bare identifiers (`foo`) and selector expressions (`pkg.Foo`,
/// `obj.Method`).
fn callee_text<'a>(call: Node<'_>, source: &'a str) -> Option<Cow<'a, str>> {
    let func = call.child_by_field_name("function")?;
    Some(Cow::Borrowed(node_text(func, source)))
}

fn handle_call(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&GoImportAliases>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
    summaries: &ReturnSummary,
) {
    let Some(callee_raw) = callee_text(node, source) else {
        return;
    };
    let resolved: Cow<'_, str> = match aliases {
        Some(a) => a.resolve(callee_raw.as_ref()),
        None => Cow::Borrowed(callee_raw.as_ref()),
    };
    // The final segment of the callee; used by `MethodName` sink
    // matching. For `db.Query` this is `"Query"`; for a bare `exec`
    // it's `"exec"`.
    let final_segment = resolved.rsplit('.').next().unwrap_or(resolved.as_ref());

    let sink_desc = spec.sinks.iter().find_map(|m| match m {
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
            break;
        }
    }
}

/// Returns the source description if `expr` evaluates to (or
/// references) a tainted value, otherwise `None`.
fn expression_taint(
    expr: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&GoImportAliases>,
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

    // Tainted selector expression root: `x.y` where `x` is tainted (or
    // any deeper chain rooted at a tainted value).
    if expr.kind() == "selector_expression" {
        if let Some(operand) = expr.child_by_field_name("operand") {
            if let Some(desc) = expression_taint(operand, source, spec, aliases, state, summaries) {
                return Some(desc);
            }
        }
    }

    // Tainted index expression: `m[k]` where `m` is tainted.
    if expr.kind() == "index_expression" {
        if let Some(operand) = expr.child_by_field_name("operand") {
            if let Some(desc) = expression_taint(operand, source, spec, aliases, state, summaries) {
                return Some(desc);
            }
        }
    }

    // Binary `+` (string concat) / other binary ops: if any operand is
    // tainted, the result is. Mirrors the JS engine.
    if expr.kind() == "binary_expression" {
        let mut cursor = expr.walk();
        for child in expr.named_children(&mut cursor) {
            if let Some(desc) = expression_taint(child, source, spec, aliases, state, summaries) {
                return Some(desc);
            }
        }
    }

    // Parenthesized / unary wrappers: recurse into children.
    if matches!(expr.kind(), "parenthesized_expression" | "unary_expression") {
        let mut cursor = expr.walk();
        for child in expr.named_children(&mut cursor) {
            if let Some(desc) = expression_taint(child, source, spec, aliases, state, summaries) {
                return Some(desc);
            }
        }
    }

    // Composite literal — `&SomeStruct{Field: tainted}`. If any field
    // value is tainted the whole literal is.
    if expr.kind() == "composite_literal" {
        let mut cursor = expr.walk();
        for child in expr.children(&mut cursor) {
            if child.kind() == "literal_value" {
                let mut inner = child.walk();
                for elem in child.named_children(&mut inner) {
                    if let Some(desc) =
                        expression_taint(elem, source, spec, aliases, state, summaries)
                    {
                        return Some(desc);
                    }
                }
            }
        }
    }
    if expr.kind() == "keyed_element" {
        let mut cursor = expr.walk();
        for child in expr.named_children(&mut cursor) {
            if let Some(desc) = expression_taint(child, source, spec, aliases, state, summaries) {
                return Some(desc);
            }
        }
    }

    // Wrapping call: `string(tainted)`, `fmt.Sprintf("%s", tainted)`,
    // `[]byte(tainted)`. Sanitizers short-circuit this and collapse to
    // clean.
    if expr.kind() == "call_expression" {
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

        // Method-call propagation on a tainted receiver: `x.foo(...)`
        // is tainted when `x` is tainted.
        if let Some(func) = expr.child_by_field_name("function") {
            if func.kind() == "selector_expression" {
                if let Some(operand) = func.child_by_field_name("operand") {
                    if let Some(desc) =
                        expression_taint(operand, source, spec, aliases, state, summaries)
                    {
                        return Some(desc);
                    }
                }
            }
        }

        // Same-file interprocedural v1: bare identifier callee whose
        // name matches a function / method in the summary map
        // propagates the summary's taint through the call result.
        if let Some(func) = expr.child_by_field_name("function") {
            if func.kind() == "identifier" {
                let callee = node_text(func, source);
                if let Some(Some(desc)) = summaries.get(callee) {
                    return Some(format!("{desc} (via {callee})"));
                }
            }
            // Method call on an arbitrary receiver with a summary
            // entry for that method's simple name. Matches the v1
            // policy documented in the module header.
            if func.kind() == "selector_expression" {
                if let Some(field) = func.child_by_field_name("field") {
                    let method = node_text(field, source);
                    if let Some(Some(desc)) = summaries.get(method) {
                        return Some(format!("{desc} (via {method})"));
                    }
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
    aliases: Option<&GoImportAliases>,
) -> bool {
    if call_node.kind() != "call_expression" {
        return false;
    }
    let Some(func) = call_node.child_by_field_name("function") else {
        return false;
    };
    let callee = node_text(func, source);
    let resolved: Cow<'_, str> = match aliases {
        Some(a) => a.resolve(callee),
        None => Cow::Borrowed(callee),
    };
    for matcher in &spec.sanitizers {
        if let NodeMatcher::Call { canonical, .. } = matcher {
            if callee == canonical.as_str() || resolved.as_ref() == canonical.as_str() {
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
    aliases: Option<&GoImportAliases>,
) -> Option<String> {
    for matcher in &spec.sources {
        match matcher {
            NodeMatcher::Attribute {
                root,
                field,
                description,
            } => {
                if node.kind() != "selector_expression" {
                    continue;
                }
                let Some(final_field) = node.child_by_field_name("field") else {
                    continue;
                };
                if node_text(final_field, source) != field.as_str() {
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
            NodeMatcher::MethodName { .. } => {
                // Sink-only matcher.
            }
        }
    }
    None
}

/// Canonical set of untrusted-input sources for Go web handlers and
/// CLI entry points.
///
/// Organized by framework; add new sources to the matching section
/// and keep the layout stable so future contributors know where
/// their entries belong.
///
/// Why no `ParamName` matcher for Gin / Echo / Fiber `c`: single-letter
/// locals named `c` are extremely common in generic Go code. Seeding
/// every `c` parameter as a source would flood false positives.
/// Instead we rely on method-call matchers (`c.Query`, `c.Param`, ...)
/// which are specific enough. The `r`/`req`/`request` pattern in
/// net/http handlers IS seeded via `ParamName` because those names
/// are idiomatic for the `*http.Request` parameter.
pub fn go_taint_sources() -> Vec<NodeMatcher> {
    vec![
        // ─── net/http handlers ───────────────────────────────────────
        NodeMatcher::ParamName {
            names: vec!["r".into(), "req".into(), "request".into()],
            description: "net/http request parameter".into(),
        },
        NodeMatcher::Attribute {
            root: "r".into(),
            field: "URL".into(),
            description: "http.Request.URL".into(),
        },
        NodeMatcher::Attribute {
            root: "r".into(),
            field: "Header".into(),
            description: "http.Request.Header".into(),
        },
        NodeMatcher::Attribute {
            root: "r".into(),
            field: "Body".into(),
            description: "http.Request.Body".into(),
        },
        NodeMatcher::Attribute {
            root: "r".into(),
            field: "Form".into(),
            description: "http.Request.Form".into(),
        },
        NodeMatcher::Call {
            canonical: "r.FormValue".into(),
            description: "http.Request.FormValue".into(),
        },
        NodeMatcher::Call {
            canonical: "r.PostFormValue".into(),
            description: "http.Request.PostFormValue".into(),
        },
        NodeMatcher::Call {
            canonical: "r.URL.Query".into(),
            description: "http.Request.URL.Query()".into(),
        },
        // ─── Gin (github.com/gin-gonic/gin) ─────────────────────────
        NodeMatcher::Call {
            canonical: "c.Query".into(),
            description: "gin *Context.Query".into(),
        },
        NodeMatcher::Call {
            canonical: "c.PostForm".into(),
            description: "gin *Context.PostForm".into(),
        },
        NodeMatcher::Call {
            canonical: "c.Param".into(),
            description: "gin *Context.Param".into(),
        },
        NodeMatcher::Call {
            canonical: "c.GetHeader".into(),
            description: "gin *Context.GetHeader".into(),
        },
        NodeMatcher::Call {
            canonical: "c.GetQuery".into(),
            description: "gin *Context.GetQuery".into(),
        },
        NodeMatcher::Call {
            canonical: "c.GetString".into(),
            description: "gin *Context.GetString".into(),
        },
        NodeMatcher::Call {
            canonical: "c.FormValue".into(),
            description: "gin *Context.FormValue".into(),
        },
        NodeMatcher::Attribute {
            root: "c".into(),
            field: "Request".into(),
            description: "gin *Context.Request".into(),
        },
        // ─── Echo (github.com/labstack/echo) ────────────────────────
        NodeMatcher::Call {
            canonical: "c.QueryParam".into(),
            description: "echo Context.QueryParam".into(),
        },
        // (c.Param / c.FormValue are shared with Gin above.)
        // ─── Fiber (github.com/gofiber/fiber/v2) ────────────────────
        NodeMatcher::Call {
            canonical: "c.Params".into(),
            description: "fiber Ctx.Params".into(),
        },
        // (c.Query / c.FormValue are shared with Gin above.)
        // ─── Generic ────────────────────────────────────────────────
        NodeMatcher::Call {
            canonical: "os.Getenv".into(),
            description: "os.Getenv".into(),
        },
        NodeMatcher::Attribute {
            root: "os".into(),
            field: "Args".into(),
            description: "os.Args".into(),
        },
    ]
}

/// Walk a selector-expression chain leftward and return the leftmost
/// identifier text. For `r.URL.Query`, returns `"r"`. For
/// `pkg.Something.Field`, returns `"pkg"`.
fn leftmost_identifier<'a>(mut node: Node<'_>, source: &'a str) -> Option<&'a str> {
    loop {
        match node.kind() {
            "identifier" | "package_identifier" => return Some(node_text(node, source)),
            "selector_expression" => {
                node = node.child_by_field_name("operand")?;
            }
            "index_expression" => {
                node = node.child_by_field_name("operand")?;
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
    eprintln!(
        "{} [{}..{}]",
        node.kind(),
        node.start_byte(),
        node.end_byte()
    );
    for child in node.children(&mut cursor) {
        debug_tree(child, depth + 1);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::Language;

    fn spec_exec_command() -> TaintSpec {
        TaintSpec {
            sources: go_taint_sources(),
            sinks: vec![NodeMatcher::Call {
                canonical: "exec.Command".into(),
                description: "exec.Command".into(),
            }],
            sanitizers: vec![],
        }
    }

    fn run(source: &str) -> Vec<TaintFinding> {
        run_with(source, &spec_exec_command())
    }

    fn run_with(source: &str, spec: &TaintSpec) -> Vec<TaintFinding> {
        let tree = parse_file(source, Language::Go).expect("parse");
        let aliases = GoImportAliases::from_tree(source, &tree);
        analyze_tree(tree.root_node(), source, spec, Some(&aliases))
    }

    #[test]
    fn direct_flow_gin_query_to_exec_command() {
        let src = r#"
package main

import "os/exec"

func handler(c *gin.Context) {
    name := c.Query("name")
    exec.Command(name)
}
"#;
        let f = run(src);
        assert_eq!(f.len(), 1);
        assert!(f[0].source_description.contains("gin"));
        assert_eq!(f[0].sink_description, "exec.Command");
    }

    #[test]
    fn net_http_form_value_to_exec() {
        let src = r#"
package main

import (
    "net/http"
    "os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
    cmd := r.FormValue("cmd")
    exec.Command(cmd)
}
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn echo_context_query_param_to_exec() {
        let src = r#"
package main

import "os/exec"

func handler(c echo.Context) error {
    name := c.QueryParam("name")
    exec.Command(name)
    return nil
}
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn fiber_ctx_query_to_exec() {
        let src = r#"
package main

import "os/exec"

func handler(c *fiber.Ctx) error {
    name := c.Query("name")
    exec.Command(name)
    return nil
}
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn os_getenv_to_exec() {
        let src = r#"
package main

import (
    "os"
    "os/exec"
)

func main() {
    path := os.Getenv("TARGET")
    exec.Command(path)
}
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn method_call_on_tainted_receiver_propagates() {
        // `r.URL` is a tainted attribute source; `.Query()` is a
        // method call on the tainted receiver and must stay tainted.
        let src = r#"
package main

import "os/exec"

func handler(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query().Get("name")
    exec.Command(q)
}
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn fmt_sprintf_wraps_taint() {
        let src = r#"
package main

import (
    "fmt"
    "os/exec"
)

func handler(c *gin.Context) {
    cmd := fmt.Sprintf("echo %s", c.Query("name"))
    exec.Command(cmd)
}
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn string_concat_propagates_taint() {
        let src = r#"
package main

import "os/exec"

func handler(c *gin.Context) {
    cmd := "echo " + c.Query("name")
    exec.Command(cmd)
}
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn reassignment_to_literal_kills_taint() {
        let src = r#"
package main

import "os/exec"

func handler(c *gin.Context) {
    name := c.Query("name")
    name = "static"
    exec.Command(name)
}
"#;
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn interprocedural_tainted_return() {
        let src = r#"
package main

import "os/exec"

func getInput(c *gin.Context) string {
    return c.Query("name")
}

func handler(c *gin.Context) {
    name := getInput(c)
    exec.Command(name)
}
"#;
        let f = run(src);
        assert_eq!(f.len(), 1);
        assert!(f[0].source_description.contains("getInput"));
    }

    #[test]
    fn interprocedural_clean_return_does_not_fire() {
        let src = r#"
package main

import "os/exec"

func staticCmd() string {
    return "ls"
}

func handler() {
    exec.Command(staticCmd())
}
"#;
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn nested_subscript_propagates() {
        // Go map-of-maps: `m[k1][k2]` — if the outer root `headers` is
        // tainted via `r.Header`, deep index access stays tainted.
        let src = r#"
package main

import "os/exec"

func handler(w http.ResponseWriter, r *http.Request) {
    headers := r.Header
    exec.Command(headers["X-Cmd"][0])
}
"#;
        assert_eq!(run(src).len(), 1);
    }

    #[test]
    fn multi_return_destructuring_taints_all() {
        // Conservative policy: when helper returns tainted, every LHS
        // name in `a, b := helper()` is tainted.
        let src = r#"
package main

import "os/exec"

func helper(c *gin.Context) (string, error) {
    return c.Query("name"), nil
}

func handler(c *gin.Context) {
    name, err := helper(c)
    _ = err
    exec.Command(name)
}
"#;
        let f = run(src);
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn sanitizer_call_kills_taint() {
        let mut spec = spec_exec_command();
        spec.sanitizers = vec![NodeMatcher::Call {
            canonical: "html.EscapeString".into(),
            description: "html.EscapeString".into(),
        }];
        let src = r#"
package main

import (
    "html"
    "os/exec"
)

func handler(c *gin.Context) {
    raw := c.Query("name")
    clean := html.EscapeString(raw)
    exec.Command(clean)
}
"#;
        assert_eq!(run_with(src, &spec).len(), 0);
    }

    #[test]
    fn alias_resolution_through_import_table() {
        // `import f "fmt"; f.Sprintf(...)` — a spec targeting
        // `fmt.Sprintf` as a sink must still match. Use a custom spec
        // so the canonical path is explicit.
        let spec = TaintSpec {
            sources: go_taint_sources(),
            sinks: vec![NodeMatcher::Call {
                canonical: "fmt.Sprintf".into(),
                description: "fmt.Sprintf".into(),
            }],
            sanitizers: vec![],
        };
        let src = r#"
package main

import f "fmt"

func handler(c *gin.Context) {
    _ = f.Sprintf("%s", c.Query("name"))
}
"#;
        let findings = run_with(src, &spec);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn closure_gin_handler_fires_taint() {
        // Closures passed as arguments to Gin router methods must be
        // analyzed. This is the idiomatic way to write Gin handlers.
        let src = r#"
package main

import (
    "os/exec"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    r.GET("/run", func(c *gin.Context) {
        cmd := c.Query("cmd")
        exec.Command(cmd).Output()
    })
}
"#;
        let f = run(src);
        assert_eq!(f.len(), 1);
        assert!(f[0].source_description.contains("gin"));
        assert_eq!(f[0].sink_description, "exec.Command");
    }

    #[test]
    fn closure_net_http_handler_fires_taint() {
        // net/http handler written as a closure.
        let src = r#"
package main

import (
    "net/http"
    "os/exec"
)

func main() {
    http.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
        cmd := r.FormValue("cmd")
        exec.Command(cmd)
    })
}
"#;
        let f = run(src);
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn no_source_no_finding() {
        let src = r#"
package main

import "os/exec"

func main() {
    exec.Command("ls", "-la")
}
"#;
        assert_eq!(run(src).len(), 0);
    }

    #[test]
    fn import_alias_table_basic() {
        let src = r#"
package main

import (
    f "fmt"
    "net/http"
    alias "some/pkg/deep"
)
"#;
        let tree = parse_file(src, Language::Go).expect("parse");
        let a = GoImportAliases::from_tree(src, &tree);
        assert_eq!(a.get("f"), Some("fmt"));
        assert_eq!(a.get("http"), Some("http"));
        assert_eq!(a.get("alias"), Some("deep"));
        assert_eq!(a.resolve("f.Sprintf"), "fmt.Sprintf");
        assert_eq!(a.resolve("http.Get"), "http.Get");
    }

    #[test]
    fn method_declaration_summary_collected() {
        // Method with tainted return; caller elsewhere uses the bare
        // method name via the summary table.
        let src = r#"
package main

import "os/exec"

type S struct{}

func (s *S) Fetch(c *gin.Context) string {
    return c.Query("name")
}

func handler(c *gin.Context) {
    var s S
    name := s.Fetch(c)
    exec.Command(name)
}
"#;
        let f = run(src);
        assert_eq!(f.len(), 1);
        assert!(f[0].source_description.contains("Fetch"));
    }
}
