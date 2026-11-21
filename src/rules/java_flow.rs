//! Lightweight flow-sensitive "is this sink argument provably safe?" check
//! for Java.
//!
//! The pattern rules and the flow-insensitive taint engine cannot see that a
//! value was replaced, folded to a constant or fetched back from a collection
//! before it reaches a sink. This module interprets a single method body in
//! source order over a tiny abstract domain:
//!
//! - compile-time constants (ints, chars, strings, booleans) so branch
//!   conditions such as `(7 * 18) + num > 200` fold and only the live branch
//!   contributes (`if`, `?:`, `switch`);
//! - definite assignment: a reassignment replaces the previous value instead of
//!   joining with it, and branches are merged only when both are reachable;
//! - `List` / `Map` locals with constant indices and keys, so `add`/`put`/
//!   `remove` followed by `get` of a safe element stays safe;
//! - calls to uniquely-named helper methods of the same file, interpreted with
//!   the caller's argument values.
//!
//! The analysis is deliberately one-sided: a value is *safe* only when it is
//! proven to be built from constants (or, for HTML output, known encoders).
//! Anything unknown (parameters, fields, unknown calls, unmodelled
//! statements) is *maybe tainted*, so using this check to suppress findings
//! never hides a flow it cannot explain.

use std::collections::HashMap;
use tree_sitter::Node;

/// Output encoders whose result is safe inside an HTML response.
const HTML_ENCODERS: &[&str] = &[
    "encodeForHTML",
    "encodeForHTMLAttribute",
    "encodeForJavaScript",
    "encodeForCSS",
    "encodeForURL",
    "forHtml",
    "forHtmlContent",
    "forHtmlAttribute",
    "forJavaScript",
    "forCssString",
    "escapeHtml",
    "escapeHtml3",
    "escapeHtml4",
    "escapeXml",
    "escapeXml10",
    "escapeXml11",
    "escapeEcmaScript",
    "escapeJavaScript",
    "htmlEscape",
];

/// String methods that return a safe value when the receiver and every
/// argument are safe.
const STRING_PASSTHROUGH: &[&str] = &[
    "toString",
    "trim",
    "strip",
    "toLowerCase",
    "toUpperCase",
    "substring",
    "concat",
    "replace",
    "replaceAll",
    "replaceFirst",
    "intern",
    "toCharArray",
    "getBytes",
    "repeat",
    "length",
    "equals",
    "equalsIgnoreCase",
    "isEmpty",
    "startsWith",
    "endsWith",
    "contains",
    "indexOf",
    "hashCode",
    "charAt",
];

const MAX_DEPTH: usize = 3;
const STEP_BUDGET: usize = 50_000;

#[derive(Clone, Debug, PartialEq)]
enum Val {
    Int(i64),
    Char(char),
    Bool(bool),
    Str(String),
    Null,
    /// Safe but not a known constant.
    Safe,
    /// Not proven safe.
    Maybe,
    List(Vec<Val>),
    Map(Vec<(String, Val)>),
}

impl Val {
    fn is_safe(&self) -> bool {
        match self {
            Val::Maybe => false,
            Val::List(items) => items.iter().all(Val::is_safe),
            Val::Map(items) => items.iter().all(|(_, v)| v.is_safe()),
            _ => true,
        }
    }

    fn as_int(&self) -> Option<i64> {
        match self {
            Val::Int(i) => Some(*i),
            Val::Char(c) => Some(*c as i64),
            _ => None,
        }
    }

    fn is_const(&self) -> bool {
        matches!(
            self,
            Val::Int(_) | Val::Char(_) | Val::Bool(_) | Val::Str(_) | Val::Null
        )
    }

    fn degrade(&self) -> Val {
        if self.is_safe() {
            Val::Safe
        } else {
            Val::Maybe
        }
    }
}

fn join(a: &Val, b: &Val) -> Val {
    if a == b {
        return a.clone();
    }
    match (a, b) {
        (Val::List(x), Val::List(y)) if x.len() == y.len() => {
            Val::List(x.iter().zip(y).map(|(p, q)| join(p, q)).collect())
        }
        (Val::Map(x), Val::Map(y))
            if x.len() == y.len() && x.iter().zip(y).all(|(p, q)| p.0 == q.0) =>
        {
            Val::Map(
                x.iter()
                    .zip(y)
                    .map(|(p, q)| (p.0.clone(), join(&p.1, &q.1)))
                    .collect(),
            )
        }
        _ => {
            if a.is_safe() && b.is_safe() {
                Val::Safe
            } else {
                Val::Maybe
            }
        }
    }
}

type Env = HashMap<String, Val>;

fn join_env(a: &Env, b: &Env) -> Env {
    let mut out = Env::new();
    for (k, v) in a {
        if let Some(w) = b.get(k) {
            out.insert(k.clone(), join(v, w));
        }
    }
    out
}

#[derive(PartialEq, Clone, Copy)]
enum Flow {
    Next,
    Break,
    Jump,
}

struct Interp<'a> {
    src: &'a str,
    root: Node<'a>,
    html: bool,
    depth: usize,
    steps: usize,
    aborted: bool,
    /// Sink byte range -> every argument safe on every visit.
    rec: HashMap<(usize, usize), bool>,
    returns: Vec<Val>,
    /// Environments captured at `break`/`continue`, joined at the enclosing
    /// loop or switch exit so a value assigned just before leaving survives.
    exits: Vec<Env>,
}

/// True when the call or `new` expression `call` sits in a method body and
/// every argument is proven safe on every path that reaches it. With `html`
/// set, known HTML encoders count as sanitisers (use for XSS sinks only).
pub fn sink_args_safe(call: Node<'_>, source: &str, html: bool) -> bool {
    let mut method = call;
    loop {
        match method.kind() {
            "method_declaration" | "constructor_declaration" => break,
            _ => match method.parent() {
                Some(p) => method = p,
                None => return false,
            },
        }
    }
    let mut root = method;
    while let Some(p) = root.parent() {
        root = p;
    }
    let Some(body) = method.child_by_field_name("body") else {
        return false;
    };
    let mut it = Interp {
        src: source,
        root,
        html,
        depth: 0,
        steps: 0,
        aborted: false,
        rec: HashMap::new(),
        returns: Vec::new(),
        exits: Vec::new(),
    };
    let mut env = Env::new();
    it.exec(body, &mut env);
    !it.aborted
        && it
            .rec
            .get(&(call.start_byte(), call.end_byte()))
            .copied()
            .unwrap_or(false)
}

impl<'a> Interp<'a> {
    fn text(&self, n: Node<'_>) -> &'a str {
        &self.src[n.byte_range()]
    }

    fn tick(&mut self) -> bool {
        self.steps += 1;
        if self.steps > STEP_BUDGET {
            self.aborted = true;
        }
        self.aborted
    }

    // ── statements ──────────────────────────────────────────────────────

    fn exec(&mut self, node: Node<'a>, env: &mut Env) -> Flow {
        if self.tick() {
            return Flow::Jump;
        }
        match node.kind() {
            "block" | "constructor_body" | "switch_block_statement_group_body" => {
                let mut c = node.walk();
                for child in node.named_children(&mut c) {
                    let f = self.exec(child, env);
                    if f != Flow::Next {
                        return f;
                    }
                }
                Flow::Next
            }
            "local_variable_declaration" => {
                let mut c = node.walk();
                for d in node.named_children(&mut c) {
                    if d.kind() != "variable_declarator" {
                        continue;
                    }
                    let Some(name) = d.child_by_field_name("name") else {
                        continue;
                    };
                    let v = match d.child_by_field_name("value") {
                        Some(value) => {
                            let v = self.eval(value, env);
                            if matches!(v, Val::List(_) | Val::Map(_)) {
                                // Aliasing a tracked collection: give up on both.
                                self.escape(value, env);
                                if value.kind() == "identifier" {
                                    Val::Maybe
                                } else {
                                    v
                                }
                            } else {
                                v
                            }
                        }
                        None => Val::Safe,
                    };
                    env.insert(self.text(name).to_string(), v);
                }
                Flow::Next
            }
            "expression_statement" => {
                if let Some(e) = node.named_child(0) {
                    self.eval(e, env);
                }
                Flow::Next
            }
            "if_statement" => {
                let cond = node
                    .child_by_field_name("condition")
                    .map(|c| self.eval(c, env))
                    .unwrap_or(Val::Maybe);
                let then = node.child_by_field_name("consequence");
                let alt = node.child_by_field_name("alternative");
                match cond {
                    Val::Bool(true) => then.map_or(Flow::Next, |t| self.exec(t, env)),
                    Val::Bool(false) => alt.map_or(Flow::Next, |a| self.exec(a, env)),
                    _ => {
                        let mut e1 = env.clone();
                        let f1 = then.map_or(Flow::Next, |t| self.exec(t, &mut e1));
                        let mut e2 = env.clone();
                        let f2 = alt.map_or(Flow::Next, |a| self.exec(a, &mut e2));
                        self.merge(env, (e1, f1), (e2, f2))
                    }
                }
            }
            "switch_expression" => self.exec_switch(node, env).1,
            "while_statement" | "for_statement" | "enhanced_for_statement" | "do_statement" => {
                self.exec_loop(node, env)
            }
            "try_statement" | "try_with_resources_statement" => self.exec_try(node, env),
            "return_statement" => {
                let v = node
                    .named_child(0)
                    .map(|e| self.eval(e, env))
                    .unwrap_or(Val::Safe);
                self.returns.push(v);
                Flow::Jump
            }
            "throw_statement" => Flow::Jump,
            "continue_statement" => {
                self.exits.push(env.clone());
                Flow::Jump
            }
            "break_statement" => {
                self.exits.push(env.clone());
                Flow::Break
            }
            "labeled_statement" | "synchronized_statement" => {
                let mut f = Flow::Next;
                let mut c = node.walk();
                for child in node.named_children(&mut c) {
                    if matches!(child.kind(), "block" | "expression_statement")
                        || child.kind().ends_with("_statement")
                    {
                        f = self.exec(child, env);
                    }
                }
                f
            }
            _ => Flow::Next,
        }
    }

    fn merge(&mut self, env: &mut Env, a: (Env, Flow), b: (Env, Flow)) -> Flow {
        match (a.1, b.1) {
            (Flow::Next, Flow::Next) => {
                *env = join_env(&a.0, &b.0);
                Flow::Next
            }
            (Flow::Next, _) => {
                *env = a.0;
                Flow::Next
            }
            (_, Flow::Next) => {
                *env = b.0;
                Flow::Next
            }
            (fa, fb) => {
                *env = join_env(&a.0, &b.0);
                if fa == Flow::Break || fb == Flow::Break {
                    Flow::Break
                } else {
                    Flow::Jump
                }
            }
        }
    }

    fn exec_loop(&mut self, node: Node<'a>, env: &mut Env) -> Flow {
        match node.kind() {
            "for_statement" => {
                let mut c = node.walk();
                let inits: Vec<_> = node.children_by_field_name("init", &mut c).collect();
                for i in inits {
                    if i.kind() == "local_variable_declaration" {
                        self.exec(i, env);
                    } else {
                        self.eval(i, env);
                    }
                }
            }
            "enhanced_for_statement" => {
                let iter = node
                    .child_by_field_name("value")
                    .map(|v| self.eval(v, env))
                    .unwrap_or(Val::Maybe);
                let elem = match &iter {
                    Val::List(items) => items.iter().fold(Val::Safe, |a, b| join(&a, b)),
                    other => other.degrade(),
                };
                if let Some(n) = node.child_by_field_name("name") {
                    env.insert(self.text(n).to_string(), elem);
                }
            }
            _ => {}
        }
        let body = node.child_by_field_name("body");
        let mark = self.exits.len();
        // Two passes so a value carried around the back edge reaches the sinks.
        let entry = env.clone();
        for _ in 0..2 {
            if let Some(cond) = node.child_by_field_name("condition") {
                if self.eval(cond, env) == Val::Bool(false) && node.kind() != "do_statement" {
                    return Flow::Next;
                }
            }
            if let Some(b) = body {
                let mut e = env.clone();
                self.exec(b, &mut e);
                *env = join_env(env, &e);
            }
            let mut c = node.walk();
            let updates: Vec<_> = node.children_by_field_name("update", &mut c).collect();
            for u in updates {
                self.eval(u, env);
            }
        }
        *env = join_env(env, &entry);
        for e in self.exits.split_off(mark) {
            *env = join_env(env, &e);
        }
        Flow::Next
    }

    fn exec_try(&mut self, node: Node<'a>, env: &mut Env) -> Flow {
        let pre = env.clone();
        if let Some(res) = node.child_by_field_name("resources") {
            let mut c = res.walk();
            for r in res.named_children(&mut c) {
                if let (Some(n), Some(v)) = (
                    r.child_by_field_name("name"),
                    r.child_by_field_name("value"),
                ) {
                    let val = self.eval(v, env);
                    env.insert(self.text(n).to_string(), val);
                }
            }
        }
        let mut flow = node
            .child_by_field_name("body")
            .map_or(Flow::Next, |b| self.exec(b, env));
        let after_body = env.clone();
        let mut c = node.walk();
        let children: Vec<_> = node.named_children(&mut c).collect();
        for ch in &children {
            if ch.kind() == "catch_clause" {
                let mut ce = join_env(&pre, &after_body);
                let mut cc = ch.walk();
                for part in ch.named_children(&mut cc) {
                    if part.kind() == "catch_formal_parameter" {
                        if let Some(n) = part.child_by_field_name("name") {
                            ce.insert(self.text(n).to_string(), Val::Maybe);
                        }
                    }
                }
                let cf = ch
                    .child_by_field_name("body")
                    .map_or(Flow::Next, |b| self.exec(b, &mut ce));
                flow = self.merge(env, (env.clone(), flow), (ce, cf));
            }
        }
        for ch in &children {
            if ch.kind() == "finally_clause" {
                let mut cc = ch.walk();
                for b in ch.named_children(&mut cc) {
                    self.exec(b, env);
                }
            }
        }
        flow
    }

    /// Returns (selected value for switch expressions, flow).
    fn exec_switch(&mut self, node: Node<'a>, env: &mut Env) -> (Val, Flow) {
        let sel = node
            .child_by_field_name("condition")
            .map(|c| self.eval(c, env))
            .unwrap_or(Val::Maybe);
        let Some(block) = node.child_by_field_name("body") else {
            return (Val::Maybe, Flow::Next);
        };
        let mut c = block.walk();
        let groups: Vec<Node<'a>> = block.named_children(&mut c).collect();
        // Each group: (labels as Option<Val> where None = default, node).
        let mut labels: Vec<Vec<Option<Val>>> = Vec::new();
        for g in &groups {
            let mut ls = Vec::new();
            let mut gc = g.walk();
            for part in g.named_children(&mut gc) {
                if part.kind() == "switch_label" {
                    let mut lc = part.walk();
                    let exprs: Vec<_> = part.named_children(&mut lc).collect();
                    if exprs.is_empty() {
                        ls.push(None);
                    }
                    for e in exprs {
                        let mut tmp = Env::new();
                        ls.push(Some(self.eval(e, &mut tmp)));
                    }
                }
            }
            labels.push(ls);
        }
        let is_rule = groups.iter().any(|g| g.kind() == "switch_rule");
        let matches_sel = |l: &Option<Val>| match (l, &sel) {
            (Some(lv), s) if lv.is_const() && s.is_const() => match (lv.as_int(), s.as_int()) {
                (Some(a), Some(b)) => a == b,
                _ => lv == s,
            },
            _ => false,
        };
        let all_const = sel.is_const()
            && labels
                .iter()
                .flatten()
                .all(|l| l.as_ref().is_none_or(Val::is_const));
        let start_indices: Vec<usize> = if all_const {
            let hit = labels.iter().position(|ls| ls.iter().any(&matches_sel));
            let def = labels.iter().position(|ls| ls.iter().any(Option::is_none));
            hit.or(def).into_iter().collect()
        } else {
            (0..groups.len()).collect()
        };
        if start_indices.is_empty() {
            return (Val::Safe, Flow::Next);
        }
        let mut result: Option<(Env, Val)> = None;
        let mark = self.exits.len();
        for &start in &start_indices {
            let mut e = env.clone();
            let mut value = Val::Safe;
            if is_rule {
                value = self.exec_rule_body(groups[start], &mut e);
            } else {
                // Run groups from `start`, falling through until a break.
                for g in &groups[start..] {
                    let mut f = Flow::Next;
                    let mut gc = g.walk();
                    for stmt in g.named_children(&mut gc) {
                        if stmt.kind() == "switch_label" {
                            continue;
                        }
                        f = self.exec(stmt, &mut e);
                        if f != Flow::Next {
                            break;
                        }
                    }
                    if f != Flow::Next {
                        break;
                    }
                }
            }
            result = Some(match result {
                None => (e, value),
                Some((pe, pv)) => (join_env(&pe, &e), join(&pv, &value)),
            });
        }
        let (mut new_env, value) = result.unwrap();
        for ex in self.exits.split_off(mark) {
            new_env = join_env(&new_env, &ex);
        }
        if !all_const {
            // Without a default, control may skip every case.
            let has_default = labels.iter().flatten().any(Option::is_none);
            if !has_default {
                new_env = join_env(&new_env, env);
            }
        }
        *env = new_env;
        (value, Flow::Next)
    }

    fn exec_rule_body(&mut self, rule: Node<'a>, env: &mut Env) -> Val {
        let mut c = rule.walk();
        let mut v = Val::Safe;
        for part in rule.named_children(&mut c) {
            match part.kind() {
                "switch_label" => {}
                "block" => {
                    self.exec(part, env);
                }
                "expression_statement" | "throw_statement" => {
                    if let Some(e) = part.named_child(0) {
                        v = self.eval(e, env);
                    }
                }
                _ => v = self.eval(part, env),
            }
        }
        v
    }

    // ── expressions ─────────────────────────────────────────────────────

    fn eval(&mut self, node: Node<'a>, env: &mut Env) -> Val {
        if self.tick() {
            return Val::Maybe;
        }
        match node.kind() {
            "decimal_integer_literal" => {
                let t = self.text(node).replace('_', "");
                let t = t.trim_end_matches(['l', 'L']);
                t.parse().map(Val::Int).unwrap_or(Val::Safe)
            }
            "hex_integer_literal"
            | "octal_integer_literal"
            | "binary_integer_literal"
            | "decimal_floating_point_literal"
            | "hex_floating_point_literal" => Val::Safe,
            "string_literal" => {
                let t = self.text(node);
                if t.starts_with("\"\"\"") || t.contains('\\') {
                    Val::Safe
                } else {
                    Val::Str(t[1..t.len().saturating_sub(1)].to_string())
                }
            }
            "character_literal" => {
                let t = self.text(node);
                let inner = &t[1..t.len().saturating_sub(1)];
                let mut it = inner.chars();
                match (it.next(), it.next()) {
                    (Some(c), None) if c != '\\' => Val::Char(c),
                    _ => Val::Safe,
                }
            }
            "true" => Val::Bool(true),
            "false" => Val::Bool(false),
            "null_literal" => Val::Null,
            "identifier" => env.get(self.text(node)).cloned().unwrap_or(Val::Maybe),
            "parenthesized_expression" => node
                .named_child(0)
                .map_or(Val::Maybe, |n| self.eval(n, env)),
            "cast_expression" => node
                .child_by_field_name("value")
                .map_or(Val::Maybe, |n| self.eval(n, env)),
            "unary_expression" => {
                let op = node
                    .child_by_field_name("operator")
                    .map(|o| self.text(o))
                    .unwrap_or("");
                let v = node
                    .child_by_field_name("operand")
                    .map_or(Val::Maybe, |n| self.eval(n, env));
                match (op, &v) {
                    ("!", Val::Bool(b)) => Val::Bool(!b),
                    ("-", Val::Int(i)) => Val::Int(-i),
                    _ => v.degrade(),
                }
            }
            "binary_expression" => self.eval_binary(node, env),
            "ternary_expression" => {
                let cond = node
                    .child_by_field_name("condition")
                    .map_or(Val::Maybe, |n| self.eval(n, env));
                let (Some(t), Some(f)) = (
                    node.child_by_field_name("consequence"),
                    node.child_by_field_name("alternative"),
                ) else {
                    return Val::Maybe;
                };
                match cond {
                    Val::Bool(true) => self.eval(t, env),
                    Val::Bool(false) => self.eval(f, env),
                    _ => {
                        let a = self.eval(t, env);
                        let b = self.eval(f, env);
                        join(&a, &b)
                    }
                }
            }
            "assignment_expression" => self.eval_assign(node, env),
            "array_initializer" => {
                let mut c = node.walk();
                let items: Vec<Node<'a>> = node.named_children(&mut c).collect();
                Val::List(items.into_iter().map(|i| self.eval(i, env)).collect())
            }
            "array_creation_expression" => match node.child_by_field_name("value") {
                Some(init) => self.eval(init, env),
                None => Val::Safe,
            },
            "array_access" => {
                let arr = node
                    .child_by_field_name("array")
                    .map_or(Val::Maybe, |n| self.eval(n, env));
                let idx = node
                    .child_by_field_name("index")
                    .map_or(Val::Maybe, |n| self.eval(n, env));
                match (&arr, idx.as_int()) {
                    (Val::List(items), Some(i)) if i >= 0 && (i as usize) < items.len() => {
                        items[i as usize].clone()
                    }
                    _ => arr.degrade(),
                }
            }
            "field_access" => {
                let obj = node.child_by_field_name("object");
                let field = node.child_by_field_name("field").map(|f| self.text(f));
                if let (Some(o), Some("length")) = (obj, field) {
                    if self.eval(o, env).is_safe() {
                        return Val::Safe;
                    }
                }
                // `Type.UPPER_SNAKE` is a compile-time constant by convention.
                if field.is_some_and(is_constant_name)
                    && obj.is_some_and(|o| o.kind() != "method_invocation")
                {
                    return Val::Safe;
                }
                Val::Maybe
            }
            "method_invocation" => self.eval_call(node, env),
            "object_creation_expression" => self.eval_new(node, env),
            _ => Val::Maybe,
        }
    }

    fn eval_binary(&mut self, node: Node<'a>, env: &mut Env) -> Val {
        let op = node
            .child_by_field_name("operator")
            .map(|o| self.text(o))
            .unwrap_or("");
        let (Some(ln), Some(rn)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return Val::Maybe;
        };
        let l = self.eval(ln, env);
        // Short-circuit folding keeps the dead operand's effects out.
        match (op, &l) {
            ("&&", Val::Bool(false)) => return Val::Bool(false),
            ("||", Val::Bool(true)) => return Val::Bool(true),
            _ => {}
        }
        let r = self.eval(rn, env);
        if let (Some(a), Some(b)) = (l.as_int(), r.as_int()) {
            let both_int = matches!(l, Val::Int(_)) || matches!(r, Val::Int(_));
            let folded = match op {
                "+" => a.checked_add(b).map(Val::Int),
                "-" => a.checked_sub(b).map(Val::Int),
                "*" => a.checked_mul(b).map(Val::Int),
                "/" if b != 0 => a.checked_div(b).map(Val::Int),
                "%" if b != 0 => a.checked_rem(b).map(Val::Int),
                ">" => Some(Val::Bool(a > b)),
                "<" => Some(Val::Bool(a < b)),
                ">=" => Some(Val::Bool(a >= b)),
                "<=" => Some(Val::Bool(a <= b)),
                "==" => Some(Val::Bool(a == b)),
                "!=" => Some(Val::Bool(a != b)),
                _ => None,
            };
            if let Some(v) = folded {
                // `'a' + 1` style char arithmetic stays an int.
                let _ = both_int;
                return v;
            }
        }
        match (op, &l, &r) {
            ("&&", Val::Bool(a), Val::Bool(b)) => return Val::Bool(*a && *b),
            ("||", Val::Bool(a), Val::Bool(b)) => return Val::Bool(*a || *b),
            ("==", a, b) if a.is_const() && b.is_const() => return Val::Bool(a == b),
            ("!=", a, b) if a.is_const() && b.is_const() => return Val::Bool(a != b),
            ("+", Val::Str(a), b) | ("+", b, Val::Str(a)) if b.is_const() => {
                let other = match b {
                    Val::Str(s) => s.clone(),
                    Val::Int(i) => i.to_string(),
                    Val::Char(c) => c.to_string(),
                    Val::Bool(x) => x.to_string(),
                    _ => "null".to_string(),
                };
                // Operand order matters for the folded text only; safety does not.
                return Val::Str(if matches!(&l, Val::Str(_)) {
                    format!("{a}{other}")
                } else {
                    format!("{other}{a}")
                });
            }
            _ => {}
        }
        if l.is_safe() && r.is_safe() {
            Val::Safe
        } else if matches!(
            op,
            "==" | "!=" | "<" | ">" | "<=" | ">=" | "&&" | "||" | "instanceof"
        ) {
            // A comparison yields a boolean, never the tainted operand.
            Val::Safe
        } else {
            Val::Maybe
        }
    }

    fn eval_assign(&mut self, node: Node<'a>, env: &mut Env) -> Val {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return Val::Maybe;
        };
        let op = node
            .child_by_field_name("operator")
            .map(|o| self.text(o))
            .unwrap_or("=");
        let mut rv = self.eval(right, env);
        if matches!(rv, Val::List(_) | Val::Map(_)) && right.kind() == "identifier" {
            self.escape(right, env);
            rv = Val::Maybe;
        }
        if left.kind() != "identifier" {
            return rv;
        }
        let name = self.text(left).to_string();
        let nv = if op == "=" {
            rv
        } else {
            let old = env.get(&name).cloned().unwrap_or(Val::Maybe);
            if old.is_safe() && rv.is_safe() {
                Val::Safe
            } else {
                Val::Maybe
            }
        };
        env.insert(name, nv.clone());
        nv
    }

    fn eval_args(&mut self, node: Node<'a>, env: &mut Env) -> Vec<Val> {
        let Some(args) = node.child_by_field_name("arguments") else {
            return Vec::new();
        };
        let mut c = args.walk();
        let nodes: Vec<Node<'a>> = args.named_children(&mut c).collect();
        let vals: Vec<Val> = nodes.iter().map(|a| self.eval(*a, env)).collect();
        // A collection handed to another call may be mutated there (or
        // aliased), so it is no longer tracked precisely afterwards.
        for a in nodes {
            self.escape(a, env);
        }
        vals
    }

    /// Stop tracking a collection variable whose identity escapes.
    fn escape(&mut self, node: Node<'a>, env: &mut Env) {
        if node.kind() == "identifier" {
            let name = self.text(node);
            if matches!(env.get(name), Some(Val::List(_) | Val::Map(_))) {
                env.insert(name.to_string(), Val::Maybe);
            }
        }
    }

    fn record(&mut self, node: Node<'a>, args: &[Val]) {
        if self.depth != 0 {
            return;
        }
        // A sink without arguments has nothing to prove safe.
        let safe = !args.is_empty() && args.iter().all(Val::is_safe);
        let e = self
            .rec
            .entry((node.start_byte(), node.end_byte()))
            .or_insert(true);
        *e = *e && safe;
    }

    fn eval_new(&mut self, node: Node<'a>, env: &mut Env) -> Val {
        let ty = node
            .child_by_field_name("type")
            .map(|t| self.text(t))
            .unwrap_or("");
        let base = ty.split('<').next().unwrap_or(ty);
        let base = base.rsplit('.').next().unwrap_or(base);
        let args = self.eval_args(node, env);
        self.record(node, &args);
        match base {
            "ArrayList" | "LinkedList" | "Vector" if args.is_empty() => Val::List(Vec::new()),
            "HashMap" | "LinkedHashMap" | "TreeMap" | "Hashtable" if args.is_empty() => {
                Val::Map(Vec::new())
            }
            _ => {
                if node.child_by_field_name("body").is_none()
                    && args.iter().all(Val::is_safe)
                    && is_value_type(base)
                {
                    Val::Safe
                } else {
                    Val::Maybe
                }
            }
        }
    }

    fn eval_call(&mut self, node: Node<'a>, env: &mut Env) -> Val {
        let name = node
            .child_by_field_name("name")
            .map(|n| self.text(n))
            .unwrap_or("");
        let obj_node = node.child_by_field_name("object");
        // Collection receivers are updated in place.
        if let Some(o) = obj_node {
            if o.kind() == "identifier" {
                let var = self.text(o).to_string();
                if matches!(env.get(&var), Some(Val::List(_) | Val::Map(_))) {
                    let args = self.eval_args(node, env);
                    self.record(node, &args);
                    return self.collection_call(&var, name, args, env);
                }
            }
        }
        let recv = obj_node.map(|o| self.eval(o, env));
        let args = self.eval_args(node, env);
        self.record(node, &args);
        let all_safe = args.iter().all(Val::is_safe);

        if self.html && HTML_ENCODERS.contains(&name) {
            return Val::Safe;
        }

        // StringBuilder-style mutation on a plain local: unsafe input taints
        // the builder itself, not just the returned value.
        if let Some(o) = obj_node {
            if o.kind() == "identifier"
                && !all_safe
                && matches!(
                    name,
                    "append" | "insert" | "replace" | "setCharAt" | "setLength"
                )
            {
                env.insert(self.text(o).to_string(), Val::Maybe);
                return Val::Maybe;
            }
        }

        match (&recv, obj_node) {
            // String/value methods on a proven-safe receiver.
            (Some(r), Some(_)) if r.is_safe() && STRING_PASSTHROUGH.contains(&name) => {
                if all_safe {
                    return fold_string_method(r, name, &args);
                }
                return Val::Maybe;
            }
            (Some(_), Some(o)) if is_static_value_call(self.text(o), name) && all_safe => {
                return Val::Safe;
            }
            _ => {}
        }

        // Same-file helper (unqualified, `this.` or `new LocalClass().`).
        let local_receiver = match obj_node {
            None => true,
            Some(o) if o.kind() == "this" => true,
            Some(o) if o.kind() == "object_creation_expression" => o
                .child_by_field_name("type")
                .is_some_and(|t| self.class_declared_in_file(self.text(t))),
            _ => false,
        };
        if local_receiver && self.depth < MAX_DEPTH {
            if let Some(m) = self.unique_method(name, args.len()) {
                return self.call_helper(m, args);
            }
        }
        Val::Maybe
    }

    fn collection_call(&mut self, var: &str, name: &str, args: Vec<Val>, env: &mut Env) -> Val {
        let cur = env.get(var).cloned().unwrap_or(Val::Maybe);
        let (new, ret) = match (cur, name, args.as_slice()) {
            (Val::List(mut v), "add", [x]) => {
                v.push(x.clone());
                (Val::List(v), Val::Safe)
            }
            (Val::List(mut v), "add", [i, x]) if idx_ok(i, v.len() + 1) => {
                v.insert(i.as_int().unwrap() as usize, x.clone());
                (Val::List(v), Val::Safe)
            }
            (Val::List(mut v), "remove", [i @ Val::Int(_)]) if idx_ok(i, v.len()) => {
                let old = v.remove(i.as_int().unwrap() as usize);
                (Val::List(v), old)
            }
            (Val::List(v), "get", [i]) if idx_ok(i, v.len()) => {
                let e = v[i.as_int().unwrap() as usize].clone();
                (Val::List(v), e)
            }
            (Val::List(mut v), "set", [i, x]) if idx_ok(i, v.len()) => {
                let old = std::mem::replace(&mut v[i.as_int().unwrap() as usize], x.clone());
                (Val::List(v), old)
            }
            (Val::List(v), "size" | "isEmpty" | "contains" | "indexOf", _) => {
                (Val::List(v), Val::Safe)
            }
            (Val::Map(mut m), "put", [Val::Str(k), x]) => {
                let old = match m.iter_mut().find(|(key, _)| key == k) {
                    Some(slot) => std::mem::replace(&mut slot.1, x.clone()),
                    None => {
                        m.push((k.clone(), x.clone()));
                        Val::Null
                    }
                };
                (Val::Map(m), old)
            }
            (Val::Map(m), "get", [Val::Str(k)]) => {
                let e = m
                    .iter()
                    .find(|(key, _)| key == k)
                    .map_or(Val::Null, |(_, v)| v.clone());
                (Val::Map(m), e)
            }
            (Val::Map(mut m), "remove", [Val::Str(k)]) => {
                let old = match m.iter().position(|(key, _)| key == k) {
                    Some(p) => m.remove(p).1,
                    None => Val::Null,
                };
                (Val::Map(m), old)
            }
            (Val::Map(m), "containsKey" | "size" | "isEmpty" | "containsValue", _) => {
                (Val::Map(m), Val::Safe)
            }
            // Anything unmodelled: keep only what is still provably safe.
            (cur, _, a) => {
                let v = if cur.is_safe() && a.iter().all(Val::is_safe) {
                    Val::Safe
                } else {
                    Val::Maybe
                };
                (v.clone(), v)
            }
        };
        env.insert(var.to_string(), new);
        ret
    }

    fn class_declared_in_file(&self, ty: &str) -> bool {
        let base = ty.split('<').next().unwrap_or(ty).trim();
        let mut found = false;
        walk(self.root, &mut |n| {
            if n.kind() == "class_declaration" {
                if let Some(name) = n.child_by_field_name("name") {
                    if self.text(name) == base {
                        found = true;
                    }
                }
            }
        });
        found
    }

    fn unique_method(&self, name: &str, arity: usize) -> Option<Node<'a>> {
        let mut hits = Vec::new();
        walk(self.root, &mut |n| {
            if n.kind() == "method_declaration" {
                if let (Some(nm), Some(ps)) = (
                    n.child_by_field_name("name"),
                    n.child_by_field_name("parameters"),
                ) {
                    if self.text(nm) == name && ps.named_child_count() == arity {
                        hits.push(n);
                    }
                }
            }
        });
        if hits.len() == 1 {
            hits.pop()
        } else {
            None
        }
    }

    fn call_helper(&mut self, method: Node<'a>, args: Vec<Val>) -> Val {
        let Some(body) = method.child_by_field_name("body") else {
            return Val::Maybe;
        };
        let mut callee = Env::new();
        if let Some(ps) = method.child_by_field_name("parameters") {
            let mut c = ps.walk();
            for (p, a) in ps.named_children(&mut c).zip(args) {
                if let Some(n) = p.child_by_field_name("name") {
                    callee.insert(self.text(n).to_string(), a);
                }
            }
        }
        let saved = std::mem::take(&mut self.returns);
        self.depth += 1;
        let flow = self.exec(body, &mut callee);
        self.depth -= 1;
        let rets = std::mem::replace(&mut self.returns, saved);
        if rets.is_empty() {
            // Falling off the end of a non-void method cannot happen; a void
            // helper returns nothing a sink could use.
            return if flow == Flow::Next {
                Val::Safe
            } else {
                Val::Maybe
            };
        }
        rets.iter()
            .skip(1)
            .fold(rets[0].clone(), |a, b| join(&a, b))
    }
}

fn is_constant_name(name: &str) -> bool {
    name.len() > 1
        && name.starts_with(|c: char| c.is_ascii_uppercase())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn idx_ok(i: &Val, len: usize) -> bool {
    matches!(i, Val::Int(n) if *n >= 0 && (*n as usize) < len)
}

fn is_value_type(base: &str) -> bool {
    matches!(
        base,
        "String" | "StringBuilder" | "StringBuffer" | "Integer" | "Long" | "Object"
    )
}

fn is_static_value_call(receiver: &str, name: &str) -> bool {
    matches!(
        (receiver, name),
        ("String", "valueOf" | "format" | "join")
            | ("Integer", "toString" | "valueOf" | "parseInt")
            | ("Long", "toString" | "valueOf" | "parseLong")
            | ("Math", _)
    )
}

fn fold_string_method(recv: &Val, name: &str, args: &[Val]) -> Val {
    match (recv, name, args) {
        (Val::Str(s), "charAt", [i]) => match i.as_int() {
            Some(n) if n >= 0 => s.chars().nth(n as usize).map_or(Val::Safe, Val::Char),
            _ => Val::Safe,
        },
        (Val::Str(s), "length", []) => Val::Int(s.chars().count() as i64),
        _ => Val::Safe,
    }
}

fn walk<'t>(node: Node<'t>, f: &mut impl FnMut(Node<'t>)) {
    f(node);
    let mut c = node.walk();
    for child in node.named_children(&mut c) {
        walk(child, f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    /// Parse `body` as a class and report whether the `sink(...)` call is safe.
    fn safe(src: &str, html: bool) -> bool {
        let mut p = Parser::new();
        p.set_language(&tree_sitter_java::LANGUAGE.into()).unwrap();
        let tree = p.parse(src, None).unwrap();
        let mut found = None;
        walk(tree.root_node(), &mut |n| {
            if n.kind() == "method_invocation"
                && n.child_by_field_name("name")
                    .is_some_and(|x| &src[x.byte_range()] == "sink")
            {
                found = Some(n);
            }
        });
        sink_args_safe(found.expect("sink call"), src, html)
    }

    fn method(body: &str) -> String {
        format!("class T {{ void m(HttpServletRequest req) {{ String param = req.getParameter(\"x\"); {body} }} }}")
    }

    #[test]
    fn constant_condition_ternary() {
        let tp = method(
            "int num = 106; String bar = (7 * 18) + num > 200 ? param : \"safe\"; sink(bar);",
        );
        let ok = method(
            "int num = 106; String bar = (7 * 18) + num > 200 ? \"safe\" : param; sink(bar);",
        );
        assert!(!safe(&tp, false));
        assert!(safe(&ok, false));
    }

    #[test]
    fn constant_condition_if() {
        let tp = method("int n = 86; String bar; if ((7 * 42) - n > 200) bar = param; else bar = \"x\"; sink(bar);");
        let ok = method("int n = 86; String bar; if ((7 * 42) - n > 200) bar = \"x\"; else bar = param; sink(bar);");
        assert!(!safe(&tp, false));
        assert!(safe(&ok, false));
    }

    #[test]
    fn unknown_condition_joins_branches() {
        let src = method("String bar = \"a\"; if (param.length() > 3) { bar = param; } sink(bar);");
        assert!(!safe(&src, false));
    }

    #[test]
    fn reassignment_and_sanitiser() {
        let tp = method("String bar = \"ok\"; bar = param; sink(bar);");
        let ok = method("String bar = param; bar = \"ok\"; sink(bar);");
        assert!(!safe(&tp, false));
        assert!(safe(&ok, false));
        let enc = method("String bar = Encode.forHtml(param); sink(bar);");
        assert!(safe(&enc, true));
        assert!(!safe(&enc, false));
    }

    #[test]
    fn list_element_selection() {
        let tp = method("java.util.List<String> l = new java.util.ArrayList<String>(); l.add(\"safe\"); l.add(param); l.add(\"more\"); l.remove(0); String bar = l.get(0); sink(bar);");
        let ok = method("java.util.List<String> l = new java.util.ArrayList<String>(); l.add(\"safe\"); l.add(param); l.add(\"more\"); l.remove(0); String bar = l.get(1); sink(bar);");
        assert!(!safe(&tp, false));
        assert!(safe(&ok, false));
    }

    #[test]
    fn map_element_selection() {
        let tp = method("java.util.HashMap<String, Object> m = new java.util.HashMap<String, Object>(); m.put(\"a\", \"x\"); m.put(\"b\", param); String bar = (String) m.get(\"b\"); sink(bar);");
        let ok = method("java.util.HashMap<String, Object> m = new java.util.HashMap<String, Object>(); m.put(\"a\", \"x\"); m.put(\"b\", param); String bar = (String) m.get(\"a\"); sink(bar);");
        let removed = method("java.util.HashMap<String, Object> m = new java.util.HashMap<String, Object>(); m.put(\"b\", param); m.remove(\"b\"); String bar = (String) m.get(\"b\"); sink(bar);");
        assert!(!safe(&tp, false));
        assert!(safe(&ok, false));
        assert!(safe(&removed, false));
    }

    #[test]
    fn switch_selects_constant() {
        let head = "String guess = \"ABC\"; char t = guess.charAt(1); String bar;";
        let tp = method(&format!("{head} switch (t) {{ case 'A': bar = \"a\"; break; case 'B': bar = param; break; default: bar = \"d\"; }} sink(bar);"));
        let ok = method(&format!("{head} switch (t) {{ case 'A': bar = param; break; case 'B': bar = \"b\"; break; default: bar = param; }} sink(bar);"));
        let unknown = method("String bar; switch (param) { case \"A\": bar = \"a\"; break; default: bar = param; } sink(bar);");
        assert!(!safe(&tp, false));
        assert!(safe(&ok, false));
        assert!(!safe(&unknown, false));
    }

    #[test]
    fn same_file_helper_is_interpreted() {
        let tp = "class T { void m(HttpServletRequest req) { String param = req.getParameter(\"x\"); String bar = new Test().f(param); sink(bar); } private class Test { public String f(String p) { String b = \"x\"; b = p; return b; } } }";
        let ok = "class T { void m(HttpServletRequest req) { String param = req.getParameter(\"x\"); String bar = new Test().f(param); sink(bar); } private class Test { public String f(String p) { String b = p; b = \"x\"; return b; } } }";
        assert!(!safe(tp, false));
        assert!(safe(ok, false));
    }

    #[test]
    fn unknown_values_are_not_safe() {
        assert!(!safe("class T { void m() { sink(field); } }", false));
        assert!(!safe("class T { void m() { sink(other()); } }", false));
    }
}
