//! Shared types and utilities for the JS/Python/Go taint engines.
//!
//! Each language-specific engine (`javascript_taint`, `python_taint`,
//! `go_taint`) re-exports these types so existing consumers are
//! unaffected.

use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

// ─── Core types ──────────────────────────────────────────────────────────

/// A pattern that matches an AST node for taint analysis.
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
///
/// Sanitizers collapse to "clean" — the engine does not track a separate
/// "sanitized" state.
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
    /// Optional rule id hint set by the batched analyzer so callers can
    /// dispatch a finding back to the correct rule.
    pub rule_id_hint: Option<String>,
    /// Approximate number of hops along the source→sink flow.
    pub hops: u8,
}

/// How cross-file findings should be attributed to rules.
#[derive(Clone)]
pub enum RuleFilter<'a> {
    /// Only emit cross-file findings whose `sink_rule_id` equals the
    /// given value.
    Single(&'a str),
    /// Emit cross-file findings whose `sink_rule_id` appears in the
    /// given set.
    Any(&'a HashSet<String>),
}

impl<'a> RuleFilter<'a> {
    pub fn allows(&self, rule_id: &str) -> bool {
        match self {
            RuleFilter::Single(id) => *id == rule_id,
            RuleFilter::Any(set) => set.contains(rule_id),
        }
    }
}

/// Return-taint summary map keyed by a function's simple name.
pub type ReturnSummary = HashMap<String, Option<String>>;

/// Inputs to the batched taint analyzer.
pub struct BatchedRule<'a> {
    pub rule_id: &'a str,
    pub spec: &'a TaintSpec,
}

// ─── Internal types (pub(super) for language engines) ────────────────────

#[derive(Clone, Debug)]
pub(super) struct TaintInfo {
    pub description: String,
    pub line: usize,
}

#[derive(Default)]
pub(super) struct TaintState {
    pub tainted: HashMap<String, TaintInfo>,
}

impl TaintState {
    pub fn taint(&mut self, name: String, description: String, line: usize) {
        self.tainted.insert(name, TaintInfo { description, line });
    }

    pub fn clear(&mut self, name: &str) {
        self.tainted.remove(name);
    }

    pub fn info(&self, name: &str) -> Option<&TaintInfo> {
        self.tainted.get(name)
    }
}

// ─── Utilities ───────────────────────────────────────────────────────────

pub(super) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

pub(super) fn sanitizer_fingerprints_eq(a: &[NodeMatcher], b: &[NodeMatcher]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let fingerprint = |matchers: &[NodeMatcher]| -> Vec<String> {
        let mut v: Vec<String> = matchers.iter().map(matcher_fingerprint).collect();
        v.sort();
        v
    };
    fingerprint(a) == fingerprint(b)
}

pub(super) fn matcher_fingerprint(m: &NodeMatcher) -> String {
    match m {
        NodeMatcher::Attribute {
            root,
            field,
            description,
        } => format!("A|{root}|{field}|{description}"),
        NodeMatcher::Call {
            canonical,
            description,
        } => format!("C|{canonical}|{description}"),
        NodeMatcher::ParamName { names, description } => {
            format!("P|{}|{description}", names.join(","))
        }
        NodeMatcher::MethodName {
            method,
            description,
        } => {
            format!("M|{method}|{description}")
        }
        NodeMatcher::MemberAssign { field, description } => {
            format!("MA|{field}|{description}")
        }
    }
}
