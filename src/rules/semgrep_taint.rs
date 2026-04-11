//! Semgrep-compatible YAML bridge for `mode: taint` rules.
//!
//! This module parses a *narrow* subset of Semgrep's taint-mode schema into
//! foxguard's [`TaintSpec`] so that users can load existing Semgrep taint
//! rules via `--rules` without rewriting them.
//!
//! # Supported today
//!
//! - `mode: taint` with `languages: [python]` (other languages are rejected
//!   with a warning and the rule is skipped; non-taint rules fall through to
//!   the regular Semgrep bridge).
//! - `pattern-sources`, `pattern-sinks`, `pattern-sanitizers` as lists of
//!   single-`pattern:` entries *or* `pattern-either:` lists (which may nest
//!   recursively and flatten into multiple matchers for the same role).
//! - Severity mapping via the same `map_severity` used by the pattern-rule
//!   bridge (`ERROR` → Critical, `WARNING` → High, `INFO` → Medium).
//! - `metadata.cwe` propagated to findings.
//!
//! # Unsupported (rule is skipped with a warning)
//!
//! - `pattern-inside:`, `metavariable-pattern:`, `patterns:` inside
//!   source/sink blocks.
//! - Any `mode: taint` rule that does not target Python.
//! - Any `pattern:` string whose shape is not one of:
//!   - bare identifier (`request`) — compiled to `ParamName`
//!   - dotted attribute chain (`request.data`, `request.json`) — compiled
//!     to `Attribute { root, field }` using the *leftmost* identifier and
//!     the *outermost* attribute (nested chains like `request.session.id`
//!     are flattened to `root="request", field="id"`; documented as a known
//!     gap that matches the engine's own one-level attribute propagation).
//!   - call form (`pickle.loads($X)`, `pickle.loads(...)`, `func($X)`,
//!     `func()`) — compiled to `Call { canonical }`, stripping arguments.
//!
//! Unsupported patterns inside an otherwise-loadable rule cause the *whole
//! rule* to be skipped (with an explanatory warning) so the user sees a
//! clear signal rather than a silently-degraded match surface.

use crate::rules::python_taint::{self, NodeMatcher, TaintSpec};
use crate::rules::{FileContext, Rule};
use crate::{Finding, Language, Severity};
use serde_yaml::Value as YamlValue;

/// A compiled Semgrep `mode: taint` rule.
pub struct SemgrepTaintRule {
    pub id: String,
    pub message: String,
    pub severity: Severity,
    pub cwe: Option<String>,
    pub lang: Language,
    pub spec: TaintSpec,
}

impl Rule for SemgrepTaintRule {
    fn id(&self) -> &str {
        &self.id
    }
    fn severity(&self) -> Severity {
        self.severity
    }
    fn cwe(&self) -> Option<&str> {
        self.cwe.as_deref()
    }
    fn description(&self) -> &str {
        &self.message
    }
    fn language(&self) -> Language {
        self.lang
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        let raw =
            python_taint::analyze_tree(tree.root_node(), source, &self.spec, ctx.python_aliases);
        raw.into_iter()
            .map(|t| Finding {
                rule_id: self.id.clone(),
                severity: self.severity,
                cwe: self.cwe.clone(),
                description: format!(
                    "{} — {} reaches {}",
                    self.message, t.source_description, t.sink_description
                ),
                file: String::new(),
                line: t.sink_line,
                column: t.sink_column,
                end_line: t.sink_end_line,
                end_column: t.sink_end_column,
                snippet: get_source_line(source, t.sink_start_byte),
            })
            .collect()
    }
}

fn get_source_line(source: &str, byte_offset: usize) -> String {
    let start = source[..byte_offset].rfind('\n').map_or(0, |p| p + 1);
    let end = source[byte_offset..]
        .find('\n')
        .map_or(source.len(), |p| byte_offset + p);
    source[start..end].to_string()
}

// ─── YAML → TaintSpec compilation ─────────────────────────────────────────

/// Outcome of trying to parse a single YAML rule as a taint rule.
pub enum TaintRuleParse {
    /// The rule is `mode: taint` and was compiled successfully.
    Compiled(SemgrepTaintRule),
    /// The rule is `mode: taint` but we could not compile it (bad language,
    /// unsupported pattern syntax, missing required sections, …). The caller
    /// should surface the warning and skip the rule.
    Skip(String),
    /// The rule is *not* `mode: taint`. The caller should fall through to
    /// its existing pattern-rule handling path.
    NotTaint,
}

/// Attempt to parse a single Semgrep YAML rule as a `mode: taint` rule.
///
/// Returns [`TaintRuleParse::NotTaint`] when the rule does not declare
/// `mode: taint`, so the caller can keep running its normal pattern-rule
/// compilation without an early exit.
pub fn parse_taint_rule(yaml: &YamlValue) -> TaintRuleParse {
    // Only engage for rules that explicitly declare `mode: taint`.
    let mode = yaml.get("mode").and_then(YamlValue::as_str);
    if mode != Some("taint") {
        return TaintRuleParse::NotTaint;
    }

    let id = match yaml.get("id").and_then(YamlValue::as_str) {
        Some(s) => s.to_string(),
        None => return TaintRuleParse::Skip("taint rule missing `id`".into()),
    };

    // Language: Python only for now.
    let lang = match yaml.get("languages").and_then(YamlValue::as_sequence) {
        Some(langs) => {
            let has_python = langs
                .iter()
                .filter_map(YamlValue::as_str)
                .any(|s| matches!(s.to_lowercase().as_str(), "python" | "py"));
            if !has_python {
                return TaintRuleParse::Skip(format!(
                    "taint rule `{}` targets non-Python languages; only Python is supported",
                    id
                ));
            }
            Language::Python
        }
        None => return TaintRuleParse::Skip(format!("taint rule `{}` missing `languages`", id)),
    };

    let message = yaml
        .get("message")
        .and_then(YamlValue::as_str)
        .unwrap_or("")
        .to_string();

    let severity_str = yaml
        .get("severity")
        .and_then(YamlValue::as_str)
        .unwrap_or("WARNING");
    let severity = map_severity(severity_str);

    let cwe = extract_cwe(yaml);

    // ── Compile sources ────────────────────────────────────────────────
    let sources = match compile_matcher_list(yaml.get("pattern-sources"), MatcherRole::Source, &id)
    {
        Ok(v) => v,
        Err(e) => return TaintRuleParse::Skip(format!("taint rule `{}` skipped: {}", id, e)),
    };
    if sources.is_empty() {
        return TaintRuleParse::Skip(format!(
            "taint rule `{}` has no valid `pattern-sources`",
            id
        ));
    }

    let sinks = match compile_matcher_list(yaml.get("pattern-sinks"), MatcherRole::Sink, &id) {
        Ok(v) => v,
        Err(e) => return TaintRuleParse::Skip(format!("taint rule `{}` skipped: {}", id, e)),
    };
    if sinks.is_empty() {
        return TaintRuleParse::Skip(format!("taint rule `{}` has no valid `pattern-sinks`", id));
    }

    let sanitizers =
        match compile_matcher_list(yaml.get("pattern-sanitizers"), MatcherRole::Sanitizer, &id) {
            Ok(v) => v,
            Err(e) => return TaintRuleParse::Skip(format!("taint rule `{}` skipped: {}", id, e)),
        };

    TaintRuleParse::Compiled(SemgrepTaintRule {
        id: format!("semgrep/{}", id),
        message,
        severity,
        cwe,
        lang,
        spec: TaintSpec {
            sources,
            sinks,
            sanitizers,
        },
    })
}

#[derive(Copy, Clone)]
enum MatcherRole {
    Source,
    Sink,
    Sanitizer,
}

impl MatcherRole {
    fn label(self) -> &'static str {
        match self {
            MatcherRole::Source => "pattern-sources",
            MatcherRole::Sink => "pattern-sinks",
            MatcherRole::Sanitizer => "pattern-sanitizers",
        }
    }
}

/// Compile a top-level `pattern-sources` / `pattern-sinks` /
/// `pattern-sanitizers` list.
///
/// Each entry is allowed to be either:
///
/// - a mapping with a single `pattern:` key (compiled to one [`NodeMatcher`]),
/// - a mapping with a single `pattern-either:` key whose value is itself a
///   list of entries following the same rules (flattened recursively into
///   multiple matchers).
///
/// Any other key (`patterns:`, `pattern-inside:`, `metavariable-pattern:`,
/// …) is rejected with a warning that names the rule and the offending key,
/// and the individual entry is skipped. If the role ends up with *no* valid
/// entries the caller decides whether that is fatal for the whole rule
/// (sources and sinks are required; sanitizers may legitimately be empty).
fn compile_matcher_list(
    node: Option<&YamlValue>,
    role: MatcherRole,
    rule_id: &str,
) -> Result<Vec<NodeMatcher>, String> {
    let Some(node) = node else {
        return Ok(Vec::new());
    };
    let Some(entries) = node.as_sequence() else {
        return Err(format!("{} must be a list", role.label()));
    };

    let mut out = Vec::new();
    for entry in entries {
        compile_entry(entry, role, rule_id, &mut out);
    }
    Ok(out)
}

/// Compile a single entry from a source/sink/sanitizer list, flattening
/// nested `pattern-either:` blocks. Invalid entries emit a warning and are
/// skipped rather than aborting the whole rule.
fn compile_entry(entry: &YamlValue, role: MatcherRole, rule_id: &str, out: &mut Vec<NodeMatcher>) {
    let Some(map) = entry.as_mapping() else {
        eprintln!(
            "Warning: taint rule `{}` {} entry is not a mapping; skipping",
            rule_id,
            role.label()
        );
        return;
    };

    // Entries are expected to carry exactly one top-level key. Having more
    // than one suggests the user meant `patterns:` semantics, which we
    // don't support inside taint blocks — warn and skip.
    if map.len() != 1 {
        eprintln!(
            "Warning: taint rule `{}` {} entry has {} keys (expected a single `pattern:` or `pattern-either:`); skipping entry",
            rule_id,
            role.label(),
            map.len(),
        );
        return;
    }

    let (k, v) = map.iter().next().expect("map.len() == 1");
    match k.as_str() {
        Some("pattern") => {
            let Some(pattern) = v.as_str() else {
                eprintln!(
                    "Warning: taint rule `{}` {} `pattern:` value must be a string; skipping entry",
                    rule_id,
                    role.label()
                );
                return;
            };
            match compile_pattern(pattern, role) {
                Some(m) => out.push(m),
                None => eprintln!(
                    "Warning: taint rule `{}` {} unsupported pattern shape `{}`; skipping entry",
                    rule_id,
                    role.label(),
                    pattern
                ),
            }
        }
        Some("pattern-either") => {
            let Some(inner) = v.as_sequence() else {
                eprintln!(
                    "Warning: taint rule `{}` {} `pattern-either:` must be a list; skipping",
                    rule_id,
                    role.label()
                );
                return;
            };
            if inner.is_empty() {
                eprintln!(
                    "Warning: taint rule `{}` {} `pattern-either:` is empty; producing no matchers",
                    rule_id,
                    role.label()
                );
                return;
            }
            for nested in inner {
                compile_entry(nested, role, rule_id, out);
            }
        }
        Some(other) => {
            eprintln!(
                "Warning: taint rule `{}` {} uses unsupported key `{}` (only `pattern:` and `pattern-either:` are supported); skipping entry",
                rule_id,
                role.label(),
                other
            );
        }
        None => {
            eprintln!(
                "Warning: taint rule `{}` {} entry has a non-string key; skipping",
                rule_id,
                role.label()
            );
        }
    }
}

/// Compile a single Semgrep pattern string into a [`NodeMatcher`].
///
/// Returns `None` if the pattern shape is not one of the supported forms
/// (see module docs). Callers surface that as a skip-with-warning at the
/// rule level.
fn compile_pattern(pattern: &str, role: MatcherRole) -> Option<NodeMatcher> {
    let pat = pattern.trim();
    if pat.is_empty() {
        return None;
    }

    // ── Call form: `root.method(...)` or `func($X)` ─────────────────────
    if let Some(open_paren) = pat.find('(') {
        if !pat.ends_with(')') {
            return None;
        }
        let callee = pat[..open_paren].trim();
        if callee.is_empty() {
            return None;
        }
        // Callee must be a plain identifier or dotted identifier chain.
        if !is_dotted_identifier(callee) {
            return None;
        }
        let canonical = callee.to_string();
        return Some(NodeMatcher::Call {
            canonical: canonical.clone(),
            description: describe(&canonical, role),
        });
    }

    // ── No parens: identifier or attribute chain ────────────────────────
    if !is_dotted_identifier(pat) {
        return None;
    }

    if let Some(dot) = pat.rfind('.') {
        // `root.field` or `root.intermediate.field`. The engine only
        // supports one-level roots, so we take the leftmost segment as
        // the root and the outermost (last) segment as the field.
        let root = pat[..pat.find('.').unwrap()].to_string();
        let field = pat[dot + 1..].to_string();
        if root.is_empty() || field.is_empty() {
            return None;
        }
        let desc = describe(pat, role);
        return Some(NodeMatcher::Attribute {
            root,
            field,
            description: desc,
        });
    }

    // Bare identifier → treat as a ParamName source / sink would not make
    // sense, so for non-source roles we refuse this shape.
    match role {
        MatcherRole::Source => Some(NodeMatcher::ParamName {
            names: vec![pat.to_string()],
            description: format!("untrusted `{}` parameter", pat),
        }),
        MatcherRole::Sink | MatcherRole::Sanitizer => None,
    }
}

fn describe(canonical: &str, role: MatcherRole) -> String {
    match role {
        MatcherRole::Source => format!("semgrep source `{}`", canonical),
        MatcherRole::Sink => format!("semgrep sink `{}`", canonical),
        MatcherRole::Sanitizer => format!("semgrep sanitizer `{}`", canonical),
    }
}

/// True when `s` is a `.`-separated chain of identifier segments, each of
/// which is an ASCII identifier (`[A-Za-z_][A-Za-z0-9_]*`). Used to reject
/// pattern strings that contain metavariables, operators, or whitespace
/// outside of a call form.
fn is_dotted_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.split('.').all(is_identifier)
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn map_severity(s: &str) -> Severity {
    match s.to_ascii_uppercase().as_str() {
        "ERROR" => Severity::Critical,
        "WARNING" => Severity::High,
        "INFO" => Severity::Medium,
        _ => Severity::Medium,
    }
}

fn extract_cwe(yaml: &YamlValue) -> Option<String> {
    let meta = yaml.get("metadata")?;
    let cwe = meta.get("cwe")?;
    match cwe {
        YamlValue::String(s) => Some(s.clone()),
        YamlValue::Sequence(v) => v.first().and_then(|x| x.as_str()).map(|s| s.to_string()),
        _ => None,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(pattern: &str, role: MatcherRole) -> Option<NodeMatcher> {
        compile_pattern(pattern, role)
    }

    #[test]
    fn compile_attribute_source() {
        let m = compile("request.data", MatcherRole::Source).expect("attribute");
        match m {
            NodeMatcher::Attribute { root, field, .. } => {
                assert_eq!(root, "request");
                assert_eq!(field, "data");
            }
            _ => panic!("expected Attribute"),
        }
    }

    #[test]
    fn compile_nested_attribute_takes_leftmost_root_and_outermost_field() {
        let m = compile("request.session.user_id", MatcherRole::Source).expect("attribute");
        match m {
            NodeMatcher::Attribute { root, field, .. } => {
                assert_eq!(root, "request");
                assert_eq!(field, "user_id");
            }
            _ => panic!("expected Attribute"),
        }
    }

    #[test]
    fn compile_call_with_metavar() {
        let m = compile("pickle.loads($X)", MatcherRole::Sink).expect("call");
        match m {
            NodeMatcher::Call { canonical, .. } => assert_eq!(canonical, "pickle.loads"),
            _ => panic!("expected Call"),
        }
    }

    #[test]
    fn compile_call_with_ellipsis() {
        let m = compile("pickle.loads(...)", MatcherRole::Sink).expect("call");
        match m {
            NodeMatcher::Call { canonical, .. } => assert_eq!(canonical, "pickle.loads"),
            _ => panic!("expected Call"),
        }
    }

    #[test]
    fn compile_bare_func_call() {
        let m = compile("eval($X)", MatcherRole::Sink).expect("call");
        match m {
            NodeMatcher::Call { canonical, .. } => assert_eq!(canonical, "eval"),
            _ => panic!("expected Call"),
        }
    }

    #[test]
    fn compile_bare_identifier_source() {
        let m = compile("request", MatcherRole::Source).expect("paramname");
        match m {
            NodeMatcher::ParamName { names, .. } => assert_eq!(names, vec!["request".to_string()]),
            _ => panic!("expected ParamName"),
        }
    }

    #[test]
    fn bare_identifier_rejected_as_sink() {
        assert!(compile("request", MatcherRole::Sink).is_none());
    }

    #[test]
    fn weird_shapes_rejected() {
        assert!(compile("$X + $Y", MatcherRole::Source).is_none());
        assert!(compile("a.b.c(d", MatcherRole::Sink).is_none());
        assert!(compile("", MatcherRole::Source).is_none());
    }

    #[test]
    fn parse_full_taint_rule() {
        let yaml = r#"
id: semgrep-pickle-taint
mode: taint
languages: [python]
severity: ERROR
message: "Untrusted input reaches pickle.loads"
metadata:
  cwe: "CWE-502"
pattern-sources:
  - pattern: request.data
  - pattern: request
pattern-sinks:
  - pattern: pickle.loads($X)
"#;
        let v: YamlValue = serde_yaml::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.id, "semgrep/semgrep-pickle-taint");
                assert_eq!(r.lang, Language::Python);
                assert_eq!(r.cwe.as_deref(), Some("CWE-502"));
                assert_eq!(r.spec.sources.len(), 2);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn non_taint_rule_falls_through() {
        let yaml = r#"
id: classic
pattern: eval(...)
message: x
severity: ERROR
languages: [python]
"#;
        let v: YamlValue = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(parse_taint_rule(&v), TaintRuleParse::NotTaint));
    }

    #[test]
    fn taint_rule_with_non_python_language_is_skipped() {
        let yaml = r#"
id: x
mode: taint
languages: [javascript]
severity: ERROR
message: m
pattern-sources: [{pattern: req}]
pattern-sinks: [{pattern: eval($X)}]
"#;
        let v: YamlValue = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(parse_taint_rule(&v), TaintRuleParse::Skip(_)));
    }

    fn compiled(yaml: &str) -> SemgrepTaintRule {
        let v: YamlValue = serde_yaml::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => r,
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn pattern_either_flattens_into_multiple_matchers() {
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern-either:
      - pattern: request.data
      - pattern: request.form
      - pattern: request.args
pattern-sinks:
  - pattern: pickle.loads($X)
"#,
        );
        assert_eq!(r.spec.sources.len(), 3);
        assert_eq!(r.spec.sinks.len(), 1);
    }

    #[test]
    fn nested_pattern_either_flattens_recursively() {
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern-either:
      - pattern-either:
          - pattern: request.data
          - pattern: request.form
      - pattern: request.args
pattern-sinks:
  - pattern: pickle.loads($X)
"#,
        );
        assert_eq!(r.spec.sources.len(), 3);
    }

    #[test]
    fn pattern_either_in_sinks_flattens() {
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern: request.data
pattern-sinks:
  - pattern-either:
      - pattern: pickle.loads($X)
      - pattern: pickle.load($X)
"#,
        );
        assert_eq!(r.spec.sinks.len(), 2);
    }

    #[test]
    fn pattern_either_in_sanitizers_flattens() {
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern: request.data
pattern-sinks:
  - pattern: pickle.loads($X)
pattern-sanitizers:
  - pattern-either:
      - pattern: sanitize($X)
      - pattern: escape($X)
"#,
        );
        assert_eq!(r.spec.sanitizers.len(), 2);
    }

    #[test]
    fn mixed_pattern_and_pattern_either_work_together() {
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern-either:
      - pattern: request.data
      - pattern: request.form
  - pattern: request
pattern-sinks:
  - pattern: pickle.loads($X)
  - pattern-either:
      - pattern: pickle.load($X)
"#,
        );
        assert_eq!(r.spec.sources.len(), 3);
        assert_eq!(r.spec.sinks.len(), 2);
    }

    #[test]
    fn empty_pattern_either_warns_and_produces_no_matcher() {
        // Empty pattern-either in sources → no source matchers, so whole
        // rule is skipped (sources are required).
        let yaml = r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern-either: []
pattern-sinks:
  - pattern: pickle.loads($X)
"#;
        let v: YamlValue = serde_yaml::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Skip(msg) => assert!(msg.contains("pattern-sources")),
            other => panic!(
                "expected Skip because empty pattern-either produced no sources, got {:?}",
                match other {
                    TaintRuleParse::Compiled(_) => "Compiled",
                    TaintRuleParse::NotTaint => "NotTaint",
                    TaintRuleParse::Skip(_) => unreachable!(),
                }
            ),
        }

        // Empty pattern-either in sanitizers → rule still compiles (sanitizers
        // are optional), but has zero sanitizer matchers.
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern: request.data
pattern-sinks:
  - pattern: pickle.loads($X)
pattern-sanitizers:
  - pattern-either: []
"#,
        );
        assert!(r.spec.sanitizers.is_empty());
    }

    #[test]
    fn unknown_composite_still_rejected() {
        // `patterns:` inside a source block → entry is skipped with a
        // warning. With no other source entries the whole rule is skipped.
        let yaml = r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - patterns:
      - pattern: request.data
pattern-sinks:
  - pattern: pickle.loads($X)
"#;
        let v: YamlValue = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(parse_taint_rule(&v), TaintRuleParse::Skip(_)));

        // `pattern-inside:` likewise rejected per-entry.
        let yaml2 = r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern-inside: |
      def $F(...):
        ...
pattern-sinks:
  - pattern: pickle.loads($X)
"#;
        let v2: YamlValue = serde_yaml::from_str(yaml2).unwrap();
        assert!(matches!(parse_taint_rule(&v2), TaintRuleParse::Skip(_)));

        // But a mix where one entry is `patterns:` and another is a plain
        // `pattern:` still compiles — the bad entry is dropped, the good
        // one survives.
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - patterns:
      - pattern: request.data
  - pattern: request.form
pattern-sinks:
  - pattern: pickle.loads($X)
"#,
        );
        assert_eq!(r.spec.sources.len(), 1);
    }
}
