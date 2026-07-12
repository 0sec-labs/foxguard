use crate::engine::parser::parse_file;
use crate::rules::common::get_source_line;
use crate::rules::Rule;
use crate::{Finding, Language, Severity};
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::OnceLock;

const RESERVED_RULE_ID_NAMESPACES: &[&str] = &[
    "py", "js", "go", "java", "php", "ruby", "cs", "csharp", "swift", "kotlin", "rs", "rust",
    "config", "manifest",
];

/// A compiled regex that prefers the fast `regex` crate but transparently falls
/// back to `fancy-regex` (a backtracking engine) for patterns the `regex` crate
/// cannot compile — most importantly PCRE features such as lookahead
/// `(?=...)` / `(?!...)`, lookbehind `(?<=...)` / `(?<!...)`, and named
/// backreferences, which many Semgrep registry rules rely on.
///
/// The `regex` crate remains the primary path: `fancy-regex` is only used when
/// the `regex` crate rejects the pattern, so the common case keeps the linear,
/// allocation-free matching of the fast engine.
#[derive(Debug, Clone)]
pub enum CompiledRegex {
    /// Compiled with the fast, linear-time `regex` crate (the common case).
    Fast(Regex),
    /// Compiled with the backtracking `fancy-regex` engine (lookaround /
    /// backreferences). `fancy_regex::Regex::is_match` returns a `Result`; any
    /// error (e.g. backtrack-limit exceeded) is treated as "no match" rather
    /// than panicking.
    Fancy(fancy_regex::Regex),
}

impl CompiledRegex {
    /// Returns the original (normalised) regex source string of whichever
    /// backend compiled it. Used for stable fingerprinting/dedup of compiled
    /// matchers that embed a regex.
    pub fn as_str(&self) -> &str {
        match self {
            CompiledRegex::Fast(re) => re.as_str(),
            CompiledRegex::Fancy(re) => re.as_str(),
        }
    }

    /// Returns `true` if the pattern matches anywhere in `text`.
    ///
    /// For the fancy-regex backend, a matcher error (such as exceeding the
    /// backtrack limit) is treated as no-match.
    pub fn is_match(&self, text: &str) -> bool {
        match self {
            CompiledRegex::Fast(re) => re.is_match(text),
            CompiledRegex::Fancy(re) => re.is_match(text).unwrap_or(false),
        }
    }

    /// Returns the non-overlapping byte ranges `(start, end)` of every match in
    /// `text`, left-to-right — the same iteration order as
    /// [`regex::Regex::find_iter`].
    ///
    /// For the fancy-regex backend, iteration stops at the first matcher error
    /// (errors are treated as "no further matches" rather than panicking).
    pub fn find_matches(&self, text: &str) -> Vec<(usize, usize)> {
        match self {
            CompiledRegex::Fast(re) => re.find_iter(text).map(|m| (m.start(), m.end())).collect(),
            CompiledRegex::Fancy(re) => re
                .find_iter(text)
                .map_while(Result::ok)
                .map(|m| (m.start(), m.end()))
                .collect(),
        }
    }
}

// ─── YAML Schema ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SemgrepFile {
    pub rules: Vec<SemgrepRuleYaml>,
}

/// Value that can be either a plain string pattern or a complex block
/// (e.g. `pattern-not-inside:` with a nested `patterns:` sub-block).
///
/// The string form is used directly as a pattern.  The block form is
/// deserialized into a raw YAML `Value` and then examined for an inner
/// `pattern:` string to extract; if none is found the constraint is
/// warn-skipped (graceful degradation consistent with the rest of the loader).
///
/// This supports rules like `last-user-is-root` in the Dockerfile registry
/// which use:
/// ```yaml
/// pattern-not-inside:
///   patterns:
///     - pattern: |
///         USER root
///         ...
///         USER $X
///     - metavariable-pattern:
///         metavariable: $X
///         patterns:
///         - pattern-not: root
/// ```
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum PatternOrBlock {
    /// Plain string — the common `pattern-not-inside: "..."` form.
    Literal(String),
    /// Complex block — accept any map/sequence so the YAML deserializes
    /// without error; we extract a usable `pattern:` string from it, if any.
    Block(serde_yaml_ng::Value),
}

impl PatternOrBlock {
    /// Extract a usable pattern string from this value.
    ///
    /// - `Literal(s)` → `Some(s)`
    /// - `Block(v)` → looks for the first `pattern:` string nested under a
    ///   `patterns:` list; returns `None` (with a warning) if nothing usable
    ///   is found.  The returned string is the first concrete sub-pattern that
    ///   can be compiled; more complex constraints (metavariable-pattern etc.)
    ///   in the block are gracefully dropped.
    pub fn into_pattern_string(self) -> Option<String> {
        match self {
            PatternOrBlock::Literal(s) => Some(s),
            PatternOrBlock::Block(v) => {
                // Try to extract the first `pattern:` string from a
                // `patterns: [{ pattern: "..." }, ...]` block.
                if let Some(clauses) = v
                    .get("patterns")
                    .and_then(serde_yaml_ng::Value::as_sequence)
                {
                    for clause in clauses {
                        if let Some(pat) =
                            clause.get("pattern").and_then(serde_yaml_ng::Value::as_str)
                        {
                            return Some(pat.to_string());
                        }
                    }
                }
                eprintln!(
                    "Warning: pattern-not-inside block has no extractable `pattern:` string; \
                     skipping constraint"
                );
                None
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SemgrepRuleYaml {
    pub id: String,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default, rename = "pattern-regex")]
    pub pattern_regex: Option<String>,
    #[serde(default, rename = "pattern-either")]
    pub pattern_either: Option<Vec<PatternEntry>>,
    #[serde(default, rename = "pattern-not")]
    pub pattern_not: Option<String>,
    #[serde(default, rename = "pattern-not-regex")]
    pub pattern_not_regex: Option<String>,
    #[serde(default, rename = "pattern-inside")]
    pub pattern_inside: Option<String>,
    /// `pattern-not-inside:` accepts either a plain string or a complex block
    /// (e.g. `patterns: [...]` sub-block).  See [`PatternOrBlock`].
    #[serde(default, rename = "pattern-not-inside")]
    pub pattern_not_inside: Option<PatternOrBlock>,
    #[serde(default)]
    pub patterns: Option<Vec<PatternClause>>,
    pub message: String,
    pub severity: SemgrepSeverity,
    pub languages: Vec<String>,
    #[serde(default)]
    pub metadata: Option<SemgrepMetadata>,
    #[serde(default)]
    pub paths: Option<SemgrepPaths>,
    /// Optional autofix template (Semgrep `fix:` key).  Metavariables in the
    /// template (e.g. `$X`) are substituted with bound values when a finding is
    /// built.  `fix-regex:` is not supported and is ignored.
    #[serde(default)]
    pub fix: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PatternEntry {
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default, rename = "pattern-regex")]
    pub pattern_regex: Option<String>,
    /// A nested `patterns:` AND-block arm, kept as a raw YAML value. Used by
    /// generic-mode package-manager rules whose `pattern-either` arms are full
    /// AND-blocks (each with a named-capture `pattern-regex` plus
    /// `metavariable-*` constraints). The AST bridge ignores this field; only
    /// the generic-mode loader consumes it (decoding leniently, so AST-only
    /// nested shapes — e.g. a `pattern-not:` whose value is itself a block —
    /// never break deserialization of an unrelated rule).
    #[serde(default)]
    pub patterns: Option<serde_yaml_ng::Value>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PatternClause {
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default, rename = "pattern-regex")]
    pub pattern_regex: Option<String>,
    #[serde(default, rename = "pattern-not")]
    pub pattern_not: Option<String>,
    #[serde(default, rename = "pattern-not-regex")]
    pub pattern_not_regex: Option<String>,
    #[serde(default, rename = "pattern-inside")]
    pub pattern_inside: Option<String>,
    /// `pattern-not-inside:` inside a `patterns:` block can be either a plain
    /// string or a nested block (`patterns: [...]`).  See [`PatternOrBlock`].
    #[serde(default, rename = "pattern-not-inside")]
    pub pattern_not_inside: Option<PatternOrBlock>,
    #[serde(default, rename = "pattern-either")]
    pub pattern_either: Option<Vec<PatternEntry>>,
    #[serde(default, rename = "metavariable-regex")]
    pub metavariable_regex: Option<SemgrepMetavariableRegexClause>,
    #[serde(default, rename = "metavariable-comparison")]
    pub metavariable_comparison: Option<SemgrepMetavariableComparisonClause>,
    #[serde(default, rename = "metavariable-pattern")]
    pub metavariable_pattern: Option<SemgrepMetavariablePatternClause>,
    #[serde(default, rename = "metavariable-analysis")]
    pub metavariable_analysis: Option<SemgrepMetavariableAnalysisClause>,
    /// `focus-metavariable:` — report the range of the named metavariable(s)
    /// instead of the full enclosing match.
    #[serde(default, rename = "focus-metavariable")]
    pub focus_metavariable: Option<FocusMetavariableValue>,
    /// `metavariable-type:` — constrain a metavariable to a declared type.
    #[serde(default, rename = "metavariable-type")]
    pub metavariable_type: Option<SemgrepMetavariableTypeClause>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SemgrepSeverity {
    Error,
    Warning,
    /// `MEDIUM` is a Semgrep severity variant used by some registry rules (e.g.
    /// supply-chain / package-manager packs).  Foxguard maps it to `High`,
    /// matching the spirit of "medium" risk in the broader threat model.
    Medium,
    Info,
}

#[derive(Debug, Deserialize)]
pub struct SemgrepMetadata {
    pub cwe: Option<CweValue>,
}

#[derive(Debug, Deserialize, Default)]
pub struct SemgrepPaths {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SemgrepMetavariableRegexClause {
    pub metavariable: String,
    pub regex: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SemgrepMetavariableComparisonClause {
    /// The metavariable to compare.  Some advanced Semgrep rules omit this key
    /// (they use `comparison: str($F1) == str($F2)` with both operands being
    /// metavariables inside the expression string). We make the field optional
    /// so those rules still deserialize; `from_yaml` will warn-skip the
    /// constraint when the field is absent because the comparison is outside
    /// our supported `$VAR <op> <number>` subset regardless.
    #[serde(default)]
    pub metavariable: Option<String>,
    pub comparison: String,
    /// Optional integer base for parsing (e.g. 16 for hex). Warn-skipped if
    /// present — we only support base-10 by default.
    #[serde(default)]
    pub base: Option<u32>,
    /// Optional strip flag (Semgrep strips L/U suffixes from integer literals).
    /// Warn-skipped if true — the common C-integer suffix case is handled via
    /// our own stripping logic.
    #[serde(default)]
    pub strip: Option<bool>,
}

/// Nested pattern forms supported inside `metavariable-pattern:`.
///
/// Supported: `pattern:`, `pattern-regex:`, and `pattern-either:` (of those
/// same forms). Anything else (nested `patterns:`, `metavariable-pattern:`,
/// `language:` override, etc.) is warn-skipped at build time.
/// Accepts either a single metavariable name (`"$X"`) or a list (`["$X", "$Y"]`),
/// matching the Semgrep `focus-metavariable:` YAML schema.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum FocusMetavariableValue {
    Single(String),
    List(Vec<String>),
}

impl FocusMetavariableValue {
    /// Expand to a flat `Vec<String>` for uniform processing.
    pub fn into_vec(self) -> Vec<String> {
        match self {
            FocusMetavariableValue::Single(s) => vec![s],
            FocusMetavariableValue::List(v) => v,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct SemgrepMetavariablePatternClause {
    pub metavariable: String,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default, rename = "pattern-regex")]
    pub pattern_regex: Option<String>,
    #[serde(default, rename = "pattern-either")]
    pub pattern_either: Option<Vec<PatternEntry>>,
}

/// A `metavariable-analysis:` clause inside a `patterns:` block.
///
/// Supported analyzers:
/// - `entropy` — matches when the metavariable's bound text has high Shannon
///   entropy (≥ `ENTROPY_THRESHOLD` bits/char). Designed to flag random secrets
///   and tokens.
/// - `redos` — **warn-skipped**: a sound, cheap heuristic is not implemented;
///   the constraint is dropped and sibling clauses are unaffected.
/// - Any other analyzer → warn-skipped (graceful degradation).
#[derive(Debug, Deserialize, Clone)]
pub struct SemgrepMetavariableAnalysisClause {
    pub metavariable: String,
    pub analyzer: String,
}

/// A `metavariable-type:` clause inside a `patterns:` block.
///
/// Constrains a metavariable to a **declared** type, e.g. only match `$X` when
/// `$X` is (declared as) a `Statement`. This is the type-constraint sibling of
/// `metavariable-regex` (constrain by regex on the bound text).
#[derive(Debug, Deserialize, Clone)]
pub struct SemgrepMetavariableTypeClause {
    pub metavariable: String,
    #[serde(rename = "type")]
    pub type_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum CweValue {
    Single(String),
    List(Vec<String>),
}

// ─── Compiled Rule ──────────────────────────────────────────────────────────

/// A compiled Semgrep-compatible rule that implements the foxguard Rule trait.
pub struct SemgrepRule {
    pub id: String,
    pub message: String,
    pub severity: Severity,
    pub lang: Language,
    pub cwe: Option<String>,
    pub matcher: PatternMatcher,
    pub path_filter: Option<PathFilter>,
    /// Optional autofix template derived from the rule's `fix:` key.
    /// Metavariables (`$NAME`) are substituted with bound text when a finding
    /// is emitted; unbound tokens are left as-is.
    pub fix_template: Option<String>,
}

/// Represents the matching strategy for a rule.
// The `Combined` variant is inherently large (it holds several constraint Vecs);
// boxing the whole enum would require pervasive indirection. Suppress the lint
// here — the enum is only heap-allocated as part of a `SemgrepRule` or another
// `PatternMatcher` arm, so no stack-smashing risk.
#[derive(Debug, Clone)]
pub enum PatternMatcher {
    /// Single pattern
    Single(CompiledAstPattern),
    /// Regex match against source text
    Regex(CompiledRegex),
    /// Match any of these patterns (OR)
    Either(Vec<PatternMatcher>),
    /// Combine multiple clauses (AND): positives must all match, negatives must not
    Combined {
        positives: Vec<PatternMatcher>,
        negatives: Vec<NegativeMatcher>,
        inside: Option<CompiledAstPattern>,
        not_inside: Option<CompiledAstPattern>,
        metavariable_regexes: Vec<MetavariableRegexConstraint>,
        metavariable_comparisons: Vec<MetavariableComparisonConstraint>,
        metavariable_patterns: Vec<MetavariablePatternConstraint>,
        metavariable_analyses: Vec<MetavariableAnalysisConstraint>,
        metavariable_types: Vec<MetavariableTypeConstraint>,
        /// `focus-metavariable:` — when non-empty, the reported finding range is
        /// overridden to point at the first listed metavariable's binding range
        /// (falling back to the full match range if the metavar isn't bound).
        focus_metavariables: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub enum NegativeMatcher {
    Pattern(CompiledAstPattern),
    Regex(CompiledRegex),
}

#[derive(Clone)]
pub struct CompiledAstPattern {
    source: String,
    tree: Option<tree_sitter::Tree>,
    selector_kind: Option<String>,
}

impl fmt::Debug for CompiledAstPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledAstPattern")
            .field("source", &self.source)
            .field("compiled", &self.tree.is_some())
            .field("selector_kind", &self.selector_kind)
            .finish()
    }
}

impl CompiledAstPattern {
    /// Compile a Semgrep pattern string for use as a negative (exclusion)
    /// matcher — the `pattern-not` constraint inside a taint `patterns:`
    /// AND-block. Returns `None` when the pattern does not parse into a
    /// usable tree-sitter pattern node, so callers can warn and skip
    /// instead of silently storing an unmatchable pattern.
    ///
    /// This reuses the same compilation path as SEARCH-mode `pattern-not`
    /// (see `build_matcher`), so positive and negative patterns agree on
    /// grammar handling, metavariable rewriting, and ellipsis behaviour.
    pub(crate) fn try_new(pattern: &str, lang: Language) -> Option<Self> {
        let compiled = Self::new(pattern.to_string(), lang);
        if compiled.pattern_node().is_some() {
            Some(compiled)
        } else {
            None
        }
    }

    /// Run this pattern against every node in `root` and return `true` if
    /// any match's byte range overlaps the half-open `[start_byte, end_byte)`
    /// span — i.e. the pattern matches *at* the candidate location.
    ///
    /// Used by the taint bridge's post-filter to enforce `pattern-not`
    /// against a finding's sink node: if a negative pattern matches the
    /// sink's range, the finding is suppressed. The overlap test mirrors
    /// SEARCH mode's `ranges_overlap` semantics (`build_matcher`), keeping
    /// positive/negative intersection behaviour consistent across modes.
    pub(crate) fn overlaps_range(
        &self,
        root: tree_sitter::Node<'_>,
        source: &str,
        start_byte: usize,
        end_byte: usize,
    ) -> bool {
        match_single_pattern(self, root, source)
            .iter()
            .any(|m| m.start_byte < end_byte && start_byte < m.end_byte)
    }

    /// Run this pattern against every node in `root` and return `true` if
    /// any match's byte range *contains* the half-open `[start_byte, end_byte)`
    /// span — i.e. the candidate location is textually **inside** a region
    /// this pattern matches.
    ///
    /// Used by the taint bridge's post-filter to enforce `pattern-inside`
    /// against a finding's sink node: a finding is kept only when its sink's
    /// range is contained by some region matched by a positive `pattern-inside`
    /// constraint. The containment test mirrors SEARCH mode's `pattern-inside`
    /// filtering (`build_matcher`: `r.start_byte >= start && r.end_byte <= end`),
    /// keeping inside-containment behaviour consistent across modes.
    pub(crate) fn contains_range(
        &self,
        root: tree_sitter::Node<'_>,
        source: &str,
        start_byte: usize,
        end_byte: usize,
    ) -> bool {
        match_single_pattern(self, root, source)
            .iter()
            .any(|m| m.start_byte <= start_byte && end_byte <= m.end_byte)
    }
}

#[derive(Debug, Clone)]
pub struct PathFilter {
    include: Option<GlobSet>,
    exclude: Option<GlobSet>,
}

#[derive(Debug, Clone)]
pub struct MetavariableRegexConstraint {
    metavariable: String,
    regex: CompiledRegex,
}

/// Comparison operator for `metavariable-comparison`.
#[derive(Debug, Clone, PartialEq)]
enum CmpOp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

/// A compiled `metavariable-comparison` constraint.
/// Supports: `$VAR <op> <number>` and `<number> <op> $VAR`,
/// where `<number>` is an integer or float literal and `<op>` is one of
/// `<`, `<=`, `>`, `>=`, `==`, `!=`.
#[derive(Debug, Clone)]
pub struct MetavariableComparisonConstraint {
    metavariable: String,
    op: CmpOp,
    /// The literal value from the comparison string.
    literal: f64,
    /// If true, the expression is `literal <op> metavar` (operands flipped).
    literal_is_lhs: bool,
}

/// A compiled `metavariable-pattern:` constraint.
///
/// The binding text for `metavariable` is re-parsed as a snippet and matched
/// against `sub_matcher`. Supported sub-matcher forms: `Single` (pattern),
/// `Regex` (pattern-regex), and `Either` (pattern-either of those). Any
/// unsupported nested shape is warn-skipped at build time.
#[derive(Debug, Clone)]
pub struct MetavariablePatternConstraint {
    metavariable: String,
    sub_matcher: PatternMatcher,
    lang: Language,
}

/// Shannon entropy threshold (bits per character) above which a string is
/// considered high-entropy.
///
/// Rationale: real secrets (AWS key `AKIA…`, base64 bearer tokens, hex API
/// keys) cluster between 3.5–4.5 bits/char, while English words and common
/// identifiers sit below 3.0 bits/char.  Semgrep's built-in entropy analyzer
/// uses a learned Gaussian-mixture cutoff that is not publicly documented;
/// **3.5 bits/char** is a documented approximation that:
///
/// - flags `"Zq7Z9kW3pL8xT2nR4dB6m"` (random high-entropy token, entropy ≈ 4.0)
/// - flags a 32-char base64 token (entropy ≈ 4.75)
/// - passes `"hello"` (entropy ≈ 2.32)
/// - passes `"password"` (entropy ≈ 2.75)
///
/// The threshold is intentionally a named constant so it can be adjusted in
/// one place without a search-and-replace.
const ENTROPY_THRESHOLD: f64 = 3.5;

/// Compute Shannon entropy (bits per character) of `s`.
///
/// Returns 0.0 for an empty string.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f64;
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// A compiled `metavariable-analysis:` constraint.
///
/// Only `analyzer: entropy` is implemented. Other analyzers (including
/// `redos`) are warn-skipped at build time and the constraint is dropped;
/// sibling clauses are unaffected.
#[derive(Debug, Clone)]
pub struct MetavariableAnalysisConstraint {
    metavariable: String,
}

impl MetavariableAnalysisConstraint {
    /// Build from a YAML clause.  Returns `Ok(Some(_))` for `entropy`,
    /// `Ok(None)` (after printing a warning) for `redos` and unknown
    /// analyzers.
    fn from_yaml(clause: &SemgrepMetavariableAnalysisClause) -> Option<Self> {
        match clause.analyzer.as_str() {
            "entropy" => Some(Self {
                metavariable: clause.metavariable.clone(),
            }),
            "redos" => {
                eprintln!(
                    "Warning: metavariable-analysis analyzer 'redos' for {} is not \
                    implemented (no sound cheap heuristic); skipping constraint",
                    clause.metavariable
                );
                None
            }
            other => {
                eprintln!(
                    "Warning: metavariable-analysis analyzer '{}' for {} is unknown; \
                    skipping constraint",
                    other, clause.metavariable
                );
                None
            }
        }
    }

    /// Returns `true` when the bound text has Shannon entropy ≥
    /// [`ENTROPY_THRESHOLD`] bits/char.  Unbound metavariables → `false`.
    fn matches(&self, bindings: &HashMap<String, String>) -> bool {
        let Some(text) = bindings.get(&self.metavariable) else {
            return false;
        };
        shannon_entropy(text) >= ENTROPY_THRESHOLD
    }
}

/// A compiled `metavariable-type:` constraint.
///
/// Constrains the bound metavariable to a declared type. Enforcement is purely
/// **syntactic**: the metavariable must bind to a simple identifier whose
/// declaration (a parameter or a local/field with a written-out type) is
/// resolvable in the surrounding tree-sitter tree of a statically-typed
/// language. When the type cannot be resolved (the binding is a complex
/// expression, or the declaration/type is not syntactically present) the
/// constraint is treated as **unsatisfied** — the candidate is dropped rather
/// than matched, so an unresolvable type never causes an over-match.
///
/// Rules whose language has no syntactic type resolution here are *not loaded*
/// at all (see [`metavariable_type_enforceable`] / `build_matcher`), so a
/// dropped-because-unenforceable constraint can never silently broaden a rule.
#[derive(Debug, Clone)]
pub struct MetavariableTypeConstraint {
    metavariable: String,
    /// The required type, normalized to its simple name (see
    /// [`normalize_type_name`]).
    type_name: String,
    lang: Language,
}

impl MetavariableTypeConstraint {
    /// Build a constraint for an enforceable language. Callers must gate on
    /// [`metavariable_type_enforceable`] first; this only normalizes the type.
    fn from_yaml(clause: &SemgrepMetavariableTypeClause, lang: Language) -> Self {
        Self {
            metavariable: clause.metavariable.clone(),
            type_name: normalize_type_name(&clause.type_name),
            lang,
        }
    }

    /// `true` when the metavariable is bound to a simple identifier whose
    /// resolved declared type (simple name) equals the required type. Any
    /// failure to resolve → `false` (drop the candidate; never over-match).
    fn matches(
        &self,
        root: tree_sitter::Node,
        source: &str,
        bindings: &HashMap<String, String>,
        binding_ranges: &HashMap<String, MetavarRange>,
    ) -> bool {
        let Some(text) = bindings.get(&self.metavariable) else {
            return false;
        };
        let name = text.trim();
        if !is_simple_identifier(name) {
            return false;
        }
        let Some(&(line, col, _, _)) = binding_ranges.get(&self.metavariable) else {
            return false;
        };
        let Some(offset) = position_to_byte_offset(source, line, col) else {
            return false;
        };
        match resolve_declared_type(self.lang, root, source, name, offset) {
            Some(declared) => normalize_type_name(&declared) == self.type_name,
            None => false,
        }
    }
}

/// Whether `metavariable-type:` can be **enforced** for `lang`. Only
/// statically-typed languages whose declarations carry a syntactic type that
/// [`resolve_declared_type`] knows how to read qualify. Rules that use
/// `metavariable-type:` on any other language are skipped by the loader rather
/// than loaded with the constraint dropped (which would over-match).
fn metavariable_type_enforceable(lang: Language) -> bool {
    matches!(
        lang,
        Language::Java
            | Language::CSharp
            | Language::Go
            | Language::Kotlin
            // TypeScript is parsed under `Language::JavaScript` (grammar chosen
            // by file extension). Plain JS has no type annotations, in which
            // case resolution fails and candidates are dropped (safe under-match).
            | Language::JavaScript
    )
}

/// Normalize a declared/required type to its simple name for comparison:
/// strip a leading `:` (TypeScript `type_annotation` text), generic arguments
/// (`List<String>` → `List`), array suffixes (`String[]` → `String`) and any
/// package/namespace qualifier (`java.sql.Statement` → `Statement`).
fn normalize_type_name(raw: &str) -> String {
    let mut s = raw.trim();
    // TypeScript `type_annotation` nodes include the leading colon.
    s = s.trim_start_matches(':').trim();
    // Drop generic type arguments.
    if let Some(idx) = s.find('<') {
        s = s[..idx].trim_end();
    }
    // Drop array/index suffixes.
    if let Some(idx) = s.find('[') {
        s = s[..idx].trim_end();
    }
    // Keep only the final path segment of a qualified name.
    if let Some(idx) = s.rfind(['.', ':']) {
        s = &s[idx + 1..];
    }
    s.trim().to_string()
}

/// A bound metavariable is type-resolvable only when it binds to a plain
/// identifier (not a field access, call, literal, or other expression).
fn is_simple_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    match chars.next() {
        Some(c) if c.is_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_alphanumeric() || c == '_')
}

// ─── Comparison parser ───────────────────────────────────────────────────────

/// Parse a comparison string of the form `$VAR <op> <number>` or
/// `<number> <op> $VAR`.  Returns `Err` with a human-readable message for
/// anything outside that supported subset (caller will warn-skip it).
fn parse_comparison(comparison: &str) -> Result<(String, CmpOp, f64, bool), String> {
    let s = comparison.trim();

    // Try longest operator first to avoid e.g. `<` matching `<=`.
    const OPS: &[(&str, CmpOp)] = &[
        ("<=", CmpOp::Le),
        (">=", CmpOp::Ge),
        ("!=", CmpOp::Ne),
        ("==", CmpOp::Eq),
        ("<", CmpOp::Lt),
        (">", CmpOp::Gt),
    ];

    for (op_str, op) in OPS {
        if let Some(idx) = s.find(op_str) {
            let lhs = s[..idx].trim();
            let rhs = s[idx + op_str.len()..].trim();

            // Figure out which side is the metavar and which is the literal.
            let (metavar, literal_str, literal_is_lhs) = if lhs.starts_with('$') {
                (lhs, rhs, false)
            } else if rhs.starts_with('$') {
                (rhs, lhs, true)
            } else {
                return Err(format!("metavariable-comparison: no metavariable in '{s}'"));
            };

            // Validate the metavar token.
            if metavariable_key(metavar).is_none() {
                return Err(format!(
                    "metavariable-comparison: invalid metavariable token '{metavar}' in '{s}'"
                ));
            }

            // Strip common C integer suffixes (L, UL, LL, etc.) and leading
            // 0x/0b so we can parse as f64.
            let literal_str = strip_numeric_suffixes(literal_str);
            let literal: f64 = parse_numeric(&literal_str).ok_or_else(|| {
                format!(
                    "metavariable-comparison: cannot parse numeric literal '{literal_str}' in '{s}'"
                )
            })?;

            return Ok((metavar.to_string(), op.clone(), literal, literal_is_lhs));
        }
    }

    Err(format!(
        "metavariable-comparison: unsupported comparison expression '{s}'"
    ))
}

/// Strip trailing C-style suffixes (`L`, `U`, `UL`, `LL`, `ULL`, etc.)
/// from an integer-literal string (case-insensitive), so `10L` parses as `10`.
fn strip_numeric_suffixes(s: &str) -> String {
    let upper = s.to_uppercase();
    // Hex/binary literals end in digits that can look like suffixes (e.g. the
    // trailing `F` in `0xFF`), so never strip from them.
    if upper.starts_with("0X") || upper.starts_with("0B") {
        return upper;
    }
    // Strip C-style integer/float suffixes: L/U (int) and F (float, e.g. `3.14f`).
    upper.trim_end_matches(['L', 'U', 'F']).to_string()
}

/// Parse a numeric string (decimal int, hex `0x…`, binary `0b…`, or float)
/// into an `f64`.
fn parse_numeric(s: &str) -> Option<f64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // Hex integer
    if let Some(hex) = s.strip_prefix("0X").or_else(|| s.strip_prefix("0x")) {
        return i64::from_str_radix(hex, 16).ok().map(|v| v as f64);
    }

    // Binary integer
    if let Some(bin) = s.strip_prefix("0B").or_else(|| s.strip_prefix("0b")) {
        return i64::from_str_radix(bin, 2).ok().map(|v| v as f64);
    }

    // Float or decimal integer — let Rust's built-in parser handle it.
    s.parse::<f64>().ok()
}

impl Rule for SemgrepRule {
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

    fn applies_to_path(&self, path: &Path) -> bool {
        self.path_filter
            .as_ref()
            .is_none_or(|filter| filter.matches(path))
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let root = tree.root_node();

        // Collect all matching nodes
        let matches = match_pattern_in_tree(&self.matcher, root, source);

        for matched_node_range in matches {
            let fix_suggestion = self
                .fix_template
                .as_deref()
                .map(|tmpl| apply_fix_template(tmpl, &matched_node_range.bindings));
            findings.push(Finding {
                rule_id: self.id.clone(),
                severity: self.severity,
                cwe: self.cwe.clone(),
                description: self.message.clone(),
                file: String::new(),
                line: matched_node_range.line,
                column: matched_node_range.column,
                end_line: matched_node_range.end_line,
                end_column: matched_node_range.end_column,
                snippet: matched_node_range.snippet,
                source_line: None,
                source_description: None,
                sink_line: None,
                sink_description: None,
                fix_suggestion,
                sink_start_byte: None,
                sink_end_byte: None,
                // External Semgrep rules are inherently fuzzier than
                // curated built-in AST-walked rules. See issue #207.
                confidence: 0.7,
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
            });
        }

        findings
    }
}

impl PathFilter {
    pub(crate) fn from_yaml(paths: Option<&SemgrepPaths>) -> Result<Option<Self>, String> {
        let Some(paths) = paths else {
            return Ok(None);
        };

        let include = compile_globset(&paths.include)?;
        let exclude = compile_globset(&paths.exclude)?;

        Ok(Some(Self { include, exclude }))
    }

    pub(crate) fn matches(&self, path: &Path) -> bool {
        let normalized = normalize_rule_path(path);

        if let Some(include) = &self.include {
            if !include.is_match(&normalized) {
                return false;
            }
        }

        if let Some(exclude) = &self.exclude {
            if exclude.is_match(&normalized) {
                return false;
            }
        }

        true
    }
}

impl MetavariableRegexConstraint {
    /// Build from a YAML clause.
    ///
    /// Returns `Some(_)` on success, `None` (after printing a warning) when the
    /// regex uses features that the Rust `regex` crate does not support
    /// (lookaheads / lookbehinds / `\Z`, etc.).  The caller continues loading
    /// the rest of the rule's clauses — this mirrors the behaviour of
    /// `MetavariableAnalysisConstraint::from_yaml`.
    fn from_yaml(clause: &SemgrepMetavariableRegexClause) -> Option<Self> {
        match compile_regex(&clause.regex) {
            Ok(regex) => Some(Self {
                metavariable: clause.metavariable.clone(),
                regex,
            }),
            Err(e) => {
                eprintln!(
                    "Warning: metavariable-regex for {} uses an unsupported regex ({}); \
                     skipping constraint",
                    clause.metavariable, e
                );
                None
            }
        }
    }

    fn matches(&self, bindings: &HashMap<String, String>) -> bool {
        bindings
            .get(&self.metavariable)
            .is_some_and(|value| self.regex.is_match(value))
    }
}

impl MetavariableComparisonConstraint {
    /// Build a constraint from a parsed YAML clause.
    ///
    /// Returns `Err` (caller should warn-skip) for:
    /// - unsupported expression shapes (no metavar, non-numeric literal, etc.)
    /// - `base:` values other than 10 (warn-skip only the constraint entry)
    fn from_yaml(clause: &SemgrepMetavariableComparisonClause) -> Result<Self, String> {
        // Warn-skip non-base-10 requests — we accept base:10 or absent.
        if let Some(base) = clause.base {
            if base != 10 {
                return Err(format!(
                    "metavariable-comparison: base:{base} is not supported (only base:10); skipping constraint"
                ));
            }
        }

        // Some advanced Semgrep rules use `comparison:` without an explicit
        // `metavariable:` key (e.g. `comparison: str($F1) == str($F2)` with
        // both operands as metavar expressions). The `metavariable` field is
        // optional in the YAML schema (see `SemgrepMetavariableComparisonClause`).
        // Those rules fall outside our supported `$VAR <op> <number>` subset, so
        // we warn-skip the constraint without failing the whole rule load.
        if clause.metavariable.is_none() {
            return Err(format!(
                "metavariable-comparison: no `metavariable:` key in clause '{}'; \
                 the comparison uses an unsupported expression form — skipping constraint",
                clause.comparison
            ));
        }

        let (metavariable, op, literal, literal_is_lhs) = parse_comparison(&clause.comparison)?;

        Ok(Self {
            metavariable,
            op,
            literal,
            literal_is_lhs,
        })
    }

    /// Evaluate the comparison against the bound metavariable.
    ///
    /// Returns `false` (no match) if:
    /// - the metavariable is not bound in `bindings`
    /// - the bound text is not parseable as a number after suffix stripping
    fn matches(&self, bindings: &HashMap<String, String>) -> bool {
        let Some(value_text) = bindings.get(&self.metavariable) else {
            return false;
        };

        // Attempt to parse the bound text as a number.
        let stripped = strip_numeric_suffixes(value_text.trim());
        let Some(value) = parse_numeric(&stripped) else {
            return false;
        };

        // `literal_is_lhs` means the original expression was `literal <op> $VAR`.
        // We flip the operand order so `lhs` and `rhs` are consistent.
        let (lhs, rhs) = if self.literal_is_lhs {
            (self.literal, value)
        } else {
            (value, self.literal)
        };

        match self.op {
            CmpOp::Lt => lhs < rhs,
            CmpOp::Le => lhs <= rhs,
            CmpOp::Gt => lhs > rhs,
            CmpOp::Ge => lhs >= rhs,
            // Exact equality: both operands come from parsing the same kind of
            // numeral, so matching Semgrep's Python exact-`==` semantics (not an
            // epsilon band) is both simpler and more correct.
            CmpOp::Eq => lhs == rhs,
            CmpOp::Ne => lhs != rhs,
        }
    }
}

impl MetavariablePatternConstraint {
    /// Build a `MetavariablePatternConstraint` from a YAML clause.
    ///
    /// Returns `None` (after printing a warning) for unsupported nested shapes
    /// such as nested `patterns:`, `metavariable-pattern:`, or a `language:`
    /// override — consistent with the codebase's graceful-degradation style.
    fn from_yaml(clause: &SemgrepMetavariablePatternClause, lang: Language) -> Option<Self> {
        let sub_matcher = if let Some(ref pat) = clause.pattern {
            PatternMatcher::Single(CompiledAstPattern::new(pat.clone(), lang))
        } else if let Some(ref regex) = clause.pattern_regex {
            match compile_regex(regex) {
                Ok(r) => PatternMatcher::Regex(r),
                Err(e) => {
                    eprintln!(
                        "Warning: metavariable-pattern for {} has invalid pattern-regex: {}; skipping constraint",
                        clause.metavariable, e
                    );
                    return None;
                }
            }
        } else if let Some(ref entries) = clause.pattern_either {
            match build_either_matchers(entries, lang) {
                Ok(matchers) => PatternMatcher::Either(matchers),
                Err(e) => {
                    eprintln!(
                        "Warning: metavariable-pattern for {} has invalid pattern-either: {}; skipping constraint",
                        clause.metavariable, e
                    );
                    return None;
                }
            }
        } else {
            eprintln!(
                "Warning: metavariable-pattern for {} has no supported nested pattern form \
                (pattern, pattern-regex, or pattern-either); skipping constraint",
                clause.metavariable
            );
            return None;
        };

        Some(Self {
            metavariable: clause.metavariable.clone(),
            sub_matcher,
            lang,
        })
    }

    /// Returns `true` when the bound text for `self.metavariable` matches
    /// `self.sub_matcher`. Unparseable binding text is treated as no-match.
    fn matches(&self, bindings: &HashMap<String, String>) -> bool {
        let Some(bound_text) = bindings.get(&self.metavariable) else {
            return false;
        };

        match &self.sub_matcher {
            // For a regex sub-matcher we don't need to re-parse the binding.
            PatternMatcher::Regex(regex) => regex.is_match(bound_text),

            // For AST sub-matchers, re-parse the binding text as a snippet
            // in the rule's language.  If parsing yields no tree we treat
            // it as no-match rather than crashing.
            _ => {
                let Some(tree) = parse_file(bound_text, self.lang) else {
                    return false;
                };
                let root = tree.root_node();
                !match_pattern_in_tree(&self.sub_matcher, root, bound_text).is_empty()
            }
        }
    }
}

impl CompiledAstPattern {
    fn new(source: String, lang: Language) -> Self {
        let source = prepare_pattern_for_grammar(source, lang);
        let tree = parse_file(&source, lang);
        let selector_kind = tree
            .as_ref()
            .and_then(|tree| first_meaningful_node(tree.root_node(), &source))
            .and_then(|node| selector_kind_for_pattern(node, &source));

        Self {
            source,
            tree,
            selector_kind,
        }
    }

    fn pattern_node(&self) -> Option<tree_sitter::Node<'_>> {
        let tree = self.tree.as_ref()?;
        first_meaningful_node(tree.root_node(), &self.source)
    }
}

const GO_ELLIPSIS_PLACEHOLDER: &str = "__foxguard_semgrep_ellipsis";
const GO_METAVAR_PREFIX: &str = "__foxguard_semgrep_meta_";

/// Rewrite/wrap a Semgrep pattern in language-specific boilerplate so the
/// grammar parses it without falling back to misleading `ERROR` nodes.
///
/// Only applied when the bare pattern fails to parse cleanly: this keeps the
/// wrapping conservative and avoids surprising existing patterns that already
/// parse fine (e.g. a full Go function declaration).
fn prepare_pattern_for_grammar(source: String, lang: Language) -> String {
    match lang {
        Language::Go => {
            // If the bare pattern already parses without errors, leave it.
            if let Some(tree) = parse_file(&source, lang) {
                if !tree.root_node().has_error() {
                    return source;
                }
            }

            let source = rewrite_go_semgrep_micro_syntax(&source);
            let package_scoped = format!("package _\n{source}\n");
            if let Some(tree) = parse_file(&package_scoped, lang) {
                if !tree.root_node().has_error() {
                    return package_scoped;
                }
            }

            format!("package _\nfunc _() {{\n{source}\n}}\n")
        }
        _ => source,
    }
}

fn rewrite_go_semgrep_micro_syntax(source: &str) -> String {
    static METAVARS_RE: OnceLock<Regex> = OnceLock::new();
    let metavars = METAVARS_RE
        .get_or_init(|| Regex::new(r"\$([A-Za-z0-9_]+)").expect("valid metavariable regex"));
    let rewritten = metavars
        .replace_all(source, format!("{GO_METAVAR_PREFIX}$1"))
        .to_string()
        .replace("...", GO_ELLIPSIS_PLACEHOLDER);

    static FUNC_ELLIPSIS_RE: OnceLock<Regex> = OnceLock::new();
    let func_ellipsis_params = FUNC_ELLIPSIS_RE.get_or_init(|| {
        Regex::new(&format!(
            r"(func\s+[A-Za-z_][A-Za-z0-9_]*\s*)\(\s*{}\s*\)",
            regex::escape(GO_ELLIPSIS_PLACEHOLDER)
        ))
        .expect("valid Go func ellipsis regex")
    });

    func_ellipsis_params
        .replace_all(&rewritten, "$1()")
        .to_string()
}

// ─── Pattern Matching Engine ────────────────────────────────────────────────

/// Source span for a single metavariable binding: (line, column, end_line, end_column).
/// All values are 1-based, mirroring `MatchRange`.
type MetavarRange = (usize, usize, usize, usize);

#[derive(Debug, Clone)]
struct MatchRange {
    start_byte: usize,
    end_byte: usize,
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
    snippet: String,
    bindings: HashMap<String, String>,
    /// Source range for each bound metavariable: metavar name → (line, col, end_line, end_col).
    binding_ranges: HashMap<String, MetavarRange>,
}

type MatchResult = Vec<MatchRange>;

fn match_pattern_in_tree(
    matcher: &PatternMatcher,
    root: tree_sitter::Node,
    source: &str,
) -> MatchResult {
    match matcher {
        PatternMatcher::Single(pat) => match_single_pattern(pat, root, source),
        PatternMatcher::Regex(regex) => match_regex_pattern(regex, source),
        PatternMatcher::Either(matchers) => {
            let mut results = Vec::new();
            for matcher in matchers {
                results.extend(match_pattern_in_tree(matcher, root, source));
            }
            results.sort_by_key(|r| (r.start_byte, r.end_byte));
            results.dedup_by_key(|r| (r.start_byte, r.end_byte));
            results
        }
        PatternMatcher::Combined {
            positives,
            negatives,
            inside,
            not_inside,
            metavariable_regexes,
            metavariable_comparisons,
            metavariable_patterns,
            metavariable_analyses,
            metavariable_types,
            focus_metavariables,
        } => {
            // If we have an inside pattern, only search within matching contexts
            let search_roots = if let Some(inside_pat) = inside {
                let inside_matches = match_single_pattern(inside_pat, root, source);
                inside_matches
                    .iter()
                    .map(|m| (m.start_byte, m.end_byte))
                    .collect::<Vec<_>>()
            } else {
                vec![]
            };

            let excluded_roots = if let Some(not_inside_pat) = not_inside {
                let excluded_matches = match_single_pattern(not_inside_pat, root, source);
                excluded_matches
                    .iter()
                    .map(|m| (m.start_byte, m.end_byte))
                    .collect::<Vec<_>>()
            } else {
                vec![]
            };

            // Find all positive matches
            let mut candidates: Option<Vec<MatchRange>> = None;
            for pos in positives {
                let matches = match_pattern_in_tree(pos, root, source);
                candidates = Some(match candidates {
                    None => matches,
                    Some(prev) => intersect_match_sets(prev, matches),
                });
            }

            let mut results = candidates.unwrap_or_default();

            // Filter out negative matches
            for neg in negatives {
                let neg_matches = match_negative_pattern(neg, root, source);
                results.retain(|r| !neg_matches.iter().any(|n| ranges_overlap(r, n)));
            }

            // If inside constraint, filter to only matches within those ranges
            if !search_roots.is_empty() {
                results.retain(|r| {
                    search_roots
                        .iter()
                        .any(|(start, end)| r.start_byte >= *start && r.end_byte <= *end)
                });
            }

            if !excluded_roots.is_empty() {
                results.retain(|r| {
                    !excluded_roots
                        .iter()
                        .any(|(start, end)| r.start_byte >= *start && r.end_byte <= *end)
                });
            }

            for constraint in metavariable_regexes {
                results.retain(|r| constraint.matches(&r.bindings));
            }

            for constraint in metavariable_comparisons {
                results.retain(|r| constraint.matches(&r.bindings));
            }

            for constraint in metavariable_patterns {
                results.retain(|r| constraint.matches(&r.bindings));
            }

            for constraint in metavariable_analyses {
                results.retain(|r| constraint.matches(&r.bindings));
            }

            // metavariable-type: keep only candidates whose bound identifier
            // resolves to the required declared type. Unresolvable → dropped.
            for constraint in metavariable_types {
                results
                    .retain(|r| constraint.matches(root, source, &r.bindings, &r.binding_ranges));
            }

            // focus-metavariable: override each result's reported range with the
            // first listed metavariable that is bound. Fall back to the full match
            // range if none of the focus metavars are bound (do not drop the finding).
            if !focus_metavariables.is_empty() {
                for result in &mut results {
                    for fmv in focus_metavariables.iter() {
                        if let Some(&(fline, fcol, fend_line, fend_col)) =
                            result.binding_ranges.get(fmv.as_str())
                        {
                            result.line = fline;
                            result.column = fcol;
                            result.end_line = fend_line;
                            result.end_column = fend_col;
                            // Update snippet to the focused metavar's source line.
                            if let Some(bound_text) = result.bindings.get(fmv.as_str()) {
                                // We derive the byte offset from line/col for snippet lookup.
                                result.snippet = find_source_line_by_line(source, fline)
                                    .unwrap_or_else(|| bound_text.clone());
                            }
                            break;
                        }
                    }
                }
            }

            results
        }
    }
}

/// Match a single pattern string against every node in the tree.
fn match_single_pattern(
    pattern: &CompiledAstPattern,
    root: tree_sitter::Node,
    source: &str,
) -> MatchResult {
    let mut results = Vec::new();

    let Some(pat_node) = pattern.pattern_node() else {
        return results;
    };

    // Walk every node in the target tree and try matching
    walk_and_match(root, source, pat_node, pattern, &mut results);

    results
}

fn match_regex_pattern(regex: &CompiledRegex, source: &str) -> MatchResult {
    regex
        .find_matches(source)
        .into_iter()
        .map(|(start, end)| {
            let (line, column) = byte_offset_to_position(source, start);
            let (end_line, end_column) = byte_offset_to_position(source, end);
            MatchRange {
                start_byte: start,
                end_byte: end,
                line,
                column,
                end_line,
                end_column,
                snippet: get_source_line(source, start),
                bindings: HashMap::new(),
                binding_ranges: HashMap::new(),
            }
        })
        .collect()
}

/// Skip wrapper nodes (module, program, expression_statement) to get the real pattern.
fn first_meaningful_node<'a>(
    node: tree_sitter::Node<'a>,
    _source: &str,
) -> Option<tree_sitter::Node<'a>> {
    let kind = node.kind();

    // These are top-level wrappers that tree-sitter adds
    if kind == "module"
        || kind == "program"
        || kind == "source_file"
        || kind == "script"
        // tree-sitter-clojure-orchard names its top-level wrapper `source`.
        || kind == "source"
    {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            // Skip the synthetic Go prelude that `prepare_pattern_for_grammar`
            // injects (`package _`) so the meaningful pattern node is the
            // user-supplied one. See #390.
            if !child.is_extra() && child.kind() != "package_clause" {
                return first_meaningful_node(child, _source);
            }
        }
        return None;
    }

    // Unwrap the synthetic Go prelude function (`func _() { <pattern> }`)
    // generated by `prepare_pattern_for_grammar`. Identified by its `_` name,
    // so user-supplied function patterns are left alone. See #390.
    if kind == "function_declaration" {
        if let Some(name) = node.child_by_field_name("name") {
            if &_source[name.byte_range()] == "_" {
                if let Some(body) = node.child_by_field_name("body") {
                    let mut cursor = body.walk();
                    let stmts: Vec<_> = body.named_children(&mut cursor).collect();
                    // `func _() { <stmt> }` → drill into the first
                    // statement_list child, then into its first statement.
                    if let Some(first) = stmts.into_iter().next() {
                        if first.kind() == "statement_list" {
                            let mut c2 = first.walk();
                            let inner: Vec<_> = first.named_children(&mut c2).collect();
                            if let Some(stmt) = inner.into_iter().next() {
                                return first_meaningful_node(stmt, _source);
                            }
                        }
                        return first_meaningful_node(first, _source);
                    }
                }
            }
        }
    }

    // expression_statement wraps a bare expression
    if kind == "expression_statement" {
        if let Some(child) = node.child(0) {
            return Some(child);
        }
    }

    Some(node)
}

fn selector_kind_for_pattern(node: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    let text = &source[node.byte_range()];
    let trimmed = text.trim();
    if metavariable_key(trimmed).is_some() || is_ellipsis_pattern(trimmed) {
        return None;
    }

    Some(node.kind().to_string())
}

fn selector_allows_node(selector_kind: Option<&str>, node: tree_sitter::Node<'_>) -> bool {
    match selector_kind {
        None => true,
        Some(kind) => {
            node.kind() == kind
                // Preserve the older wrapper-leniency path in `match_node`;
                // single-child wrappers may still match their child.
                || node.named_child_count() == 1
                || node.child_count() == 1
        }
    }
}

fn walk_and_match(
    node: tree_sitter::Node,
    source: &str,
    pat_node: tree_sitter::Node,
    pattern: &CompiledAstPattern,
    results: &mut MatchResult,
) {
    if selector_allows_node(pattern.selector_kind.as_deref(), node) {
        let mut bindings = HashMap::new();
        let mut binding_ranges: HashMap<String, MetavarRange> = HashMap::new();
        if match_node(
            node,
            source,
            pat_node,
            &pattern.source,
            &mut bindings,
            &mut binding_ranges,
        ) {
            let start = node.start_position();
            let end = node.end_position();
            results.push(MatchRange {
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                line: start.row + 1,
                column: start.column + 1,
                end_line: end.row + 1,
                end_column: end.column + 1,
                snippet: get_source_line(source, node.start_byte()),
                bindings,
                binding_ranges,
            });
            // Don't recurse into children of a matched node to avoid duplicates
            return;
        }
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_and_match(child, source, pat_node, pattern, results);
    }
}

/// Try to match a pattern AST node against a target AST node.
/// Returns true if they match, populating metavariable bindings and their source ranges.
fn match_node(
    target: tree_sitter::Node,
    target_src: &str,
    pattern: tree_sitter::Node,
    pat_src: &str,
    bindings: &mut HashMap<String, String>,
    binding_ranges: &mut HashMap<String, MetavarRange>,
) -> bool {
    let pat_text = &pat_src[pattern.byte_range()];

    // ── Metavariable: $X matches any node ──
    if let Some(metavar) = metavariable_key(pat_text) {
        let target_text = &target_src[target.byte_range()];
        if let Some(existing) = bindings.get(&metavar) {
            return existing == target_text;
        }
        let start = target.start_position();
        let end = target.end_position();
        bindings.insert(metavar.clone(), target_text.to_string());
        binding_ranges.insert(
            metavar,
            (start.row + 1, start.column + 1, end.row + 1, end.column + 1),
        );
        return true;
    }

    // ── Ellipsis: ... matches anything ──
    if is_ellipsis_pattern(pat_text) {
        return true;
    }

    // ── String literal "..." matches any string ──
    if is_any_string_pattern(pat_text) && is_string_node(target, target_src) {
        return true;
    }

    // ── Leaf nodes: compare text directly ──
    if pattern.child_count() == 0 {
        let target_text = &target_src[target.byte_range()];
        return pat_text == target_text;
    }

    // ── Non-leaf: kinds must match (approximately) ──
    // Be lenient: if kinds differ, we still try if the structure matches
    if pattern.kind() != target.kind() {
        // Allow some flexibility for expression wrappers
        if pattern.child_count() == 1 {
            if let Some(pc) = pattern.child(0) {
                return match_node(target, target_src, pc, pat_src, bindings, binding_ranges);
            }
        }
        if target.child_count() == 1 {
            if let Some(tc) = target.child(0) {
                return match_node(tc, target_src, pattern, pat_src, bindings, binding_ranges);
            }
        }
        return false;
    }

    if let Some(pattern_gap) = operator_token(pattern, pat_src) {
        match operator_token(target, target_src) {
            Some(target_gap) if target_gap == pattern_gap => {}
            _ => return false,
        }
    }

    // ── Match children, handling ... ellipsis ──
    let pat_children = named_children(pattern);
    let target_children = named_children(target);

    match_children_with_ellipsis(
        &target_children,
        target_src,
        &pat_children,
        pat_src,
        bindings,
        binding_ranges,
    )
}

fn named_children(node: tree_sitter::Node) -> Vec<tree_sitter::Node> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn operator_token(node: tree_sitter::Node, source: &str) -> Option<String> {
    if !matches!(
        node.kind(),
        "binary_expression" | "binary_operator" | "boolean_operator" | "comparison_operator"
    ) {
        return None;
    }

    let children = named_children(node);
    if children.len() < 2 {
        return None;
    }

    let gap = &source[children[0].end_byte()..children[1].start_byte()];
    let normalized = gap
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '$')
        .collect::<String>();

    (!normalized.is_empty()).then_some(normalized)
}

/// Check if a pattern child sequence at index `pi` represents a split metavariable
/// (e.g., ERROR("$") + identifier("VAR") -> "$VAR").
fn check_split_metavar(
    pat_children: &[tree_sitter::Node],
    pi: usize,
    pat_src: &str,
) -> Option<String> {
    if pi + 1 >= pat_children.len() {
        return None;
    }
    let first = pat_children[pi];
    let second = pat_children[pi + 1];
    let first_text = &pat_src[first.byte_range()];
    let second_text = &pat_src[second.byte_range()];

    // Case 1: ERROR node with "$" followed by identifier
    if first.kind() == "ERROR" && first_text.trim() == "$" && second.kind() == "identifier" {
        let metavar = format!("${}", second_text);
        return Some(metavar);
    }

    // Case 2: ERROR node that contains the full "$VAR" text
    if first.kind() == "ERROR" {
        return metavariable_key(first_text);
    }

    None
}

/// Match pattern children against target children, handling `...` ellipsis.
fn match_children_with_ellipsis(
    target_children: &[tree_sitter::Node],
    target_src: &str,
    pat_children: &[tree_sitter::Node],
    pat_src: &str,
    bindings: &mut HashMap<String, String>,
    binding_ranges: &mut HashMap<String, MetavarRange>,
) -> bool {
    if pat_children.is_empty() {
        return true;
    }

    let mut ti = 0;
    let mut pi = 0;

    while pi < pat_children.len() {
        let pat_child = pat_children[pi];
        let pat_text = &pat_src[pat_child.byte_range()];

        if is_ellipsis_pattern(pat_text) {
            // Ellipsis: skip zero or more target children
            pi += 1;
            if pi >= pat_children.len() {
                // ... at the end matches everything remaining
                return true;
            }
            // Try to find a target child that matches the next pattern child
            let next_pat = pat_children[pi];
            while ti < target_children.len() {
                let mut sub_bindings = bindings.clone();
                let mut sub_ranges = binding_ranges.clone();
                if match_node(
                    target_children[ti],
                    target_src,
                    next_pat,
                    pat_src,
                    &mut sub_bindings,
                    &mut sub_ranges,
                ) {
                    // Continue matching from here
                    *bindings = sub_bindings;
                    *binding_ranges = sub_ranges;
                    pi += 1;
                    ti += 1;
                    break;
                }
                ti += 1;
            }
            if ti > target_children.len() {
                return false;
            }
        } else if let Some(metavar) = check_split_metavar(pat_children, pi, pat_src) {
            // Split metavar: ERROR("$") + identifier("VAR") => treat as $VAR
            if ti >= target_children.len() {
                return false;
            }
            let target_node = target_children[ti];
            let target_text = &target_src[target_node.byte_range()];
            if let Some(existing) = bindings.get(&metavar) {
                if existing != target_text {
                    return false;
                }
            } else {
                let start = target_node.start_position();
                let end = target_node.end_position();
                bindings.insert(metavar.clone(), target_text.to_string());
                binding_ranges.insert(
                    metavar.clone(),
                    (start.row + 1, start.column + 1, end.row + 1, end.column + 1),
                );
            }
            ti += 1;
            // Skip both the ERROR and identifier pattern children
            pi += 2;
        } else if pat_child.kind() == "ERROR" && pat_src[pat_child.byte_range()].trim() == "$" {
            // Lone ERROR "$" without following identifier -- skip it
            pi += 1;
        } else {
            if ti >= target_children.len() {
                return false;
            }
            if !match_node(
                target_children[ti],
                target_src,
                pat_child,
                pat_src,
                bindings,
                binding_ranges,
            ) {
                return false;
            }
            ti += 1;
            pi += 1;
        }
    }

    true
}

/// Check if text looks like a Semgrep metavariable: $VAR, $X, $DB, etc.
#[cfg(test)]
fn is_metavar(text: &str) -> bool {
    metavariable_key(text).is_some()
}

/// Substitute bound metavariable values into a Semgrep `fix:` template.
///
/// Tokens of the form `$NAME` (where `NAME` is one or more ASCII alphanumeric
/// or underscore characters) are replaced with the text bound to that
/// metavariable.  Unbound tokens are left literal.  The replacement is applied
/// longest-match-first so that e.g. `$FOOBAR` is not split into `$FOO` + `BAR`.
fn apply_fix_template(template: &str, bindings: &HashMap<String, String>) -> String {
    static METAVAR_RE: OnceLock<Regex> = OnceLock::new();
    let re = METAVAR_RE.get_or_init(|| {
        Regex::new(r"\$[A-Za-z0-9_]+").expect("valid metavariable regex for fix template")
    });
    re.replace_all(template, |caps: &regex::Captures<'_>| -> String {
        let token = caps.get(0).map_or("", |m| m.as_str());
        bindings
            .get(token)
            .cloned()
            .unwrap_or_else(|| token.to_string())
    })
    .into_owned()
}

fn metavariable_key(text: &str) -> Option<String> {
    let t = text.trim();
    if t.starts_with('$')
        && t.len() > 1
        && t[1..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Some(t.to_string());
    }

    t.strip_prefix(GO_METAVAR_PREFIX)
        .filter(|name| {
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
        .map(|name| format!("${name}"))
}

fn is_ellipsis_pattern(text: &str) -> bool {
    matches!(text.trim(), "..." | GO_ELLIPSIS_PLACEHOLDER)
}

// ─── metavariable-type resolution ────────────────────────────────────────────

/// Convert a 1-based (line, byte-column) position — as stored in a
/// [`MetavarRange`] — back to a byte offset into `source`. Inverse of
/// [`byte_offset_to_position`] (columns are byte offsets within the line).
fn position_to_byte_offset(source: &str, line: usize, col: usize) -> Option<usize> {
    let mut idx = 0usize;
    for (current_line, l) in (1usize..).zip(source.split_inclusive('\n')) {
        if current_line == line {
            let off = idx + col.saturating_sub(1);
            return Some(off.min(source.len()));
        }
        idx += l.len();
    }
    None
}

/// Tree-sitter node kinds that introduce a lexical scope, used to bound where a
/// declaration is visible. Union across the supported statically-typed grammars.
const SCOPE_KINDS: &[&str] = &[
    // shared / block-like
    "block",
    "statement_block",
    "function_body",
    "constructor_body",
    "class_body",
    "declaration_list",
    "statements",
    "switch_block",
    "program",
    "source_file",
    "compilation_unit",
    // parameter-bearing declarations (so params are visible in their body)
    "method_declaration",
    "constructor_declaration",
    "function_declaration",
    "local_function_statement",
    "lambda_expression",
    // self-scoping statements whose header declares a variable
    "for_statement",
    "enhanced_for_statement",
    "for_each_statement",
    "catch_clause",
];

/// Byte range of the nearest enclosing scope for a declaration node. Falls back
/// to the whole file when no scope ancestor is found.
fn scope_range_for_decl(node: tree_sitter::Node) -> (usize, usize) {
    let mut n = node;
    while let Some(parent) = n.parent() {
        if SCOPE_KINDS.contains(&parent.kind()) {
            return (parent.start_byte(), parent.end_byte());
        }
        n = parent;
    }
    (0, usize::MAX)
}

/// Text of a type node, or `None` if absent/empty.
fn type_node_text<'a>(node: Option<tree_sitter::Node>, source: &'a str) -> Option<&'a str> {
    let n = node?;
    let text = &source[n.byte_range()];
    (!text.trim().is_empty()).then_some(text)
}

/// First child of `node` (recursively, breadth-first over direct children) whose
/// kind is `kind`.
fn find_child_of_kind<'a>(
    node: tree_sitter::Node<'a>,
    kind: &str,
) -> Option<tree_sitter::Node<'a>> {
    let mut cursor = node.walk();
    let found = node.children(&mut cursor).find(|c| c.kind() == kind);
    found
}

/// If `node` declares a variable/parameter named `name`, return its declared
/// type text together with the byte range over which the declaration is in
/// scope. Purely syntactic, per statically-typed grammar.
fn decl_type_for<'a>(
    lang: Language,
    node: tree_sitter::Node<'a>,
    source: &'a str,
    name: &str,
) -> Option<(&'a str, (usize, usize))> {
    let name_matches = |n: Option<tree_sitter::Node>| -> bool {
        n.map(|n| &source[n.byte_range()] == name).unwrap_or(false)
    };

    match lang {
        Language::Java => match node.kind() {
            "formal_parameter" | "spread_parameter" => {
                if name_matches(node.child_by_field_name("name")) {
                    let ty = type_node_text(node.child_by_field_name("type"), source)?;
                    return Some((ty, scope_range_for_decl(node)));
                }
                None
            }
            "catch_formal_parameter" => {
                if name_matches(node.child_by_field_name("name")) {
                    let ct = find_child_of_kind(node, "catch_type")?;
                    let ty = type_node_text(Some(ct), source)?;
                    return Some((ty, scope_range_for_decl(node)));
                }
                None
            }
            "enhanced_for_statement" => {
                if name_matches(node.child_by_field_name("name")) {
                    let ty = type_node_text(node.child_by_field_name("type"), source)?;
                    // Scope is the loop itself (header + body).
                    return Some((ty, (node.start_byte(), node.end_byte())));
                }
                None
            }
            "local_variable_declaration" | "field_declaration" => {
                let ty = type_node_text(node.child_by_field_name("type"), source)?;
                let mut cursor = node.walk();
                for declarator in node.children(&mut cursor) {
                    if declarator.kind() == "variable_declarator"
                        && name_matches(declarator.child_by_field_name("name"))
                    {
                        return Some((ty, scope_range_for_decl(node)));
                    }
                }
                None
            }
            _ => None,
        },
        Language::CSharp => match node.kind() {
            "parameter" => {
                if name_matches(node.child_by_field_name("name")) {
                    let ty = type_node_text(node.child_by_field_name("type"), source)?;
                    return Some((ty, scope_range_for_decl(node)));
                }
                None
            }
            "variable_declaration" => {
                let ty = type_node_text(node.child_by_field_name("type"), source)?;
                let mut cursor = node.walk();
                for declarator in node.children(&mut cursor) {
                    if declarator.kind() == "variable_declarator"
                        && name_matches(declarator.child_by_field_name("name"))
                    {
                        return Some((ty, scope_range_for_decl(node)));
                    }
                }
                None
            }
            _ => None,
        },
        Language::Go => match node.kind() {
            "parameter_declaration" => {
                if name_matches(node.child_by_field_name("name")) {
                    let ty = type_node_text(node.child_by_field_name("type"), source)?;
                    return Some((ty, scope_range_for_decl(node)));
                }
                None
            }
            "var_spec" | "const_spec" => {
                if name_matches(node.child_by_field_name("name")) {
                    let ty = type_node_text(node.child_by_field_name("type"), source)?;
                    return Some((ty, scope_range_for_decl(node)));
                }
                None
            }
            _ => None,
        },
        Language::Kotlin => match node.kind() {
            // Function value parameters and `val`/`var` bindings share the
            // `simple_identifier : user_type` shape (no field names).
            "parameter" | "variable_declaration" => {
                let ident = find_child_of_kind(node, "simple_identifier")?;
                if &source[ident.byte_range()] != name {
                    return None;
                }
                let ty = type_node_text(find_child_of_kind(node, "user_type"), source)?;
                Some((ty, scope_range_for_decl(node)))
            }
            _ => None,
        },
        // TypeScript (parsed under Language::JavaScript with the TS grammar).
        Language::JavaScript => match node.kind() {
            "required_parameter" | "optional_parameter" => {
                if name_matches(node.child_by_field_name("pattern")) {
                    let ty = type_node_text(node.child_by_field_name("type"), source)?;
                    return Some((ty, scope_range_for_decl(node)));
                }
                None
            }
            "variable_declarator" => {
                if name_matches(node.child_by_field_name("name")) {
                    let ty = type_node_text(node.child_by_field_name("type"), source)?;
                    return Some((ty, scope_range_for_decl(node)));
                }
                None
            }
            _ => None,
        },
        _ => None,
    }
}

/// Resolve the declared type (raw text) of the identifier `name` used at byte
/// `offset`, picking the innermost in-scope declaration. `None` when no
/// syntactic declaration is found.
fn resolve_declared_type(
    lang: Language,
    root: tree_sitter::Node,
    source: &str,
    name: &str,
    offset: usize,
) -> Option<String> {
    let mut best: Option<(usize, String)> = None;
    collect_declared_type(lang, root, source, name, offset, &mut best);
    best.map(|(_, ty)| ty)
}

fn collect_declared_type(
    lang: Language,
    node: tree_sitter::Node,
    source: &str,
    name: &str,
    offset: usize,
    best: &mut Option<(usize, String)>,
) {
    if let Some((ty, (scope_start, scope_end))) = decl_type_for(lang, node, source, name) {
        if offset >= scope_start && offset < scope_end {
            // Prefer the innermost scope (largest start byte).
            if best
                .as_ref()
                .map(|(s, _)| scope_start >= *s)
                .unwrap_or(true)
            {
                *best = Some((scope_start, ty.to_string()));
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_declared_type(lang, child, source, name, offset, best);
    }
}

/// Check if the pattern text is the special "..." (match-any-string) string literal.
fn is_any_string_pattern(text: &str) -> bool {
    let t = text.trim();
    t == "\"...\"" || t == "'...'"
}

/// Check if a target node is a string literal.
fn is_string_node(node: tree_sitter::Node, _source: &str) -> bool {
    matches!(
        node.kind(),
        "string"
            | "string_literal"
            | "interpreted_string_literal"
            | "raw_string_literal"
            | "template_string"
    )
}

fn byte_offset_to_position(source: &str, byte_offset: usize) -> (usize, usize) {
    let prefix = &source[..byte_offset];
    let line = prefix.bytes().filter(|b| *b == b'\n').count() + 1;
    let line_start = prefix.rfind('\n').map_or(0, |pos| pos + 1);
    let column = byte_offset - line_start + 1;
    (line, column)
}

/// Return the source text for a given 1-based line number, trimming the trailing newline.
/// Returns `None` if the line number is out of range.
fn find_source_line_by_line(source: &str, line: usize) -> Option<String> {
    source
        .lines()
        .nth(line.saturating_sub(1))
        .map(|s| s.to_string())
}

fn ranges_overlap(left: &MatchRange, right: &MatchRange) -> bool {
    left.start_byte < right.end_byte && right.start_byte < left.end_byte
}

fn merge_bindings(
    left: &HashMap<String, String>,
    right: &HashMap<String, String>,
) -> Option<HashMap<String, String>> {
    let mut merged = left.clone();

    for (key, value) in right {
        if let Some(existing) = merged.get(key) {
            if existing != value {
                return None;
            }
        } else {
            merged.insert(key.clone(), value.clone());
        }
    }

    Some(merged)
}

fn merge_binding_ranges(
    left: &HashMap<String, MetavarRange>,
    right: &HashMap<String, MetavarRange>,
) -> HashMap<String, MetavarRange> {
    let mut merged = left.clone();
    for (key, value) in right {
        merged.entry(key.clone()).or_insert(*value);
    }
    merged
}

fn intersect_match_sets(left: Vec<MatchRange>, right: Vec<MatchRange>) -> Vec<MatchRange> {
    let mut merged = Vec::new();

    for left_match in left {
        for right_match in &right {
            if !ranges_overlap(&left_match, right_match) {
                continue;
            }

            let Some(bindings) = merge_bindings(&left_match.bindings, &right_match.bindings) else {
                continue;
            };

            let binding_ranges =
                merge_binding_ranges(&left_match.binding_ranges, &right_match.binding_ranges);

            let mut combined = left_match.clone();
            combined.bindings = bindings;
            combined.binding_ranges = binding_ranges;
            merged.push(combined);
        }
    }

    merged.sort_by_key(|r| (r.start_byte, r.end_byte));
    merged.dedup_by_key(|r| (r.start_byte, r.end_byte));
    merged
}

fn match_negative_pattern(
    negative: &NegativeMatcher,
    root: tree_sitter::Node,
    source: &str,
) -> MatchResult {
    match negative {
        NegativeMatcher::Pattern(pattern) => match_single_pattern(pattern, root, source),
        NegativeMatcher::Regex(regex) => match_regex_pattern(regex, source),
    }
}

// ─── File Loading ───────────────────────────────────────────────────────────

fn map_severity(s: &SemgrepSeverity) -> Severity {
    match s {
        SemgrepSeverity::Error => Severity::Critical,
        SemgrepSeverity::Warning => Severity::High,
        // `MEDIUM` is used by some Semgrep registry packs (e.g. supply-chain rules).
        // Map to `High` to preserve the intent of "non-trivial risk"; foxguard
        // does not have a dedicated Medium->Medium mapping in its severity enum.
        SemgrepSeverity::Medium => Severity::High,
        SemgrepSeverity::Info => Severity::Medium,
    }
}

fn map_language(lang_str: &str) -> Option<Language> {
    match lang_str.to_lowercase().as_str() {
        "javascript" | "js" | "typescript" | "ts" | "jsx" | "tsx" => Some(Language::JavaScript),
        "python" | "py" => Some(Language::Python),
        "go" | "golang" => Some(Language::Go),
        "ruby" | "rb" => Some(Language::Ruby),
        "java" => Some(Language::Java),
        "php" => Some(Language::Php),
        "rust" | "rs" => Some(Language::Rust),
        "csharp" | "c#" | "cs" => Some(Language::CSharp),
        "swift" => Some(Language::Swift),
        "kotlin" | "kt" => Some(Language::Kotlin),
        "c" => Some(Language::C),
        "hcl" | "terraform" | "tf" => Some(Language::Hcl),
        "solidity" | "sol" => Some(Language::Solidity),
        "yaml" | "yml" => Some(Language::Yaml),
        "dockerfile" | "docker" => Some(Language::Dockerfile),
        "bash" | "sh" => Some(Language::Bash),
        "ocaml" | "ml" | "mli" => Some(Language::Ocaml),
        "scala" | "sc" => Some(Language::Scala),
        "elixir" | "ex" | "exs" => Some(Language::Elixir),
        "json" => Some(Language::Json),
        "apex" => Some(Language::Apex),
        "clojure" | "clj" | "cljs" | "cljc" => Some(Language::Clojure),
        "html" | "htm" => Some(Language::Html),
        "xml" => Some(Language::Xml),
        "dart" => Some(Language::Dart),
        "haskell" | "hs" => Some(Language::Haskell),
        _ => None,
    }
}

/// True when a rule's `languages` selects generic (spacegrep) matching.
/// Generic rules are AST-less and handled by [`crate::rules::generic_mode`].
///
/// Note: `languages: [regex]` is *not* generic mode — it is a distinct Semgrep
/// mode that runs pure `pattern-regex` against raw file bytes.  Those rules are
/// routed to [`build_regex_mode_rules`] instead.
fn is_generic_language_rule(languages: &[String]) -> bool {
    languages.iter().any(|l| l.to_lowercase() == "generic")
}

/// True when a rule targets Semgrep's pure-regex mode (`languages: [regex]`).
///
/// Regex-mode rules only support `pattern-regex` and `pattern-not-regex`; they
/// do not use a tree-sitter AST and are run against raw text on every file that
/// passes the rule's `paths:` filter.
fn is_regex_language_rule(languages: &[String]) -> bool {
    languages.iter().any(|l| l.to_lowercase() == "regex")
}

// ─── Regex-mode Rule ─────────────────────────────────────────────────────────

/// Every language the scanner can hand to a rule. A regex-mode rule is
/// language-agnostic and runs against every file's raw text, so we register one
/// rule instance per detectable language (fan-out mirrors the generic-mode
/// approach). The compiled matcher is shared via `Arc`, so the fan-out is cheap.
const REGEX_MODE_ALL_LANGUAGES: &[Language] = &[
    Language::JavaScript,
    Language::Python,
    Language::Go,
    Language::Ruby,
    Language::Java,
    Language::Php,
    Language::Rust,
    Language::CSharp,
    Language::Swift,
    Language::Kotlin,
    Language::C,
    Language::Hcl,
    Language::Solidity,
    Language::Yaml,
    Language::NginxConf,
    Language::ApacheConf,
    Language::HAProxyConf,
    Language::Dockerfile,
    Language::Manifest,
    Language::Bash,
    Language::Ocaml,
    Language::Scala,
    Language::Elixir,
    Language::Json,
    Language::Apex,
    Language::Clojure,
    Language::Html,
    Language::Xml,
    Language::Dart,
    Language::Haskell,
];

/// A compiled Semgrep `languages: [regex]` rule.
///
/// Regex-mode rules carry only `pattern-regex` / `pattern-not-regex` matchers
/// and are run against the raw text of every scanned file (no tree-sitter parse
/// required).  One rule instance is created per detectable language so the
/// existing `rule.language() == file_language` dispatch continues to work.
struct RegexModeRule {
    id: String,
    message: String,
    severity: Severity,
    cwe: Option<String>,
    /// Language this instance is registered under.
    lang: Language,
    /// The positive regex(es) — all must match at least once (AND semantics when
    /// multiple are present, matching Semgrep's `patterns:` AND-block behaviour).
    positives: std::sync::Arc<Vec<CompiledRegex>>,
    /// Negative regexes — if any match the entire file, the finding is suppressed.
    negatives: std::sync::Arc<Vec<CompiledRegex>>,
    path_filter: Option<std::sync::Arc<PathFilter>>,
}

impl Rule for RegexModeRule {
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
    fn applies_to_path(&self, path: &Path) -> bool {
        self.path_filter
            .as_ref()
            .is_none_or(|filter| filter.matches(path))
    }

    fn check(&self, source: &str, _tree: &tree_sitter::Tree) -> Vec<Finding> {
        // Run the positive regexes in intersection: each positive must produce
        // at least one match.  If any positive misses, the rule doesn't fire.
        let candidates: Option<Vec<MatchRange>> =
            self.positives
                .iter()
                .fold(None, |acc: Option<Vec<MatchRange>>, re| {
                    let hits: Vec<MatchRange> = match_regex_pattern(re, source);
                    Some(match acc {
                        None => hits,
                        Some(prev) => {
                            // Intersect: keep matches from `prev` that overlap with
                            // at least one match from `hits` (AND semantics across
                            // patterns: clauses, mirroring the AST Combined path).
                            prev.into_iter()
                                .filter(|p| {
                                    hits.iter().any(|h| {
                                        p.start_byte < h.end_byte && h.start_byte < p.end_byte
                                    })
                                })
                                .collect()
                        }
                    })
                });

        let mut results = candidates.unwrap_or_default();
        if results.is_empty() {
            return Vec::new();
        }

        // Apply negative filters: drop any positive match that overlaps with a
        // negative regex match anywhere in the file.
        for neg in self.negatives.iter() {
            let neg_hits: Vec<MatchRange> = match_regex_pattern(neg, source);
            if !neg_hits.is_empty() {
                results.retain(|r| {
                    !neg_hits
                        .iter()
                        .any(|n| r.start_byte < n.end_byte && n.start_byte < r.end_byte)
                });
            }
        }

        results
            .into_iter()
            .map(|m| Finding {
                rule_id: self.id.clone(),
                severity: self.severity,
                cwe: self.cwe.clone(),
                description: self.message.clone(),
                file: String::new(),
                line: m.line,
                column: m.column,
                end_line: m.end_line,
                end_column: m.end_column,
                snippet: m.snippet,
                source_line: None,
                source_description: None,
                sink_line: None,
                sink_description: None,
                fix_suggestion: None,
                sink_start_byte: None,
                sink_end_byte: None,
                confidence: 0.7,
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
            })
            .collect()
    }
}

/// Compile a `languages: [regex]` rule into one [`RegexModeRule`] per
/// detectable language. Warns and returns an empty vec for rules that carry
/// only AST patterns (no `pattern-regex` anywhere).
fn build_regex_mode_rules(
    yaml: &SemgrepRuleYaml,
    severity: Severity,
    cwe: &Option<String>,
    path_filter: &Option<PathFilter>,
) -> Result<Vec<Box<dyn Rule>>, String> {
    // Collect all pattern-regex clauses from top-level AND from patterns: blocks.
    let mut positives: Vec<CompiledRegex> = Vec::new();
    let mut negatives: Vec<CompiledRegex> = Vec::new();

    // Helper: push a compiled regex or warn-skip if unsupported features are used.
    // Consistent with MetavariableRegexConstraint::from_yaml graceful degradation.
    macro_rules! push_regex {
        ($dest:expr, $re:expr, $label:expr) => {
            match compile_regex($re) {
                Ok(r) => $dest.push(r),
                Err(e) => eprintln!(
                    "Warning: regex-mode rule '{}' {} has unsupported regex ({}); \
                     skipping clause",
                    yaml.id, $label, e
                ),
            }
        };
    }

    // Top-level pattern-regex / pattern-not-regex.
    if let Some(ref re) = yaml.pattern_regex {
        push_regex!(positives, re, "pattern-regex");
    }
    if let Some(ref re) = yaml.pattern_not_regex {
        push_regex!(negatives, re, "pattern-not-regex");
    }

    // patterns: [...] blocks — collect pattern-regex / pattern-not-regex subclauses.
    if let Some(ref clauses) = yaml.patterns {
        for clause in clauses {
            if let Some(ref re) = clause.pattern_regex {
                push_regex!(positives, re, "patterns[].pattern-regex");
            }
            if let Some(ref re) = clause.pattern_not_regex {
                push_regex!(negatives, re, "patterns[].pattern-not-regex");
            }
            // Nested pattern-either entries may also carry pattern-regex.
            if let Some(ref entries) = clause.pattern_either {
                for entry in entries {
                    if let Some(ref re) = entry.pattern_regex {
                        push_regex!(positives, re, "patterns[].pattern-either[].pattern-regex");
                    }
                }
            }
        }
    }

    // Top-level pattern-either regex entries.
    if let Some(ref entries) = yaml.pattern_either {
        for entry in entries {
            if let Some(ref re) = entry.pattern_regex {
                push_regex!(positives, re, "pattern-either[].pattern-regex");
            }
        }
    }

    if positives.is_empty() {
        // Rule has no regex patterns at all (only AST patterns that regex mode
        // cannot execute). Warn-skip rather than build a no-op matcher.
        eprintln!(
            "Warning: languages: [regex] rule '{}' has no pattern-regex; \
             regex mode cannot run AST patterns — skipping",
            yaml.id
        );
        return Ok(Vec::new());
    }

    let positives = std::sync::Arc::new(positives);
    let negatives = std::sync::Arc::new(negatives);
    let path_filter = path_filter.clone().map(std::sync::Arc::new);

    let rules = REGEX_MODE_ALL_LANGUAGES
        .iter()
        .map(|&lang| {
            Box::new(RegexModeRule {
                id: format!("semgrep/{}", yaml.id),
                message: yaml.message.clone(),
                severity,
                cwe: cwe.clone(),
                lang,
                positives: std::sync::Arc::clone(&positives),
                negatives: std::sync::Arc::clone(&negatives),
                path_filter: path_filter.clone(),
            }) as Box<dyn Rule>
        })
        .collect();

    Ok(rules)
}

/// Compile a generic-mode rule via [`crate::rules::generic_mode`]. Thin
/// adapter: pulls the supported generic-mode fields off the YAML and delegates
/// all matching logic to that module.
///
/// Mapping from YAML → [`GenericRuleSpec`]:
/// - Top-level `pattern` / `pattern-regex` / `pattern-either` / `pattern-not` /
///   `pattern-not-regex` are forwarded as-is.
/// - `patterns:` AND-blocks are mapped clause-by-clause into
///   [`GenericPatternsClause`] structs; unsupported sub-clauses (e.g.
///   `pattern-inside`, `metavariable-*`) are warn-skipped without aborting
///   the rest of the rule.
fn build_generic_mode_rules(
    yaml: &SemgrepRuleYaml,
    severity: Severity,
    cwe: &Option<String>,
    path_filter: &Option<PathFilter>,
) -> Result<Vec<Box<dyn Rule>>, String> {
    use crate::rules::generic_mode::{
        build_generic_rules, GenericEitherEntry, GenericPatternsClause, GenericRuleSpec,
    };

    // Map one `patterns:` clause into a generic clause, preserving the
    // metavariable constraints + focus that operate over named regex captures.
    // Returns `None` for clauses with no expressible content (pattern-inside /
    // pattern-not-inside / empty) so they are warn-skipped without aborting.
    //
    // `strict` is set for clauses inside a `pattern-either` arm that is a nested
    // `patterns:` AND-block (the new package-manager rule shape). In strict mode,
    // a clause carrying an unenforceable constraint (metavariable-pattern /
    // metavariable-analysis) flags the block as unbuildable so the arm is
    // warn-skipped rather than loaded broadened. For top-level `patterns:`
    // blocks (`strict == false`) we preserve the established
    // load-with-dropped-constraint behaviour to avoid regressing rules that
    // already loaded that way.
    fn map_clause(
        clause: &PatternClause,
        rule_id: &str,
        strict: bool,
    ) -> Option<GenericPatternsClause> {
        if clause.pattern_inside.is_some() {
            eprintln!(
                "Warning: generic mode does not support pattern-inside in rule '{rule_id}'; \
                 skipping clause"
            );
            return None;
        }
        if clause.pattern_not_inside.is_some() {
            eprintln!(
                "Warning: generic mode does not support pattern-not-inside in rule '{rule_id}'; \
                 skipping clause"
            );
            return None;
        }
        let pattern_either_entries: Vec<GenericEitherEntry> = clause
            .pattern_either
            .iter()
            .flatten()
            .map(map_either_arm)
            .collect();

        let metavariable_regex = clause
            .metavariable_regex
            .as_ref()
            .map(|mr| (mr.metavariable.clone(), mr.regex.clone()));
        let metavariable_comparison = clause
            .metavariable_comparison
            .as_ref()
            .map(|mc| (mc.metavariable.clone(), mc.comparison.clone()));
        let focus_metavariable = clause
            .focus_metavariable
            .clone()
            .and_then(|f| f.into_vec().into_iter().next());

        // metavariable-pattern / metavariable-analysis cannot be enforced in
        // generic mode. In strict mode (a `pattern-either` arm), flag the clause
        // so its `patterns:` block refuses to load — dropping the constraint
        // would broaden the rule into false positives. In lenient mode
        // (top-level `patterns:`), keep the legacy load-broadened behaviour.
        let unsupported_constraint = strict
            && (clause.metavariable_pattern.is_some() || clause.metavariable_analysis.is_some());

        let has_positive = clause.pattern.is_some()
            || clause.pattern_regex.is_some()
            || !pattern_either_entries.is_empty();
        let has_negative = clause.pattern_not.is_some() || clause.pattern_not_regex.is_some();
        let has_constraint = metavariable_regex.is_some()
            || metavariable_comparison.is_some()
            || focus_metavariable.is_some()
            || unsupported_constraint;

        if !has_positive && !has_negative && !has_constraint {
            return None;
        }

        Some(GenericPatternsClause {
            pattern: clause.pattern.clone(),
            pattern_regex: clause.pattern_regex.clone(),
            pattern_either: pattern_either_entries,
            pattern_not: clause.pattern_not.clone(),
            pattern_not_regex: clause.pattern_not_regex.clone(),
            metavariable_regex,
            metavariable_comparison,
            focus_metavariable,
            unsupported_constraint,
        })
    }

    // Map one `pattern-either` arm. An arm is either a simple pattern/regex or a
    // nested `patterns:` AND-block (the package-manager rule shape).
    fn map_either_arm(entry: &PatternEntry) -> GenericEitherEntry {
        // Decode the raw `patterns:` value into typed clauses leniently. If it
        // does not fit our `PatternClause` shape (e.g. an AST-only nested form),
        // we simply skip it — the arm degrades to its `pattern`/`pattern-regex`
        // (usually empty), which the generic builder warn-skips.
        let patterns = entry
            .patterns
            .as_ref()
            .and_then(|v| serde_yaml_ng::from_value::<Vec<PatternClause>>(v.clone()).ok())
            .unwrap_or_default()
            .iter()
            .filter_map(|c| map_clause(c, "<pattern-either arm>", true))
            .collect();
        GenericEitherEntry {
            pattern: entry.pattern.clone(),
            pattern_regex: entry.pattern_regex.clone(),
            patterns,
        }
    }

    // Top-level pattern-either: simple `pattern:` / `pattern-regex:` arms and
    // nested `patterns:` AND-block arms are all forwarded.
    let pattern_either: Vec<GenericEitherEntry> = yaml
        .pattern_either
        .iter()
        .flatten()
        .map(map_either_arm)
        .collect();

    // Map top-level `patterns:` clauses.
    let patterns_clauses: Vec<GenericPatternsClause> = yaml
        .patterns
        .iter()
        .flatten()
        .filter_map(|clause| map_clause(clause, &yaml.id, false))
        .collect();

    build_generic_rules(GenericRuleSpec {
        id: &yaml.id,
        message: &yaml.message,
        severity,
        cwe: cwe.clone(),
        pattern: yaml.pattern.as_deref(),
        pattern_regex: yaml.pattern_regex.as_deref(),
        pattern_either,
        pattern_not: yaml.pattern_not.as_deref(),
        pattern_not_regex: yaml.pattern_not_regex.as_deref(),
        patterns_clauses,
        path_filter: path_filter.clone(),
    })
}

fn build_matcher(yaml: &SemgrepRuleYaml, lang: Language) -> Result<PatternMatcher, String> {
    // Combined patterns (AND)
    if let Some(ref clauses) = yaml.patterns {
        let mut positives = Vec::new();
        let mut negatives = Vec::new();
        let mut inside = None;
        let mut not_inside = None;
        let mut metavariable_regexes = Vec::new();
        let mut metavariable_comparisons = Vec::new();
        let mut metavariable_patterns = Vec::new();
        let mut metavariable_analyses = Vec::new();
        let mut metavariable_types = Vec::new();
        let mut focus_metavariables: Vec<String> = Vec::new();

        for clause in clauses {
            if let Some(ref p) = clause.pattern {
                positives.push(PatternMatcher::Single(CompiledAstPattern::new(
                    p.clone(),
                    lang,
                )));
            }
            if let Some(ref regex) = clause.pattern_regex {
                // Gracefully skip individual pattern-regex clauses that use
                // unsupported features (lookahead/lookbehind, backreferences,
                // etc.) — consistent with MetavariableRegexConstraint::from_yaml.
                // The sibling clauses are unaffected; the rule loads with a
                // broader but functional matcher.
                match compile_regex(regex) {
                    Ok(r) => positives.push(PatternMatcher::Regex(r)),
                    Err(e) => eprintln!(
                        "Warning: patterns: clause has unsupported pattern-regex ({}); \
                         skipping clause",
                        e
                    ),
                }
            }
            if let Some(ref pn) = clause.pattern_not {
                negatives.push(NegativeMatcher::Pattern(CompiledAstPattern::new(
                    pn.clone(),
                    lang,
                )));
            }
            if let Some(ref regex) = clause.pattern_not_regex {
                // Gracefully skip unsupported negative-regex clauses too.
                match compile_regex(regex) {
                    Ok(r) => negatives.push(NegativeMatcher::Regex(r)),
                    Err(e) => eprintln!(
                        "Warning: patterns: clause has unsupported pattern-not-regex ({}); \
                         skipping clause",
                        e
                    ),
                }
            }
            if let Some(ref pi) = clause.pattern_inside {
                inside = Some(CompiledAstPattern::new(pi.clone(), lang));
            }
            if let Some(pni) = clause.pattern_not_inside.clone() {
                if let Some(pat_str) = pni.into_pattern_string() {
                    not_inside = Some(CompiledAstPattern::new(pat_str, lang));
                }
                // If into_pattern_string returns None it already printed a warning;
                // the constraint is gracefully skipped.
            }
            if let Some(ref pe) = clause.pattern_either {
                let matchers = build_either_matchers(pe, lang)?;
                positives.push(PatternMatcher::Either(matchers));
            }
            if let Some(ref mr) = clause.metavariable_regex {
                if let Some(constraint) = MetavariableRegexConstraint::from_yaml(mr) {
                    metavariable_regexes.push(constraint);
                }
                // If from_yaml returns None it already printed a warning; we
                // continue loading the rest of the rule's clauses.
            }
            if let Some(ref mc) = clause.metavariable_comparison {
                match MetavariableComparisonConstraint::from_yaml(mc) {
                    Ok(constraint) => metavariable_comparisons.push(constraint),
                    Err(e) => eprintln!("Warning: {e}"),
                }
            }
            if let Some(ref mp) = clause.metavariable_pattern {
                if let Some(constraint) = MetavariablePatternConstraint::from_yaml(mp, lang) {
                    metavariable_patterns.push(constraint);
                }
                // If from_yaml returns None it already printed a warning; we
                // continue loading the rest of the rule's clauses.
            }
            if let Some(ref ma) = clause.metavariable_analysis {
                if let Some(constraint) = MetavariableAnalysisConstraint::from_yaml(ma) {
                    metavariable_analyses.push(constraint);
                }
                // If from_yaml returns None it already printed a warning; we
                // continue loading the rest of the rule's clauses.
            }
            if let Some(ref mt) = clause.metavariable_type {
                // FAITHFULNESS: a `metavariable-type:` constraint we cannot
                // enforce must not be silently dropped — that would broaden the
                // rule into an over-match. For languages without syntactic type
                // resolution we skip the whole rule instead.
                if !metavariable_type_enforceable(lang) {
                    return Err(format!(
                        "metavariable-type on {} is not enforceable for {} \
                         (no syntactic type resolution); skipping rule",
                        mt.metavariable, lang
                    ));
                }
                metavariable_types.push(MetavariableTypeConstraint::from_yaml(mt, lang));
            }
            if let Some(ref fmv) = clause.focus_metavariable {
                focus_metavariables.extend(fmv.clone().into_vec());
            }
        }

        return Ok(PatternMatcher::Combined {
            positives,
            negatives,
            inside,
            not_inside,
            metavariable_regexes,
            metavariable_comparisons,
            metavariable_patterns,
            metavariable_analyses,
            metavariable_types,
            focus_metavariables,
        });
    }

    let mut positives = Vec::new();
    let mut negatives = Vec::new();

    if let Some(ref pat) = yaml.pattern {
        positives.push(PatternMatcher::Single(CompiledAstPattern::new(
            pat.clone(),
            lang,
        )));
    }
    if let Some(ref regex) = yaml.pattern_regex {
        // Gracefully skip unsupported top-level pattern-regex.
        match compile_regex(regex) {
            Ok(r) => positives.push(PatternMatcher::Regex(r)),
            Err(e) => eprintln!(
                "Warning: top-level pattern-regex uses unsupported features ({}); \
                 skipping pattern",
                e
            ),
        }
    }
    if let Some(ref either) = yaml.pattern_either {
        positives.push(PatternMatcher::Either(build_either_matchers(either, lang)?));
    }
    if let Some(ref pat) = yaml.pattern_not {
        negatives.push(NegativeMatcher::Pattern(CompiledAstPattern::new(
            pat.clone(),
            lang,
        )));
    }
    if let Some(ref regex) = yaml.pattern_not_regex {
        // Gracefully skip unsupported top-level pattern-not-regex.
        match compile_regex(regex) {
            Ok(r) => negatives.push(NegativeMatcher::Regex(r)),
            Err(e) => eprintln!(
                "Warning: top-level pattern-not-regex uses unsupported features ({}); \
                 skipping pattern",
                e
            ),
        }
    }

    // Extract the `pattern-not-inside` string from either the literal or block form.
    // `PatternOrBlock::into_pattern_string` is a consuming method; we clone so
    // the borrow checker is happy.
    let not_inside_pat: Option<CompiledAstPattern> =
        yaml.pattern_not_inside.clone().and_then(|pob| {
            pob.into_pattern_string()
                .map(|pat| CompiledAstPattern::new(pat, lang))
        });

    if positives.len() == 1
        && negatives.is_empty()
        && yaml.pattern_inside.is_none()
        && not_inside_pat.is_none()
    {
        return Ok(positives.into_iter().next().expect("checked len == 1"));
    }

    if !positives.is_empty() {
        return Ok(PatternMatcher::Combined {
            positives,
            negatives,
            inside: yaml
                .pattern_inside
                .as_ref()
                .map(|pattern| CompiledAstPattern::new(pattern.clone(), lang)),
            not_inside: not_inside_pat,
            metavariable_regexes: Vec::new(),
            metavariable_comparisons: Vec::new(),
            metavariable_patterns: Vec::new(),
            metavariable_analyses: Vec::new(),
            metavariable_types: Vec::new(),
            focus_metavariables: Vec::new(),
        });
    }

    // Fallback: empty matcher that matches nothing
    Ok(PatternMatcher::Either(Vec::new()))
}

fn build_either_matchers(
    entries: &[PatternEntry],
    lang: Language,
) -> Result<Vec<PatternMatcher>, String> {
    let mut matchers = Vec::new();

    for entry in entries {
        if let Some(ref pattern) = entry.pattern {
            matchers.push(PatternMatcher::Single(CompiledAstPattern::new(
                pattern.clone(),
                lang,
            )));
        }
        if let Some(ref regex) = entry.pattern_regex {
            // Gracefully skip individual pattern-regex entries that use
            // unsupported features (lookahead/lookbehind, backreferences, etc.)
            // — consistent with MetavariableRegexConstraint::from_yaml.  The
            // remaining entries in the pattern-either list are still compiled;
            // the rule loads with a broader but functional matcher.
            match compile_regex(regex) {
                Ok(r) => matchers.push(PatternMatcher::Regex(r)),
                Err(e) => eprintln!(
                    "Warning: pattern-either entry has unsupported pattern-regex ({}); \
                     skipping entry",
                    e
                ),
            }
        }
    }

    Ok(matchers)
}

pub(crate) fn compile_regex(pattern: &str) -> Result<CompiledRegex, String> {
    // `\Z` is a Python/PCRE end-of-string anchor meaning "end of string before
    // optional trailing newline".  The Rust `regex` crate uses `$` with the
    // `MULTILINE` flag off for the same semantics (match at absolute end).
    // We normalise it here so rules that use `\Z` load successfully.
    let normalised = pattern.replace(r"\Z", "$");

    // The Rust `regex` crate is stricter than PCRE/Python `re` about bare `{`.
    // In PCRE, a `{` not followed by a valid quantifier `{N}`, `{N,}`, or
    // `{N,M}` is treated as a literal brace.  In Rust's `regex` crate it
    // causes a hard parse error ("repetition operator missing expression" or
    // "repetition quantifier expects a valid decimal").  Many Semgrep registry
    // rules written for PCRE contain template-syntax patterns like `{{` or
    // `{%` that use literal braces without escaping.  We apply a conservative
    // normalisation pass that escapes any `{` not already escaped and not
    // followed by a valid quantifier body.
    let normalised = escape_bare_braces(&normalised);

    // Fast path: the linear-time `regex` crate handles the overwhelming
    // majority of patterns.  Keep it as the primary engine.
    match Regex::new(&normalised) {
        Ok(re) => Ok(CompiledRegex::Fast(re)),
        // Fallback path: the `regex` crate rejected the pattern.  This is the
        // case for PCRE features it deliberately does not support —
        // lookahead `(?=...)`/`(?!...)`, lookbehind `(?<=...)`/`(?<!...)`, and
        // named/numeric backreferences.  The backtracking `fancy-regex`
        // engine supports these, so we retry there before giving up.
        Err(fast_err) => match fancy_regex::Regex::new(&normalised) {
            Ok(re) => Ok(CompiledRegex::Fancy(re)),
            Err(fancy_err) => Err(format!(
                "Invalid pattern-regex '{}': {} (fancy-regex fallback also failed: {})",
                pattern, fast_err, fancy_err
            )),
        },
    }
}

/// Escape bare `{` characters that Rust's `regex` crate would reject as
/// invalid quantifier-start tokens.
///
/// A `{` is a valid quantifier start when it is:
/// - preceded by an even number of backslashes (i.e. not already escaped), and
/// - followed by one or two decimal sequences matching `N` or `N,M`.
///
/// Any `{` not matching that shape is escaped to `\{`.  This converts
/// PCRE-style template patterns like `{{` (Django/Flask/Jinja) or `{%`
/// (template tag) into the `\{\{` / `\{%` forms that Rust's `regex` crate
/// accepts without changing any valid quantifiers such as `{20}` or `{1,3}`.
fn escape_bare_braces(s: &str) -> String {
    // We walk byte-by-byte, tracking:
    //   - whether the previous byte was a backslash (escape tracking)
    //   - whether we're inside a character class `[...]` (quantifiers are
    //     literal inside classes)
    let bytes = s.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(n + 8);
    let mut i = 0;
    let mut backslash_run = 0usize; // number of consecutive preceding backslashes
    let mut in_class = false; // inside [...]

    while i < n {
        let b = bytes[i];

        match b {
            b'\\' => {
                backslash_run += 1;
                out.push(b as char);
                i += 1;
            }
            b'[' if backslash_run.is_multiple_of(2) => {
                in_class = true;
                backslash_run = 0;
                out.push('[');
                i += 1;
            }
            b']' if backslash_run.is_multiple_of(2) => {
                in_class = false;
                backslash_run = 0;
                out.push(']');
                i += 1;
            }
            b'{' if backslash_run.is_multiple_of(2) && !in_class => {
                backslash_run = 0;
                // Peek ahead: is this a valid quantifier `{N}`, `{N,}`, `{N,M}`?
                if looks_like_quantifier(bytes, i + 1) {
                    out.push('{');
                } else {
                    // Not a valid quantifier — escape it.
                    out.push_str(r"\{");
                }
                i += 1;
            }
            b'}' if backslash_run.is_multiple_of(2) && !in_class => {
                backslash_run = 0;
                // A `}` that closes a `{` we already escaped (or a stray `}`)
                // should also be escaped.  We do this conservatively: only
                // escape `}` when it is NOT immediately closing a valid
                // quantifier opened in the pattern.  Since we rewrote all
                // non-quantifier `{` above, any remaining unmatched `}` is
                // also bare and should be `\}`.
                //
                // Simple heuristic: `}` not preceded by digits or `,` + digit
                // is treated as a stray closing brace and escaped.
                let prev = out.as_bytes().last().copied();
                if matches!(prev, Some(b'0'..=b'9') | Some(b',') | Some(b'{')) {
                    // Looks like it closes a quantifier we left open — leave as-is.
                    out.push('}');
                } else {
                    out.push_str(r"\}");
                }
                i += 1;
            }
            _ => {
                backslash_run = 0;
                out.push(b as char);
                i += 1;
            }
        }
    }

    out
}

/// Returns `true` when the bytes starting at `pos` look like the inside of a
/// valid regex quantifier: `N}`, `N,}`, or `N,M}` where N and M are decimal
/// integers.
fn looks_like_quantifier(bytes: &[u8], pos: usize) -> bool {
    let n = bytes.len();
    let mut i = pos;

    // At least one digit required.
    if i >= n || !bytes[i].is_ascii_digit() {
        return false;
    }
    while i < n && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i >= n {
        return false;
    }

    match bytes[i] {
        b'}' => true, // `{N}`
        b',' => {
            i += 1;
            // Optional second number.
            while i < n && bytes[i].is_ascii_digit() {
                i += 1;
            }
            i < n && bytes[i] == b'}'
        }
        _ => false,
    }
}

fn compile_globset(patterns: &[String]) -> Result<Option<GlobSet>, String> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob =
            Glob::new(pattern).map_err(|e| format!("Invalid paths glob '{}': {}", pattern, e))?;
        builder.add(glob);
    }

    builder
        .build()
        .map(Some)
        .map_err(|e| format!("Failed to build paths globset: {}", e))
}

fn normalize_rule_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn extract_cwe(yaml: &SemgrepRuleYaml) -> Option<String> {
    let meta = yaml.metadata.as_ref()?;
    let cwe = meta.cwe.as_ref()?;
    match cwe {
        CweValue::Single(s) => Some(s.clone()),
        CweValue::List(v) => v.first().cloned(),
    }
}

fn reserved_rule_namespace(rule_id: &str) -> Option<&'static str> {
    let (namespace, _) = rule_id.split_once('/')?;
    RESERVED_RULE_ID_NAMESPACES
        .iter()
        .copied()
        .find(|reserved| *reserved == namespace)
}

fn validate_semgrep_rule_id(rule_id: &str, source_label: &str) -> Result<(), String> {
    let Some(namespace) = reserved_rule_namespace(rule_id) else {
        return Ok(());
    };

    Err(format!(
        "Rule id '{}' in {} uses reserved namespace '{}/'. YAML rule packs must use a pack-specific namespace such as 'kernel/dirty-frag/...' or 'acme/security/...'. Reserved namespaces: {}",
        rule_id,
        source_label,
        namespace,
        RESERVED_RULE_ID_NAMESPACES.join(", ")
    ))
}

/// Parse a single Semgrep YAML file into foxguard rules.
pub fn parse_semgrep_file(path: &Path) -> Result<Vec<Box<dyn Rule>>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    parse_semgrep_str(&content, &path.display().to_string())
}

/// Parse a Semgrep YAML document (passed as an in-memory string) into
/// foxguard rules.
///
/// This sibling of [`parse_semgrep_file`] exists so the registry can load
/// bundled rule packs embedded into the binary at compile time
/// (`include_dir!` blobs have no filesystem path). `source_label` is used
/// purely for error messages — pass the embedded path or any human-readable
/// identifier.
pub fn parse_semgrep_str(content: &str, source_label: &str) -> Result<Vec<Box<dyn Rule>>, String> {
    use crate::rules::semgrep_taint::{self, TaintRuleParse};
    use serde_yaml_ng::Value as YamlValue;

    // First pass: parse as an untyped Value so we can detect `mode: taint`
    // rules and route them to the taint bridge without breaking the strict
    // `SemgrepRuleYaml` schema used for pattern rules.
    let raw_doc: YamlValue = serde_yaml_ng::from_str(content)
        .map_err(|e| format!("Failed to parse YAML {}: {}", source_label, e))?;

    let mut rules: Vec<Box<dyn Rule>> = Vec::new();
    let mut pattern_rule_nodes: Vec<YamlValue> = Vec::new();

    if let Some(raw_rules) = raw_doc.get("rules").and_then(YamlValue::as_sequence) {
        for raw_rule in raw_rules {
            if let Some(rule_id) = raw_rule.get("id").and_then(YamlValue::as_str) {
                validate_semgrep_rule_id(rule_id, source_label)?;
            }

            if raw_rule
                .get("engine")
                .and_then(YamlValue::as_str)
                .is_some_and(|engine| {
                    engine.eq_ignore_ascii_case("coccinelle")
                        || engine.eq_ignore_ascii_case("codeql")
                })
            {
                continue;
            }

            match semgrep_taint::parse_taint_rule(raw_rule) {
                TaintRuleParse::Compiled(r) => rules.push(Box::new(r)),
                TaintRuleParse::Skip(msg) => eprintln!("Warning: {}", msg),
                TaintRuleParse::NotTaint => pattern_rule_nodes.push(raw_rule.clone()),
            }
        }
    }

    // Second pass: the non-taint rules go through the existing strict
    // deserialization path. Re-serialize them into a minimal `SemgrepFile`
    // so we reuse `build_matcher`, path filters, language mapping, etc.
    let pattern_file = YamlValue::Mapping({
        let mut m = serde_yaml_ng::Mapping::new();
        m.insert(
            YamlValue::String("rules".into()),
            YamlValue::Sequence(pattern_rule_nodes),
        );
        m
    });
    let semgrep_file: SemgrepFile = serde_yaml_ng::from_value(pattern_file)
        .map_err(|e| format!("Failed to parse YAML {}: {}", source_label, e))?;

    for yaml_rule in semgrep_file.rules {
        let cwe = extract_cwe(&yaml_rule);
        let severity = map_severity(&yaml_rule.severity);
        let path_filter = PathFilter::from_yaml(yaml_rule.paths.as_ref())?;

        // `languages: [generic]` — AST-less spacegrep rules routed to the
        // generic-mode (tokenized) matcher.  See `generic_mode.rs`.
        if is_generic_language_rule(&yaml_rule.languages) {
            rules.extend(build_generic_mode_rules(
                &yaml_rule,
                severity,
                &cwe,
                &path_filter,
            )?);
            continue;
        }

        // `languages: [regex]` — pure regex rules that run `pattern-regex` /
        // `pattern-not-regex` against raw file text, with no tree-sitter parse.
        // They are language-agnostic and fan out across all detectable languages.
        if is_regex_language_rule(&yaml_rule.languages) {
            rules.extend(build_regex_mode_rules(
                &yaml_rule,
                severity,
                &cwe,
                &path_filter,
            )?);
            continue;
        }

        let mut mapped_languages = Vec::new();
        for lang_str in &yaml_rule.languages {
            if let Some(lang) = map_language(lang_str) {
                if !mapped_languages.contains(&lang) {
                    mapped_languages.push(lang);
                }
            }
        }

        for lang in mapped_languages {
            let matcher = build_matcher(&yaml_rule, lang)?;
            rules.push(Box::new(SemgrepRule {
                id: format!("semgrep/{}", yaml_rule.id),
                message: yaml_rule.message.clone(),
                severity,
                lang,
                cwe: cwe.clone(),
                matcher,
                path_filter: path_filter.clone(),
                fix_template: yaml_rule.fix.clone(),
            }));
        }
    }

    Ok(rules)
}

/// Load all Semgrep YAML rules from a file or directory (recursive).
pub fn load_semgrep_rules(path: &Path) -> Vec<Box<dyn Rule>> {
    let mut rules = Vec::new();

    if path.is_file() {
        match parse_semgrep_file(path) {
            Ok(r) => rules.extend(r),
            Err(e) => eprintln!("Warning: {}", e),
        }
    } else if path.is_dir() {
        let walker = walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_type().is_file()
                    && matches!(
                        e.path().extension().and_then(|s| s.to_str()),
                        Some("yaml" | "yml")
                    )
            });

        for entry in walker {
            match parse_semgrep_file(entry.path()) {
                Ok(r) => rules.extend(r),
                Err(e) => eprintln!("Warning: {}", e),
            }
        }
    }

    rules
}

/// Load all Semgrep YAML rules from an embedded [`include_dir::Dir`] tree.
///
/// Used for the rule packs that ship inside the `foxguard` binary
/// (currently `rules/kernel/dirty-frag-class/`). Walks the tree
/// recursively, picks up every `.yaml` / `.yml` file, and parses each as a
/// Semgrep document. CodeQL-engine rules are skipped inside
/// `parse_semgrep_str` (handled by the separate CodeQL bridge), so it is
/// safe to pass mixed packs.
pub fn load_semgrep_rules_from_embedded(dir: &include_dir::Dir<'_>) -> Vec<Box<dyn Rule>> {
    let mut rules = Vec::new();
    walk_embedded_dir(dir, &mut rules);
    rules
}

fn walk_embedded_dir(dir: &include_dir::Dir<'_>, rules: &mut Vec<Box<dyn Rule>>) {
    for file in dir.files() {
        let path = file.path();
        let ext = path.extension().and_then(|s| s.to_str());
        if !matches!(ext, Some("yaml" | "yml")) {
            continue;
        }
        let Some(content) = file.contents_utf8() else {
            eprintln!(
                "Warning: embedded rule {} is not valid UTF-8, skipping",
                path.display()
            );
            continue;
        };
        let label = format!("<bundled:{}>", path.display());
        match parse_semgrep_str(content, &label) {
            Ok(r) => rules.extend(r),
            Err(e) => eprintln!("Warning: {e}"),
        }
    }
    for subdir in dir.dirs() {
        // `queries/` subtrees hold CodeQL `.ql` files plus `qlpack.yml` /
        // `codeql-pack.lock.yml` pack metadata. Those `.yml` files match
        // our extension filter but are NOT Semgrep rules — they belong to
        // the CodeQL bridge. Skip the whole subtree so we don't print
        // spurious parse warnings at startup.
        if subdir.path().file_name().and_then(|s| s.to_str()) == Some("queries") {
            continue;
        }
        walk_embedded_dir(subdir, rules);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_yaml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_parse_simple_rule() {
        let yaml = r#"
rules:
  - id: test-eval
    pattern: eval(...)
    message: Do not use eval
    severity: ERROR
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id(), "semgrep/test-eval");
        assert_eq!(rules[0].severity(), Severity::Critical);
    }

    #[test]
    fn test_reserved_rule_id_namespace_is_rejected() {
        let yaml = r#"
rules:
  - id: py/custom-eval
    pattern: eval(...)
    message: Do not use eval
    severity: ERROR
    languages: [python]
"#;

        let err = match parse_semgrep_str(yaml, "org-pack.yml") {
            Ok(_) => panic!("reserved rule namespace should be rejected"),
            Err(err) => err,
        };
        assert!(err.contains("py/custom-eval"));
        assert!(err.contains("reserved namespace 'py/'"));
        assert!(err.contains("org-pack.yml"));
    }

    #[test]
    fn test_reserved_rule_id_alias_namespaces_are_rejected() {
        for namespace in ["cs", "csharp", "rs", "rust"] {
            let rule_id = format!("{namespace}/custom-rule");
            assert_eq!(reserved_rule_namespace(&rule_id), Some(namespace));
        }
    }

    #[test]
    fn ast_patterns_are_compiled_during_rule_load() {
        let yaml = r#"
rules:
  - id: test-eval
    pattern: eval(...)
    message: Do not use eval
    severity: ERROR
    languages: [python]
"#;
        let parsed: SemgrepFile = serde_yaml_ng::from_str(yaml).unwrap();
        let matcher = build_matcher(&parsed.rules[0], Language::Python).unwrap();

        match matcher {
            PatternMatcher::Single(pattern) => {
                assert!(pattern.tree.is_some());
                assert_eq!(pattern.selector_kind.as_deref(), Some("call"));
            }
            other => panic!("expected single compiled AST pattern, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_pattern_either() {
        let yaml = r#"
rules:
  - id: dangerous-funcs
    pattern-either:
      - pattern: eval(...)
      - pattern: exec(...)
    message: Dangerous function
    severity: WARNING
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn test_dedup_mapped_languages() {
        let yaml = r#"
rules:
  - id: js-send
    pattern: res.send("Hello World")
    message: Exact Express response send call
    severity: WARNING
    languages: [javascript, typescript]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].language(), Language::JavaScript);
    }

    #[test]
    fn test_metavar_detection() {
        assert!(is_metavar("$VAR"));
        assert!(is_metavar("$X"));
        assert!(is_metavar("$DB_NAME"));
        assert!(!is_metavar("$"));
        assert!(!is_metavar("foo"));
        assert!(!is_metavar("$foo.bar"));
    }

    #[test]
    fn test_match_eval_pattern() {
        let yaml = r#"
rules:
  - id: test-eval
    pattern: eval(...)
    message: No eval
    severity: ERROR
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "x = eval(user_input)\ny = safe_func()\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn semgrep_compat_findings_are_emitted_at_confidence_zero_point_seven() {
        // External Semgrep-compat rules default to confidence=0.7
        // because pattern rules are inherently fuzzier than curated
        // built-in AST-walked rules. See issue #207.
        let yaml = r#"
rules:
  - id: test-eval
    pattern: eval(...)
    message: No eval
    severity: ERROR
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "x = eval(user_input)\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);
        assert_eq!(findings.len(), 1);
        assert!((findings[0].confidence - 0.7).abs() < f32::EPSILON);
    }

    #[test]
    fn test_match_hardcoded_string() {
        let yaml = r#"
rules:
  - id: hardcoded-password
    pattern: password = "..."
    message: Hardcoded password
    severity: WARNING
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "password = \"supersecret\"\nusername = \"admin\"\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn test_match_string_concat_with_metavar() {
        let yaml = r#"
rules:
  - id: string-concat
    pattern: '"..." + $VAR'
    message: String concatenation
    severity: WARNING
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "query = \"SELECT \" + user_input\nsafe = 1 + 2\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn test_match_pattern_regex() {
        let yaml = r#"
rules:
  - id: regex-secret
    pattern-regex: "(?m)^SECRET_KEY\\s*="
    message: Regex secret
    severity: ERROR
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "password = \"supersecret\"\nSECRET_KEY = \"django-secret\"\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
    }

    #[test]
    fn test_pattern_not_regex_filters_matches() {
        let yaml = r#"
rules:
  - id: password-assign
    patterns:
      - pattern-regex: "(?m)^.*password.*="
      - pattern-not-regex: "not_password"
    message: Password assignment
    severity: WARNING
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "password = \"supersecret\"\nnot_password = \"safe\"\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn test_metavariable_regex_filters_bound_matches() {
        let yaml = r#"
rules:
  - id: user-input-only
    patterns:
      - pattern: '"..." + $VAR'
      - metavariable-regex:
          metavariable: $VAR
          regex: ^user_input$
    message: user input only
    severity: ERROR
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "query = \"SELECT \" + user_input\nquery2 = \"SELECT \" + safe_value\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn test_pattern_not_inside_excludes_nested_matches() {
        let yaml = r#"
rules:
  - id: redirect-outside-helpers
    patterns:
      - pattern: redirect(...)
      - pattern-not-inside: |
          def safe_redirect(...):
            ...
    message: redirect outside helper
    severity: WARNING
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "def safe_redirect(url):\n    return redirect(url)\n\ndef do_redirect(url):\n    return redirect(url)\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 5);
    }

    // ─── metavariable-comparison unit tests ─────────────────────────────────

    #[test]
    fn test_parse_comparison_lt() {
        let (mv, op, lit, flip) = parse_comparison("$X < 10").unwrap();
        assert_eq!(mv, "$X");
        assert_eq!(op, CmpOp::Lt);
        assert!((lit - 10.0).abs() < f64::EPSILON);
        assert!(!flip);
    }

    #[test]
    fn test_parse_comparison_le() {
        let (mv, op, lit, _flip) = parse_comparison("$X <= 5.5").unwrap();
        assert_eq!(op, CmpOp::Le);
        assert!((lit - 5.5).abs() < f64::EPSILON);
        assert_eq!(mv, "$X");
    }

    #[test]
    fn test_parse_comparison_gt() {
        let (_mv, op, lit, _flip) = parse_comparison("$N > 100").unwrap();
        assert_eq!(op, CmpOp::Gt);
        assert!((lit - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_comparison_ge() {
        let (_mv, op, lit, _flip) = parse_comparison("$N >= 0").unwrap();
        assert_eq!(op, CmpOp::Ge);
        assert!((lit - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_comparison_eq() {
        let (mv, op, lit, _flip) = parse_comparison("$VAL == 42").unwrap();
        assert_eq!(op, CmpOp::Eq);
        assert!((lit - 42.0).abs() < f64::EPSILON);
        assert_eq!(mv, "$VAL");
    }

    #[test]
    fn test_parse_comparison_ne() {
        let (_mv, op, lit, _flip) = parse_comparison("$VAL != 0").unwrap();
        assert_eq!(op, CmpOp::Ne);
        assert!((lit - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_comparison_literal_lhs() {
        let (mv, op, lit, flip) = parse_comparison("10 < $X").unwrap();
        assert_eq!(mv, "$X");
        // op is stored as-is from the expression; `flip` indicates literal is LHS
        assert_eq!(op, CmpOp::Lt);
        assert!((lit - 10.0).abs() < f64::EPSILON);
        assert!(flip);
    }

    #[test]
    fn test_parse_comparison_no_metavar_is_err() {
        assert!(parse_comparison("10 < 20").is_err());
    }

    #[test]
    fn test_parse_comparison_no_operator_is_err() {
        assert!(parse_comparison("$X 10").is_err());
    }

    #[test]
    fn test_constraint_matches_numeric_match() {
        let clause = SemgrepMetavariableComparisonClause {
            metavariable: Some("$X".to_string()),
            comparison: "$X < 10".to_string(),
            base: None,
            strip: None,
        };
        let constraint = MetavariableComparisonConstraint::from_yaml(&clause).unwrap();
        let mut bindings = HashMap::new();
        bindings.insert("$X".to_string(), "5".to_string());
        assert!(constraint.matches(&bindings));
    }

    #[test]
    fn test_constraint_non_match() {
        let clause = SemgrepMetavariableComparisonClause {
            metavariable: Some("$X".to_string()),
            comparison: "$X < 10".to_string(),
            base: None,
            strip: None,
        };
        let constraint = MetavariableComparisonConstraint::from_yaml(&clause).unwrap();
        let mut bindings = HashMap::new();
        bindings.insert("$X".to_string(), "15".to_string());
        assert!(!constraint.matches(&bindings));
    }

    #[test]
    fn test_constraint_non_numeric_binding_no_match() {
        let clause = SemgrepMetavariableComparisonClause {
            metavariable: Some("$X".to_string()),
            comparison: "$X < 10".to_string(),
            base: None,
            strip: None,
        };
        let constraint = MetavariableComparisonConstraint::from_yaml(&clause).unwrap();
        let mut bindings = HashMap::new();
        bindings.insert("$X".to_string(), "not_a_number".to_string());
        assert!(!constraint.matches(&bindings));
    }

    #[test]
    fn test_constraint_unbound_metavar_no_match() {
        let clause = SemgrepMetavariableComparisonClause {
            metavariable: Some("$X".to_string()),
            comparison: "$X < 10".to_string(),
            base: None,
            strip: None,
        };
        let constraint = MetavariableComparisonConstraint::from_yaml(&clause).unwrap();
        let bindings = HashMap::new(); // $X not bound
        assert!(!constraint.matches(&bindings));
    }

    #[test]
    fn test_constraint_float_comparison() {
        let clause = SemgrepMetavariableComparisonClause {
            metavariable: Some("$X".to_string()),
            comparison: "$X >= 3.14".to_string(),
            base: None,
            strip: None,
        };
        let constraint = MetavariableComparisonConstraint::from_yaml(&clause).unwrap();
        let mut bindings = HashMap::new();
        bindings.insert("$X".to_string(), "3.14".to_string());
        assert!(constraint.matches(&bindings));
        let mut bindings2 = HashMap::new();
        bindings2.insert("$X".to_string(), "2.0".to_string());
        assert!(!constraint.matches(&bindings2));
    }

    #[test]
    fn test_numeric_suffix_strips_c_float_f_and_preserves_hex() {
        // C float suffix `f`/`F` must be stripped so `2.5f` parses.
        assert_eq!(parse_numeric(&strip_numeric_suffixes("2.5f")), Some(2.5));
        assert_eq!(parse_numeric(&strip_numeric_suffixes("2.5F")), Some(2.5));
        // Integer suffixes still stripped.
        assert_eq!(parse_numeric(&strip_numeric_suffixes("10UL")), Some(10.0));
        // Hex/binary literals must NOT lose their trailing digits to suffix stripping.
        assert_eq!(parse_numeric(&strip_numeric_suffixes("0xFF")), Some(255.0));
        assert_eq!(parse_numeric(&strip_numeric_suffixes("0xff")), Some(255.0));
        assert_eq!(parse_numeric(&strip_numeric_suffixes("0b101")), Some(5.0));
    }

    #[test]
    fn test_constraint_eq_is_exact() {
        let clause = SemgrepMetavariableComparisonClause {
            metavariable: Some("$X".to_string()),
            comparison: "$X == 5".to_string(),
            base: None,
            strip: None,
        };
        let constraint = MetavariableComparisonConstraint::from_yaml(&clause).unwrap();
        let mut hit = HashMap::new();
        hit.insert("$X".to_string(), "5".to_string());
        assert!(constraint.matches(&hit));
        let mut miss = HashMap::new();
        miss.insert("$X".to_string(), "6".to_string());
        assert!(!constraint.matches(&miss));
    }

    #[test]
    fn test_constraint_eq_c_float_suffix_binding() {
        // Regression for the `f` suffix bug: a bound C float literal `1.5f`
        // must compare equal to the literal `1.5` rather than being dropped.
        let clause = SemgrepMetavariableComparisonClause {
            metavariable: Some("$X".to_string()),
            comparison: "$X == 1.5".to_string(),
            base: None,
            strip: None,
        };
        let constraint = MetavariableComparisonConstraint::from_yaml(&clause).unwrap();
        let mut bindings = HashMap::new();
        bindings.insert("$X".to_string(), "1.5f".to_string());
        assert!(constraint.matches(&bindings));
    }

    #[test]
    fn test_constraint_unsupported_base_warn_skip() {
        let clause = SemgrepMetavariableComparisonClause {
            metavariable: Some("$X".to_string()),
            comparison: "$X < 10".to_string(),
            base: Some(16),
            strip: None,
        };
        // Should return Err, not panic
        assert!(MetavariableComparisonConstraint::from_yaml(&clause).is_err());
    }

    #[test]
    fn test_metavariable_comparison_filters_matches_end_to_end() {
        // Full pipeline: parse rule YAML → build matcher → check source
        let yaml = r#"
rules:
  - id: small-arg
    patterns:
      - pattern: foo($X)
      - metavariable-comparison:
          metavariable: $X
          comparison: $X < 10
    message: foo called with small arg
    severity: WARNING
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();
        assert_eq!(rules.len(), 1);

        // foo(5) → match (5 < 10)
        // foo(20) → no match (20 >= 10)
        // foo(bar) → no match (non-numeric)
        let source = "foo(5)\nfoo(20)\nfoo(bar)\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn test_metavariable_comparison_eq_operator_end_to_end() {
        let yaml = r#"
rules:
  - id: exact-zero
    patterns:
      - pattern: check($N)
      - metavariable-comparison:
          metavariable: $N
          comparison: $N == 0
    message: called with zero
    severity: WARNING
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "check(0)\ncheck(1)\ncheck(2)\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 1);
    }

    /// metavariable-pattern: the binding for $FUNC must itself match a nested
    /// AST sub-pattern.
    #[test]
    fn test_metavariable_pattern_match() {
        // $FUNC must itself be a call matching `dangerous(...)`.
        // Source line 1 calls eval(dangerous(x)) — $FUNC captures dangerous(x)
        // which matches `dangerous(...)`.
        // Source line 2 calls eval(safe(x)) — $FUNC captures safe(x)
        // which does NOT match `dangerous(...)`.
        let yaml = r#"
rules:
  - id: mvp-match
    patterns:
      - pattern: eval($FUNC)
      - metavariable-pattern:
          metavariable: $FUNC
          pattern: dangerous(...)
    message: dangerous arg in eval
    severity: ERROR
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "eval(dangerous(x))\neval(safe(x))\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);
        assert_eq!(findings.len(), 1, "expected exactly one finding");
        assert_eq!(findings[0].line, 1);
    }

    /// Non-match case: binding exists but the sub-pattern does not match it.
    #[test]
    fn test_metavariable_pattern_no_match() {
        let yaml = r#"
rules:
  - id: mvp-no-match
    patterns:
      - pattern: eval($FUNC)
      - metavariable-pattern:
          metavariable: $FUNC
          pattern: dangerous(...)
    message: dangerous arg
    severity: ERROR
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "eval(safe(x))\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);
        assert_eq!(
            findings.len(),
            0,
            "expected no findings when sub-pattern does not match"
        );
    }

    /// pattern-regex nested form: the bound text is matched via regex.
    #[test]
    fn test_metavariable_pattern_regex_nested() {
        let yaml = r#"
rules:
  - id: mvp-regex
    patterns:
      - pattern: '"..." + $VAR'
      - metavariable-pattern:
          metavariable: $VAR
          pattern-regex: '^user_'
    message: user-prefixed var in concat
    severity: WARNING
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "q = \"SELECT \" + user_input\nq2 = \"SELECT \" + data\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly one finding for user_ variable"
        );
        assert_eq!(findings[0].line, 1);
    }

    /// Warn-skip: an unsupported nested shape should warn and skip the
    /// constraint without crashing, leaving other clauses active.
    #[test]
    fn test_metavariable_pattern_unsupported_nested_shape_warn_skip() {
        // metavariable-pattern clause has neither pattern, pattern-regex, nor
        // pattern-either — it has no recognised keys at all. The constraint
        // should be silently dropped and the positive pattern `eval(...)` still
        // fires on the source (no constraint to filter with).
        let yaml = r#"
rules:
  - id: mvp-warn-skip
    patterns:
      - pattern: eval(...)
      - metavariable-pattern:
          metavariable: $FUNC
    message: eval usage (constraint skipped)
    severity: ERROR
    languages: [python]
"#;
        let f = make_yaml(yaml);
        // Loading must succeed (no panic, no Err).
        let rules = parse_semgrep_file(f.path()).unwrap();
        assert_eq!(rules.len(), 1, "rule should still load after warn-skip");

        // The positive pattern fires; the skipped constraint is absent.
        let source = "eval(x)\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);
        // Without the constraint, the positive `eval(...)` still matches.
        assert!(!findings.is_empty(), "positive pattern should still fire");
    }

    // ─── focus-metavariable tests ────────────────────────────────────────────

    /// focus-metavariable: the reported finding range must point at $VAR (the
    /// argument), NOT at the outer call expression.
    ///
    /// Source: `foo(bar)\n`
    ///   - full match `foo(bar)` is at line 1, col 1..8
    ///   - argument `bar` is at line 1, col 5..7 (1-based)
    ///
    /// With focus-metavariable: $ARG, the finding should have line=1, col=5.
    #[test]
    fn test_focus_metavariable_range_override() {
        let yaml = r#"
rules:
  - id: focus-test
    patterns:
      - pattern: foo($ARG)
      - focus-metavariable: $ARG
    message: focus on arg
    severity: WARNING
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        // "foo(bar)\n" — `bar` starts at byte 4 (0-based), which is col 5 (1-based)
        let source = "foo(bar)\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);

        assert_eq!(findings.len(), 1, "expected one finding");

        // The full match `foo(bar)` is at line 1, column 1.
        // With focus-metavariable, it should instead point at `bar` (col 5).
        assert_eq!(findings[0].line, 1, "finding should be on line 1");
        assert_ne!(
            findings[0].column, 1,
            "column should NOT be 1 (that's the full match start); focus-metavariable must override it"
        );
        // `bar` is the 5th character on line 1 (1-based).
        assert_eq!(
            findings[0].column, 5,
            "focused metavariable $ARG should start at column 5"
        );
    }

    /// focus-metavariable with a list: accept `focus-metavariable: [$ARG]`.
    #[test]
    fn test_focus_metavariable_list_syntax() {
        let yaml = r#"
rules:
  - id: focus-list-test
    patterns:
      - pattern: foo($ARG)
      - focus-metavariable: [$ARG]
    message: focus on arg
    severity: WARNING
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "foo(bar)\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);

        assert_eq!(findings.len(), 1, "expected one finding");
        assert_eq!(findings[0].column, 5, "$ARG should start at column 5");
    }

    /// focus-metavariable fallback: when the named metavar is not bound in a
    /// match (won't happen in a well-formed rule, but verify no crash/drop).
    #[test]
    fn test_focus_metavariable_unbound_fallback() {
        // This rule focuses on $MISSING which is never bound by the pattern.
        // The finding must still be emitted at the full match range.
        let yaml = r#"
rules:
  - id: focus-fallback
    patterns:
      - pattern: eval(...)
      - focus-metavariable: $MISSING
    message: fallback test
    severity: WARNING
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "eval(user_input)\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);

        // Finding must still be emitted (no drop on missing metavar).
        assert_eq!(findings.len(), 1, "finding must not be dropped");
        // Falls back to full match at line 1, column 1
        assert_eq!(findings[0].line, 1);
        assert_eq!(
            findings[0].column, 1,
            "should fall back to full match column"
        );
    }

    // ─── fix: autofix template tests ────────────────────────────────────────

    /// (a) A rule with `fix:` referencing a metavar produces a finding whose
    /// `fix_suggestion` has the metavar substituted with the bound value.
    #[test]
    fn test_fix_template_substitutes_bound_metavar() {
        let yaml = r#"
rules:
  - id: use-safe-func
    pattern: unsafe_call($X)
    fix: safe_call($X)
    message: Use safe_call instead
    severity: WARNING
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "unsafe_call(user_data)\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].fix_suggestion.as_deref(),
            Some("safe_call(user_data)"),
            "metavar $X should be substituted with the bound text 'user_data'"
        );
    }

    /// (b) A rule without `fix:` yields `fix_suggestion: None`.
    #[test]
    fn test_no_fix_key_yields_no_fix_suggestion() {
        let yaml = r#"
rules:
  - id: test-eval-no-fix
    pattern: eval(...)
    message: Do not use eval
    severity: ERROR
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "eval(user_input)\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);

        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].fix_suggestion.is_none(),
            "fix_suggestion should be None when no fix: key is present"
        );
    }

    /// (c) An unbound metavar token in the template is left literal — no panic.
    #[test]
    fn test_fix_template_unbound_metavar_left_literal() {
        let yaml = r#"
rules:
  - id: fix-unbound
    pattern: eval(...)
    fix: safe_eval($UNBOUND)
    message: Use safe_eval
    severity: WARNING
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "eval(x)\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);

        assert_eq!(findings.len(), 1);
        // $UNBOUND is not bound by the pattern (which uses ..., no named metavar)
        // so the token should remain as-is in the suggestion.
        assert_eq!(
            findings[0].fix_suggestion.as_deref(),
            Some("safe_eval($UNBOUND)"),
            "unbound metavar token should be left literal, not panic"
        );
    }

    /// (a2) fix: with multiple metavars — each is substituted independently.
    #[test]
    fn test_fix_template_multiple_metavars() {
        let yaml = r#"
rules:
  - id: fix-multi
    pattern: old($A, $B)
    fix: new($B, $A)
    message: swap args
    severity: INFO
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "old(foo, bar)\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].fix_suggestion.as_deref(),
            Some("new(bar, foo)"),
            "both metavars should be substituted correctly"
        );
    }

    // ─── metavariable-analysis / entropy unit tests ──────────────────────────

    /// `shannon_entropy` sanity checks: high-entropy token vs low-entropy word.
    #[test]
    fn test_shannon_entropy_values() {
        // "Zq7Z9kW3pL8xT2nR4dB6m" — random high-entropy token
        let high = shannon_entropy("Zq7Z9kW3pL8xT2nR4dB6m");
        assert!(
            high >= 3.5,
            "expected entropy >= 3.5 for high-entropy token, got {high}"
        );

        // "hello" — low entropy
        let low = shannon_entropy("hello");
        assert!(low < 3.0, "expected entropy < 3.0 for 'hello', got {low}");

        // empty string
        assert_eq!(shannon_entropy(""), 0.0);
    }

    /// entropy constraint: matches a high-entropy token.
    #[test]
    fn test_metavariable_analysis_entropy_matches_high_entropy() {
        let clause = SemgrepMetavariableAnalysisClause {
            metavariable: "$TOKEN".to_string(),
            analyzer: "entropy".to_string(),
        };
        let constraint = MetavariableAnalysisConstraint::from_yaml(&clause)
            .expect("entropy analyzer should build successfully");

        let mut bindings = HashMap::new();
        // base64-ish token with high entropy
        bindings.insert(
            "$TOKEN".to_string(),
            "aB3xQz9mKp2LwYv5NtRsUhJdEfCgOiV7".to_string(),
        );
        assert!(
            constraint.matches(&bindings),
            "entropy constraint must match a high-entropy token"
        );
    }

    /// entropy constraint: does NOT match a low-entropy word.
    #[test]
    fn test_metavariable_analysis_entropy_no_match_low_entropy() {
        let clause = SemgrepMetavariableAnalysisClause {
            metavariable: "$TOKEN".to_string(),
            analyzer: "entropy".to_string(),
        };
        let constraint = MetavariableAnalysisConstraint::from_yaml(&clause).unwrap();

        let mut bindings = HashMap::new();
        bindings.insert("$TOKEN".to_string(), "password".to_string());
        assert!(
            !constraint.matches(&bindings),
            "entropy constraint must NOT match 'password'"
        );
    }

    /// entropy constraint: unbound metavar → no match (no panic).
    #[test]
    fn test_metavariable_analysis_entropy_unbound_metavar_no_match() {
        let clause = SemgrepMetavariableAnalysisClause {
            metavariable: "$TOKEN".to_string(),
            analyzer: "entropy".to_string(),
        };
        let constraint = MetavariableAnalysisConstraint::from_yaml(&clause).unwrap();

        let bindings = HashMap::new(); // $TOKEN not bound
        assert!(
            !constraint.matches(&bindings),
            "unbound metavar must return false (no panic)"
        );
    }

    /// redos analyzer: warn-skips without crashing (from_yaml returns None).
    #[test]
    fn test_metavariable_analysis_redos_warn_skips() {
        let clause = SemgrepMetavariableAnalysisClause {
            metavariable: "$RE".to_string(),
            analyzer: "redos".to_string(),
        };
        // Must return None (warn-skip), not panic or Err.
        let result = MetavariableAnalysisConstraint::from_yaml(&clause);
        assert!(
            result.is_none(),
            "redos analyzer must warn-skip (return None)"
        );
    }

    /// Unknown analyzer: warn-skips without crashing.
    #[test]
    fn test_metavariable_analysis_unknown_analyzer_warn_skips() {
        let clause = SemgrepMetavariableAnalysisClause {
            metavariable: "$X".to_string(),
            analyzer: "future-magic-analyzer".to_string(),
        };
        let result = MetavariableAnalysisConstraint::from_yaml(&clause);
        assert!(
            result.is_none(),
            "unknown analyzer must warn-skip (return None)"
        );
    }

    /// End-to-end: a rule with metavariable-analysis entropy fires on a
    /// high-entropy bound value and is suppressed on a low-entropy value.
    #[test]
    fn test_metavariable_analysis_entropy_end_to_end() {
        let yaml = r#"
rules:
  - id: hardcoded-secret-entropy
    patterns:
      - pattern: 'token = "$VALUE"'
      - metavariable-analysis:
          metavariable: $VALUE
          analyzer: entropy
    message: Hardcoded high-entropy token detected
    severity: ERROR
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();
        assert_eq!(rules.len(), 1, "rule must load successfully");

        // High-entropy token: should fire
        let high_entropy_source = r#"token = "aB3xQz9mKp2LwYv5NtRsUhJdEfCgOiV7"
"#;
        let tree = parse_file(high_entropy_source, Language::Python).unwrap();
        let findings = rules[0].check(high_entropy_source, &tree);
        assert_eq!(
            findings.len(),
            1,
            "entropy rule must fire on high-entropy token"
        );

        // Low-entropy token: should NOT fire
        let low_entropy_source = r#"token = "password"
"#;
        let tree2 = parse_file(low_entropy_source, Language::Python).unwrap();
        let findings2 = rules[0].check(low_entropy_source, &tree2);
        assert_eq!(
            findings2.len(),
            0,
            "entropy rule must NOT fire on low-entropy word"
        );
    }

    /// End-to-end: a rule with redos analyzer must load (warn-skip) and the
    /// positive pattern still fires (constraint is absent, not blocking).
    #[test]
    fn test_metavariable_analysis_redos_warn_skip_end_to_end() {
        let yaml = r#"
rules:
  - id: redos-test
    patterns:
      - pattern: 'regex = "$PATTERN"'
      - metavariable-analysis:
          metavariable: $PATTERN
          analyzer: redos
    message: Possible ReDoS pattern
    severity: WARNING
    languages: [python]
"#;
        let f = make_yaml(yaml);
        // Rule must load without error; warn-skip is printed to stderr.
        let rules = parse_semgrep_file(f.path()).unwrap();
        assert_eq!(rules.len(), 1, "rule must load after warn-skip");

        // With redos constraint dropped, the positive pattern fires unconstrained.
        let source = r#"regex = "(a+)+"
"#;
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);
        // The positive pattern still matches; no crash.
        assert_eq!(
            findings.len(),
            1,
            "positive pattern must still fire when redos constraint is warn-skipped"
        );
    }

    /// focus-metavariable: two-line source — confirm the focused metavar is on
    /// line 2 when the match is on line 2.
    #[test]
    fn test_focus_metavariable_multiline_source() {
        let yaml = r#"
rules:
  - id: focus-multiline
    patterns:
      - pattern: sink($X)
      - focus-metavariable: $X
    message: focus on X
    severity: WARNING
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        // Only line 2 has a match.
        let source = "safe(a)\nsink(b)\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);

        assert_eq!(findings.len(), 1, "expected one finding on line 2");
        assert_eq!(
            findings[0].line, 2,
            "focused metavar $X should be on line 2"
        );
        // `b` is the 6th character on line 2 in "sink(b)"
        assert_eq!(findings[0].column, 6, "$X (`b`) should be at column 6");
    }

    // ── languages: [regex] ────────────────────────────────────────────────────

    /// (a) A `languages: [regex]` rule with `pattern-regex` loads (produces rule
    /// instances) and FIRES on a file whose text matches.
    #[test]
    fn regex_lang_rule_loads_and_fires_on_matching_text() {
        let yaml = r#"
rules:
  - id: test/detect-token
    pattern-regex: "MYTOKEN[0-9]{4}"
    languages: [regex]
    message: Token detected
    severity: ERROR
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();
        // Fan-out produces one instance per detectable language.
        assert!(
            !rules.is_empty(),
            "regex-mode rule should produce at least one rule instance"
        );

        // All instances should have the correct id, severity, and language.
        for rule in &rules {
            assert_eq!(rule.id(), "semgrep/test/detect-token");
            assert_eq!(rule.severity(), Severity::Critical);
        }

        // Pick any instance and run it against matching text.
        let source = "access_token = \"MYTOKEN1234\"\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly one finding for matching text"
        );
        assert_eq!(findings[0].line, 1);
    }

    /// (b) The same rule does NOT fire on non-matching text.
    #[test]
    fn regex_lang_rule_does_not_fire_on_non_matching_text() {
        let yaml = r#"
rules:
  - id: test/detect-token
    pattern-regex: "MYTOKEN[0-9]{4}"
    languages: [regex]
    message: Token detected
    severity: ERROR
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();

        let source = "access_token = \"NOT_A_TOKEN\"\n";
        let tree = parse_file(source, Language::Python).unwrap();
        let findings = rules[0].check(source, &tree);
        assert!(
            findings.is_empty(),
            "regex-mode rule must not fire on non-matching text"
        );
    }

    /// (c) `paths.include` / `paths.exclude` respected by the regex-mode rule.
    #[test]
    fn regex_lang_rule_respects_paths_filter() {
        let yaml = r#"
rules:
  - id: test/jsp-scriptlet
    pattern-regex: "<%[^@]"
    languages: [regex]
    message: JSP scriptlet detected
    severity: WARNING
    paths:
      include:
        - "*.jsp"
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();
        assert!(!rules.is_empty(), "should produce at least one rule");

        // Should apply to .jsp files.
        assert!(
            rules[0].applies_to_path(std::path::Path::new("view.jsp")),
            "rule should apply to .jsp files"
        );
        // Should NOT apply to .py files.
        assert!(
            !rules[0].applies_to_path(std::path::Path::new("main.py")),
            "rule must not apply to .py files when paths.include = [*.jsp]"
        );
    }

    /// (d) A `languages: [regex]` rule with only an AST `pattern:` (no
    /// `pattern-regex`) should warn-skip (produce zero rule instances).
    #[test]
    fn regex_lang_rule_with_only_ast_pattern_warns_and_skips() {
        let yaml = r#"
rules:
  - id: test/ast-only-in-regex-mode
    pattern: eval(...)
    languages: [regex]
    message: This should be skipped
    severity: ERROR
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();
        assert!(
            rules.is_empty(),
            "regex-mode rule with only an AST pattern must produce zero rule instances"
        );
    }

    /// Regex-mode rule with `patterns:` block (pattern-regex + pattern-not-regex)
    /// loads and correctly applies negation.
    #[test]
    fn regex_lang_rule_patterns_block_with_negation() {
        let yaml = r#"
rules:
  - id: test/detect-artifactory-token
    patterns:
      - pattern-regex: "\\bAKC[a-zA-Z0-9]{10,}"
      - pattern-not-regex: "sha(128|256|512)"
    languages: [regex]
    message: Artifactory token detected
    severity: ERROR
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).unwrap();
        assert!(!rules.is_empty(), "should produce rule instances");

        let tree = parse_file("x = 1\n", Language::Python).unwrap();

        // Matching text without the excluded pattern — should fire.
        let matching = "token = \"AKCp1234567890abcdef\"\n";
        let findings = rules[0].check(matching, &tree);
        assert_eq!(
            findings.len(),
            1,
            "should fire on text matching pattern-regex"
        );

        // Text matching the negative pattern — should NOT fire.
        let negated = "hash = \"sha256_AKCp1234567890abcdef\"\n";
        let findings = rules[0].check(negated, &tree);
        assert!(
            findings.is_empty(),
            "should not fire when pattern-not-regex also matches"
        );
    }

    // ── Regression tests for "loader rejected (other)" fixes ────────────────

    /// Fix 1: `severity: MEDIUM` must load without error.
    ///
    /// Regression for rules such as `supply-chain/audit/go-audit-...` that
    /// use `MEDIUM` as their severity value.  Previously the serde deserialiser
    /// rejected the value because the enum only had ERROR/WARNING/INFO.
    #[test]
    fn test_severity_medium_loads() {
        let yaml = r#"
rules:
  - id: medium-sev-rule
    pattern: foo()
    message: medium severity rule
    severity: MEDIUM
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).expect("MEDIUM severity rule must load");
        assert_eq!(rules.len(), 1);
    }

    /// Fix 2: `metavariable-comparison:` without a `metavariable:` key must
    /// warn-skip the comparison constraint and still load the rule.
    ///
    /// Regression for rules such as `python/sql-injection-...` that use
    /// `comparison: str($F1) == str($F2)` (two metavar operands, no single
    /// bound metavar key).
    #[test]
    fn test_metavariable_comparison_without_metavariable_key_loads_rule() {
        let yaml = r#"
rules:
  - id: cmp-no-metavar-key
    patterns:
      - pattern: foo($F1, $F2)
      - metavariable-comparison:
          comparison: $F1 > $F2
    message: comparison without metavariable key
    severity: WARNING
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).expect(
            "rule with metavariable-comparison missing `metavariable:` key must still load",
        );
        assert_eq!(rules.len(), 1);
    }

    /// Fix 3: `metavariable-regex:` with a lookahead pattern must warn-skip
    /// the constraint and still load the rule.
    ///
    /// Regression for rules such as `javascript/hardcoded-...` that use
    /// `(?!...)` lookahead assertions in their `metavariable-regex` value.
    /// The Rust `regex` crate does not support PCRE lookaheads; previously
    /// this caused the entire rule to fail to load.
    #[test]
    fn test_metavariable_regex_with_lookahead_loads_rule() {
        let yaml = r#"
rules:
  - id: mv-regex-lookahead
    patterns:
      - pattern: |
          var $X = "...";
      - metavariable-regex:
          metavariable: $X
          regex: '(?!localhost).*'
    message: hardcoded non-localhost value
    severity: WARNING
    languages: [javascript]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path())
            .expect("rule with lookahead in metavariable-regex must still load");
        assert_eq!(rules.len(), 1);
    }

    /// Fix 4: `\Z` in a `pattern-regex` value must compile successfully.
    ///
    /// Regression for the PHP `assert-use-audit` rule which uses `\Z` (Python
    /// end-of-string anchor) in its primary `pattern-regex`.  The Rust `regex`
    /// crate uses `$` for the same purpose; we normalise `\Z` → `$` before
    /// compilation.
    #[test]
    fn test_pattern_regex_backslash_z_anchor_loads() {
        // `\Z` normalised to `$` — the rule must load without error.
        let yaml = r#"
rules:
  - id: pattern-regex-z-anchor
    pattern-regex: 'assert\s*\(\s*\$\w+\s*\)\s*\Z'
    message: assert usage
    severity: WARNING
    languages: [php]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path())
            .expect("pattern-regex with \\Z anchor must load after normalisation");
        assert_eq!(rules.len(), 1);
    }

    // ─── Dockerfile language tests ────────────────────────────────────────────

    /// A `languages: [dockerfile]` rule loads without error.
    #[test]
    fn test_dockerfile_language_rule_loads() {
        let yaml = r#"
rules:
  - id: dockerfile-no-latest
    pattern-regex: ':latest'
    message: Avoid using the latest tag in Dockerfile FROM instructions
    severity: WARNING
    languages: [dockerfile]
"#;
        let f = make_yaml(yaml);
        let rules =
            parse_semgrep_file(f.path()).expect("dockerfile language rule must load without error");
        assert_eq!(rules.len(), 1, "expected one rule for dockerfile language");
    }

    /// A `languages: [docker]` alias also loads.
    #[test]
    fn test_docker_language_alias_loads() {
        let yaml = r#"
rules:
  - id: docker-root-user
    pattern-regex: 'USER\s+root'
    message: Container should not run as root
    severity: ERROR
    languages: [docker]
"#;
        let f = make_yaml(yaml);
        let rules =
            parse_semgrep_file(f.path()).expect("docker language alias must load without error");
        assert!(
            !rules.is_empty(),
            "docker alias should produce rule instances"
        );
    }

    /// A `languages: [dockerfile]` `pattern-regex` rule matches inside a sample Dockerfile.
    #[test]
    fn test_dockerfile_pattern_regex_matches() {
        use crate::engine::parser::parse_path;
        use std::path::Path;

        let yaml = r#"
rules:
  - id: dockerfile-latest-tag
    pattern-regex: ':latest'
    message: Avoid :latest tag
    severity: WARNING
    languages: [dockerfile]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).expect("rule must load");
        assert_eq!(rules.len(), 1);

        let source = "FROM ubuntu:latest\nRUN apt-get update\nCMD [\"/bin/bash\"]\n";
        let tree = parse_path(source, Language::Dockerfile, Path::new("Dockerfile"))
            .expect("Dockerfile must parse");
        assert!(
            !tree.root_node().has_error(),
            "Dockerfile parse must be error-free"
        );

        let findings = rules[0].check(source, &tree);
        assert!(
            !findings.is_empty(),
            "pattern-regex ':latest' must match 'ubuntu:latest' in Dockerfile"
        );
    }

    /// A `languages: [bash]` rule loads successfully.
    #[test]
    fn test_bash_language_loads() {
        let yaml = r#"
rules:
  - id: bash-eval-call
    pattern: eval $X
    message: Avoid eval in bash
    severity: WARNING
    languages: [bash]
"#;
        let f = make_yaml(yaml);
        let rules =
            parse_semgrep_file(f.path()).expect("bash language rule must load without error");
        assert_eq!(rules.len(), 1, "expected one rule for bash language");
    }

    /// A `languages: [ocaml]` rule loads successfully.
    #[test]
    fn test_ocaml_language_loads() {
        let yaml = r#"
rules:
  - id: ocaml-pattern
    pattern-regex: 'Sys\.command'
    message: Avoid Sys.command
    severity: WARNING
    languages: [ocaml]
"#;
        let f = make_yaml(yaml);
        let rules =
            parse_semgrep_file(f.path()).expect("ocaml language rule must load without error");
        assert!(!rules.is_empty(), "expected rules for ocaml language");
    }

    /// A `languages: [apex]` `pattern:` rule loads and matches inside Apex source.
    #[test]
    fn test_apex_pattern_loads_and_matches() {
        use crate::engine::parser::parse_path;
        use std::path::Path;

        let yaml = r#"
rules:
  - id: apex-debug-call
    pattern: System.debug(...)
    message: Avoid System.debug
    severity: WARNING
    languages: [apex]
"#;
        let rules = parse_semgrep_str(yaml, "apex.yml")
            .expect("apex language rule must load without error");
        assert_eq!(rules.len(), 1, "expected one rule for apex language");

        let source = "public class A {\n  void f() {\n    System.debug('x');\n  }\n}\n";
        let tree = parse_path(source, Language::Apex, Path::new("A.cls")).expect("Apex must parse");
        assert!(
            !tree.root_node().has_error(),
            "Apex parse must be error-free"
        );
        let findings = rules[0].check(source, &tree);
        assert!(
            !findings.is_empty(),
            "pattern System.debug(...) must match in Apex"
        );
    }

    /// A `languages: [clojure]` `pattern:` rule loads and matches inside Clojure source.
    #[test]
    fn test_clojure_pattern_loads_and_matches() {
        use crate::engine::parser::parse_path;
        use std::path::Path;

        let yaml = r#"
rules:
  - id: clojure-eval-call
    pattern: (eval $X)
    message: Avoid eval
    severity: WARNING
    languages: [clojure]
"#;
        let rules = parse_semgrep_str(yaml, "clojure.yml")
            .expect("clojure language rule must load without error");
        assert_eq!(rules.len(), 1, "expected one rule for clojure language");

        let source = "(defn f [x]\n  (eval x))\n";
        let tree = parse_path(source, Language::Clojure, Path::new("core.clj"))
            .expect("Clojure must parse");
        assert!(
            !tree.root_node().has_error(),
            "Clojure parse must be error-free"
        );
        let findings = rules[0].check(source, &tree);
        assert!(
            !findings.is_empty(),
            "pattern (eval ...) must match in Clojure"
        );
    }

    /// A `languages: [html]` `pattern-regex` rule loads and matches inside HTML source.
    #[test]
    fn test_html_pattern_loads_and_matches() {
        use crate::engine::parser::parse_path;
        use std::path::Path;

        let yaml = r#"
rules:
  - id: html-inline-onclick
    pattern-regex: 'onclick='
    message: Avoid inline event handlers
    severity: WARNING
    languages: [html]
"#;
        let rules = parse_semgrep_str(yaml, "html.yml").expect("html language rule must load");
        assert_eq!(rules.len(), 1, "expected one rule for html language");

        let source =
            "<html>\n  <body>\n    <button onclick=\"go()\">x</button>\n  </body>\n</html>\n";
        let tree =
            parse_path(source, Language::Html, Path::new("index.html")).expect("HTML must parse");
        assert!(
            !tree.root_node().has_error(),
            "HTML parse must be error-free"
        );
        let findings = rules[0].check(source, &tree);
        assert!(
            !findings.is_empty(),
            "pattern-regex onclick= must match in HTML"
        );
    }

    /// A `languages: [xml]` `pattern-regex` rule loads and matches inside XML source.
    #[test]
    fn test_xml_pattern_loads_and_matches() {
        use crate::engine::parser::parse_path;
        use std::path::Path;

        let yaml = r#"
rules:
  - id: xml-doctype
    pattern-regex: '<!DOCTYPE'
    message: Avoid DOCTYPE declarations
    severity: WARNING
    languages: [xml]
"#;
        let rules = parse_semgrep_str(yaml, "xml.yml").expect("xml language rule must load");
        assert_eq!(rules.len(), 1, "expected one rule for xml language");

        let source =
            "<?xml version=\"1.0\"?>\n<!DOCTYPE root>\n<root>\n  <child>text</child>\n</root>\n";
        let tree =
            parse_path(source, Language::Xml, Path::new("data.xml")).expect("XML must parse");
        let findings = rules[0].check(source, &tree);
        assert!(
            !findings.is_empty(),
            "pattern-regex <!DOCTYPE must match in XML"
        );
    }

    /// A `languages: [dart]` search rule loads and matches inside Dart source.
    #[test]
    fn test_dart_pattern_loads_and_matches() {
        use crate::engine::parser::parse_path;
        use std::path::Path;

        let yaml = r#"
rules:
  - id: dart-print-call
    pattern-regex: 'print\('
    message: Avoid print
    severity: WARNING
    languages: [dart]
"#;
        let rules = parse_semgrep_str(yaml, "dart.yml").expect("dart language rule must load");
        assert_eq!(rules.len(), 1, "expected one rule for dart language");

        let source = "void main() {\n  print('hello');\n}\n";
        let tree =
            parse_path(source, Language::Dart, Path::new("main.dart")).expect("Dart must parse");
        assert!(
            !tree.root_node().has_error(),
            "Dart parse must be error-free"
        );
        let findings = rules[0].check(source, &tree);
        assert!(
            !findings.is_empty(),
            "pattern-regex print\\( must match in Dart"
        );
    }

    /// A `languages: [haskell]` `pattern-regex` rule loads and matches inside Haskell source.
    #[test]
    fn test_haskell_pattern_loads_and_matches() {
        use crate::engine::parser::parse_path;
        use std::path::Path;

        let yaml = r#"
rules:
  - id: haskell-foreign-import
    pattern-regex: '\bforeign\s+import\b'
    message: Review Haskell FFI boundary
    severity: WARNING
    languages: [haskell]
"#;
        let rules =
            parse_semgrep_str(yaml, "haskell.yml").expect("haskell language rule must load");
        assert_eq!(rules.len(), 1, "expected one rule for haskell language");

        let source = "module Bindings where\nforeign import ccall \"foo\" c_foo :: IO ()\n";
        let tree = parse_path(source, Language::Haskell, Path::new("Bindings.hs"))
            .expect("Haskell must parse");
        assert!(
            !tree.root_node().has_error(),
            "Haskell parse must be error-free"
        );
        let findings = rules[0].check(source, &tree);
        assert!(
            !findings.is_empty(),
            "pattern-regex foreign import must match in Haskell"
        );
    }

    /// A `languages: [scala]` rule loads successfully.
    #[test]
    fn test_scala_language_loads() {
        let yaml = r#"
rules:
  - id: scala-pattern
    pattern-regex: 'Runtime\.getRuntime\(\)'
    message: Avoid Runtime.getRuntime
    severity: WARNING
    languages: [scala]
"#;
        let f = make_yaml(yaml);
        let rules =
            parse_semgrep_file(f.path()).expect("scala language rule must load without error");
        assert!(!rules.is_empty(), "expected rules for scala language");
    }

    /// A `languages: [elixir]` rule loads successfully.
    #[test]
    fn test_elixir_language_loads() {
        let yaml = r#"
rules:
  - id: elixir-pattern
    pattern: System.cmd($CMD, ...)
    message: Avoid System.cmd with untrusted input
    severity: WARNING
    languages: [elixir]
"#;
        let f = make_yaml(yaml);
        let rules =
            parse_semgrep_file(f.path()).expect("elixir language rule must load without error");
        assert_eq!(rules.len(), 1, "expected one rule for elixir language");
    }

    /// A `languages: [json]` rule loads successfully.
    #[test]
    fn test_json_language_loads() {
        let yaml = r#"
rules:
  - id: json-pattern
    pattern-regex: '"password"\s*:\s*"[^"]+"'
    message: Hardcoded password in JSON
    severity: ERROR
    languages: [json]
"#;
        let f = make_yaml(yaml);
        let rules =
            parse_semgrep_file(f.path()).expect("json language rule must load without error");
        assert!(!rules.is_empty(), "expected rules for json language");
    }

    // ─── Regression tests for the PR #fix-loader-rejected-2 batch ────────────
    // Each test names the specific registry rule (or shape) that was previously
    // rejected and now must load.

    /// Bare `{{` in a `pattern-regex` (Flask/Django template rules).
    ///
    /// Regression for `template-unescaped-with-safe`, `template-autoescape-off`,
    /// `template-var-unescaped-with-safeseq`, `debug-template-tag`, etc.
    /// The Rust `regex` crate rejects bare `{` not forming a valid quantifier;
    /// we now escape them in `compile_regex` via `escape_bare_braces`.
    #[test]
    fn test_bare_double_brace_in_pattern_regex_loads() {
        let yaml = r#"
rules:
  - id: test/flask-template-safe-filter
    pattern-regex: '{{.*?\|\s*safe(\s*}})?'
    message: Jinja2 template uses |safe filter
    severity: WARNING
    languages: [regex]
    paths:
      include:
        - "*.html"
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path())
            .expect("pattern-regex with bare {{ must load after brace normalisation");
        assert!(
            !rules.is_empty(),
            "bare {{ pattern-regex rule must produce at least one rule instance"
        );
    }

    /// Bare `{%` in a `pattern-regex` (Flask autoescape-off rule).
    ///
    /// Regression for `template-autoescape-off` (flask, django).
    #[test]
    fn test_bare_brace_percent_in_pattern_regex_loads() {
        let yaml = r#"
rules:
  - id: test/flask-autoescape-off
    pattern-regex: '{%\s*autoescape\s+false\s*%}'
    message: Flask autoescape disabled
    severity: WARNING
    languages: [regex]
    paths:
      include:
        - "*.html"
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path())
            .expect("pattern-regex with bare {% must load after brace normalisation");
        assert!(
            !rules.is_empty(),
            "bare {{%}} pattern-regex rule must produce at least one rule instance"
        );
    }

    /// `{` followed by `[` (not a digit) in a `pattern-regex` (slow-pattern-general-func).
    ///
    /// Regression for `slow-pattern-general-func` (yaml language).
    #[test]
    fn test_bare_brace_before_bracket_in_pattern_regex_loads() {
        // `{[\s\n]*` — the `{` is not a valid quantifier start here.
        let yaml = r#"
rules:
  - id: test/slow-pattern
    pattern-regex: 'function[^{]*{[\s\n]*\.\.\.[\s\n]*}'
    message: Slow pattern
    severity: WARNING
    languages: [yaml]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path())
            .expect("pattern-regex with bare { before [ must load after brace normalisation");
        assert!(
            !rules.is_empty(),
            "rule must produce at least one instance after brace normalisation"
        );
    }

    /// `!{.*?}` in a `pattern-either` entry (Pug explicit-unescape rule).
    ///
    /// Regression for `template-explicit-unescape` (pug).  The rule uses two
    /// `pattern-either` entries; the `!{.*?}` entry previously caused the
    /// whole rule to fail.  After the brace-normalisation fix the entry loads
    /// and the rule produces matchers for the remaining entry too.
    #[test]
    fn test_bare_brace_in_pattern_either_entry_loads() {
        let yaml = r#"
rules:
  - id: test/pug-unescape
    pattern-either:
      - pattern-regex: '\w.*(!=)[^=].*'
      - pattern-regex: '!{.*?}'
    message: Pug explicit unescape
    severity: WARNING
    languages: [regex]
    paths:
      include:
        - "*.pug"
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path())
            .expect("pattern-either with bare { entry must load after brace normalisation");
        assert!(
            !rules.is_empty(),
            "rule with pattern-either including bare-brace regex must load"
        );
    }

    /// Lookahead in a `pattern-either` entry must be gracefully skipped.
    ///
    /// Regression for `aws-lambda-environment-credentials` (hcl): its
    /// `pattern-either:` block mixes `pattern-inside:` entries (which work)
    /// with `pattern-regex:` entries that use lookbehind (which Rust's
    /// `regex` crate rejects).  The bad `pattern-regex` entries should be
    /// warn-skipped; the two `pattern-inside` entries should still compile,
    /// and the rule should load.
    #[test]
    fn test_lookahead_in_pattern_either_entry_is_gracefully_skipped() {
        let yaml = r#"
rules:
  - id: test/aws-credential-detection
    patterns:
      - pattern-inside: |
          resource "$ANY" $ANYTHING {
            ...
          }
      - pattern-either:
          - pattern-inside: 'AWS_ACCESS_KEY_ID = "$Y"'
          - pattern-regex: '(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])'
          - pattern-inside: 'AWS_SECRET_ACCESS_KEY = "$Y"'
      - focus-metavariable: $Y
    message: Hardcoded AWS credential
    severity: ERROR
    languages: [hcl]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path())
            .expect("rule with lookahead in pattern-either must load with the bad entry skipped");
        // The rule loads (the two pattern-inside entries survive); it may not
        // match the exact HCL shape but it must not be rejected entirely.
        assert!(
            !rules.is_empty(),
            "rule must produce at least one rule instance"
        );
    }

    /// `pattern-not-regex` with a backreference must be gracefully skipped.
    ///
    /// Regression for `detected-artifactory-password`: its `patterns:` block
    /// has valid `pattern-regex` positives but a `pattern-not-regex` using
    /// `\1` (backreference).  The bad negative should be warn-skipped and the
    /// rule should load with the remaining patterns intact.
    #[test]
    fn test_backreference_in_pattern_not_regex_is_gracefully_skipped() {
        let yaml = r#"
rules:
  - id: test/artifactory-password
    patterns:
      - pattern-regex: '\bAP[0-9A-F][a-zA-Z0-9]{8,}'
      - pattern-regex: '(?i)artifactory'
      - pattern-not-regex: '(\w|\.|\*)\1{4}'
    languages: [regex]
    message: Artifactory token detected
    severity: ERROR
    paths:
      exclude:
        - "*.svg"
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).expect(
            "rule with backreference in pattern-not-regex must load with that entry skipped",
        );
        assert!(
            !rules.is_empty(),
            "rule must produce at least one rule instance"
        );
    }

    /// `pattern-not-inside:` with a nested `patterns:` block must load.
    ///
    /// Regression for `last-user-is-root` (dockerfile): the rule uses
    /// `pattern-not-inside:` with a map value (`patterns: [...]`) instead of
    /// a plain string.  Previously the YAML deserializer rejected this with
    /// "invalid type: map, expected a string".
    ///
    /// After the fix, the outermost `pattern:` string is extracted from the
    /// nested block and used as the `not_inside` constraint; the inner
    /// `metavariable-pattern:` sub-constraint is gracefully dropped.
    #[test]
    fn test_pattern_not_inside_nested_block_loads() {
        let yaml = r#"
rules:
  - id: test/last-user-is-root
    patterns:
      - pattern: USER root
      - pattern-not-inside:
          patterns:
            - pattern: |
                USER root
                ...
                USER $X
            - metavariable-pattern:
                metavariable: $X
                patterns:
                  - pattern-not: root
    message: Last container user is root
    severity: ERROR
    languages: [dockerfile]
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path())
            .expect("rule with nested patterns: block inside pattern-not-inside: must load");
        assert!(
            !rules.is_empty(),
            "rule must produce at least one rule instance"
        );
    }

    /// `{{{` triple brace in a `pattern-either` (Mustache explicit-unescape).
    ///
    /// Regression for `template-explicit-unescape` (mustache): its second
    /// `pattern-either` entry `{{[\s]*&.*}}` should load after brace
    /// normalisation.  The first entry (which also has a lookahead) is
    /// gracefully skipped; the rule still loads from the second entry.
    #[test]
    fn test_double_brace_ampersand_pattern_in_pattern_either_loads() {
        let yaml = r#"
rules:
  - id: test/mustache-unescape
    pattern-either:
      - pattern-regex: '{{{((?!include).)*?}}}'
      - pattern-regex: '{{[\s]*&.*}}'
    message: Mustache explicit unescape
    severity: WARNING
    languages: [regex]
    paths:
      include:
        - "*.mustache"
        - "*.hbs"
        - "*.html"
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path()).expect(
            "mustache pattern-either with brace+lookahead entry must load (second entry survives)",
        );
        assert!(
            !rules.is_empty(),
            "rule must produce at least one rule instance from the second pattern-either entry"
        );
    }

    /// `brace_normalisation` unit tests for the `escape_bare_braces` helper.
    ///
    /// Verifies that:
    /// - `{N}`, `{N,}`, `{N,M}` quantifiers are left untouched.
    /// - `{{`, `{%`, `{[`, `!{` (non-quantifier) are escaped to `\{`.
    /// - Already-escaped `\{` is not double-escaped.
    /// - Character classes `[{]` are left alone (the `{` inside is already
    ///   literal in that context).
    #[test]
    fn test_escape_bare_braces_quantifiers_unchanged() {
        // Valid quantifiers must pass through unchanged.
        assert_eq!(escape_bare_braces(r"[A-Z]{20}"), r"[A-Z]{20}");
        assert_eq!(escape_bare_braces(r"foo{1,3}bar"), r"foo{1,3}bar");
        assert_eq!(escape_bare_braces(r"\w{8,}"), r"\w{8,}");
    }

    #[test]
    fn test_escape_bare_braces_template_syntax_escaped() {
        // Template syntax uses `{{` / `{%` without escaping — these must be
        // rewritten to `\{` forms so Rust's `regex` crate accepts them.
        let result = escape_bare_braces(r"{{.*?\|\s*safe(\s*}})?");
        // The compiled regex must be accepted by Rust's regex crate.
        Regex::new(&result).expect("normalised regex must compile");

        let result2 = escape_bare_braces(r"{%\s*autoescape\s+false\s*%}");
        Regex::new(&result2).expect("normalised regex must compile");

        let result3 = escape_bare_braces(r"!{.*?}");
        Regex::new(&result3).expect("normalised regex must compile");
    }

    #[test]
    fn test_escape_bare_braces_already_escaped_not_doubled() {
        // `\{` is already escaped; `escape_bare_braces` must not add another `\`.
        let input = r"\{foo\}";
        let result = escape_bare_braces(input);
        assert_eq!(
            result, input,
            "already-escaped braces must not be double-escaped"
        );
    }

    #[test]
    fn test_escape_bare_braces_inside_char_class_unchanged() {
        // `[{]` — `{` inside a character class is already literal; the
        // normalisation should leave it (and its surrounding class) intact.
        let input = r"[{}\s]*";
        let result = escape_bare_braces(input);
        Regex::new(&result).expect("normalised regex must compile");
    }

    /// `compile_regex` must keep using the fast `regex` crate for ordinary
    /// patterns that contain no PCRE-only features — the fancy-regex fallback
    /// is reserved for patterns the fast engine rejects.
    #[test]
    fn test_compile_regex_fast_path_for_plain_pattern() {
        let compiled = compile_regex(r"password\s*=").expect("plain pattern must compile");
        assert!(
            matches!(compiled, CompiledRegex::Fast(_)),
            "a pattern with no lookaround/backref must compile on the fast `regex` crate"
        );
        assert!(
            compiled.is_match("password = 'hunter2'"),
            "fast-path regex must match the obvious case"
        );
        assert!(
            !compiled.is_match("token = 'hunter2'"),
            "fast-path regex must not match unrelated text"
        );
        // The fast engine reports byte ranges just like the fancy one.
        assert_eq!(
            compiled.find_matches("x; password=1"),
            vec![(3, 12)],
            "fast-path find_matches must return the matched byte range"
        );
    }

    /// `compile_regex` must transparently fall back to the backtracking
    /// `fancy-regex` engine when the fast `regex` crate rejects a PCRE
    /// lookahead, and the resulting matcher must honour the lookahead.
    #[test]
    fn test_compile_regex_fancy_path_for_lookahead() {
        // Anchored negative lookahead: at the start of the string, match
        // `password =` only when it is NOT prefixed by `test_`. Anchoring with
        // `^` ties the negative lookahead to the whole-line result so the
        // exclusion is observable. The fast `regex` crate rejects `(?!...)`.
        let pattern = r"^(?!test_)password\s*=";
        assert!(
            Regex::new(pattern).is_err(),
            "sanity: the fast `regex` crate must reject this lookahead pattern"
        );

        let compiled = compile_regex(pattern).expect("lookahead pattern must compile via fallback");
        assert!(
            matches!(compiled, CompiledRegex::Fancy(_)),
            "a lookahead pattern must compile on the fancy-regex fallback engine"
        );

        // Real password assignment → the negative lookahead allows the match.
        assert!(
            compiled.is_match("password = 'secret'"),
            "fancy-path regex must match a non-test password assignment"
        );
        // `test_password =` → the `^` anchor pins the match attempt to position
        // 0, where the negative lookahead `(?!test_)` fails, so there is no
        // match anywhere.
        assert!(
            !compiled.is_match("test_password = 'secret'"),
            "fancy-path regex must reject a `test_`-prefixed password assignment"
        );
    }

    /// End-to-end: a `languages: [regex]` rule whose `pattern-regex` uses a PCRE
    /// lookahead now LOADS (previously warn-skipped as `loader rejected
    /// (other)`) and fires on the right source while sparing the excluded one.
    #[test]
    fn regex_lang_rule_with_lookahead_loads_and_matches() {
        let yaml = r#"
rules:
  - id: test/lookahead-password
    pattern-regex: '^(?!test_)password\s*='
    languages: [regex]
    message: Hardcoded password assignment
    severity: ERROR
"#;
        let f = make_yaml(yaml);
        let rules = parse_semgrep_file(f.path())
            .expect("lookahead pattern-regex rule must load via the fancy-regex fallback");
        assert!(
            !rules.is_empty(),
            "lookahead regex-mode rule must produce at least one rule instance"
        );

        // Source the rule SHOULD flag (real password assignment).
        let hit_src = "password = 'hunter2'\n";
        let tree = parse_file(hit_src, Language::Python).unwrap();
        let findings = rules[0].check(hit_src, &tree);
        assert!(
            !findings.is_empty(),
            "rule must fire on a non-test password assignment"
        );

        // Source the rule should NOT flag (the `test_` prefix is excluded by the
        // negative lookahead).
        let miss_src = "test_password = 'hunter2'\n";
        let tree = parse_file(miss_src, Language::Python).unwrap();
        let findings = rules[0].check(miss_src, &tree);
        assert!(
            findings.is_empty(),
            "rule must NOT fire when the negative lookahead excludes the match"
        );
    }

    /// Bridge-level test for the generic-mode lookahead lever. A
    /// `languages: [generic]` rule whose `pattern-regex` uses a negative
    /// lookahead (`(?!\S)`, the exact shape of the registry rule
    /// `google-maps-apikeyleak`) must now LOAD via `parse_semgrep_str` and FIRE
    /// through the scanner entrypoint (`rule.check`), with a safe near-miss.
    /// Previously the generic-mode `regex` crate rejected the lookahead and the
    /// rule produced no live matcher (counted as a generic-mode skip).
    #[test]
    fn generic_lang_rule_with_lookahead_loads_and_fires() {
        let yaml = r#"
rules:
  - id: test/generic-maps-apikey
    patterns:
      - pattern-regex: 'AIza[0-9A-Za-z_\-]{4}(?!\S)'
    languages: [generic]
    message: Detected a Google Maps API key
    severity: WARNING
"#;
        let rules = parse_semgrep_str(yaml, "generic-lookahead.yml")
            .expect("generic-mode rule with lookahead must load via fancy-regex");
        assert!(
            !rules.is_empty(),
            "generic-mode lookahead rule must produce at least one rule instance"
        );

        // Generic-mode rules ignore the tree; any valid tree satisfies the
        // `Rule::check` signature. The key must be at a token boundary: here it
        // is followed by whitespace, so the `(?!\S)` lookahead is satisfied.
        let firing = "key = AIza1234\nnext line\n";
        let tree = parse_file(firing, Language::JavaScript).unwrap();
        let findings = rules[0].check(firing, &tree);
        assert!(
            !findings.is_empty(),
            "generic lookahead rule must fire on a key followed by whitespace"
        );

        // Near-miss: the key token is immediately followed by another non-space
        // char, so the negative lookahead `(?!\S)` fails and nothing matches.
        let safe = "key = AIza1234EXTRA\n";
        let tree = parse_file(safe, Language::JavaScript).unwrap();
        let findings = rules[0].check(safe, &tree);
        assert!(
            findings.is_empty(),
            "generic lookahead rule must NOT fire when the lookahead is violated"
        );
    }

    // ── metavariable-type (search mode) ──────────────────────────────────────

    const METAVAR_TYPE_JAVA_RULE: &str = r#"
rules:
  - id: sql-execute-on-statement
    patterns:
      - pattern: $X.executeQuery($Q)
      - metavariable-type:
          metavariable: $X
          type: Statement
    message: executeQuery on a Statement
    severity: ERROR
    languages: [java]
"#;

    /// metavariable-type FIRES when the metavariable's declared type matches.
    #[test]
    fn test_metavariable_type_fires_on_matching_type() {
        let f = make_yaml(METAVAR_TYPE_JAVA_RULE);
        let rules = parse_semgrep_file(f.path()).expect("rule must load for java");
        assert_eq!(rules.len(), 1, "one java rule expected");

        let source = "class A { void m(String q) { Statement s; s.executeQuery(q); } }";
        let tree = parse_file(source, Language::Java).unwrap();
        let findings = rules[0].check(source, &tree);
        assert_eq!(
            findings.len(),
            1,
            "must fire when $X is declared as Statement"
        );
    }

    /// metavariable-type is SILENT when the declared type differs (a subtype
    /// with a name that merely *contains* the required type name must not match).
    #[test]
    fn test_metavariable_type_silent_on_wrong_type() {
        let f = make_yaml(METAVAR_TYPE_JAVA_RULE);
        let rules = parse_semgrep_file(f.path()).expect("rule must load for java");

        let source = "class A { void m(String q) { PreparedStatement p; p.executeQuery(q); } }";
        let tree = parse_file(source, Language::Java).unwrap();
        let findings = rules[0].check(source, &tree);
        assert!(
            findings.is_empty(),
            "must not fire when $X is a PreparedStatement, not a Statement"
        );
    }

    /// A parameter's declared type is resolvable too (not just locals).
    #[test]
    fn test_metavariable_type_resolves_parameter() {
        let f = make_yaml(METAVAR_TYPE_JAVA_RULE);
        let rules = parse_semgrep_file(f.path()).expect("rule must load for java");

        let fires = "class A { void m(Statement s, String q) { s.executeQuery(q); } }";
        let tree = parse_file(fires, Language::Java).unwrap();
        assert_eq!(
            rules[0].check(fires, &tree).len(),
            1,
            "must fire when the Statement is a method parameter"
        );

        let silent = "class A { void m(PreparedStatement s, String q) { s.executeQuery(q); } }";
        let tree = parse_file(silent, Language::Java).unwrap();
        assert!(
            rules[0].check(silent, &tree).is_empty(),
            "must not fire when the parameter is a PreparedStatement"
        );
    }

    /// Fully-qualified declared types match by simple name (`java.sql.Statement`
    /// satisfies `type: Statement`).
    #[test]
    fn test_metavariable_type_matches_qualified_name() {
        let f = make_yaml(METAVAR_TYPE_JAVA_RULE);
        let rules = parse_semgrep_file(f.path()).expect("rule must load for java");

        let source = "class A { void m(String q) { java.sql.Statement s; s.executeQuery(q); } }";
        let tree = parse_file(source, Language::Java).unwrap();
        assert_eq!(
            rules[0].check(source, &tree).len(),
            1,
            "qualified type java.sql.Statement must satisfy type: Statement"
        );
    }

    /// A `metavariable-type:` rule on a language with no syntactic type
    /// resolution (python) is SKIPPED by the loader rather than loaded with the
    /// constraint dropped (which would over-match).
    #[test]
    fn test_metavariable_type_unenforceable_language_skips_rule() {
        let yaml = r#"
rules:
  - id: py-concat
    patterns:
      - pattern: $X + $Y
      - metavariable-type:
          metavariable: $X
          type: str
    message: string concat
    severity: ERROR
    languages: [python]
"#;
        let f = make_yaml(yaml);
        let result = parse_semgrep_file(f.path());
        assert!(
            result.is_err(),
            "metavariable-type on python must cause the rule to be skipped, not loaded"
        );
    }
}
