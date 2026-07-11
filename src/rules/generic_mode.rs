//! Semgrep `generic` mode (a.k.a. spacegrep / `languages: [generic]`).
//!
//! Generic mode does **not** use a tree-sitter AST. It matches a tokenized
//! pattern against the raw text of a file, where:
//!
//! * `...` is an ellipsis that matches any run of tokens (including across
//!   whitespace and newlines, per semgrep's default for generic patterns),
//! * `$X` metavariables bind a single token span and enforce equality (the
//!   same metavariable must bind the same text everywhere it appears),
//! * every other token must match literally.
//!
//! This module is intentionally self-contained so it can evolve without
//! touching the AST-backed Semgrep bridge in `semgrep_compat.rs`. The compat
//! bridge only routes `languages: [generic]` (and the `regex` alias) rules
//! here; all generic/spacegrep matching logic lives in this file.
//!
//! ## Scope
//!
//! Supported: `pattern`, `pattern-either`, `patterns:` (AND-block with
//! `pattern:`, `pattern-not:`, `pattern-regex:`, `pattern-not-regex:`, and
//! nested `pattern-either:`), `pattern-regex:` / `pattern-not-regex:`
//! (passthrough against raw text), `...` ellipsis, `$METAVAR` binding with
//! equality enforcement, and `paths.include` / `paths.exclude` scoping
//! (handled by the shared [`PathFilter`] on the compat side).
//!
//! Also supported: a `pattern-either` arm that is itself a `patterns:`
//! AND-block, and **metavariable constraints over named regex captures** —
//! when a `pattern-regex` has `(?P<NAME>…)` groups and a sibling
//! `metavariable-regex` / `metavariable-comparison` references `$NAME`, the
//! constraint is evaluated against the captured group text at match time and a
//! candidate is reported only when every constraint passes (see
//! [`GenericMatcher::RegexConstraints`]). `focus-metavariable: $NAME` narrows
//! the reported span to that capture.
//!
//! Deliberately **not** implemented here: `metavariable-pattern` and
//! `metavariable-analysis` in generic mode (a `patterns:` arm that carries one
//! refuses to load rather than silently dropping the constraint and broadening
//! into false positives — see `build_patterns_block`), `pattern-inside` /
//! `pattern-not-inside` for generic mode (warn-skipped gracefully), and the
//! deep-vs-shallow ellipsis brace-aware matching semgrep applies to
//! brace-delimited languages. Generic mode here treats the file as a flat
//! token stream.

use crate::rules::common::get_source_line;
use crate::rules::semgrep_compat::PathFilter;
use crate::rules::Rule;
use crate::{Finding, Language, Severity};
use fancy_regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Every file language foxguard can hand to a rule. A generic-mode rule is
/// language-agnostic — semgrep runs it against any file that matches the
/// rule's `paths:` scope — so we register one rule instance per detectable
/// language and let the (shared) [`PathFilter`] narrow the targets. The
/// compiled matcher is shared via `Arc`, so the per-language fan-out is cheap.
const ALL_LANGUAGES: &[Language] = &[
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

// ─── Tokenizer ──────────────────────────────────────────────────────────────

/// A single token with its byte span in the original source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Token<'a> {
    text: &'a str,
    start: usize,
    end: usize,
}

/// Tokenize `source` into a flat stream of word / punctuation tokens,
/// discarding whitespace. A "word" is a maximal run of ASCII alphanumerics
/// and underscores; every other non-whitespace byte becomes its own
/// single-character token. This mirrors spacegrep's default tokenization
/// closely enough for the config-file rule packs we target.
fn tokenize(source: &str) -> Vec<Token<'_>> {
    let mut tokens = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if is_word_byte(b) {
            let start = i;
            while i < bytes.len() && is_word_byte(bytes[i]) {
                i += 1;
            }
            tokens.push(Token {
                text: &source[start..i],
                start,
                end: i,
            });
        } else {
            // Multi-byte UTF-8 punctuation: take the whole char so byte spans
            // stay on char boundaries.
            let char_len = utf8_char_len(b);
            let end = (i + char_len).min(source.len());
            tokens.push(Token {
                text: &source[i..end],
                start: i,
                end,
            });
            i = end;
        }
    }
    tokens
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn utf8_char_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else if first >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

// ─── Compiled pattern ─────────────────────────────────────────────────────────

/// A single element of a tokenized generic pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PatternElem {
    /// `...` — matches any run of tokens (zero or more).
    Ellipsis,
    /// `$X` — binds a single token's text, enforcing equality on repeats.
    Metavar(String),
    /// A literal token that must match exactly.
    Literal(String),
}

/// Compile a generic pattern string into a token sequence.
fn compile_pattern(pattern: &str) -> Vec<PatternElem> {
    tokenize(pattern)
        .into_iter()
        .map(|tok| classify(tok.text))
        .collect::<Vec<_>>()
        .pipe_coalesce_ellipsis()
}

/// Classify a single pattern token. The `$` of a metavariable tokenizes
/// separately from its name (since `$` is punctuation and the name is a word),
/// so the `$ NAME` fold happens later in [`fold_dollars`].
fn classify(text: &str) -> RawElem {
    if text == "$" {
        RawElem::Dollar
    } else {
        RawElem::Elem(PatternElem::Literal(text.to_string()))
    }
}

/// Intermediate token before `$` + name coalescing and `.` + `.` + `.`
/// (ellipsis) coalescing.
#[derive(Debug, Clone)]
enum RawElem {
    Dollar,
    Elem(PatternElem),
}

trait CoalesceExt {
    fn pipe_coalesce_ellipsis(self) -> Vec<PatternElem>;
}

impl CoalesceExt for Vec<RawElem> {
    fn pipe_coalesce_ellipsis(self) -> Vec<PatternElem> {
        // First fold `$` + word into a metavar, then fold `.` `.` `.` into an
        // ellipsis. Both run in a single left-to-right pass each.
        let folded_metavars = fold_dollars(self);
        fold_ellipsis(folded_metavars)
    }
}

fn fold_dollars(raw: Vec<RawElem>) -> Vec<PatternElem> {
    let mut out = Vec::new();
    let mut iter = raw.into_iter().peekable();
    while let Some(elem) = iter.next() {
        match elem {
            RawElem::Dollar => {
                // `$` followed by a literal word → metavariable.
                if let Some(RawElem::Elem(PatternElem::Literal(name))) = iter.peek() {
                    if is_metavar_name(name) {
                        let name = name.clone();
                        iter.next();
                        out.push(PatternElem::Metavar(format!("${name}")));
                        continue;
                    }
                }
                // Lone `$` is a literal dollar sign.
                out.push(PatternElem::Literal("$".to_string()));
            }
            RawElem::Elem(e) => out.push(e),
        }
    }
    out
}

fn fold_ellipsis(elems: Vec<PatternElem>) -> Vec<PatternElem> {
    let mut out: Vec<PatternElem> = Vec::new();
    let mut dots = 0usize;
    for elem in elems {
        if matches!(&elem, PatternElem::Literal(l) if l == ".") {
            dots += 1;
            if dots == 3 {
                out.push(PatternElem::Ellipsis);
                dots = 0;
            }
            continue;
        }
        // Flush any pending stray dots (fewer than 3) as literals.
        for _ in 0..dots {
            out.push(PatternElem::Literal(".".to_string()));
        }
        dots = 0;
        out.push(elem);
    }
    for _ in 0..dots {
        out.push(PatternElem::Literal(".".to_string()));
    }
    out
}

fn is_metavar_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// ─── Metavariable constraints over named regex captures ─────────────────────────

/// Comparison operator for a `metavariable-comparison` over a named capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmpOp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

/// A constraint that a named regex capture group (`$NAME` → `(?P<NAME>…)`) must
/// satisfy for a [`GenericMatcher::RegexConstraints`] candidate to be reported.
///
/// Both forms drop the candidate (no match) when the referenced group did not
/// capture in the candidate (an absent binding can never satisfy the
/// constraint), mirroring Semgrep's "constraint over an unbound metavariable
/// fails" behaviour.
#[derive(Debug, Clone)]
enum MvConstraint {
    /// `metavariable-regex`: the captured group text must match `re`.
    Regex { group: String, re: Regex },
    /// `metavariable-comparison`: the captured group text, parsed as a number,
    /// must satisfy the comparison against `literal`. `literal_is_lhs` is true
    /// for `<number> <op> $VAR` (operands flipped).
    Compare {
        group: String,
        op: CmpOp,
        literal: f64,
        literal_is_lhs: bool,
    },
}

impl MvConstraint {
    /// Evaluate against the captured-group bindings collected for a candidate.
    fn passes(&self, captures: &HashMap<String, String>) -> bool {
        match self {
            MvConstraint::Regex { group, re } => captures
                .get(group)
                .is_some_and(|text| re.is_match(text).unwrap_or(false)),
            MvConstraint::Compare {
                group,
                op,
                literal,
                literal_is_lhs,
            } => {
                let Some(text) = captures.get(group) else {
                    return false;
                };
                let Some(value) = parse_numeric(text.trim()) else {
                    return false;
                };
                let (lhs, rhs) = if *literal_is_lhs {
                    (*literal, value)
                } else {
                    (value, *literal)
                };
                match op {
                    CmpOp::Lt => lhs < rhs,
                    CmpOp::Le => lhs <= rhs,
                    CmpOp::Gt => lhs > rhs,
                    CmpOp::Ge => lhs >= rhs,
                    CmpOp::Eq => (lhs - rhs).abs() < f64::EPSILON,
                    CmpOp::Ne => (lhs - rhs).abs() >= f64::EPSILON,
                }
            }
        }
    }

    /// The named capture group this constraint references.
    fn group(&self) -> &str {
        match self {
            MvConstraint::Regex { group, .. } | MvConstraint::Compare { group, .. } => group,
        }
    }
}

/// Build a `metavariable-regex` constraint over a named capture. The
/// `metavariable` is `$NAME`; we strip the `$` to get the regex group name.
/// Returns `None` (the caller warn-skips) if the regex does not compile.
fn build_mv_regex(metavariable: &str, regex: &str) -> Option<MvConstraint> {
    let group = metavariable.trim_start_matches('$').to_string();
    match compile_regex(regex) {
        Ok(re) => Some(MvConstraint::Regex { group, re }),
        Err(e) => {
            eprintln!(
                "Warning: generic metavariable-regex for {metavariable} did not compile ({e}); \
                 skipping constraint"
            );
            None
        }
    }
}

/// Build a `metavariable-comparison` constraint over a named capture. Only the
/// `$VAR <op> number` / `number <op> $VAR` subset is supported (the `int(...)`
/// wrapper Semgrep uses is stripped first). Returns `None` (warn-skip) for
/// anything outside that subset.
fn build_mv_comparison(metavariable: Option<&str>, comparison: &str) -> Option<MvConstraint> {
    let (group, op, literal, literal_is_lhs) = parse_generic_comparison(comparison)?;
    // If the YAML supplies an explicit `metavariable:` key, prefer it (it names
    // the capture even when the comparison expression wraps it, e.g.
    // `int($AGE) < 7`). Otherwise use the metavar parsed from the expression.
    let group = metavariable
        .map(|m| m.trim_start_matches('$').to_string())
        .unwrap_or(group);
    Some(MvConstraint::Compare {
        group,
        op,
        literal,
        literal_is_lhs,
    })
}

/// Parse a comparison string of the form `$VAR <op> <number>` or
/// `<number> <op> $VAR`, tolerating an `int(...)` / `str(...)` wrapper around
/// the metavariable. Returns the capture-group name (no `$`), the operator, the
/// numeric literal, and whether the literal is on the left.
fn parse_generic_comparison(comparison: &str) -> Option<(String, CmpOp, f64, bool)> {
    let s = comparison.trim();
    // Longest operator first so `<` does not pre-empt `<=`.
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
            let (metavar_side, literal_str, literal_is_lhs) = if let Some(g) = capture_name(lhs) {
                (g, rhs, false)
            } else {
                let g = capture_name(rhs)?;
                (g, lhs, true)
            };
            let literal = parse_numeric(literal_str.trim())?;
            return Some((metavar_side, *op, literal, literal_is_lhs));
        }
    }
    None
}

/// Extract the capture-group name from a comparison operand that is a (possibly
/// `int(...)`/`str(...)`-wrapped) metavariable like `$AGE`. Returns the name
/// without the leading `$`, or `None` if the operand is not a metavariable.
fn capture_name(operand: &str) -> Option<String> {
    let mut t = operand.trim();
    // Strip a single `int(...)` / `str(...)` / `float(...)` wrapper.
    for wrapper in ["int(", "str(", "float("] {
        if let Some(inner) = t.strip_prefix(wrapper) {
            if let Some(inner) = inner.strip_suffix(')') {
                t = inner.trim();
                break;
            }
        }
    }
    let name = t.strip_prefix('$')?;
    if !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        Some(name.to_string())
    } else {
        None
    }
}

/// Parse a decimal/hex/binary/float numeric literal into an `f64`.
fn parse_numeric(s: &str) -> Option<f64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0X").or_else(|| s.strip_prefix("0x")) {
        return i64::from_str_radix(hex, 16).ok().map(|v| v as f64);
    }
    if let Some(bin) = s.strip_prefix("0B").or_else(|| s.strip_prefix("0b")) {
        return i64::from_str_radix(bin, 2).ok().map(|v| v as f64);
    }
    s.parse::<f64>().ok()
}

// ─── Matcher ──────────────────────────────────────────────────────────────────

/// The compiled matching strategy for one generic rule.
#[derive(Debug, Clone)]
enum GenericMatcher {
    /// Tokenized pattern.
    Pattern(Vec<PatternElem>),
    /// `pattern-regex` passthrough against the raw text.
    Regex(Regex),
    /// `pattern-either` — any inner matcher matching is a match.
    Either(Vec<GenericMatcher>),
    /// A `patterns:` AND-block whose positives are `pattern-regex` with named
    /// capture groups, constrained by `metavariable-regex` /
    /// `metavariable-comparison` clauses that reference those captures (`$NAME`
    /// maps to the `(?P<NAME>…)` group). A candidate match (from the first
    /// regex) is kept only when every other positive regex also matches an
    /// overlapping span and every constraint passes against the captured group
    /// text. The reported span is the `focus-metavariable` capture's span when
    /// one is set, else the first regex's whole match.
    RegexConstraints {
        regexes: Vec<Regex>,
        constraints: Vec<MvConstraint>,
        focus: Option<String>,
    },
    /// One positive matcher with negative filters (`pattern-not`).
    ///
    /// A candidate is dropped if any negative matcher overlaps its span.
    Filtered {
        positive: Box<GenericMatcher>,
        negatives: Vec<GenericMatcher>,
    },
    /// `patterns:` AND-block: all positives must produce at least one match;
    /// matches from later positives are intersected (must overlap) with the
    /// accumulated set; negatives exclude any overlapping matches.
    ///
    /// This mirrors the AST-engine `Combined` path but over generic tokens.
    Combined {
        positives: Vec<GenericMatcher>,
        negatives: Vec<GenericMatcher>,
    },
}

#[derive(Debug, Clone)]
struct GenericMatch {
    start_byte: usize,
    end_byte: usize,
}

impl GenericMatcher {
    fn find_all(&self, source: &str, tokens: &[Token<'_>]) -> Vec<GenericMatch> {
        match self {
            GenericMatcher::Pattern(elems) => find_pattern(elems, tokens),
            GenericMatcher::Regex(re) => re
                .find_iter(source)
                // `fancy-regex` yields `Result<Match, _>` (a backtracking
                // failure surfaces as `Err`); skip errored steps and keep the
                // successful matches.
                .filter_map(|m| m.ok())
                .map(|m| GenericMatch {
                    start_byte: m.start(),
                    end_byte: m.end(),
                })
                .collect(),
            GenericMatcher::Either(inner) => {
                let mut all = Vec::new();
                for m in inner {
                    all.extend(m.find_all(source, tokens));
                }
                dedup(all)
            }
            GenericMatcher::RegexConstraints {
                regexes,
                constraints,
                focus,
            } => find_regex_constraints(source, regexes, constraints, focus.as_deref()),
            GenericMatcher::Filtered {
                positive,
                negatives,
            } => {
                let mut matches = positive.find_all(source, tokens);
                if !negatives.is_empty() {
                    apply_negatives(&mut matches, negatives, source, tokens);
                }
                matches
            }
            GenericMatcher::Combined {
                positives,
                negatives,
            } => {
                // AND semantics: start with all matches from the first positive,
                // then intersect with each subsequent positive (keep only those
                // that overlap at least one match from the next positive).
                // Finally, apply negatives.
                let mut candidates: Option<Vec<GenericMatch>> = None;
                for pos in positives {
                    let hits = pos.find_all(source, tokens);
                    candidates = Some(match candidates {
                        None => hits,
                        Some(prev) => {
                            // Intersect: keep prev matches that overlap ≥1 hit.
                            prev.into_iter()
                                .filter(|p| hits.iter().any(|h| overlaps(p, h)))
                                .collect()
                        }
                    });
                }
                let mut results = candidates.unwrap_or_default();
                if !negatives.is_empty() {
                    apply_negatives(&mut results, negatives, source, tokens);
                }
                results
            }
        }
    }
}

/// Apply negative matchers to a list of candidate matches.
///
/// Negative semantics:
/// - `Pattern` negatives: span-overlap — a positive match is dropped if any
///   negative *token-pattern* match overlaps its byte range.
/// - `Regex` negatives: file-level — if the regex matches **anywhere** in the
///   file, **all** positive matches are dropped. This mirrors Semgrep's
///   `pattern-not-regex` semantics in generic/regex mode where the regex is
///   evaluated against the whole file, not individual match spans.
fn apply_negatives(
    positives: &mut Vec<GenericMatch>,
    negatives: &[GenericMatcher],
    source: &str,
    tokens: &[Token<'_>],
) {
    for neg in negatives {
        if positives.is_empty() {
            break;
        }
        match neg {
            // Regex negative: file-level — if it matches anywhere, clear all.
            GenericMatcher::Regex(re) => {
                // `fancy-regex`'s `is_match` returns `Result`; treat a
                // backtracking error as "no match" (do not clear).
                if re.is_match(source).unwrap_or(false) {
                    positives.clear();
                }
            }
            // Pattern/Either/Filtered/Combined negatives: span-overlap.
            _ => {
                let neg_matches = neg.find_all(source, tokens);
                positives.retain(|m| !neg_matches.iter().any(|n| overlaps(m, n)));
            }
        }
    }
}

fn overlaps(a: &GenericMatch, b: &GenericMatch) -> bool {
    a.start_byte < b.end_byte && b.start_byte < a.end_byte
}

fn dedup(mut matches: Vec<GenericMatch>) -> Vec<GenericMatch> {
    matches.sort_by_key(|m| (m.start_byte, m.end_byte));
    matches.dedup_by_key(|m| (m.start_byte, m.end_byte));
    matches
}

/// Try to match `elems` against the token stream, starting at every token
/// position. Returns the byte span of each match.
fn find_pattern(elems: &[PatternElem], tokens: &[Token<'_>]) -> Vec<GenericMatch> {
    if elems.is_empty() {
        return Vec::new();
    }
    let mut matches = Vec::new();
    for start in 0..tokens.len() {
        let mut bindings: HashMap<String, String> = HashMap::new();
        if let Some(end_idx) = match_from(elems, tokens, start, &mut bindings) {
            // `end_idx` is one past the last matched token. Skip empty matches
            // (e.g. a pattern that is only a trailing ellipsis).
            if end_idx > start {
                let span_start = tokens[start].start;
                let span_end = tokens[end_idx - 1].end;
                matches.push(GenericMatch {
                    start_byte: span_start,
                    end_byte: span_end,
                });
            }
        }
    }
    dedup(matches)
}

/// Match a `patterns:` AND-block of named-capture `pattern-regex` clauses with
/// `metavariable-*` constraints over those captures.
///
/// Semantics (tailored to the generic-mode package-manager rules):
/// 1. Each match of the **first** regex is a candidate span.
/// 2. Named captures from that match seed the candidate's binding map.
/// 3. Every **other** positive regex must also match an overlapping span; its
///    named captures are merged in. If a required regex has no overlapping
///    match, the candidate is dropped (AND semantics).
/// 4. Every constraint must pass against the merged captures.
/// 5. The reported span is the `focus` capture's span when that group captured
///    in the candidate, else the first regex's whole match span.
fn find_regex_constraints(
    source: &str,
    regexes: &[Regex],
    constraints: &[MvConstraint],
    focus: Option<&str>,
) -> Vec<GenericMatch> {
    let Some((first, rest)) = regexes.split_first() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for cand in first.captures_iter(source).filter_map(|c| c.ok()) {
        let Some(whole) = cand.get(0) else { continue };
        let cand_start = whole.start();
        let cand_end = whole.end();

        // Seed bindings + focus span from the first regex's named captures.
        let mut captures: HashMap<String, String> = HashMap::new();
        let mut focus_span: Option<(usize, usize)> = None;
        collect_named(first, &cand, focus, &mut captures, &mut focus_span);

        // Require every other positive regex to match an overlapping span.
        let mut all_present = true;
        for re in rest {
            let mut matched = false;
            for c in re.captures_iter(source).filter_map(|c| c.ok()) {
                if let Some(m0) = c.get(0) {
                    if m0.start() < cand_end && cand_start < m0.end() {
                        collect_named(re, &c, focus, &mut captures, &mut focus_span);
                        matched = true;
                        break;
                    }
                }
            }
            if !matched {
                all_present = false;
                break;
            }
        }
        if !all_present {
            continue;
        }

        // Every metavariable constraint must reference a captured group and pass.
        if !constraints
            .iter()
            .all(|c| captures.contains_key(c.group()) && c.passes(&captures))
        {
            continue;
        }

        let (start_byte, end_byte) = focus_span.unwrap_or((cand_start, cand_end));
        out.push(GenericMatch {
            start_byte,
            end_byte,
        });
    }
    dedup(out)
}

/// Merge a regex match's named capture groups into `captures`, and record the
/// `focus` group's byte span when present.
fn collect_named(
    re: &Regex,
    caps: &fancy_regex::Captures<'_>,
    focus: Option<&str>,
    captures: &mut HashMap<String, String>,
    focus_span: &mut Option<(usize, usize)>,
) {
    for name in re.capture_names().flatten() {
        if let Some(m) = caps.name(name) {
            captures
                .entry(name.to_string())
                .or_insert_with(|| m.as_str().to_string());
            if Some(name) == focus && focus_span.is_none() {
                *focus_span = Some((m.start(), m.end()));
            }
        }
    }
}

/// Recursive token matcher. Returns the index one past the last matched token
/// on success. `...` matches a (lazy) run of tokens; `$X` binds one token with
/// equality enforcement; literals must match exactly.
fn match_from(
    elems: &[PatternElem],
    tokens: &[Token<'_>],
    mut ti: usize,
    bindings: &mut HashMap<String, String>,
) -> Option<usize> {
    let mut pi = 0;
    while pi < elems.len() {
        match &elems[pi] {
            PatternElem::Ellipsis => {
                // Trailing ellipsis matches the rest (including nothing); the
                // span ends at the last preceding matched token, so return the
                // current cursor position.
                if pi + 1 == elems.len() {
                    return Some(ti);
                }
                // Lazily advance: try to match the remainder of the pattern at
                // each subsequent token position.
                let rest = &elems[pi + 1..];
                for skip in ti..=tokens.len() {
                    let mut trial = bindings.clone();
                    if let Some(end) = match_from(rest, tokens, skip, &mut trial) {
                        *bindings = trial;
                        return Some(end);
                    }
                }
                return None;
            }
            PatternElem::Metavar(name) => {
                let tok = tokens.get(ti)?;
                if let Some(existing) = bindings.get(name) {
                    if existing != tok.text {
                        return None;
                    }
                } else {
                    bindings.insert(name.clone(), tok.text.to_string());
                }
                ti += 1;
                pi += 1;
            }
            PatternElem::Literal(lit) => {
                let tok = tokens.get(ti)?;
                if tok.text != lit {
                    return None;
                }
                ti += 1;
                pi += 1;
            }
        }
    }
    Some(ti)
}

// ─── Rule ─────────────────────────────────────────────────────────────────────

/// A compiled generic-mode rule. One instance per detectable language (the
/// matcher is shared via `Arc`); path filtering decides which files actually
/// run it.
pub struct GenericRule {
    id: String,
    message: String,
    severity: Severity,
    lang: Language,
    cwe: Option<String>,
    matcher: Arc<GenericMatcher>,
    path_filter: Option<Arc<PathFilter>>,
}

impl Rule for GenericRule {
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
        let tokens = tokenize(source);
        let mut matches = self.matcher.find_all(source, &tokens);
        matches.sort_by_key(|m| (m.start_byte, m.end_byte));
        matches.dedup_by_key(|m| (m.start_byte, m.end_byte));

        matches
            .into_iter()
            .map(|m| {
                let (line, column) = byte_offset_to_position(source, m.start_byte);
                let (end_line, end_column) = byte_offset_to_position(source, m.end_byte);
                Finding {
                    rule_id: self.id.clone(),
                    severity: self.severity,
                    cwe: self.cwe.clone(),
                    description: self.message.clone(),
                    file: String::new(),
                    line,
                    column,
                    end_line,
                    end_column,
                    snippet: get_source_line(source, m.start_byte),
                    source_line: None,
                    source_description: None,
                    sink_line: None,
                    sink_description: None,
                    fix_suggestion: None,
                    sink_start_byte: None,
                    sink_end_byte: None,
                    // Generic-mode matches are text-based and fuzzier than
                    // curated AST rules; mirror the AST-bridge default.
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
                }
            })
            .collect()
    }
}

fn byte_offset_to_position(source: &str, byte_offset: usize) -> (usize, usize) {
    let byte_offset = byte_offset.min(source.len());
    let prefix = &source[..byte_offset];
    let line = prefix.bytes().filter(|b| *b == b'\n').count() + 1;
    let line_start = prefix.rfind('\n').map_or(0, |pos| pos + 1);
    let column = byte_offset - line_start + 1;
    (line, column)
}

// ─── Construction (called from the compat bridge) ──────────────────────────────

// ─── Clause types for `patterns:` AND-blocks ────────────────────────────────

/// A single entry inside a `patterns:` (AND) block for generic mode.
///
/// Supports `pattern:`, `pattern-not:`, `pattern-regex:`, `pattern-not-regex:`,
/// and `pattern-either:` (OR of patterns). Unsupported sub-clauses such as
/// `pattern-inside:` / `pattern-not-inside:` and constraint clauses are
/// warn-skipped at the caller side; they do not abort sibling clauses.
#[derive(Debug, Clone, Default)]
pub struct GenericPatternsClause {
    /// A positive spacegrep pattern that must match.
    pub pattern: Option<String>,
    /// A positive raw-text regex that must match.
    pub pattern_regex: Option<String>,
    /// OR-list of patterns to treat as a single positive sub-matcher.
    pub pattern_either: Vec<GenericEitherEntry>,
    /// A negative spacegrep pattern that must NOT overlap any positive match.
    pub pattern_not: Option<String>,
    /// A negative raw-text regex that must NOT match anywhere.
    pub pattern_not_regex: Option<String>,
    /// `metavariable-regex:` over a named capture group of a sibling
    /// `pattern-regex` (`metavariable`, `regex`).
    pub metavariable_regex: Option<(String, String)>,
    /// `metavariable-comparison:` over a named capture group
    /// (`metavariable` (optional), `comparison`).
    pub metavariable_comparison: Option<(Option<String>, String)>,
    /// `focus-metavariable:` naming the named capture whose span should be the
    /// reported finding range.
    pub focus_metavariable: Option<String>,
    /// Set when the clause carries a constraint generic mode cannot enforce
    /// (`metavariable-pattern`, `metavariable-analysis`). Dropping such a
    /// constraint would broaden the rule into false positives, so the
    /// containing `patterns:` block is treated as unbuildable (the arm/rule is
    /// warn-skipped rather than loaded without the constraint).
    pub unsupported_constraint: bool,
}

/// One arm inside a `pattern-either:` list.
///
/// An arm is either a simple `pattern:` / `pattern-regex:`, or a nested
/// `patterns:` AND-block (its clauses live in `patterns`).
#[derive(Debug, Clone, Default)]
pub struct GenericEitherEntry {
    pub pattern: Option<String>,
    pub pattern_regex: Option<String>,
    /// A nested `patterns:` AND-block (used by the package-manager rules whose
    /// `pattern-either` arms are full AND-blocks with metavariable constraints
    /// over named regex captures).
    pub patterns: Vec<GenericPatternsClause>,
}

// ─── Matcher builders ─────────────────────────────────────────────────────────

/// Build a single `GenericMatcher` from a `pattern-either:` OR-list.
///
/// Each arm is a simple `pattern:` / `pattern-regex:`, or a nested `patterns:`
/// AND-block (with optional metavariable constraints over named captures). An
/// arm that fails to build is warn-skipped so sibling arms still load; the
/// whole OR-list errors only when *no* arm yields a matcher.
fn build_either_matcher(entries: &[GenericEitherEntry]) -> Result<GenericMatcher, String> {
    let mut inner = Vec::new();
    for entry in entries {
        if !entry.patterns.is_empty() {
            match build_patterns_block(&entry.patterns) {
                Ok(m) => inner.push(m),
                Err(e) => eprintln!(
                    "Warning: generic pattern-either arm (patterns: block) did not build ({e}); \
                     skipping arm"
                ),
            }
            continue;
        }
        if let Some(ref p) = entry.pattern {
            inner.push(GenericMatcher::Pattern(compile_pattern(p)));
        } else if let Some(ref re) = entry.pattern_regex {
            inner.push(GenericMatcher::Regex(compile_regex(re)?));
        }
    }
    if inner.is_empty() {
        return Err(
            "pattern-either: block has no supported pattern or pattern-regex entries".to_string(),
        );
    }
    if inner.len() == 1 {
        Ok(inner.into_iter().next().expect("checked len==1"))
    } else {
        Ok(GenericMatcher::Either(inner))
    }
}

/// Build a `GenericMatcher` from a `patterns:` AND-block, honouring
/// `metavariable-regex` / `metavariable-comparison` constraints over named
/// capture groups of the block's `pattern-regex` clauses and an optional
/// `focus-metavariable`.
///
/// When the block carries such metavariable constraints (or a focus on a named
/// capture), the positive `pattern-regex` clauses are compiled into a single
/// [`GenericMatcher::RegexConstraints`] so the constraints are *enforced* (not
/// dropped). Otherwise the block degrades to the plain `Combined`/`Filtered`
/// behaviour over its positive/negative matchers.
fn build_patterns_block(clauses: &[GenericPatternsClause]) -> Result<GenericMatcher, String> {
    // A clause carrying a constraint we cannot enforce (metavariable-pattern /
    // metavariable-analysis) must not silently load broadened — refuse the
    // whole block so the caller warn-skips it.
    if clauses.iter().any(|c| c.unsupported_constraint) {
        return Err(
            "patterns: block uses a constraint generic mode cannot enforce \
             (metavariable-pattern / metavariable-analysis)"
                .to_string(),
        );
    }

    // Gather constraints + focus across the whole block.
    let mut constraints: Vec<MvConstraint> = Vec::new();
    let mut focus: Option<String> = None;
    for clause in clauses {
        if let Some((ref mv, ref re)) = clause.metavariable_regex {
            if let Some(c) = build_mv_regex(mv, re) {
                constraints.push(c);
            }
        }
        if let Some((ref mv, ref cmp)) = clause.metavariable_comparison {
            if let Some(c) = build_mv_comparison(mv.as_deref(), cmp) {
                constraints.push(c);
            }
        }
        if focus.is_none() {
            if let Some(ref f) = clause.focus_metavariable {
                focus = Some(f.trim_start_matches('$').to_string());
            }
        }
    }

    // Collect positive pattern-regex sources and any spacegrep patterns.
    let mut regexes: Vec<Regex> = Vec::new();
    let mut other_positives: Vec<GenericMatcher> = Vec::new();
    let mut negatives: Vec<GenericMatcher> = Vec::new();
    for clause in clauses {
        if let Some(ref p) = clause.pattern {
            other_positives.push(GenericMatcher::Pattern(compile_pattern(p)));
        }
        if let Some(ref re) = clause.pattern_regex {
            match compile_regex(re) {
                Ok(r) => regexes.push(r),
                Err(e) => eprintln!(
                    "Warning: generic patterns clause has invalid pattern-regex: {e}; skipping clause"
                ),
            }
        }
        if !clause.pattern_either.is_empty() {
            match build_either_matcher(&clause.pattern_either) {
                Ok(m) => other_positives.push(m),
                Err(e) => eprintln!(
                    "Warning: generic patterns clause has invalid pattern-either: {e}; skipping clause"
                ),
            }
        }
        if let Some(ref pn) = clause.pattern_not {
            negatives.push(GenericMatcher::Pattern(compile_pattern(pn)));
        }
        if let Some(ref re) = clause.pattern_not_regex {
            match compile_regex(re) {
                Ok(r) => negatives.push(GenericMatcher::Regex(r)),
                Err(e) => eprintln!(
                    "Warning: generic patterns clause has invalid pattern-not-regex: {e}; skipping clause"
                ),
            }
        }
    }

    // Determine whether the constraints/focus actually reference named captures
    // present in the block's regexes. If so, build the enforcing matcher.
    let named: std::collections::HashSet<String> = regexes
        .iter()
        .flat_map(|r| r.capture_names().flatten().map(|s| s.to_string()))
        .collect();
    let focus_named = focus.as_ref().is_some_and(|f| named.contains(f));
    let constrained = !constraints.is_empty() || focus_named;

    // Assemble the list of positive matchers for the AND-block.
    let mut positives: Vec<GenericMatcher> = other_positives;
    if constrained && !regexes.is_empty() {
        // Constraints that reference a group absent from every regex can never
        // pass (an unbound capture fails the constraint), which would silently
        // make the arm dead. Reject so the caller warn-skips this arm rather
        // than loading a never-firing matcher.
        if let Some(missing) = constraints.iter().find(|c| !named.contains(c.group())) {
            return Err(format!(
                "metavariable constraint references capture '${}' not present in any pattern-regex",
                missing.group()
            ));
        }
        positives.push(GenericMatcher::RegexConstraints {
            regexes,
            constraints,
            // Only carry a focus that names a real capture group.
            focus: if focus_named { focus } else { None },
        });
    } else {
        // No enforceable named-capture constraints: each regex is a plain
        // positive and the existing Combined/Filtered semantics apply.
        positives.extend(regexes.into_iter().map(GenericMatcher::Regex));
    }

    if positives.is_empty() {
        return Err("generic patterns: block has no supported positive matchers".to_string());
    }

    if positives.len() == 1 && negatives.is_empty() {
        return Ok(positives.into_iter().next().expect("len==1"));
    }
    if positives.len() == 1 {
        return Ok(GenericMatcher::Filtered {
            positive: Box::new(positives.into_iter().next().expect("len==1")),
            negatives,
        });
    }
    Ok(GenericMatcher::Combined {
        positives,
        negatives,
    })
}

/// Build the generic matcher tree from the full rule spec.
///
/// Dispatch order:
/// 1. `patterns:` AND-block if present → `Combined` matcher.
/// 2. Top-level `pattern-either:` → `Either` matcher (with optional `pattern-not`).
/// 3. Top-level `pattern:` → `Pattern` (with optional `pattern-not`).
/// 4. Top-level `pattern-regex:` → `Regex` (with optional `pattern-not-regex`).
/// 5. Else → error (no expressible matcher).
fn build_matcher(spec: &GenericRuleSpec<'_>) -> Result<GenericMatcher, String> {
    // ── 1. `patterns:` AND-block ──────────────────────────────────────────────
    if !spec.patterns_clauses.is_empty() {
        return build_patterns_block(&spec.patterns_clauses);
    }

    // ── 2–5. Top-level single-operator forms ──────────────────────────────────

    // Helper: wrap in Filtered when there are negatives.
    let wrap_with_negatives = |positive: GenericMatcher,
                               pattern_not: Option<&str>,
                               pattern_not_regex: Option<&str>|
     -> Result<GenericMatcher, String> {
        let mut negatives: Vec<GenericMatcher> = Vec::new();
        if let Some(pn) = pattern_not {
            negatives.push(GenericMatcher::Pattern(compile_pattern(pn)));
        }
        if let Some(re) = pattern_not_regex {
            negatives.push(GenericMatcher::Regex(compile_regex(re)?));
        }
        if negatives.is_empty() {
            Ok(positive)
        } else {
            Ok(GenericMatcher::Filtered {
                positive: Box::new(positive),
                negatives,
            })
        }
    };

    if !spec.pattern_either.is_empty() {
        let positive = build_either_matcher(&spec.pattern_either)?;
        return wrap_with_negatives(positive, spec.pattern_not, spec.pattern_not_regex);
    }

    if let Some(p) = spec.pattern {
        let positive = GenericMatcher::Pattern(compile_pattern(p));
        return wrap_with_negatives(positive, spec.pattern_not, spec.pattern_not_regex);
    }

    if let Some(re) = spec.pattern_regex {
        let positive = GenericMatcher::Regex(compile_regex(re)?);
        return wrap_with_negatives(positive, spec.pattern_not, spec.pattern_not_regex);
    }

    Err("generic rule has no expressible matcher (no pattern / pattern-regex / pattern-either / patterns)".to_string())
}

fn compile_regex(pattern: &str) -> Result<Regex, String> {
    // `\Z` is a Python/PCRE end-of-string anchor; normalise to `$` for
    // consistency (same semantics with MULTILINE off). `fancy-regex` (a
    // backtracking engine) is used here instead of the `regex` crate so that
    // lookaround assertions (`(?=...)`, `(?!...)`) used by several generic-mode
    // registry rules compile.
    let normalised = pattern.replace(r"\Z", "$");
    Regex::new(&normalised).map_err(|e| format!("Invalid pattern-regex '{pattern}': {e}"))
}

/// Parameters extracted from the compat YAML layer, kept as a small POD so the
/// compat-side dispatch stays a couple of lines.
pub struct GenericRuleSpec<'a> {
    pub id: &'a str,
    pub message: &'a str,
    pub severity: Severity,
    pub cwe: Option<String>,
    /// Top-level `pattern:`.
    pub pattern: Option<&'a str>,
    /// Top-level `pattern-regex:`.
    pub pattern_regex: Option<&'a str>,
    /// Top-level `pattern-either:` entries (may contain `pattern:` and/or
    /// `pattern-regex:` arms).
    pub pattern_either: Vec<GenericEitherEntry>,
    /// Top-level `pattern-not:`.
    pub pattern_not: Option<&'a str>,
    /// Top-level `pattern-not-regex:`.
    pub pattern_not_regex: Option<&'a str>,
    /// `patterns:` AND-block clauses.
    pub patterns_clauses: Vec<GenericPatternsClause>,
    pub path_filter: Option<PathFilter>,
}

/// Compile a generic-mode rule spec into one boxed [`GenericRule`] per
/// detectable language. The compiled matcher and path filter are shared via
/// `Arc` so the fan-out is cheap.
pub fn build_generic_rules(spec: GenericRuleSpec<'_>) -> Result<Vec<Box<dyn Rule>>, String> {
    let matcher = Arc::new(build_matcher(&spec)?);
    let path_filter = spec.path_filter.map(Arc::new);

    let rules = ALL_LANGUAGES
        .iter()
        .map(|&lang| {
            Box::new(GenericRule {
                id: format!("semgrep/{}", spec.id),
                message: spec.message.to_string(),
                severity: spec.severity,
                lang,
                cwe: spec.cwe.clone(),
                matcher: Arc::clone(&matcher),
                path_filter: path_filter.clone(),
            }) as Box<dyn Rule>
        })
        .collect();

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, source: &str) -> Vec<(usize, usize)> {
        let m = GenericMatcher::Pattern(compile_pattern(pattern));
        let tokens = tokenize(source);
        m.find_all(source, &tokens)
            .into_iter()
            .map(|m| byte_offset_to_position(source, m.start_byte))
            .collect()
    }

    #[test]
    fn tokenizes_words_and_punctuation() {
        let toks: Vec<&str> = tokenize("ssl_protocols TLSv1;")
            .iter()
            .map(|t| t.text)
            .collect();
        assert_eq!(toks, vec!["ssl_protocols", "TLSv1", ";"]);
    }

    #[test]
    fn compiles_metavar_and_ellipsis() {
        let elems = compile_pattern("listen $PORT ... ssl");
        assert_eq!(
            elems,
            vec![
                PatternElem::Literal("listen".to_string()),
                PatternElem::Metavar("$PORT".to_string()),
                PatternElem::Ellipsis,
                PatternElem::Literal("ssl".to_string()),
            ]
        );
    }

    #[test]
    fn lone_dollar_is_literal() {
        let elems = compile_pattern("cost $ 5");
        assert_eq!(
            elems,
            vec![
                PatternElem::Literal("cost".to_string()),
                PatternElem::Literal("$".to_string()),
                PatternElem::Literal("5".to_string()),
            ]
        );
    }

    #[test]
    fn literal_match_finds_line() {
        let positions = matches(
            "ssl_protocols TLSv1",
            "server {\n  ssl_protocols TLSv1;\n}\n",
        );
        assert_eq!(positions, vec![(2, 3)]);
    }

    #[test]
    fn ellipsis_matches_token_run() {
        // `...` should span across other directives.
        let positions = matches(
            "location ... proxy_pass",
            "location /api {\n  proxy_pass http://up;\n}\n",
        );
        assert_eq!(positions.len(), 1);
    }

    #[test]
    fn ellipsis_crosses_newlines() {
        let positions = matches("foo ... baz", "foo\nbar\nbaz\n");
        assert_eq!(positions.len(), 1);
        assert_eq!(positions[0].0, 1);
    }

    #[test]
    fn metavar_equality_is_enforced() {
        // Same metavar twice must bind the same token.
        assert_eq!(matches("$X = $X", "a = a").len(), 1);
        assert!(matches("$X = $X", "a = b").is_empty());
    }

    #[test]
    fn metavar_binds_single_token() {
        let positions = matches("set $KEY $VAL", "set color red\nset size 10\n");
        assert_eq!(positions.len(), 2);
    }

    #[test]
    fn pattern_not_filters_overlapping_matches() {
        let matcher = GenericMatcher::Filtered {
            positive: Box::new(GenericMatcher::Pattern(compile_pattern(
                "ssl_protocols ...",
            ))),
            negatives: vec![GenericMatcher::Pattern(compile_pattern(
                "ssl_protocols TLSv1_3",
            ))],
        };
        let source = "ssl_protocols TLSv1;\nssl_protocols TLSv1_3;\n";
        let tokens = tokenize(source);
        let found = matcher.find_all(source, &tokens);
        // The TLSv1_3 line is excluded by pattern-not; only the TLSv1 line
        // (up to the line-ending `;`) survives. Ellipsis is greedy-lazy and
        // may span further, so assert the surviving match starts on line 1.
        assert!(!found.is_empty());
        for m in &found {
            assert_eq!(byte_offset_to_position(source, m.start_byte).0, 1);
        }
    }

    #[test]
    fn multiline_pattern_matches_across_lines() {
        let positions = matches(
            "server { ... listen 80",
            "server {\n  server_name x;\n  listen 80;\n}\n",
        );
        assert_eq!(positions.len(), 1);
        assert_eq!(positions[0].0, 1);
    }

    #[test]
    fn regex_passthrough_matches() {
        let m = GenericMatcher::Regex(compile_regex(r"AKIA[0-9A-Z]{4}").unwrap());
        let source = "key = AKIA1234XYZ\n";
        let tokens = tokenize(source);
        assert_eq!(m.find_all(source, &tokens).len(), 1);
    }

    /// Generic-mode `pattern-regex` now compiles PCRE lookaround assertions
    /// (`(?=...)`, `(?!...)`) via the `fancy-regex` backtracking engine. The
    /// plain `regex` crate rejects these, which previously made several
    /// `languages: [generic]` registry rules (e.g. `google-maps-apikeyleak`,
    /// `poetry-missing-solver-min-release-age`) fail to load. This is the
    /// low-level compile + match check.
    #[test]
    fn regex_with_negative_lookahead_compiles_and_matches() {
        // Shape mirrors `google-maps-apikeyleak`: a key token that must NOT be
        // immediately followed by a non-space character (the `(?!\S)` tail).
        let m = GenericMatcher::Regex(
            compile_regex(r"AIza[0-9A-Za-z_\-]{4}(?!\S)")
                .expect("negative-lookahead regex must compile via fancy-regex"),
        );
        let hit = "key = AIza1234 rest\n";
        let toks = tokenize(hit);
        assert_eq!(
            m.find_all(hit, &toks).len(),
            1,
            "lookahead-satisfied key (followed by space) must match"
        );

        // Near-miss: the key is followed by a non-space char, so the negative
        // lookahead fails and there is no match.
        let miss = "key = AIza1234XYZ\n";
        let toks = tokenize(miss);
        assert!(
            m.find_all(miss, &toks).is_empty(),
            "lookahead-violating key (trailing non-space) must NOT match"
        );
    }

    #[test]
    fn build_generic_rules_fans_out_per_language() {
        let spec = GenericRuleSpec {
            id: "generic-test",
            message: "msg",
            severity: Severity::High,
            cwe: None,
            pattern: Some("ssl_protocols TLSv1"),
            pattern_regex: None,
            pattern_either: Vec::new(),
            pattern_not: None,
            pattern_not_regex: None,
            patterns_clauses: Vec::new(),
            path_filter: None,
        };
        let rules = build_generic_rules(spec).unwrap();
        assert_eq!(rules.len(), ALL_LANGUAGES.len());
        assert_eq!(rules[0].id(), "semgrep/generic-test");
    }

    // ─── New tests for patterns: AND-block, pattern-either, pattern-regex ────

    /// Create a minimal dummy tree for rules that don't use the AST.
    /// Generic-mode rules ignore the tree entirely; we parse Rust source
    /// (which is always available as a test dependency) to get a valid tree
    /// to satisfy the Rule::check() signature.
    fn dummy_tree() -> tree_sitter::Tree {
        use crate::engine::parser::parse_file;
        parse_file("fn main() {}", Language::Rust).expect("Rust parser must succeed")
    }

    /// `patterns:` AND-block: pattern + pattern-not loads and fires only when
    /// the positive matches but the negative does not overlap.
    #[test]
    fn generic_patterns_and_block_with_pattern_not() {
        let spec = GenericRuleSpec {
            id: "and-block-test",
            message: "msg",
            severity: Severity::High,
            cwe: None,
            pattern: None,
            pattern_regex: None,
            pattern_either: Vec::new(),
            pattern_not: None,
            pattern_not_regex: None,
            patterns_clauses: vec![GenericPatternsClause {
                pattern: Some("ssl_protocols ...".to_string()),
                pattern_not: Some("ssl_protocols TLSv1_3".to_string()),
                ..Default::default()
            }],
            path_filter: None,
        };
        let rules = build_generic_rules(spec).unwrap();
        assert_eq!(rules.len(), ALL_LANGUAGES.len());

        let tree = dummy_tree();

        let findings = rules[0].check("ssl_protocols TLSv1;\n", &tree);
        assert!(
            !findings.is_empty(),
            "expected a finding for ssl_protocols TLSv1"
        );

        let findings = rules[0].check("ssl_protocols TLSv1_3;\n", &tree);
        assert!(
            findings.is_empty(),
            "expected no finding when pattern-not matches (ssl_protocols TLSv1_3)"
        );
    }

    /// `patterns:` block with a `pattern-either:` clause: fires when any of the
    /// OR-branches matches.
    #[test]
    fn generic_patterns_with_pattern_either_clause() {
        let spec = GenericRuleSpec {
            id: "either-in-patterns",
            message: "msg",
            severity: Severity::High,
            cwe: None,
            pattern: None,
            pattern_regex: None,
            pattern_either: Vec::new(),
            pattern_not: None,
            pattern_not_regex: None,
            patterns_clauses: vec![GenericPatternsClause {
                pattern_either: vec![
                    GenericEitherEntry {
                        pattern: Some("rewrite ... redirect".to_string()),
                        pattern_regex: None,
                        patterns: Vec::new(),
                    },
                    GenericEitherEntry {
                        pattern: Some("rewrite ... permanent".to_string()),
                        pattern_regex: None,
                        patterns: Vec::new(),
                    },
                ],
                ..Default::default()
            }],
            path_filter: None,
        };
        let rules = build_generic_rules(spec).unwrap();
        assert_eq!(rules.len(), ALL_LANGUAGES.len());

        let tree = dummy_tree();

        let source_redirect = "rewrite ^/old$ /new redirect;\n";
        let source_permanent = "rewrite ^/old$ /new permanent;\n";
        let source_none = "location / { proxy_pass http://up; }\n";

        assert!(
            !rules[0].check(source_redirect, &tree).is_empty(),
            "expected a finding for 'rewrite ... redirect'"
        );
        assert!(
            !rules[0].check(source_permanent, &tree).is_empty(),
            "expected a finding for 'rewrite ... permanent'"
        );
        assert!(
            rules[0].check(source_none, &tree).is_empty(),
            "expected no finding when neither branch matches"
        );
    }

    /// Top-level `pattern-either:` generic rule: loads and fires on either branch
    /// (both spacegrep `pattern:` and `pattern-regex:` arms are supported).
    #[test]
    fn generic_top_level_pattern_either() {
        let spec = GenericRuleSpec {
            id: "top-either",
            message: "msg",
            severity: Severity::High,
            cwe: None,
            pattern: None,
            pattern_regex: None,
            pattern_either: vec![
                GenericEitherEntry {
                    pattern: Some("ssl_protocols TLSv1".to_string()),
                    pattern_regex: None,
                    patterns: Vec::new(),
                },
                GenericEitherEntry {
                    pattern: Some("ssl_protocols TLSv1_1".to_string()),
                    pattern_regex: None,
                    patterns: Vec::new(),
                },
            ],
            pattern_not: None,
            pattern_not_regex: None,
            patterns_clauses: Vec::new(),
            path_filter: None,
        };
        let rules = build_generic_rules(spec).unwrap();

        let tree = dummy_tree();

        assert!(!rules[0].check("ssl_protocols TLSv1;\n", &tree).is_empty());
        assert!(!rules[0].check("ssl_protocols TLSv1_1;\n", &tree).is_empty());
        assert!(rules[0].check("ssl_protocols TLSv1_3;\n", &tree).is_empty());
    }

    /// Top-level `pattern-either:` with `pattern-regex:` arms (not just `pattern:`)
    /// loads correctly — this covers rules like mcp-tool-poisoning.
    #[test]
    fn generic_top_level_pattern_either_regex_arms() {
        let spec = GenericRuleSpec {
            id: "top-either-regex",
            message: "msg",
            severity: Severity::High,
            cwe: None,
            pattern: None,
            pattern_regex: None,
            pattern_either: vec![
                GenericEitherEntry {
                    pattern: None,
                    pattern_regex: Some("ANTHROPIC_BASE_URL\\s*=".to_string()),
                    patterns: Vec::new(),
                },
                GenericEitherEntry {
                    pattern: None,
                    pattern_regex: Some("OPENAI_BASE_URL\\s*=".to_string()),
                    patterns: Vec::new(),
                },
            ],
            pattern_not: None,
            pattern_not_regex: None,
            patterns_clauses: Vec::new(),
            path_filter: None,
        };
        let rules = build_generic_rules(spec).unwrap();

        let tree = dummy_tree();

        assert!(!rules[0]
            .check("ANTHROPIC_BASE_URL = https://evil.com\n", &tree)
            .is_empty());
        assert!(!rules[0]
            .check("OPENAI_BASE_URL = https://evil.com\n", &tree)
            .is_empty());
        assert!(rules[0]
            .check("SOME_OTHER_URL = https://safe.com\n", &tree)
            .is_empty());
    }

    /// `pattern-regex:` in `patterns:` clause loads and fires on a raw-text match.
    #[test]
    fn generic_patterns_with_pattern_regex_clause() {
        let spec = GenericRuleSpec {
            id: "regex-in-patterns",
            message: "msg",
            severity: Severity::High,
            cwe: None,
            pattern: None,
            pattern_regex: None,
            pattern_either: Vec::new(),
            pattern_not: None,
            pattern_not_regex: None,
            patterns_clauses: vec![GenericPatternsClause {
                // Match baseURL = "..." where the URL does NOT start with 'h'
                // (i.e., not http/https). Use explicit hex escape for the quote.
                pattern_regex: Some("baseURL\\s*=\\s*\"[^h]".to_string()),
                ..Default::default()
            }],
            path_filter: None,
        };
        let rules = build_generic_rules(spec).unwrap();

        let tree = dummy_tree();

        let match_src = "baseURL = \"/relative/path\"\n";
        let no_match_src = "baseURL = \"https://example.com\"\n";

        assert!(
            !rules[0].check(match_src, &tree).is_empty(),
            "expected a finding for non-http baseURL"
        );
        assert!(
            rules[0].check(no_match_src, &tree).is_empty(),
            "expected no finding for https baseURL"
        );
    }

    /// `patterns:` block with `pattern-not-regex:` clause.
    #[test]
    fn generic_patterns_with_pattern_not_regex() {
        let spec = GenericRuleSpec {
            id: "not-regex-test",
            message: "msg",
            severity: Severity::High,
            cwe: None,
            pattern: None,
            pattern_regex: None,
            pattern_either: Vec::new(),
            pattern_not: None,
            pattern_not_regex: None,
            patterns_clauses: vec![GenericPatternsClause {
                pattern: Some("baseURL = ...".to_string()),
                pattern_not_regex: Some("(?i)https://".to_string()),
                ..Default::default()
            }],
            path_filter: None,
        };
        let rules = build_generic_rules(spec).unwrap();

        let tree = dummy_tree();

        // No https → fires.
        let match_src = "baseURL = \"/relative\"\n";
        // Has https → suppressed.
        let no_match_src = "baseURL = \"https://example.com\"\n";

        assert!(
            !rules[0].check(match_src, &tree).is_empty(),
            "expected finding when no https"
        );
        assert!(
            rules[0].check(no_match_src, &tree).is_empty(),
            "expected no finding when https present"
        );
    }

    /// `pattern-regex:` at top level (outside patterns block) loads and fires.
    #[test]
    fn generic_top_level_pattern_regex() {
        let spec = GenericRuleSpec {
            id: "top-regex",
            message: "msg",
            severity: Severity::High,
            cwe: None,
            pattern: None,
            pattern_regex: Some("ANTHROPIC_BASE_URL\\s*="),
            pattern_either: Vec::new(),
            pattern_not: None,
            pattern_not_regex: None,
            patterns_clauses: Vec::new(),
            path_filter: None,
        };
        let rules = build_generic_rules(spec).unwrap();

        let tree = dummy_tree();

        assert!(!rules[0]
            .check("ANTHROPIC_BASE_URL = https://evil.com\n", &tree)
            .is_empty());
        assert!(rules[0]
            .check("ANTHROPIC_BASE_URL_EXTRA = something\n", &tree)
            .is_empty());
    }

    /// A `patterns:` block with no expressible positive matcher must return an
    /// error rather than producing a no-op rule.
    #[test]
    fn generic_patterns_empty_positives_returns_error() {
        let spec = GenericRuleSpec {
            id: "empty-positives",
            message: "msg",
            severity: Severity::High,
            cwe: None,
            pattern: None,
            pattern_regex: None,
            pattern_either: Vec::new(),
            pattern_not: None,
            pattern_not_regex: None,
            // A clause with only a pattern-not and no positive — should fail.
            patterns_clauses: vec![GenericPatternsClause {
                pattern_not: Some("foo".to_string()),
                ..Default::default()
            }],
            path_filter: None,
        };
        assert!(build_generic_rules(spec).is_err());
    }

    /// `paths:` filter is respected: `applies_to_path` returns false for paths
    /// outside the include glob.
    #[test]
    fn generic_paths_filter_respected() {
        use crate::rules::semgrep_compat::{PathFilter, SemgrepPaths};
        use std::path::PathBuf;

        let path_filter = PathFilter::from_yaml(Some(&SemgrepPaths {
            include: vec!["*.conf".to_string()],
            exclude: vec![],
        }))
        .unwrap()
        .unwrap();

        let spec = GenericRuleSpec {
            id: "path-filter-test",
            message: "msg",
            severity: Severity::High,
            cwe: None,
            pattern: Some("ssl_protocols TLSv1"),
            pattern_regex: None,
            pattern_either: Vec::new(),
            pattern_not: None,
            pattern_not_regex: None,
            patterns_clauses: Vec::new(),
            path_filter: Some(path_filter),
        };
        let rules = build_generic_rules(spec).unwrap();
        let rule = &rules[0];

        assert!(rule.applies_to_path(&PathBuf::from("nginx/site.conf")));
        assert!(!rule.applies_to_path(&PathBuf::from("nginx/site.py")));
    }

    // ─── Named-capture metavariable constraints (package-manager rules) ──────

    /// Helper: load a single-rule YAML via the real loader and report whether
    /// any of the fan-out rule objects fires on `source`. Generic-mode rules
    /// ignore the tree, so a Rust dummy tree is fine.
    fn loader_fires(rule_yaml: &str, source: &str) -> bool {
        use crate::rules::semgrep_compat::parse_semgrep_str;
        let rules = parse_semgrep_str(rule_yaml, "<test>").expect("rule must load");
        assert!(!rules.is_empty(), "rule produced no rule objects");
        let tree = dummy_tree();
        rules.iter().any(|r| !r.check(source, &tree).is_empty())
    }

    /// `metavariable-comparison` over a named regex capture is *enforced*: a
    /// `pattern-either` arm that is a `patterns:` AND-block with
    /// `pattern-regex: (?P<AGE>\d+)` and `int($AGE) < 7` must fire on a too-low
    /// value and NOT fire on a safe value (proving the constraint isn't dropped).
    /// This mirrors `npm-missing-minimum-release-age` branch 2.
    #[test]
    fn named_capture_comparison_is_enforced() {
        let yaml = r#"
rules:
  - id: min-age-too-low
    pattern-either:
      - patterns:
          - pattern-regex: 'min-release-age\s*=\s*\d+'
          - pattern-regex: '=\s*(?P<AGE>\d+)'
          - metavariable-comparison:
              metavariable: $AGE
              comparison: int($AGE) < 7
          - focus-metavariable: $AGE
    message: min-release-age set too low
    severity: MEDIUM
    languages: [generic]
"#;
        // Violation present (3 < 7) → fires.
        assert!(loader_fires(yaml, "min-release-age = 3\n"));
        // Constraint satisfied as safe (7 is not < 7) → must NOT fire.
        assert!(!loader_fires(yaml, "min-release-age = 7\n"));
        assert!(!loader_fires(yaml, "min-release-age = 30\n"));
    }

    /// `metavariable-regex` over a named regex capture is *enforced*: a
    /// `pattern-regex: (?P<VAL>"[^"]+")`-style capture with a
    /// `metavariable-regex` that the captured text must match. Fires when the
    /// captured value matches, not when it does not. Mirrors the
    /// `uv-missing-dependency-cooldown` invalid-format branch shape.
    #[test]
    fn named_capture_regex_is_enforced() {
        let yaml = r#"
rules:
  - id: exclude-newer-bad-format
    pattern-either:
      - patterns:
          - pattern-regex: 'exclude-newer\s*=\s*"(?P<VAL>[^"]+)"'
          - metavariable-regex:
              metavariable: $VAL
              regex: '^(?!\d+ days?$)(?!\d{4}-\d{2}-\d{2}$)'
          - focus-metavariable: $VAL
    message: exclude-newer invalid format
    severity: MEDIUM
    languages: [generic]
"#;
        // "soon" is not "<n> days" / a date → constraint matches → fires.
        assert!(loader_fires(yaml, "exclude-newer = \"soon\"\n"));
        // "7 days" satisfies the negative-lookahead exclusion → constraint
        // fails → must NOT fire (constraint enforced, not dropped).
        assert!(!loader_fires(yaml, "exclude-newer = \"7 days\"\n"));
        // A bare date is also excluded → must NOT fire.
        assert!(!loader_fires(yaml, "exclude-newer = \"2026-01-01\"\n"));
    }

    /// A `pattern-either` arm that is a `patterns:` AND-block carrying a
    /// `metavariable-pattern` (which generic mode cannot enforce) must be
    /// warn-skipped — if it were the rule's only arm, the rule fails to load
    /// rather than loading with the constraint silently dropped. Mirrors
    /// `use-absolute-workdir`.
    #[test]
    fn unenforceable_metavariable_pattern_arm_refuses_to_load() {
        use crate::rules::semgrep_compat::parse_semgrep_str;
        let yaml = r#"
rules:
  - id: relative-workdir
    pattern-either:
      - patterns:
          - pattern: WORKDIR $VALUE
          - metavariable-pattern:
              metavariable: $VALUE
              patterns:
                - pattern-not-regex: (\/.*)
    message: relative WORKDIR
    severity: WARNING
    languages: [generic]
"#;
        // The only arm is unenforceable → no live matcher → rule rejected.
        assert!(parse_semgrep_str(yaml, "<test>").is_err());
    }

    /// A metavariable constraint that references a capture group absent from
    /// every `pattern-regex` would silently make the arm dead; the arm must be
    /// rejected (and, when it is the only arm, the rule fails to load) rather
    /// than loaded as a never-firing matcher.
    #[test]
    fn constraint_referencing_unknown_capture_refuses_to_load() {
        use crate::rules::semgrep_compat::parse_semgrep_str;
        let yaml = r#"
rules:
  - id: bad-capture-ref
    pattern-either:
      - patterns:
          - pattern-regex: 'value\s*=\s*(?P<AGE>\d+)'
          - metavariable-comparison:
              metavariable: $NOPE
              comparison: int($NOPE) < 7
    message: bad capture reference
    severity: MEDIUM
    languages: [generic]
"#;
        assert!(parse_semgrep_str(yaml, "<test>").is_err());
    }

    #[test]
    fn parse_generic_comparison_handles_int_wrapper() {
        let (g, op, lit, lhs) = parse_generic_comparison("int($AGE) < 604800").unwrap();
        assert_eq!(g, "AGE");
        assert_eq!(op, CmpOp::Lt);
        assert_eq!(lit, 604800.0);
        assert!(!lhs);
        // Flipped operands.
        let (g, op, lit, lhs) = parse_generic_comparison("7 >= $DAYS").unwrap();
        assert_eq!(g, "DAYS");
        assert_eq!(op, CmpOp::Ge);
        assert_eq!(lit, 7.0);
        assert!(lhs);
    }
}
