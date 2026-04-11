use crate::engine::parser::parse_file;
use crate::rules::Rule;
use crate::{Finding, Language, Severity};
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

// ─── YAML Schema ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SemgrepFile {
    pub rules: Vec<SemgrepRuleYaml>,
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
    #[serde(default, rename = "pattern-not-inside")]
    pub pattern_not_inside: Option<String>,
    #[serde(default)]
    pub patterns: Option<Vec<PatternClause>>,
    pub message: String,
    pub severity: SemgrepSeverity,
    pub languages: Vec<String>,
    #[serde(default)]
    pub metadata: Option<SemgrepMetadata>,
    #[serde(default)]
    pub paths: Option<SemgrepPaths>,
}

#[derive(Debug, Deserialize)]
pub struct PatternEntry {
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default, rename = "pattern-regex")]
    pub pattern_regex: Option<String>,
}

#[derive(Debug, Deserialize)]
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
    #[serde(default, rename = "pattern-not-inside")]
    pub pattern_not_inside: Option<String>,
    #[serde(default, rename = "pattern-either")]
    pub pattern_either: Option<Vec<PatternEntry>>,
    #[serde(default, rename = "metavariable-regex")]
    pub metavariable_regex: Option<SemgrepMetavariableRegexClause>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SemgrepSeverity {
    Error,
    Warning,
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
}

/// Represents the matching strategy for a rule.
#[derive(Debug, Clone)]
pub enum PatternMatcher {
    /// Single pattern
    Single(String),
    /// Regex match against source text
    Regex(Regex),
    /// Match any of these patterns (OR)
    Either(Vec<PatternMatcher>),
    /// Combine multiple clauses (AND): positives must all match, negatives must not
    Combined {
        positives: Vec<PatternMatcher>,
        negatives: Vec<NegativeMatcher>,
        inside: Option<String>,
        not_inside: Option<String>,
        metavariable_regexes: Vec<MetavariableRegexConstraint>,
    },
}

#[derive(Debug, Clone)]
pub enum NegativeMatcher {
    Pattern(String),
    Regex(Regex),
}

#[derive(Debug, Clone)]
pub struct PathFilter {
    include: Option<GlobSet>,
    exclude: Option<GlobSet>,
}

#[derive(Debug, Clone)]
pub struct MetavariableRegexConstraint {
    metavariable: String,
    regex: Regex,
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
        let matches = match_pattern_in_tree(&self.matcher, root, source, self.lang);

        for matched_node_range in matches {
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
            });
        }

        findings
    }
}

impl PathFilter {
    fn from_yaml(paths: Option<&SemgrepPaths>) -> Result<Option<Self>, String> {
        let Some(paths) = paths else {
            return Ok(None);
        };

        let include = compile_globset(&paths.include)?;
        let exclude = compile_globset(&paths.exclude)?;

        Ok(Some(Self { include, exclude }))
    }

    fn matches(&self, path: &Path) -> bool {
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
    fn from_yaml(clause: &SemgrepMetavariableRegexClause) -> Result<Self, String> {
        Ok(Self {
            metavariable: clause.metavariable.clone(),
            regex: compile_regex(&clause.regex)?,
        })
    }

    fn matches(&self, bindings: &HashMap<String, String>) -> bool {
        bindings
            .get(&self.metavariable)
            .is_some_and(|value| self.regex.is_match(value))
    }
}

// ─── Pattern Matching Engine ────────────────────────────────────────────────

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
}

type MatchResult = Vec<MatchRange>;

fn match_pattern_in_tree(
    matcher: &PatternMatcher,
    root: tree_sitter::Node,
    source: &str,
    lang: Language,
) -> MatchResult {
    match matcher {
        PatternMatcher::Single(pat) => match_single_pattern(pat, root, source, lang),
        PatternMatcher::Regex(regex) => match_regex_pattern(regex, source),
        PatternMatcher::Either(matchers) => {
            let mut results = Vec::new();
            for matcher in matchers {
                results.extend(match_pattern_in_tree(matcher, root, source, lang));
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
        } => {
            // If we have an inside pattern, only search within matching contexts
            let search_roots = if let Some(inside_pat) = inside {
                let inside_matches = match_single_pattern(inside_pat, root, source, lang);
                inside_matches
                    .iter()
                    .map(|m| (m.start_byte, m.end_byte))
                    .collect::<Vec<_>>()
            } else {
                vec![]
            };

            let excluded_roots = if let Some(not_inside_pat) = not_inside {
                let excluded_matches = match_single_pattern(not_inside_pat, root, source, lang);
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
                let matches = match_pattern_in_tree(pos, root, source, lang);
                candidates = Some(match candidates {
                    None => matches,
                    Some(prev) => intersect_match_sets(prev, matches),
                });
            }

            let mut results = candidates.unwrap_or_default();

            // Filter out negative matches
            for neg in negatives {
                let neg_matches = match_negative_pattern(neg, root, source, lang);
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

            results
        }
    }
}

/// Match a single pattern string against every node in the tree.
fn match_single_pattern(
    pattern: &str,
    root: tree_sitter::Node,
    source: &str,
    lang: Language,
) -> MatchResult {
    let mut results = Vec::new();

    // Parse the pattern as source code to get a pattern AST
    let pattern_tree = match parse_file(pattern, lang) {
        Some(t) => t,
        None => return results,
    };

    let pat_root = pattern_tree.root_node();
    // Find the first meaningful child of the pattern (skip module/program wrapper)
    let pat_node = first_meaningful_node(pat_root, pattern);

    if pat_node.is_none() {
        return results;
    }
    let pat_node = pat_node.unwrap();

    // Walk every node in the target tree and try matching
    walk_and_match(root, source, pat_node, pattern, &mut results);

    results
}

fn match_regex_pattern(regex: &Regex, source: &str) -> MatchResult {
    regex
        .find_iter(source)
        .map(|matched| {
            let (line, column) = byte_offset_to_position(source, matched.start());
            let (end_line, end_column) = byte_offset_to_position(source, matched.end());
            MatchRange {
                start_byte: matched.start(),
                end_byte: matched.end(),
                line,
                column,
                end_line,
                end_column,
                snippet: get_source_line(source, matched.start()),
                bindings: HashMap::new(),
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
    if kind == "module" || kind == "program" || kind == "source_file" || kind == "script" {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if !child.is_extra() {
                return first_meaningful_node(child, _source);
            }
        }
        return None;
    }

    // expression_statement wraps a bare expression
    if kind == "expression_statement" {
        if let Some(child) = node.child(0) {
            return Some(child);
        }
    }

    Some(node)
}

fn walk_and_match(
    node: tree_sitter::Node,
    source: &str,
    pat_node: tree_sitter::Node,
    pat_source: &str,
    results: &mut MatchResult,
) {
    let mut bindings = HashMap::new();
    if match_node(node, source, pat_node, pat_source, &mut bindings) {
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
        });
        // Don't recurse into children of a matched node to avoid duplicates
        return;
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_and_match(child, source, pat_node, pat_source, results);
    }
}

/// Try to match a pattern AST node against a target AST node.
/// Returns true if they match, populating metavariable bindings.
fn match_node(
    target: tree_sitter::Node,
    target_src: &str,
    pattern: tree_sitter::Node,
    pat_src: &str,
    bindings: &mut HashMap<String, String>,
) -> bool {
    let pat_text = &pat_src[pattern.byte_range()];

    // ── Metavariable: $X matches any node ──
    if is_metavar(pat_text) {
        let target_text = &target_src[target.byte_range()];
        if let Some(existing) = bindings.get(pat_text) {
            return existing == target_text;
        }
        bindings.insert(pat_text.to_string(), target_text.to_string());
        return true;
    }

    // ── Ellipsis: ... matches anything ──
    if pat_text.trim() == "..." {
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
                return match_node(target, target_src, pc, pat_src, bindings);
            }
        }
        if target.child_count() == 1 {
            if let Some(tc) = target.child(0) {
                return match_node(tc, target_src, pattern, pat_src, bindings);
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
    if first.kind() == "ERROR" && is_metavar(first_text) {
        return Some(first_text.to_string());
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
) -> bool {
    if pat_children.is_empty() {
        return true;
    }

    let mut ti = 0;
    let mut pi = 0;

    while pi < pat_children.len() {
        let pat_child = pat_children[pi];
        let pat_text = &pat_src[pat_child.byte_range()];

        if pat_text.trim() == "..." {
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
                if match_node(
                    target_children[ti],
                    target_src,
                    next_pat,
                    pat_src,
                    &mut sub_bindings,
                ) {
                    // Continue matching from here
                    *bindings = sub_bindings;
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
            let target_text = &target_src[target_children[ti].byte_range()];
            if let Some(existing) = bindings.get(&metavar) {
                if existing != target_text {
                    return false;
                }
            } else {
                bindings.insert(metavar.clone(), target_text.to_string());
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
fn is_metavar(text: &str) -> bool {
    let t = text.trim();
    t.starts_with('$')
        && t.len() > 1
        && t[1..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
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

fn get_source_line(source: &str, byte_offset: usize) -> String {
    let start = source[..byte_offset].rfind('\n').map_or(0, |p| p + 1);
    let end = source[byte_offset..]
        .find('\n')
        .map_or(source.len(), |p| byte_offset + p);
    source[start..end].to_string()
}

fn byte_offset_to_position(source: &str, byte_offset: usize) -> (usize, usize) {
    let prefix = &source[..byte_offset];
    let line = prefix.bytes().filter(|b| *b == b'\n').count() + 1;
    let line_start = prefix.rfind('\n').map_or(0, |pos| pos + 1);
    let column = byte_offset - line_start + 1;
    (line, column)
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

            let mut combined = left_match.clone();
            combined.bindings = bindings;
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
    lang: Language,
) -> MatchResult {
    match negative {
        NegativeMatcher::Pattern(pattern) => match_single_pattern(pattern, root, source, lang),
        NegativeMatcher::Regex(regex) => match_regex_pattern(regex, source),
    }
}

// ─── File Loading ───────────────────────────────────────────────────────────

fn map_severity(s: &SemgrepSeverity) -> Severity {
    match s {
        SemgrepSeverity::Error => Severity::Critical,
        SemgrepSeverity::Warning => Severity::High,
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
        _ => None,
    }
}

fn build_matcher(yaml: &SemgrepRuleYaml) -> Result<PatternMatcher, String> {
    // Combined patterns (AND)
    if let Some(ref clauses) = yaml.patterns {
        let mut positives = Vec::new();
        let mut negatives = Vec::new();
        let mut inside = None;
        let mut not_inside = None;
        let mut metavariable_regexes = Vec::new();

        for clause in clauses {
            if let Some(ref p) = clause.pattern {
                positives.push(PatternMatcher::Single(p.clone()));
            }
            if let Some(ref regex) = clause.pattern_regex {
                positives.push(PatternMatcher::Regex(compile_regex(regex)?));
            }
            if let Some(ref pn) = clause.pattern_not {
                negatives.push(NegativeMatcher::Pattern(pn.clone()));
            }
            if let Some(ref regex) = clause.pattern_not_regex {
                negatives.push(NegativeMatcher::Regex(compile_regex(regex)?));
            }
            if let Some(ref pi) = clause.pattern_inside {
                inside = Some(pi.clone());
            }
            if let Some(ref pni) = clause.pattern_not_inside {
                not_inside = Some(pni.clone());
            }
            if let Some(ref pe) = clause.pattern_either {
                let matchers = build_either_matchers(pe)?;
                positives.push(PatternMatcher::Either(matchers));
            }
            if let Some(ref mr) = clause.metavariable_regex {
                metavariable_regexes.push(MetavariableRegexConstraint::from_yaml(mr)?);
            }
        }

        return Ok(PatternMatcher::Combined {
            positives,
            negatives,
            inside,
            not_inside,
            metavariable_regexes,
        });
    }

    let mut positives = Vec::new();
    let mut negatives = Vec::new();

    if let Some(ref pat) = yaml.pattern {
        positives.push(PatternMatcher::Single(pat.clone()));
    }
    if let Some(ref regex) = yaml.pattern_regex {
        positives.push(PatternMatcher::Regex(compile_regex(regex)?));
    }
    if let Some(ref either) = yaml.pattern_either {
        positives.push(PatternMatcher::Either(build_either_matchers(either)?));
    }
    if let Some(ref pat) = yaml.pattern_not {
        negatives.push(NegativeMatcher::Pattern(pat.clone()));
    }
    if let Some(ref regex) = yaml.pattern_not_regex {
        negatives.push(NegativeMatcher::Regex(compile_regex(regex)?));
    }

    if positives.len() == 1
        && negatives.is_empty()
        && yaml.pattern_inside.is_none()
        && yaml.pattern_not_inside.is_none()
    {
        return Ok(positives.into_iter().next().unwrap());
    }

    if !positives.is_empty() {
        return Ok(PatternMatcher::Combined {
            positives,
            negatives,
            inside: yaml.pattern_inside.clone(),
            not_inside: yaml.pattern_not_inside.clone(),
            metavariable_regexes: Vec::new(),
        });
    }

    // Fallback: empty matcher that matches nothing
    Ok(PatternMatcher::Either(Vec::new()))
}

fn build_either_matchers(entries: &[PatternEntry]) -> Result<Vec<PatternMatcher>, String> {
    let mut matchers = Vec::new();

    for entry in entries {
        if let Some(ref pattern) = entry.pattern {
            matchers.push(PatternMatcher::Single(pattern.clone()));
        }
        if let Some(ref regex) = entry.pattern_regex {
            matchers.push(PatternMatcher::Regex(compile_regex(regex)?));
        }
    }

    Ok(matchers)
}

fn compile_regex(pattern: &str) -> Result<Regex, String> {
    Regex::new(pattern).map_err(|e| format!("Invalid pattern-regex '{}': {}", pattern, e))
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

/// Parse a single Semgrep YAML file into foxguard rules.
pub fn parse_semgrep_file(path: &Path) -> Result<Vec<Box<dyn Rule>>, String> {
    use crate::rules::semgrep_taint::{self, TaintRuleParse};
    use serde_yaml::Value as YamlValue;

    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    // First pass: parse as an untyped Value so we can detect `mode: taint`
    // rules and route them to the taint bridge without breaking the strict
    // `SemgrepRuleYaml` schema used for pattern rules.
    let raw_doc: YamlValue = serde_yaml::from_str(&content)
        .map_err(|e| format!("Failed to parse YAML {}: {}", path.display(), e))?;

    let mut rules: Vec<Box<dyn Rule>> = Vec::new();
    let mut pattern_rule_nodes: Vec<YamlValue> = Vec::new();

    if let Some(raw_rules) = raw_doc.get("rules").and_then(YamlValue::as_sequence) {
        for raw_rule in raw_rules {
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
        let mut m = serde_yaml::Mapping::new();
        m.insert(
            YamlValue::String("rules".into()),
            YamlValue::Sequence(pattern_rule_nodes),
        );
        m
    });
    let semgrep_file: SemgrepFile = serde_yaml::from_value(pattern_file)
        .map_err(|e| format!("Failed to parse YAML {}: {}", path.display(), e))?;

    for yaml_rule in semgrep_file.rules {
        let cwe = extract_cwe(&yaml_rule);
        let severity = map_severity(&yaml_rule.severity);
        let matcher = build_matcher(&yaml_rule)?;
        let path_filter = PathFilter::from_yaml(yaml_rule.paths.as_ref())?;

        let mut mapped_languages = Vec::new();
        for lang_str in &yaml_rule.languages {
            if let Some(lang) = map_language(lang_str) {
                if !mapped_languages.contains(&lang) {
                    mapped_languages.push(lang);
                }
            }
        }

        for lang in mapped_languages {
            rules.push(Box::new(SemgrepRule {
                id: format!("semgrep/{}", yaml_rule.id),
                message: yaml_rule.message.clone(),
                severity,
                lang,
                cwe: cwe.clone(),
                matcher: matcher.clone(),
                path_filter: path_filter.clone(),
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
}
