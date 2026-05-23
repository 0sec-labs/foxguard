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
    Single(CompiledAstPattern),
    /// Regex match against source text
    Regex(Regex),
    /// Match any of these patterns (OR)
    Either(Vec<PatternMatcher>),
    /// Combine multiple clauses (AND): positives must all match, negatives must not
    Combined {
        positives: Vec<PatternMatcher>,
        negatives: Vec<NegativeMatcher>,
        inside: Option<CompiledAstPattern>,
        not_inside: Option<CompiledAstPattern>,
        metavariable_regexes: Vec<MetavariableRegexConstraint>,
    },
}

#[derive(Debug, Clone)]
pub enum NegativeMatcher {
    Pattern(CompiledAstPattern),
    Regex(Regex),
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
        let matches = match_pattern_in_tree(&self.matcher, root, source);

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
                source_line: None,
                source_description: None,
                sink_line: None,
                sink_description: None,
                fix_suggestion: None,
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
    let metavars = Regex::new(r"\$([A-Za-z0-9_]+)").expect("valid metavariable regex");
    let rewritten = metavars
        .replace_all(source, format!("{GO_METAVAR_PREFIX}$1"))
        .to_string()
        .replace("...", GO_ELLIPSIS_PLACEHOLDER);

    let func_ellipsis_params = Regex::new(&format!(
        r"(func\s+[A-Za-z_][A-Za-z0-9_]*\s*)\(\s*{}\s*\)",
        regex::escape(GO_ELLIPSIS_PLACEHOLDER)
    ))
    .expect("valid Go func ellipsis regex");

    func_ellipsis_params
        .replace_all(&rewritten, "$1()")
        .to_string()
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
        if match_node(node, source, pat_node, &pattern.source, &mut bindings) {
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
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_and_match(child, source, pat_node, pattern, results);
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
    if let Some(metavar) = metavariable_key(pat_text) {
        let target_text = &target_src[target.byte_range()];
        if let Some(existing) = bindings.get(&metavar) {
            return existing == target_text;
        }
        bindings.insert(metavar, target_text.to_string());
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
#[cfg(test)]
fn is_metavar(text: &str) -> bool {
    metavariable_key(text).is_some()
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
        _ => None,
    }
}

fn build_matcher(yaml: &SemgrepRuleYaml, lang: Language) -> Result<PatternMatcher, String> {
    // Combined patterns (AND)
    if let Some(ref clauses) = yaml.patterns {
        let mut positives = Vec::new();
        let mut negatives = Vec::new();
        let mut inside = None;
        let mut not_inside = None;
        let mut metavariable_regexes = Vec::new();

        for clause in clauses {
            if let Some(ref p) = clause.pattern {
                positives.push(PatternMatcher::Single(CompiledAstPattern::new(
                    p.clone(),
                    lang,
                )));
            }
            if let Some(ref regex) = clause.pattern_regex {
                positives.push(PatternMatcher::Regex(compile_regex(regex)?));
            }
            if let Some(ref pn) = clause.pattern_not {
                negatives.push(NegativeMatcher::Pattern(CompiledAstPattern::new(
                    pn.clone(),
                    lang,
                )));
            }
            if let Some(ref regex) = clause.pattern_not_regex {
                negatives.push(NegativeMatcher::Regex(compile_regex(regex)?));
            }
            if let Some(ref pi) = clause.pattern_inside {
                inside = Some(CompiledAstPattern::new(pi.clone(), lang));
            }
            if let Some(ref pni) = clause.pattern_not_inside {
                not_inside = Some(CompiledAstPattern::new(pni.clone(), lang));
            }
            if let Some(ref pe) = clause.pattern_either {
                let matchers = build_either_matchers(pe, lang)?;
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
        positives.push(PatternMatcher::Single(CompiledAstPattern::new(
            pat.clone(),
            lang,
        )));
    }
    if let Some(ref regex) = yaml.pattern_regex {
        positives.push(PatternMatcher::Regex(compile_regex(regex)?));
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
        negatives.push(NegativeMatcher::Regex(compile_regex(regex)?));
    }

    if positives.len() == 1
        && negatives.is_empty()
        && yaml.pattern_inside.is_none()
        && yaml.pattern_not_inside.is_none()
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
            not_inside: yaml
                .pattern_not_inside
                .as_ref()
                .map(|pattern| CompiledAstPattern::new(pattern.clone(), lang)),
            metavariable_regexes: Vec::new(),
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
    use serde_yaml::Value as YamlValue;

    // First pass: parse as an untyped Value so we can detect `mode: taint`
    // rules and route them to the taint bridge without breaking the strict
    // `SemgrepRuleYaml` schema used for pattern rules.
    let raw_doc: YamlValue = serde_yaml::from_str(content)
        .map_err(|e| format!("Failed to parse YAML {}: {}", source_label, e))?;

    let mut rules: Vec<Box<dyn Rule>> = Vec::new();
    let mut pattern_rule_nodes: Vec<YamlValue> = Vec::new();

    if let Some(raw_rules) = raw_doc.get("rules").and_then(YamlValue::as_sequence) {
        for raw_rule in raw_rules {
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
        let mut m = serde_yaml::Mapping::new();
        m.insert(
            YamlValue::String("rules".into()),
            YamlValue::Sequence(pattern_rule_nodes),
        );
        m
    });
    let semgrep_file: SemgrepFile = serde_yaml::from_value(pattern_file)
        .map_err(|e| format!("Failed to parse YAML {}: {}", source_label, e))?;

    for yaml_rule in semgrep_file.rules {
        let cwe = extract_cwe(&yaml_rule);
        let severity = map_severity(&yaml_rule.severity);
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
            let matcher = build_matcher(&yaml_rule, lang)?;
            rules.push(Box::new(SemgrepRule {
                id: format!("semgrep/{}", yaml_rule.id),
                message: yaml_rule.message.clone(),
                severity,
                lang,
                cwe: cwe.clone(),
                matcher,
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
    fn ast_patterns_are_compiled_during_rule_load() {
        let yaml = r#"
rules:
  - id: test-eval
    pattern: eval(...)
    message: Do not use eval
    severity: ERROR
    languages: [python]
"#;
        let parsed: SemgrepFile = serde_yaml::from_str(yaml).unwrap();
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
}
