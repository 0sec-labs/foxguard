use crate::rules::cross_file::CrossFileSummaryMap;
use crate::rules::go_taint::{self, go_aliases_from_tree};
use crate::rules::javascript_taint::{self, js_aliases_from_tree};
use crate::rules::python_aliases::{from_tree as py_aliases_from_tree, resolve_imports_to_paths};
use crate::rules::python_taint;
use crate::rules::{
    common::AliasTable, AstAnalysisRequirement, FileContext, Rule, RuleRegistry, TaintEngine,
};
use crate::{Finding, Language};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use rayon::prelude::*;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// Result of a scan with metadata.
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub stats: ScanStats,
    pub duration: std::time::Duration,
}

struct AstRuleBatch<'a> {
    entries: Vec<AstRuleBatchEntry<'a>>,
    syntax_tree_rules: usize,
    context_rules: usize,
}

struct AstRuleBatchEntry<'a> {
    rule: &'a dyn Rule,
    requirement: AstAnalysisRequirement,
}

impl<'a> AstRuleBatch<'a> {
    fn from_rules(rules: &[&'a dyn Rule]) -> Self {
        let mut syntax_tree_rules = 0;
        let mut context_rules = 0;
        let entries = rules
            .iter()
            .map(|rule| {
                let requirement = rule.ast_analysis_requirement();
                match requirement {
                    AstAnalysisRequirement::SyntaxTree => syntax_tree_rules += 1,
                    AstAnalysisRequirement::FileContext => context_rules += 1,
                }
                AstRuleBatchEntry {
                    rule: *rule,
                    requirement,
                }
            })
            .collect();

        Self {
            entries,
            syntax_tree_rules,
            context_rules,
        }
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn run(&self, source: &str, tree: &tree_sitter::Tree, ctx: &FileContext<'_>) -> Vec<Finding> {
        let mut findings = Vec::with_capacity(self.syntax_tree_rules + self.context_rules);
        for entry in &self.entries {
            match entry.requirement {
                AstAnalysisRequirement::SyntaxTree => {
                    findings.extend(entry.rule.check(source, tree));
                }
                AstAnalysisRequirement::FileContext => {
                    findings.extend(entry.rule.check_with_context(source, tree, ctx));
                }
            }
        }
        findings
    }
}

/// File accounting for a scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanStats {
    pub files_discovered: usize,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub files_ignored: usize,
    pub unsupported_files: usize,
    pub noise_files: usize,
    pub too_large_files: usize,
    pub metadata_error_files: usize,
    pub binary_files: usize,
    pub read_error_files: usize,
    pub minified_files: usize,
    pub parse_error_files: usize,
}

impl ScanStats {
    fn record_discovered(&mut self) {
        self.files_discovered += 1;
    }

    fn record_scanned(&mut self) {
        self.files_scanned += 1;
    }

    fn record_skipped(&mut self, reason: ScanSkipReason) {
        self.files_skipped += 1;
        match reason {
            ScanSkipReason::Ignored => self.files_ignored += 1,
            ScanSkipReason::Unsupported => self.unsupported_files += 1,
            ScanSkipReason::Noise => self.noise_files += 1,
            ScanSkipReason::TooLarge => self.too_large_files += 1,
            ScanSkipReason::MetadataError => self.metadata_error_files += 1,
            ScanSkipReason::Binary => self.binary_files += 1,
            ScanSkipReason::ReadError => self.read_error_files += 1,
            ScanSkipReason::Minified => self.minified_files += 1,
            ScanSkipReason::ParseError => self.parse_error_files += 1,
        }
    }

    fn extend(&mut self, other: ScanStats) {
        self.files_discovered += other.files_discovered;
        self.files_scanned += other.files_scanned;
        self.files_skipped += other.files_skipped;
        self.files_ignored += other.files_ignored;
        self.unsupported_files += other.unsupported_files;
        self.noise_files += other.noise_files;
        self.too_large_files += other.too_large_files;
        self.metadata_error_files += other.metadata_error_files;
        self.binary_files += other.binary_files;
        self.read_error_files += other.read_error_files;
        self.minified_files += other.minified_files;
        self.parse_error_files += other.parse_error_files;
    }

    pub fn skipped_summary(&self) -> Option<String> {
        if self.files_skipped == 0 {
            return None;
        }

        let mut parts = Vec::new();
        push_count(&mut parts, self.files_ignored, "ignored");
        push_count(&mut parts, self.unsupported_files, "unsupported extension");
        push_count(&mut parts, self.noise_files, "noise path");
        push_count(&mut parts, self.too_large_files, "too large");
        push_count(&mut parts, self.metadata_error_files, "metadata error");
        push_count(&mut parts, self.binary_files, "binary or non-UTF-8");
        push_count(&mut parts, self.read_error_files, "read error");
        push_count(&mut parts, self.minified_files, "minified");
        push_count(&mut parts, self.parse_error_files, "parse error");

        Some(parts.join(", "))
    }
}

#[derive(Debug, Clone, Copy)]
enum ScanSkipReason {
    Ignored,
    Unsupported,
    Noise,
    TooLarge,
    MetadataError,
    Binary,
    ReadError,
    Minified,
    ParseError,
}

struct FileScanOutcome {
    findings: Vec<Finding>,
    stats: ScanStats,
}

impl FileScanOutcome {
    fn skipped(reason: ScanSkipReason) -> Self {
        let mut stats = ScanStats::default();
        stats.record_skipped(reason);
        Self {
            findings: Vec::new(),
            stats,
        }
    }
}

struct PreparedFile {
    source: String,
    tree: tree_sitter::Tree,
    aliases: AliasTable,
    canonical_path: PathBuf,
}

fn push_count(parts: &mut Vec<String>, count: usize, label: &str) {
    if count == 0 {
        return;
    }
    parts.push(format!(
        "{} {}{}",
        count,
        label,
        if count == 1 { "" } else { "s" }
    ));
}

#[derive(Default)]
pub struct PathExcludeMatcher {
    prefixes: Vec<String>,
    globset: Option<GlobSet>,
}

impl PathExcludeMatcher {
    pub fn new(patterns: &[String]) -> Result<Self, String> {
        if patterns.is_empty() {
            return Ok(Self::default());
        }

        let mut prefixes = Vec::new();
        let mut builder = GlobSetBuilder::new();
        let mut has_globs = false;

        for pattern in patterns {
            let normalized = normalize_match_path(Path::new(pattern));
            if normalized.is_empty() {
                continue;
            }

            if has_glob_metacharacters(pattern) {
                let glob = Glob::new(&normalized)
                    .map_err(|e| format!("Invalid exclude glob '{}': {}", pattern, e))?;
                builder.add(glob);
                has_globs = true;
            } else {
                prefixes.push(normalized.trim_end_matches('/').to_string());
            }
        }

        let globset = if has_globs {
            Some(
                builder
                    .build()
                    .map_err(|e| format!("Failed to build exclude patterns: {}", e))?,
            )
        } else {
            None
        };

        Ok(Self { prefixes, globset })
    }

    pub(crate) fn is_excluded(&self, path: &Path) -> bool {
        let normalized = normalize_match_path(path);

        self.prefixes.iter().any(|prefix| {
            normalized == *prefix
                || normalized
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }) || self
            .globset
            .as_ref()
            .is_some_and(|globset| globset.is_match(&normalized))
    }
}

#[derive(Default)]
struct InlineIgnoreSpec {
    all_rules: bool,
    rule_ids: HashSet<String>,
}

impl InlineIgnoreSpec {
    fn matches(&self, rule_id: &str) -> bool {
        self.all_rules || self.rule_ids.contains(rule_id)
    }

    fn merge(&mut self, other: Self) {
        self.all_rules |= other.all_rules;
        self.rule_ids.extend(other.rule_ids);
    }
}

/// Detect config file language from filename and parent directory heuristics.
fn detect_config_language(path: &Path) -> Option<Language> {
    let filename = path.file_name().and_then(|f| f.to_str())?;
    let filename_lower = filename.to_ascii_lowercase();

    // Exact filename matches
    match filename {
        "nginx.conf" => return Some(Language::NginxConf),
        "httpd.conf" | "apache2.conf" => return Some(Language::ApacheConf),
        "haproxy.cfg" => return Some(Language::HAProxyConf),
        "Cargo.lock" | "requirements.txt" | "poetry.lock" | "Pipfile.lock"
        | "pnpm-lock.yaml" | "package-lock.json" => return Some(Language::Manifest),
        _ => {}
    }

    // Dockerfile variants: Dockerfile, Dockerfile.prod, dockerfile, etc.
    if filename_lower == "dockerfile" || filename_lower.starts_with("dockerfile.") {
        return Some(Language::Dockerfile);
    }

    // .conf files under nginx-related or Apache-related directories
    if filename_lower.ends_with(".conf") {
        let path_str = path.to_string_lossy();
        let path_lower = path_str.to_ascii_lowercase();
        if path_lower.contains("nginx") || path_lower.contains("conf.d/") {
            return Some(Language::NginxConf);
        }
        if path_lower.contains("apache")
            || path_lower.contains("httpd")
            || path_lower.contains("sites-available/")
            || path_lower.contains("sites-enabled/")
            || path_lower.contains("mods-enabled/")
        {
            return Some(Language::ApacheConf);
        }
    }

    // .cfg files under haproxy directories
    if filename_lower.ends_with(".cfg") {
        let path_str = path.to_string_lossy();
        if path_str.to_ascii_lowercase().contains("haproxy") {
            return Some(Language::HAProxyConf);
        }
    }

    None
}

/// Detect language from filename or file extension.
pub fn detect_language(path: &Path) -> Option<Language> {
    if let Some(lang) = detect_config_language(path) {
        return Some(lang);
    }

    match path.extension()?.to_str()? {
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" => Some(Language::JavaScript),
        "py" | "pyw" => Some(Language::Python),
        "go" => Some(Language::Go),
        "rb" | "rake" | "gemspec" => Some(Language::Ruby),
        "java" => Some(Language::Java),
        "php" => Some(Language::Php),
        "rs" => Some(Language::Rust),
        "cs" => Some(Language::CSharp),
        "swift" => Some(Language::Swift),
        "kt" | "kts" => Some(Language::Kotlin),
        "c" | "h" => Some(Language::C),
        _ => None,
    }
}

/// Scan a directory (or single file) and return findings with metadata.
pub fn scan_directory(
    root: &str,
    registry: &RuleRegistry,
    max_file_size: u64,
    excludes: Option<&PathExcludeMatcher>,
) -> ScanResult {
    scan_directory_with_notices(root, registry, max_file_size, excludes).0
}

pub fn scan_directory_with_notices(
    root: &str,
    registry: &RuleRegistry,
    max_file_size: u64,
    excludes: Option<&PathExcludeMatcher>,
) -> (ScanResult, Vec<String>) {
    let root_path = Path::new(root);
    let scan_root = scan_root(root_path);

    let (files, stats) = collect_scan_files(root_path, scan_root, excludes);
    scan_files(scan_root, files, registry, max_file_size, stats)
}

/// Scan an explicit list of paths.
pub fn scan_paths(
    paths: &[PathBuf],
    registry: &RuleRegistry,
    max_file_size: u64,
    excludes: Option<&PathExcludeMatcher>,
) -> ScanResult {
    scan_paths_with_root(Path::new("."), paths, registry, max_file_size, excludes)
}

/// Scan an explicit list of paths relative to a scan root.
pub fn scan_paths_with_root(
    root: &Path,
    paths: &[PathBuf],
    registry: &RuleRegistry,
    max_file_size: u64,
    excludes: Option<&PathExcludeMatcher>,
) -> ScanResult {
    scan_paths_with_root_with_notices(root, paths, registry, max_file_size, excludes).0
}

pub fn scan_paths_with_root_with_notices(
    root: &Path,
    paths: &[PathBuf],
    registry: &RuleRegistry,
    max_file_size: u64,
    excludes: Option<&PathExcludeMatcher>,
) -> (ScanResult, Vec<String>) {
    let scan_root = scan_root(root);
    let (files, stats) = collect_explicit_scan_files(scan_root, paths, excludes);
    scan_files(scan_root, files, registry, max_file_size, stats)
}

fn collect_scan_files(
    root_path: &Path,
    scan_root: &Path,
    excludes: Option<&PathExcludeMatcher>,
) -> (Vec<(PathBuf, Language)>, ScanStats) {
    let mut files = Vec::new();
    let mut stats = ScanStats::default();

    if root_path.is_file() {
        stats.record_discovered();
        collect_scan_file(
            root_path.to_path_buf(),
            scan_root,
            excludes,
            &mut stats,
            &mut files,
        );
        return (files, stats);
    }

    for entry in WalkBuilder::new(root_path)
        .follow_links(false) // never follow symlinks
        .hidden(true) // skip hidden files
        .git_ignore(true) // respect .gitignore
        .build()
    {
        let Ok(entry) = entry else {
            continue;
        };
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }

        stats.record_discovered();
        collect_scan_file(
            entry.into_path(),
            scan_root,
            excludes,
            &mut stats,
            &mut files,
        );
    }

    (files, stats)
}

fn collect_explicit_scan_files(
    scan_root: &Path,
    paths: &[PathBuf],
    excludes: Option<&PathExcludeMatcher>,
) -> (Vec<(PathBuf, Language)>, ScanStats) {
    let mut files = Vec::new();
    let mut stats = ScanStats::default();

    for path in paths {
        stats.record_discovered();
        collect_scan_file(path.clone(), scan_root, excludes, &mut stats, &mut files);
    }

    (files, stats)
}

fn collect_scan_file(
    path: PathBuf,
    scan_root: &Path,
    excludes: Option<&PathExcludeMatcher>,
    stats: &mut ScanStats,
    files: &mut Vec<(PathBuf, Language)>,
) {
    if excludes.is_some_and(|matcher| matcher.is_excluded(&relative_scan_path(scan_root, &path))) {
        stats.record_skipped(ScanSkipReason::Ignored);
        return;
    }

    let Some(language) = detect_language(&path) else {
        stats.record_skipped(ScanSkipReason::Unsupported);
        return;
    };

    files.push((path, language));
}

/// Check if a file path is in a directory that typically contains
/// test fixtures, vendored code, or generated assets.
fn is_noise_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    let noise_dirs = [
        "/vendor/",
        "/node_modules/",
        "/__fixtures__/",
        "/__mocks__/",
        "/__tests__/",
        "/__snapshots__/",
        "/dist/",
        "/build/",
        "/.next/",
        "/coverage/",
        "/.cache/",
        "/spec/",
        "/stubs/",
        "/generated/",
        "/gen/",
    ];
    for dir in &noise_dirs {
        if path_str.contains(dir) {
            return true;
        }
    }
    // Skip .min.js / .min.css files
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    if name.contains(".min.") {
        return true;
    }
    false
}

const MIN_SIZE_FOR_MINIFY_CHECK: usize = 2000;
const MAX_FIRST_LINE_LEN: usize = 1000;
const MAX_AVG_LINE_LEN: usize = 300;

fn is_minified(source: &str) -> bool {
    if source.len() < MIN_SIZE_FOR_MINIFY_CHECK {
        return false;
    }
    if let Some(first_newline) = source.find('\n') {
        if first_newline > MAX_FIRST_LINE_LEN {
            return true;
        }
    } else {
        return source.len() > MIN_SIZE_FOR_MINIFY_CHECK;
    }
    let line_count = source.bytes().filter(|b| *b == b'\n').count().max(1);
    let avg_line_len = source.len() / line_count;
    avg_line_len > MAX_AVG_LINE_LEN
}

fn inline_ignore_regex() -> &'static Regex {
    static INLINE_IGNORE_REGEX: OnceLock<Regex> = OnceLock::new();
    INLINE_IGNORE_REGEX.get_or_init(|| {
        Regex::new(r"^foxguard\s*:\s*ignore(?:\[(?P<rules>[^\]]*)\])?\s*$")
            .expect("invalid inline ignore regex")
    })
}

fn block_comment_ignore_regex() -> &'static Regex {
    static BLOCK_IGNORE_REGEX: OnceLock<Regex> = OnceLock::new();
    BLOCK_IGNORE_REGEX.get_or_init(|| {
        Regex::new(r"/\*\s*foxguard[\s:-]*ignore(?:\[(?P<rules>[^\]]*)\])?\s*\*/")
            .expect("invalid block comment ignore regex")
    })
}

fn parse_block_comment_ignore(line: &str) -> Option<(bool, InlineIgnoreSpec)> {
    let captures = block_comment_ignore_regex().captures(line)?;
    let full_match = captures.get(0).expect("group 0 always present");

    let mut spec = InlineIgnoreSpec::default();
    match captures.name("rules").map(|rules| rules.as_str().trim()) {
        None | Some("") => spec.all_rules = true,
        Some(rules) => {
            for rule_id in rules
                .split(',')
                .map(str::trim)
                .filter(|rule| !rule.is_empty())
            {
                spec.rule_ids.insert(rule_id.to_string());
            }
            if spec.rule_ids.is_empty() {
                spec.all_rules = true;
            }
        }
    }

    let comment_only =
        line[..full_match.start()].trim().is_empty() && line[full_match.end()..].trim().is_empty();
    Some((comment_only, spec))
}

fn inline_ignore_directives(source: &str, language: Language) -> HashMap<usize, InlineIgnoreSpec> {
    if !source.contains("foxguard") {
        return HashMap::new();
    }

    let lines: Vec<&str> = source.lines().collect();
    let mut directives = HashMap::new();

    for (index, line) in lines.iter().enumerate() {
        let line_number = index + 1;
        let Some((comment_only, spec)) = parse_inline_ignore(line, language) else {
            continue;
        };

        let target_line = if comment_only {
            next_code_line(&lines, line_number, language)
        } else {
            Some(line_number)
        };

        if let Some(target_line) = target_line {
            directives
                .entry(target_line)
                .or_insert_with(InlineIgnoreSpec::default)
                .merge(spec);
        }
    }

    directives
}

fn parse_inline_ignore(line: &str, language: Language) -> Option<(bool, InlineIgnoreSpec)> {
    let mut markers = comment_markers(language)
        .iter()
        .copied()
        .flat_map(|marker| {
            let mut positions = Vec::new();
            let mut start = 0;
            while let Some(offset) = line[start..].find(marker) {
                let index = start + offset;
                positions.push((index, marker));
                start = index + marker.len();
            }
            positions
        })
        .collect::<Vec<_>>();

    markers.sort_by_key(|(index, _)| *index);

    for (index, marker) in markers {
        let comment_text = line[index + marker.len()..].trim();
        let Some(captures) = inline_ignore_regex().captures(comment_text) else {
            continue;
        };

        let mut spec = InlineIgnoreSpec::default();
        match captures.name("rules").map(|rules| rules.as_str().trim()) {
            None | Some("") => spec.all_rules = true,
            Some(rules) => {
                for rule_id in rules
                    .split(',')
                    .map(str::trim)
                    .filter(|rule| !rule.is_empty())
                {
                    spec.rule_ids.insert(rule_id.to_string());
                }
                if spec.rule_ids.is_empty() {
                    spec.all_rules = true;
                }
            }
        }

        let comment_only = line[..index].trim().is_empty();
        return Some((comment_only, spec));
    }

    // Fallback: block comment /* foxguard: ignore */ — only for languages with /* */ syntax
    if matches!(
        language,
        Language::JavaScript
            | Language::Go
            | Language::Java
            | Language::Rust
            | Language::CSharp
            | Language::Swift
            | Language::Php
    ) {
        if let Some(result) = parse_block_comment_ignore(line) {
            return Some(result);
        }
    }

    None
}

fn next_code_line(lines: &[&str], line_number: usize, language: Language) -> Option<usize> {
    for (index, line) in lines.iter().enumerate().skip(line_number) {
        let trimmed = line.trim();
        if trimmed.is_empty() || is_comment_only_line(trimmed, language) {
            continue;
        }
        return Some(index + 1);
    }
    None
}

fn is_comment_only_line(trimmed_line: &str, language: Language) -> bool {
    comment_markers(language)
        .iter()
        .any(|marker| trimmed_line.starts_with(marker))
}

fn comment_markers(language: Language) -> &'static [&'static str] {
    match language {
        Language::Python | Language::Ruby => &["#"],
        Language::Php => &["//", "#"],
        Language::JavaScript
        | Language::Go
        | Language::Java
        | Language::Rust
        | Language::CSharp
        | Language::Swift
        | Language::Kotlin
        | Language::C => &["//"],
        Language::NginxConf
        | Language::ApacheConf
        | Language::HAProxyConf
        | Language::Dockerfile
        | Language::Manifest => &["#"],
    }
}

fn apply_inline_ignores(
    findings: Vec<Finding>,
    directives: &HashMap<usize, InlineIgnoreSpec>,
) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|finding| {
            !(finding.line..=finding.end_line).any(|line| {
                directives
                    .get(&line)
                    .is_some_and(|spec| spec.matches(&finding.rule_id))
            })
        })
        .collect()
}

fn scan_files(
    scan_root: &Path,
    files: Vec<(PathBuf, Language)>,
    registry: &RuleRegistry,
    max_file_size: u64,
    mut stats: ScanStats,
) -> (ScanResult, Vec<String>) {
    let start = Instant::now();
    let warnings = Mutex::new(Vec::new());

    let mut taint_specs_by_lang: HashMap<Language, Vec<crate::rules::RegistryTaintSpec>> =
        HashMap::new();
    for (_, language) in &files {
        taint_specs_by_lang
            .entry(*language)
            .or_insert_with(|| registry.taint_specs_for_language(*language));
    }

    let has_python_taint_rules = taint_specs_by_lang
        .get(&Language::Python)
        .is_some_and(|specs| !specs.is_empty());
    let has_js_taint_rules = taint_specs_by_lang
        .get(&Language::JavaScript)
        .is_some_and(|specs| !specs.is_empty());
    let has_go_taint_rules = taint_specs_by_lang
        .get(&Language::Go)
        .is_some_and(|specs| !specs.is_empty());
    let mut prepared_files: HashMap<PathBuf, PreparedFile> = HashMap::new();

    // ── Pass 1: Extract cross-file taint summaries ────────────────────
    // Run pass 1 for Python, Go, and JS files when there are multiple
    // files of the same language — single-file scans cannot benefit from
    // cross-file analysis.

    // Build a per-language file index in a single pass over the file list.
    let mut files_by_lang: HashMap<Language, Vec<&(PathBuf, Language)>> = HashMap::new();
    for entry in &files {
        if !is_noise_path(&entry.0) {
            files_by_lang.entry(entry.1).or_default().push(entry);
        }
    }
    let python_files: Vec<_> = files_by_lang.remove(&Language::Python).unwrap_or_default();
    let go_files: Vec<_> = files_by_lang.remove(&Language::Go).unwrap_or_default();
    let js_files: Vec<_> = files_by_lang
        .remove(&Language::JavaScript)
        .unwrap_or_default();

    let (mut cross_file_summaries, has_python_cross_file): (CrossFileSummaryMap, bool) =
        if has_python_taint_rules && python_files.len() > 1 {
            let rule_specs: Vec<_> = taint_specs_by_lang
                .get(&Language::Python)
                .into_iter()
                .flat_map(|specs| specs.iter())
                .filter(|spec| matches!(spec.engine, TaintEngine::Python))
                .map(|spec| (spec.rule_id, spec.spec.clone()))
                .collect();
            let prepared_python: Vec<_> = python_files
                .par_iter()
                .filter_map(|(path, _)| {
                    if std::fs::metadata(path).ok()?.len() > max_file_size {
                        return None;
                    }
                    let source = std::fs::read_to_string(path).ok()?;
                    if is_minified(&source) {
                        return None;
                    }
                    let tree = super::parser::parse_file(&source, Language::Python)?;
                    if tree.root_node().has_error() {
                        return None;
                    }
                    let aliases = py_aliases_from_tree(&source, &tree);
                    let summaries = python_taint::extract_cross_file_summaries(
                        tree.root_node(),
                        &source,
                        Some(&aliases),
                        &rule_specs,
                    );
                    // Canonicalize the path for consistent lookups.
                    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
                    Some((
                        path.clone(),
                        PreparedFile {
                            source,
                            tree,
                            aliases,
                            canonical_path: canonical,
                        },
                        summaries,
                    ))
                })
                .collect();
            let mut summaries = CrossFileSummaryMap::new();
            for (path, prepared, file_summaries) in prepared_python {
                if !file_summaries.is_empty() {
                    summaries.insert(prepared.canonical_path.clone(), file_summaries);
                }
                prepared_files.insert(path, prepared);
            }
            let has_summaries = !summaries.is_empty();
            (summaries, has_summaries)
        } else {
            (CrossFileSummaryMap::new(), false)
        };

    // JavaScript cross-file summaries: extract from all JS/TS files.
    let mut has_js_cross_file = false;
    if has_js_taint_rules && js_files.len() > 1 {
        let js_rule_specs: Vec<_> = taint_specs_by_lang
            .get(&Language::JavaScript)
            .into_iter()
            .flat_map(|specs| specs.iter())
            .filter(|spec| matches!(spec.engine, TaintEngine::JavaScript))
            .map(|spec| (spec.rule_id, spec.spec.clone()))
            .collect();
        let prepared_js: Vec<_> = js_files
            .par_iter()
            .filter_map(|(path, _)| {
                if std::fs::metadata(path).ok()?.len() > max_file_size {
                    return None;
                }
                let source = std::fs::read_to_string(path).ok()?;
                if is_minified(&source) {
                    return None;
                }
                let tree = super::parser::parse_path(&source, Language::JavaScript, path)?;
                if treats_tree_errors_as_parse_failures(Language::JavaScript, path)
                    && tree.root_node().has_error()
                {
                    return None;
                }
                let aliases = js_aliases_from_tree(&source, &tree);
                let summaries = javascript_taint::extract_cross_file_summaries(
                    tree.root_node(),
                    &source,
                    Some(&aliases),
                    &js_rule_specs,
                );
                let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
                Some((
                    path.clone(),
                    PreparedFile {
                        source,
                        tree,
                        aliases,
                        canonical_path: canonical,
                    },
                    summaries,
                ))
            })
            .collect();
        let mut js_summaries = CrossFileSummaryMap::new();
        for (path, prepared, file_summaries) in prepared_js {
            if !file_summaries.is_empty() {
                js_summaries.insert(prepared.canonical_path.clone(), file_summaries);
            }
            prepared_files.insert(path, prepared);
        }
        has_js_cross_file = !js_summaries.is_empty();
        cross_file_summaries.extend(js_summaries);
    }

    // Go cross-file summaries: extract from all Go files.
    let mut has_go_cross_file = false;
    if has_go_taint_rules && go_files.len() > 1 {
        let go_rule_specs: Vec<_> = taint_specs_by_lang
            .get(&Language::Go)
            .into_iter()
            .flat_map(|specs| specs.iter())
            .filter(|spec| matches!(spec.engine, TaintEngine::Go))
            .map(|spec| (spec.rule_id, spec.spec.clone()))
            .collect();
        let prepared_go: Vec<_> = go_files
            .par_iter()
            .filter_map(|(path, _)| {
                if std::fs::metadata(path).ok()?.len() > max_file_size {
                    return None;
                }
                let source = std::fs::read_to_string(path).ok()?;
                if is_minified(&source) {
                    return None;
                }
                let tree = super::parser::parse_file(&source, Language::Go)?;
                if tree.root_node().has_error() {
                    return None;
                }
                let aliases = go_aliases_from_tree(&source, &tree);
                let summaries = go_taint::extract_cross_file_summaries(
                    tree.root_node(),
                    &source,
                    Some(&aliases),
                    &go_rule_specs,
                );
                let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
                Some((
                    path.clone(),
                    PreparedFile {
                        source,
                        tree,
                        aliases,
                        canonical_path: canonical,
                    },
                    summaries,
                ))
            })
            .collect();
        let mut go_summaries = CrossFileSummaryMap::new();
        for (path, prepared, file_summaries) in prepared_go {
            if !file_summaries.is_empty() {
                go_summaries.insert(prepared.canonical_path.clone(), file_summaries);
            }
            prepared_files.insert(path, prepared);
        }
        has_go_cross_file = !go_summaries.is_empty();
        cross_file_summaries.extend(go_summaries);
    }

    let has_cross_file = !cross_file_summaries.is_empty();

    let canonical_path_lookup: HashMap<PathBuf, PathBuf> = {
        let mut lookup = HashMap::with_capacity(prepared_files.len() * 3);
        for (path, prepared) in &prepared_files {
            let canonical = &prepared.canonical_path;
            lookup.insert(path.clone(), canonical.clone());
            lookup.insert(canonical.clone(), canonical.clone());
            if path.is_relative() {
                lookup.insert(scan_root.join(path), canonical.clone());
            }
        }
        lookup
    };

    // Build a directory→files index for Go same-package resolution.
    // All .go files in the same directory share the same package.
    let go_dir_index: HashMap<PathBuf, Vec<PathBuf>> = if has_go_cross_file {
        let mut index: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();
        for (path, lang) in &files {
            if matches!(lang, Language::Go) && !is_noise_path(path) {
                if let Some(dir) = path.parent() {
                    let canonical = prepared_files
                        .get(path)
                        .map(|prepared| prepared.canonical_path.clone())
                        .unwrap_or_else(|| resolve_canonical_path(&canonical_path_lookup, path));
                    index.entry(dir.to_path_buf()).or_default().push(canonical);
                }
            }
        }
        index
    } else {
        HashMap::new()
    };

    // ── Pass 2: Full analysis with cross-file summaries available ─────
    let outcomes: Vec<FileScanOutcome> = files
        .par_iter()
        .map(|(path, language)| {
            // Skip files in test/vendor/fixture directories
            if is_noise_path(path) {
                return FileScanOutcome::skipped(ScanSkipReason::Noise);
            }

            match std::fs::metadata(path) {
                Ok(m) if m.len() > max_file_size => {
                    warnings.lock().expect("lock poisoned").push(format!(
                        "warning: skipping {} ({} bytes exceeds --max-file-size)",
                        path.display(),
                        m.len()
                    ));
                    return FileScanOutcome::skipped(ScanSkipReason::TooLarge);
                }
                Err(_) => {
                    warnings.lock().expect("lock poisoned").push(format!(
                        "warning: skipping {} (cannot read metadata)",
                        path.display()
                    ));
                    return FileScanOutcome::skipped(ScanSkipReason::MetadataError);
                }
                _ => {}
            }

            let prepared = prepared_files.get(path);
            let owned_source;
            let source = if let Some(prepared) = prepared {
                prepared.source.as_str()
            } else {
                let read_source = match std::fs::read_to_string(path) {
                    Ok(source) => source,
                    Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                        warnings.lock().expect("lock poisoned").push(format!(
                            "warning: skipping {} (binary or non-UTF-8 content)",
                            path.display()
                        ));
                        return FileScanOutcome::skipped(ScanSkipReason::Binary);
                    }
                    Err(error) => {
                        warnings.lock().expect("lock poisoned").push(format!(
                            "warning: skipping {} (cannot read file: {})",
                            path.display(),
                            error
                        ));
                        return FileScanOutcome::skipped(ScanSkipReason::ReadError);
                    }
                };
                if is_minified(&read_source) {
                    return FileScanOutcome::skipped(ScanSkipReason::Minified);
                }
                owned_source = read_source;
                owned_source.as_str()
            };

            let inline_ignores = inline_ignore_directives(source, *language);

            let owned_tree;
            let tree = if let Some(prepared) = prepared {
                if treats_tree_errors_as_parse_failures(*language, path)
                    && prepared.tree.root_node().has_error()
                {
                    warnings.lock().expect("lock poisoned").push(format!(
                        "warning: skipping {} (parse error)",
                        path.display()
                    ));
                    return FileScanOutcome::skipped(ScanSkipReason::ParseError);
                }
                &prepared.tree
            } else {
                let Some(parsed_tree) = super::parser::parse_path(source, *language, path) else {
                    warnings.lock().expect("lock poisoned").push(format!(
                        "warning: skipping {} (parser could not build a syntax tree)",
                        path.display()
                    ));
                    return FileScanOutcome::skipped(ScanSkipReason::ParseError);
                };
                if treats_tree_errors_as_parse_failures(*language, path)
                    && parsed_tree.root_node().has_error()
                {
                    warnings.lock().expect("lock poisoned").push(format!(
                        "warning: skipping {} (parse error)",
                        path.display()
                    ));
                    return FileScanOutcome::skipped(ScanSkipReason::ParseError);
                }
                owned_tree = parsed_tree;
                &owned_tree
            };
            let mut file_stats = ScanStats::default();
            file_stats.record_scanned();

            let file_str = path.display().to_string();
            let relative_path = relative_scan_path(scan_root, path);
            let analysis_plan = registry.analysis_plan_for_path(*language, &relative_path);
            let ast_rule_batch = AstRuleBatch::from_rules(&analysis_plan.ast_rules);
            if ast_rule_batch.is_empty() && analysis_plan.taint_specs.is_empty() {
                return FileScanOutcome {
                    findings: Vec::new(),
                    stats: file_stats,
                };
            }

            // Per-file analysis context. Python builds an import alias table so
            // rules can resolve aliased callees (`import pickle as p; p.loads(x)`)
            // back to their canonical dotted paths before sink matching.
            let owned_python_aliases;
            let python_aliases = if matches!(language, Language::Python) {
                if let Some(prepared) = prepared {
                    Some(&prepared.aliases)
                } else {
                    owned_python_aliases = py_aliases_from_tree(source, tree);
                    Some(&owned_python_aliases)
                }
            } else {
                None
            };
            let owned_javascript_aliases;
            let javascript_aliases = if matches!(language, Language::JavaScript) {
                if let Some(prepared) = prepared {
                    Some(&prepared.aliases)
                } else {
                    owned_javascript_aliases = js_aliases_from_tree(source, tree);
                    Some(&owned_javascript_aliases)
                }
            } else {
                None
            };
            let owned_go_aliases;
            let go_aliases = if matches!(language, Language::Go) {
                if let Some(prepared) = prepared {
                    Some(&prepared.aliases)
                } else {
                    owned_go_aliases = go_aliases_from_tree(source, tree);
                    Some(&owned_go_aliases)
                }
            } else {
                None
            };

            // Build Python import-to-path map for cross-file resolution.
            let python_import_paths =
                if has_python_cross_file && matches!(language, Language::Python) {
                    let mut imports = resolve_imports_to_paths(source, tree, path);
                    // Canonicalize all paths to match the summary map keys.
                    let canonical: HashMap<String, PathBuf> = imports
                        .drain()
                        .map(|(k, v)| {
                            let canon = resolve_canonical_path(&canonical_path_lookup, &v);
                            (k, canon)
                        })
                        .collect();
                    Some(canonical)
                } else {
                    None
                };

            // Build JavaScript import-to-path map for cross-file resolution.
            let javascript_import_paths = if has_js_cross_file
                && matches!(language, Language::JavaScript)
            {
                let mut imports = javascript_taint::resolve_js_imports_to_paths(source, tree, path);
                let canonical: HashMap<String, PathBuf> = imports
                    .drain()
                    .map(|(k, v)| {
                        let canon = resolve_canonical_path(&canonical_path_lookup, &v);
                        (k, canon)
                    })
                    .collect();
                Some(canonical)
            } else {
                None
            };

            // Build Go same-package paths for cross-file resolution.
            // All .go files in the same directory share a package, so
            // we provide the paths of sibling files (excluding self).
            let go_same_package_paths = if has_go_cross_file && matches!(language, Language::Go) {
                path.parent().and_then(|dir| {
                    let canonical_self = prepared
                        .map(|prepared| prepared.canonical_path.clone())
                        .unwrap_or_else(|| resolve_canonical_path(&canonical_path_lookup, path));
                    go_dir_index.get(dir).map(|siblings| {
                        siblings
                            .iter()
                            .filter(|p| **p != canonical_self)
                            .cloned()
                            .collect::<Vec<_>>()
                    })
                })
            } else {
                None
            };

            let ctx = FileContext {
                python_aliases,
                javascript_aliases,
                go_aliases,
                cross_file_summaries: if has_cross_file {
                    Some(&cross_file_summaries)
                } else {
                    None
                },
                python_import_paths: python_import_paths.as_ref(),
                javascript_import_paths: javascript_import_paths.as_ref(),
                go_same_package_paths,
            };

            let mut file_findings = Vec::new();

            // Go taint rules share identical Pass 1 summaries across all
            // rules in the same sanitizer-group. Instead of walking the
            // AST once per rule, run them all through a single batched
            // call that computes summaries once and emits per-rule
            // findings in a single walk per sanitizer-group. See
            // `crate::rules::go::run_go_taint_batched` for details.
            let enabled_go_taint_ids: std::collections::HashSet<&str> =
                if matches!(language, Language::Go) {
                    analysis_plan
                        .taint_specs
                        .iter()
                        .filter(|spec| matches!(spec.engine, TaintEngine::Go))
                        .map(|spec| spec.rule_id)
                        .collect()
                } else {
                    std::collections::HashSet::new()
                };
            if !enabled_go_taint_ids.is_empty() {
                file_findings.extend(crate::rules::go::run_go_taint_batched(
                    source,
                    tree,
                    &ctx,
                    &enabled_go_taint_ids,
                ));
            }

            // Python taint rules share identical Pass 1 summaries across
            // all rules in the same sanitizer-group. Same rationale as
            // the Go block above — see `crate::rules::python::run_py_taint_batched`.
            let enabled_py_taint_ids: std::collections::HashSet<&str> =
                if matches!(language, Language::Python) {
                    analysis_plan
                        .taint_specs
                        .iter()
                        .filter(|spec| matches!(spec.engine, TaintEngine::Python))
                        .map(|spec| spec.rule_id)
                        .collect()
                } else {
                    std::collections::HashSet::new()
                };
            if !enabled_py_taint_ids.is_empty() {
                file_findings.extend(crate::rules::python::run_py_taint_batched(
                    source,
                    tree,
                    &ctx,
                    &enabled_py_taint_ids,
                ));
            }

            // JavaScript taint rules: same batched approach as Go/Python
            // above — see `crate::rules::javascript::run_js_taint_batched`.
            let enabled_js_taint_ids: std::collections::HashSet<&str> =
                if matches!(language, Language::JavaScript) {
                    analysis_plan
                        .taint_specs
                        .iter()
                        .filter(|spec| matches!(spec.engine, TaintEngine::JavaScript))
                        .map(|spec| spec.rule_id)
                        .collect()
                } else {
                    std::collections::HashSet::new()
                };
            if !enabled_js_taint_ids.is_empty() {
                file_findings.extend(crate::rules::javascript::run_js_taint_batched(
                    source,
                    tree,
                    &ctx,
                    &enabled_js_taint_ids,
                ));
            }

            // Kotlin taint rules: dispatched the same way as the other
            // language engines via `run_kt_taint_batched`. The Kotlin
            // engine doesn't share Pass 1 summaries (it's intra-function
            // only and has no cross-file work yet), but the dispatcher
            // routes all enabled Kotlin taint rules through a single
            // entry point for parity.
            let enabled_kt_taint_ids: std::collections::HashSet<&str> =
                if matches!(language, Language::Kotlin) {
                    analysis_plan
                        .taint_specs
                        .iter()
                        .filter(|spec| matches!(spec.engine, TaintEngine::Kotlin))
                        .map(|spec| spec.rule_id)
                        .collect()
                } else {
                    std::collections::HashSet::new()
                };
            if !enabled_kt_taint_ids.is_empty() {
                file_findings.extend(crate::rules::kotlin::run_kt_taint_batched(
                    source,
                    tree,
                    &enabled_kt_taint_ids,
                ));
            }

            // C taint rules: same batched approach as Kotlin above.
            // No cross-file analysis; each function is analyzed
            // independently.
            let enabled_c_taint_ids: std::collections::HashSet<&str> =
                if matches!(language, Language::C) {
                    analysis_plan
                        .taint_specs
                        .iter()
                        .filter(|spec| matches!(spec.engine, TaintEngine::C))
                        .map(|spec| spec.rule_id)
                        .collect()
                } else {
                    std::collections::HashSet::new()
                };
            if !enabled_c_taint_ids.is_empty() {
                file_findings.extend(crate::rules::c::run_c_taint_batched(
                    source,
                    tree,
                    &enabled_c_taint_ids,
                ));
            }

            file_findings.extend(ast_rule_batch.run(source, tree, &ctx));

            for finding in &mut file_findings {
                finding.file = file_str.clone();
            }

            FileScanOutcome {
                findings: apply_inline_ignores(file_findings, &inline_ignores),
                stats: file_stats,
            }
        })
        .collect();

    let mut results = Vec::new();
    for outcome in outcomes {
        stats.extend(outcome.stats);
        results.extend(outcome.findings);
    }

    results.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
    (
        ScanResult {
            findings: results,
            files_scanned: stats.files_scanned,
            stats,
            duration: start.elapsed(),
        },
        warnings.into_inner().unwrap_or_default(),
    )
}

fn resolve_canonical_path(lookup: &HashMap<PathBuf, PathBuf>, path: &Path) -> PathBuf {
    if let Some(canonical) = lookup.get(path) {
        return canonical.clone();
    }
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn treats_tree_errors_as_parse_failures(language: Language, _path: &Path) -> bool {
    !matches!(
        language,
        Language::NginxConf
            | Language::ApacheConf
            | Language::HAProxyConf
            | Language::Dockerfile
            | Language::Manifest
    )
}

fn scan_root(path: &Path) -> &Path {
    if path.is_file() {
        path.parent().unwrap_or_else(|| Path::new("."))
    } else {
        path
    }
}

fn relative_scan_path(scan_root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(scan_root).unwrap_or(path).to_path_buf()
}

fn has_glob_metacharacters(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?') || pattern.contains('[') || pattern.contains('{')
}

fn normalize_match_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct CountingRule {
        id: &'static str,
        requirement: AstAnalysisRequirement,
        syntax_calls: Arc<AtomicUsize>,
        context_calls: Arc<AtomicUsize>,
    }

    impl Rule for CountingRule {
        fn id(&self) -> &str {
            self.id
        }
        fn severity(&self) -> crate::Severity {
            crate::Severity::Low
        }
        fn cwe(&self) -> Option<&str> {
            None
        }
        fn description(&self) -> &str {
            "test rule"
        }
        fn language(&self) -> Language {
            Language::JavaScript
        }
        fn ast_analysis_requirement(&self) -> AstAnalysisRequirement {
            self.requirement
        }
        fn check(&self, _source: &str, _tree: &tree_sitter::Tree) -> Vec<Finding> {
            self.syntax_calls.fetch_add(1, Ordering::SeqCst);
            Vec::new()
        }
        fn check_with_context(
            &self,
            _source: &str,
            _tree: &tree_sitter::Tree,
            _ctx: &FileContext<'_>,
        ) -> Vec<Finding> {
            self.context_calls.fetch_add(1, Ordering::SeqCst);
            Vec::new()
        }
    }

    #[test]
    fn block_comment_ignore_js() {
        let result = parse_inline_ignore("/* foxguard: ignore */", Language::JavaScript);
        assert!(result.is_some());
        let (comment_only, spec) = result.unwrap();
        assert!(comment_only);
        assert!(spec.all_rules);
    }

    #[test]
    fn block_comment_ignore_go() {
        let result = parse_inline_ignore("/* foxguard: ignore */", Language::Go);
        assert!(result.is_some());
    }

    #[test]
    fn block_comment_ignore_java() {
        let result = parse_inline_ignore("/* foxguard: ignore */", Language::Java);
        assert!(result.is_some());
    }

    #[test]
    fn block_comment_ignore_not_python() {
        let result = parse_inline_ignore("/* foxguard: ignore */", Language::Python);
        assert!(result.is_none());
    }

    #[test]
    fn block_comment_ignore_not_ruby() {
        let result = parse_inline_ignore("/* foxguard: ignore */", Language::Ruby);
        assert!(result.is_none());
    }

    #[test]
    fn block_comment_ignore_with_rule_id() {
        let result =
            parse_inline_ignore("/* foxguard: ignore[js/no-eval] */", Language::JavaScript);
        assert!(result.is_some());
        let (_, spec) = result.unwrap();
        assert!(!spec.all_rules);
        assert!(spec.rule_ids.contains("js/no-eval"));
    }

    #[test]
    fn path_exclude_matcher_matches_prefixes_recursively() {
        let matcher =
            PathExcludeMatcher::new(&["vendor".to_string()]).expect("failed to build matcher");

        assert!(matcher.is_excluded(Path::new("vendor/file.js")));
        assert!(matcher.is_excluded(Path::new("vendor/nested/file.js")));
        assert!(!matcher.is_excluded(Path::new("src/vendor/file.js")));
    }

    #[test]
    fn path_exclude_matcher_matches_globs() {
        let matcher = PathExcludeMatcher::new(&["generated/**/*.js".to_string()])
            .expect("failed to build matcher");

        assert!(matcher.is_excluded(Path::new("generated/foo/bar.js")));
        assert!(!matcher.is_excluded(Path::new("generated/foo/bar.ts")));
    }

    #[test]
    fn ast_rule_batch_dispatches_by_analysis_requirement() {
        let syntax_calls = Arc::new(AtomicUsize::new(0));
        let context_calls = Arc::new(AtomicUsize::new(0));
        let syntax_rule = CountingRule {
            id: "test/syntax",
            requirement: AstAnalysisRequirement::SyntaxTree,
            syntax_calls: Arc::clone(&syntax_calls),
            context_calls: Arc::clone(&context_calls),
        };
        let context_rule = CountingRule {
            id: "test/context",
            requirement: AstAnalysisRequirement::FileContext,
            syntax_calls: Arc::clone(&syntax_calls),
            context_calls: Arc::clone(&context_calls),
        };
        let rules: Vec<&dyn Rule> = vec![&syntax_rule, &context_rule];
        let batch = AstRuleBatch::from_rules(&rules);
        let source = "const value = 1;\n";
        let tree = super::super::parser::parse_file(source, Language::JavaScript).expect("parse");

        let findings = batch.run(source, &tree, &FileContext::default());

        assert!(findings.is_empty());
        assert_eq!(syntax_calls.load(Ordering::SeqCst), 1);
        assert_eq!(context_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn scan_stats_track_ignored_and_unsupported_files() {
        let repo = tempfile::tempdir().expect("failed to create temp dir");
        std::fs::write(repo.path().join("included.js"), "const value = 1;\n")
            .expect("failed to write included file");
        std::fs::write(repo.path().join("ignored.js"), "const value = 2;\n")
            .expect("failed to write ignored file");
        std::fs::write(repo.path().join("README.md"), "# fixture\n")
            .expect("failed to write unsupported file");

        let excludes =
            PathExcludeMatcher::new(&["ignored.js".to_string()]).expect("exclude matcher");
        let (result, notices) = scan_directory_with_notices(
            repo.path().to_str().expect("non-utf8 path"),
            &RuleRegistry::empty(),
            1_048_576,
            Some(&excludes),
        );

        assert!(notices.is_empty(), "unexpected notices: {notices:?}");
        assert_eq!(result.files_scanned, 1);
        assert_eq!(result.stats.files_discovered, 3);
        assert_eq!(result.stats.files_scanned, 1);
        assert_eq!(result.stats.files_skipped, 2);
        assert_eq!(result.stats.files_ignored, 1);
        assert_eq!(result.stats.unsupported_files, 1);
    }

    #[test]
    fn scan_stats_track_binary_and_parse_error_files() {
        let repo = tempfile::tempdir().expect("failed to create temp dir");
        std::fs::write(repo.path().join("binary.js"), [0xff, 0xfe])
            .expect("failed to write binary file");
        std::fs::write(repo.path().join("broken.js"), "function (\n")
            .expect("failed to write broken file");

        let (result, notices) = scan_directory_with_notices(
            repo.path().to_str().expect("non-utf8 path"),
            &RuleRegistry::empty(),
            1_048_576,
            None,
        );

        assert_eq!(result.files_scanned, 0);
        assert_eq!(result.stats.files_discovered, 2);
        assert_eq!(result.stats.files_skipped, 2);
        assert_eq!(result.stats.binary_files, 1);
        assert_eq!(result.stats.parse_error_files, 1);
        assert!(
            notices
                .iter()
                .any(|notice| notice.contains("binary or non-UTF-8")),
            "expected binary warning, got {notices:?}"
        );
        assert!(
            notices.iter().any(|notice| notice.contains("parse error")),
            "expected parse warning, got {notices:?}"
        );
    }
}
