use crate::rules::cross_file::CrossFileSummaryMap;
use crate::rules::go_taint::{self, go_aliases_from_tree};
use crate::rules::javascript_taint::{self, js_aliases_from_tree};
use crate::rules::python_aliases::{from_tree as py_aliases_from_tree, resolve_imports_to_paths};
use crate::rules::python_taint;
use crate::rules::{common::AliasTable, FileContext, RuleRegistry};
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
    pub duration: std::time::Duration,
}

struct PreparedFile {
    source: String,
    tree: tree_sitter::Tree,
    aliases: AliasTable,
    canonical_path: PathBuf,
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

    fn is_excluded(&self, path: &Path) -> bool {
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

/// Detect language from file extension.
fn detect_language(path: &Path) -> Option<Language> {
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

    let files: Vec<_> = if root_path.is_file() {
        if let Some(lang) = detect_language(root_path) {
            if excludes.is_some_and(|matcher| {
                matcher.is_excluded(&relative_scan_path(scan_root, root_path))
            }) {
                vec![]
            } else {
                vec![(root_path.to_path_buf(), lang)]
            }
        } else {
            vec![]
        }
    } else {
        WalkBuilder::new(root)
            .follow_links(false) // never follow symlinks
            .hidden(true) // skip hidden files
            .git_ignore(true) // respect .gitignore
            .build()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_some_and(|ft| ft.is_file()))
            .filter_map(|entry| {
                let path = entry.into_path();
                if excludes.is_some_and(|matcher| {
                    matcher.is_excluded(&relative_scan_path(scan_root, &path))
                }) {
                    return None;
                }
                detect_language(&path).map(|lang| (path, lang))
            })
            .collect()
    };

    scan_files(scan_root, files, registry, max_file_size)
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
    let files = paths
        .iter()
        .filter(|path| {
            !excludes
                .is_some_and(|matcher| matcher.is_excluded(&relative_scan_path(scan_root, path)))
        })
        .filter_map(|path| detect_language(path).map(|lang| (path.clone(), lang)))
        .collect();
    scan_files(scan_root, files, registry, max_file_size)
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
    let full_match = captures.get(0).unwrap();

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
        | Language::Kotlin => &["//"],
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
) -> (ScanResult, Vec<String>) {
    let start = Instant::now();
    let file_count = files.len();
    let warnings = Mutex::new(Vec::new());

    let mut rules_by_lang: HashMap<Language, Vec<&dyn crate::rules::Rule>> = HashMap::new();
    for (_, language) in &files {
        rules_by_lang
            .entry(*language)
            .or_insert_with(|| registry.rules_for_language(*language));
    }

    let has_python_taint_rules = rules_by_lang
        .get(&Language::Python)
        .is_some_and(|rules| rules.iter().any(|rule| rule.id().contains("/taint-")));
    let has_js_taint_rules = rules_by_lang
        .get(&Language::JavaScript)
        .is_some_and(|rules| rules.iter().any(|rule| rule.id().contains("/taint-")));
    let has_go_taint_rules = rules_by_lang
        .get(&Language::Go)
        .is_some_and(|rules| rules.iter().any(|rule| rule.id().contains("/taint-")));
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
            let rule_specs = crate::rules::python::python_taint_rule_specs();
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
        let js_rule_specs = crate::rules::javascript::js_taint_rule_specs();
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
                let tree = super::parser::parse_file(&source, Language::JavaScript)?;
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
        let go_rule_specs = crate::rules::go::go_taint_rule_specs();
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

    let canonical_path_lookup: HashMap<PathBuf, PathBuf> = prepared_files
        .iter()
        .flat_map(|(path, prepared)| {
            let canonical = prepared.canonical_path.clone();
            let mut entries = vec![
                (path.clone(), canonical.clone()),
                (canonical.clone(), canonical),
            ];
            if path.is_relative() {
                entries.push((scan_root.join(path), prepared.canonical_path.clone()));
            }
            entries
        })
        .collect();

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
    let mut results: Vec<Finding> = files
        .par_iter()
        .flat_map(|(path, language)| {
            // Skip files in test/vendor/fixture directories
            if is_noise_path(path) {
                return Vec::new();
            }

            match std::fs::metadata(path) {
                Ok(m) if m.len() > max_file_size => {
                    warnings.lock().unwrap().push(format!(
                        "warning: skipping {} ({} bytes exceeds --max-file-size)",
                        path.display(),
                        m.len()
                    ));
                    return Vec::new();
                }
                Err(_) => {
                    warnings.lock().unwrap().push(format!(
                        "warning: skipping {} (cannot read metadata)",
                        path.display()
                    ));
                    return Vec::new();
                }
                _ => {}
            }

            let prepared = prepared_files.get(path);
            let owned_source;
            let source = if let Some(prepared) = prepared {
                prepared.source.as_str()
            } else {
                let Ok(read_source) = std::fs::read_to_string(path) else {
                    return Vec::new();
                };
                if is_minified(&read_source) {
                    return Vec::new();
                }
                owned_source = read_source;
                owned_source.as_str()
            };

            let inline_ignores = inline_ignore_directives(source, *language);

            let owned_tree;
            let tree = if let Some(prepared) = prepared {
                &prepared.tree
            } else {
                let Some(parsed_tree) = super::parser::parse_file(source, *language) else {
                    return Vec::new();
                };
                owned_tree = parsed_tree;
                &owned_tree
            };

            let file_str = path.display().to_string();
            let relative_path = relative_scan_path(scan_root, path);
            let Some(rules) = rules_by_lang.get(language) else {
                return Vec::new();
            };

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
            for rule in rules {
                if !rule.applies_to_path(&relative_path) {
                    continue;
                }
                file_findings.extend(rule.check_with_context(source, tree, &ctx));
            }

            for finding in &mut file_findings {
                finding.file = file_str.clone();
            }

            apply_inline_ignores(file_findings, &inline_ignores)
        })
        .collect();

    results.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
    (
        ScanResult {
            findings: results,
            files_scanned: file_count,
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
}
