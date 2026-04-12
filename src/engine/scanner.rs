use crate::rules::cross_file::CrossFileSummaryMap;
use crate::rules::go_taint::{self, go_aliases_from_tree};
use crate::rules::javascript_taint::{self, js_aliases_from_tree};
use crate::rules::python_aliases::{from_tree as py_aliases_from_tree, resolve_imports_to_paths};
use crate::rules::python_taint;
use crate::rules::{FileContext, RuleRegistry};
use crate::{Finding, Language};
use ignore::WalkBuilder;
use rayon::prelude::*;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Instant;

/// Result of a scan with metadata.
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub duration: std::time::Duration,
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
pub fn scan_directory(root: &str, registry: &RuleRegistry, max_file_size: u64) -> ScanResult {
    let root_path = Path::new(root);

    let files: Vec<_> = if root_path.is_file() {
        if let Some(lang) = detect_language(root_path) {
            vec![(root_path.to_path_buf(), lang)]
        } else {
            vec![]
        }
    } else {
        WalkBuilder::new(root)
            .hidden(true) // skip hidden files
            .git_ignore(true) // respect .gitignore
            .build()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_some_and(|ft| ft.is_file()))
            .filter_map(|entry| {
                let path = entry.into_path();
                detect_language(&path).map(|lang| (path, lang))
            })
            .collect()
    };

    scan_files(scan_root(root_path), files, registry, max_file_size)
}

/// Scan an explicit list of paths.
pub fn scan_paths(paths: &[PathBuf], registry: &RuleRegistry, max_file_size: u64) -> ScanResult {
    scan_paths_with_root(Path::new("."), paths, registry, max_file_size)
}

/// Scan an explicit list of paths relative to a scan root.
pub fn scan_paths_with_root(
    root: &Path,
    paths: &[PathBuf],
    registry: &RuleRegistry,
    max_file_size: u64,
) -> ScanResult {
    let files = paths
        .iter()
        .filter_map(|path| detect_language(path).map(|lang| (path.clone(), lang)))
        .collect();
    scan_files(scan_root(root), files, registry, max_file_size)
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

fn inline_ignore_directives(source: &str, language: Language) -> HashMap<usize, InlineIgnoreSpec> {
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
) -> ScanResult {
    let start = Instant::now();
    let file_count = files.len();

    // ── Pass 1: Extract cross-file taint summaries ────────────────────
    // Run pass 1 for Python and Go files when there are multiple files
    // of the same language — single-file scans cannot benefit from
    // cross-file analysis.

    let python_files: Vec<&(PathBuf, Language)> = files
        .iter()
        .filter(|(path, lang)| matches!(lang, Language::Python) && !is_noise_path(path))
        .collect();

    let go_files: Vec<&(PathBuf, Language)> = files
        .iter()
        .filter(|(path, lang)| matches!(lang, Language::Go) && !is_noise_path(path))
        .collect();

    let mut cross_file_summaries: CrossFileSummaryMap = if python_files.len() > 1 {
        let rule_specs = crate::rules::python::python_taint_rule_specs();
        python_files
            .par_iter()
            .filter_map(|(path, _)| {
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
                if summaries.is_empty() {
                    None
                } else {
                    // Canonicalize the path for consistent lookups.
                    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
                    Some((canonical, summaries))
                }
            })
            .collect()
    } else {
        CrossFileSummaryMap::new()
    };

    let js_files: Vec<&(PathBuf, Language)> = files
        .iter()
        .filter(|(path, lang)| matches!(lang, Language::JavaScript) && !is_noise_path(path))
        .collect();

    // JavaScript cross-file summaries: extract from all JS/TS files.
    if js_files.len() > 1 {
        let js_rule_specs = crate::rules::javascript::js_taint_rule_specs();
        let js_summaries: CrossFileSummaryMap = js_files
            .par_iter()
            .filter_map(|(path, _)| {
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
                if summaries.is_empty() {
                    None
                } else {
                    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
                    Some((canonical, summaries))
                }
            })
            .collect();
        cross_file_summaries.extend(js_summaries);
    }

    // Go cross-file summaries: extract from all Go files.
    if go_files.len() > 1 {
        let go_rule_specs = crate::rules::go::go_taint_rule_specs();
        let go_summaries: CrossFileSummaryMap = go_files
            .par_iter()
            .filter_map(|(path, _)| {
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
                if summaries.is_empty() {
                    None
                } else {
                    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
                    Some((canonical, summaries))
                }
            })
            .collect();
        cross_file_summaries.extend(go_summaries);
    }

    let has_cross_file = !cross_file_summaries.is_empty();

    // Build a directory→files index for Go same-package resolution.
    // All .go files in the same directory share the same package.
    let go_dir_index: HashMap<PathBuf, Vec<PathBuf>> = if has_cross_file {
        let mut index: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();
        for (path, lang) in &files {
            if matches!(lang, Language::Go) && !is_noise_path(path) {
                if let Some(dir) = path.parent() {
                    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
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
                    eprintln!(
                        "warning: skipping {} ({} bytes exceeds --max-file-size)",
                        path.display(),
                        m.len()
                    );
                    return Vec::new();
                }
                Err(_) => {
                    eprintln!(
                        "warning: skipping {} (cannot read metadata)",
                        path.display()
                    );
                    return Vec::new();
                }
                _ => {}
            }

            let Ok(source) = std::fs::read_to_string(path) else {
                return Vec::new();
            };

            // Skip minified files (likely bundled/compiled assets)
            if is_minified(&source) {
                return Vec::new();
            }

            let inline_ignores = inline_ignore_directives(&source, *language);

            let Some(tree) = super::parser::parse_file(&source, *language) else {
                return Vec::new();
            };

            let file_str = path.display().to_string();
            let relative_path = relative_scan_path(scan_root, path);
            let rules = registry.rules_for_language(*language);

            // Per-file analysis context. Python builds an import alias table so
            // rules can resolve aliased callees (`import pickle as p; p.loads(x)`)
            // back to their canonical dotted paths before sink matching.
            let python_aliases = if matches!(language, Language::Python) {
                Some(py_aliases_from_tree(&source, &tree))
            } else {
                None
            };
            let javascript_aliases = if matches!(language, Language::JavaScript) {
                Some(js_aliases_from_tree(&source, &tree))
            } else {
                None
            };
            let go_aliases = if matches!(language, Language::Go) {
                Some(go_aliases_from_tree(&source, &tree))
            } else {
                None
            };

            // Build Python import-to-path map for cross-file resolution.
            let python_import_paths = if has_cross_file && matches!(language, Language::Python) {
                let mut imports = resolve_imports_to_paths(&source, &tree, path);
                // Canonicalize all paths to match the summary map keys.
                let canonical: HashMap<String, PathBuf> = imports
                    .drain()
                    .map(|(k, v)| {
                        let canon = std::fs::canonicalize(&v).unwrap_or(v);
                        (k, canon)
                    })
                    .collect();
                Some(canonical)
            } else {
                None
            };

            // Build JavaScript import-to-path map for cross-file resolution.
            let javascript_import_paths =
                if has_cross_file && matches!(language, Language::JavaScript) {
                    let mut imports =
                        javascript_taint::resolve_js_imports_to_paths(&source, &tree, path);
                    let canonical: HashMap<String, PathBuf> = imports
                        .drain()
                        .map(|(k, v)| {
                            let canon = std::fs::canonicalize(&v).unwrap_or(v);
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
            let go_same_package_paths = if has_cross_file && matches!(language, Language::Go) {
                path.parent().and_then(|dir| {
                    let canonical_self =
                        std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
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
                python_aliases: python_aliases.as_ref(),
                javascript_aliases: javascript_aliases.as_ref(),
                go_aliases: go_aliases.as_ref(),
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
                let mut rule_findings = rule.check_with_context(&source, &tree, &ctx);
                for f in &mut rule_findings {
                    f.file = file_str.clone();
                }
                let rule_findings = apply_inline_ignores(rule_findings, &inline_ignores);
                file_findings.extend(rule_findings);
            }
            file_findings
        })
        .collect();

    results.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
    ScanResult {
        findings: results,
        files_scanned: file_count,
        duration: start.elapsed(),
    }
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
