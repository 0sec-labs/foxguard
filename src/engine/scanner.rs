use crate::rules::go_taint::go_aliases_from_tree;
use crate::rules::javascript_taint::js_aliases_from_tree;
use crate::rules::python_aliases::from_tree as py_aliases_from_tree;
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
        _ => None,
    }
}

/// Scan a directory (or single file) and return findings with metadata.
pub fn scan_directory(root: &str, registry: &RuleRegistry) -> ScanResult {
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

    scan_files(scan_root(root_path), files, registry)
}

/// Scan an explicit list of paths.
pub fn scan_paths(paths: &[PathBuf], registry: &RuleRegistry) -> ScanResult {
    scan_paths_with_root(Path::new("."), paths, registry)
}

/// Scan an explicit list of paths relative to a scan root.
pub fn scan_paths_with_root(root: &Path, paths: &[PathBuf], registry: &RuleRegistry) -> ScanResult {
    let files = paths
        .iter()
        .filter_map(|path| detect_language(path).map(|lang| (path.clone(), lang)))
        .collect();
    scan_files(scan_root(root), files, registry)
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
        "/dist/",
        "/build/",
        "/.next/",
        "/coverage/",
        "/.cache/",
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
        | Language::Swift => &["//"],
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
) -> ScanResult {
    let start = Instant::now();
    let file_count = files.len();

    let mut results: Vec<Finding> = files
        .par_iter()
        .flat_map(|(path, language)| {
            // Skip files in test/vendor/fixture directories
            if is_noise_path(path) {
                return Vec::new();
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
            let ctx = FileContext {
                python_aliases: python_aliases.as_ref(),
                javascript_aliases: javascript_aliases.as_ref(),
                go_aliases: go_aliases.as_ref(),
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
