use crate::rules::python_aliases::ImportAliases;
use crate::rules::{FileContext, RuleRegistry};
use crate::{Finding, Language};
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

/// Result of a scan with metadata.
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub duration: std::time::Duration,
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

/// Detect minified files: very long lines suggest bundled/compiled code.
fn is_minified(source: &str) -> bool {
    // If file is small, it's not minified
    if source.len() < 2000 {
        return false;
    }
    // Check the first line — minified files usually have one huge line
    if let Some(first_newline) = source.find('\n') {
        if first_newline > 1000 {
            return true;
        }
    } else {
        // No newline at all and file is over 2KB — definitely minified
        return source.len() > 2000;
    }
    // Check average line length
    let line_count = source.bytes().filter(|b| *b == b'\n').count().max(1);
    let avg_line_len = source.len() / line_count;
    avg_line_len > 300
}

fn scan_files(
    scan_root: &Path,
    files: Vec<(PathBuf, Language)>,
    registry: &RuleRegistry,
) -> ScanResult {
    let start = Instant::now();
    let file_count = files.len();
    let findings = Mutex::new(Vec::new());

    files.par_iter().for_each(|(path, language)| {
        // Skip files in test/vendor/fixture directories
        if is_noise_path(path) {
            return;
        }

        let Ok(source) = std::fs::read_to_string(path) else {
            return;
        };

        // Skip minified files (likely bundled/compiled assets)
        if is_minified(&source) {
            return;
        }

        let Some(tree) = super::parser::parse_file(&source, *language) else {
            return;
        };

        let file_str = path.display().to_string();
        let relative_path = relative_scan_path(scan_root, path);
        let rules = registry.rules_for_language(*language);

        // Per-file analysis context. Python builds an import alias table so
        // rules can resolve aliased callees (`import pickle as p; p.loads(x)`)
        // back to their canonical dotted paths before sink matching.
        let python_aliases = if matches!(language, Language::Python) {
            Some(ImportAliases::from_tree(&source, &tree))
        } else {
            None
        };
        let ctx = FileContext {
            python_aliases: python_aliases.as_ref(),
        };

        for rule in rules {
            if !rule.applies_to_path(&relative_path) {
                continue;
            }
            let mut rule_findings = rule.check_with_context(&source, &tree, &ctx);
            for f in &mut rule_findings {
                f.file = file_str.clone();
            }
            if !rule_findings.is_empty() {
                findings.lock().unwrap().extend(rule_findings);
            }
        }
    });

    let mut results = findings.into_inner().unwrap();
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
