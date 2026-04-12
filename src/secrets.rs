use crate::{Finding, Severity};
use ignore::WalkBuilder;
use regex::Regex;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

struct SecretPattern {
    rule_id: &'static str,
    severity: Severity,
    cwe: Option<&'static str>,
    description: &'static str,
    regex: Regex,
}

#[derive(Debug, Clone, Default)]
pub struct SecretScanConfig {
    excluded_paths: Vec<PathBuf>,
    ignored_rules: HashSet<String>,
}

impl SecretScanConfig {
    pub fn from_inputs(
        _root: &Path,
        excluded_paths: &[String],
        exclude_path_file: Option<&Path>,
        ignored_rules: &[String],
    ) -> Result<Self, String> {
        let mut all_excluded_paths = excluded_paths.to_vec();

        if let Some(path) = exclude_path_file {
            let content = std::fs::read_to_string(path).map_err(|e| {
                format!("Failed to read exclude path file {}: {}", path.display(), e)
            })?;

            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                all_excluded_paths.push(trimmed.to_string());
            }
        }

        Ok(Self {
            excluded_paths: all_excluded_paths.into_iter().map(PathBuf::from).collect(),
            ignored_rules: ignored_rules.iter().cloned().collect(),
        })
    }

    fn should_skip_path(&self, root: &Path, path: &Path) -> bool {
        if self.excluded_paths.is_empty() {
            return false;
        }

        let relative = normalize_relative_path(relative_path(root, path));
        let absolute = path.canonicalize().ok();

        self.excluded_paths.iter().any(|prefix| {
            if prefix.as_os_str().is_empty() {
                return false;
            }

            if prefix.is_absolute() {
                absolute
                    .as_ref()
                    .is_some_and(|absolute| absolute == prefix || absolute.starts_with(prefix))
            } else {
                let prefix = normalize_relative_path(prefix);
                relative == prefix || relative.starts_with(&prefix)
            }
        })
    }

    fn should_skip_rule(&self, rule_id: &str) -> bool {
        self.ignored_rules.contains(rule_id)
    }
}

fn patterns() -> &'static [SecretPattern] {
    static PATTERNS: OnceLock<Vec<SecretPattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            SecretPattern {
                rule_id: "secret/aws-access-key-id",
                severity: Severity::Critical,
                cwe: Some("CWE-798"),
                description: "Possible AWS access key ID detected",
                regex: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
            },
            SecretPattern {
                rule_id: "secret/aws-secret-access-key",
                severity: Severity::Critical,
                cwe: Some("CWE-798"),
                description: "Possible AWS secret access key detected",
                regex: Regex::new(
                    r#"(?i)\baws_secret_access_key\b\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?"#,
                )
                .unwrap(),
            },
            SecretPattern {
                rule_id: "secret/github-token",
                severity: Severity::Critical,
                cwe: Some("CWE-798"),
                description: "Possible GitHub personal access token detected",
                regex: Regex::new(r"\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b")
                    .unwrap(),
            },
            SecretPattern {
                rule_id: "secret/gitlab-token",
                severity: Severity::Critical,
                cwe: Some("CWE-798"),
                description: "Possible GitLab personal access token detected",
                regex: Regex::new(r"\bglpat-[A-Za-z0-9\-_]{20,}\b").unwrap(),
            },
            SecretPattern {
                rule_id: "secret/npm-token",
                severity: Severity::High,
                cwe: Some("CWE-798"),
                description: "Possible npm access token detected",
                regex: Regex::new(r"\bnpm_[A-Za-z0-9]{36}\b").unwrap(),
            },
            SecretPattern {
                rule_id: "secret/slack-token",
                severity: Severity::High,
                cwe: Some("CWE-798"),
                description: "Possible Slack token detected",
                regex: Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").unwrap(),
            },
            SecretPattern {
                rule_id: "secret/stripe-live-key",
                severity: Severity::Critical,
                cwe: Some("CWE-798"),
                description: "Possible Stripe live secret key detected",
                regex: Regex::new(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b").unwrap(),
            },
            SecretPattern {
                rule_id: "secret/private-key",
                severity: Severity::Critical,
                cwe: Some("CWE-798"),
                description: "Private key material detected",
                regex: Regex::new(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----")
                    .unwrap(),
            },
        ]
    })
}

fn redact_match(line: &str, start: usize, end: usize) -> String {
    let mut redacted = String::with_capacity(line.len());
    redacted.push_str(&line[..start]);
    redacted.push_str("[REDACTED]");
    redacted.push_str(&line[end..]);
    redacted
}

pub fn scan_directory(root: &str) -> Vec<Finding> {
    scan_directory_with_config(root, &SecretScanConfig::default())
}

pub fn scan_directory_with_config(root: &str, config: &SecretScanConfig) -> Vec<Finding> {
    let root_path = Path::new(root);
    let files: Vec<PathBuf> = if root_path.is_file() {
        vec![root_path.to_path_buf()]
    } else {
        WalkBuilder::new(root)
            .hidden(true)
            .git_ignore(true)
            .build()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_some_and(|ft| ft.is_file()))
            .map(|entry| entry.into_path())
            .collect()
    };

    scan_paths_with_config(root_path, &files, config)
}

pub fn scan_paths(paths: &[PathBuf]) -> Vec<Finding> {
    scan_paths_with_config(Path::new("."), paths, &SecretScanConfig::default())
}

pub fn scan_paths_with_config(
    root: &Path,
    paths: &[PathBuf],
    config: &SecretScanConfig,
) -> Vec<Finding> {
    let patterns = patterns();
    let mut findings = Vec::new();

    for path in paths {
        if config.should_skip_path(root, path) {
            continue;
        }

        let Some(source) = read_scannable_text(path) else {
            continue;
        };

        for (line_idx, line) in source.lines().enumerate() {
            for pattern in patterns {
                if config.should_skip_rule(pattern.rule_id) {
                    continue;
                }

                for matched in pattern.regex.find_iter(line) {
                    findings.push(Finding {
                        rule_id: pattern.rule_id.to_string(),
                        severity: pattern.severity,
                        cwe: pattern.cwe.map(str::to_string),
                        description: pattern.description.to_string(),
                        file: path.display().to_string(),
                        line: line_idx + 1,
                        column: matched.start() + 1,
                        end_line: line_idx + 1,
                        end_column: matched.end() + 1,
                        snippet: redact_match(line, matched.start(), matched.end()),
                        source_line: None,
                        source_description: None,
                        sink_line: None,
                        sink_description: None,
                        fix_suggestion: None,
                    });
                }
            }
        }
    }

    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
    findings
}

fn relative_path<'a>(root: &'a Path, path: &'a Path) -> &'a Path {
    let base = if root.is_file() {
        root.parent().unwrap_or_else(|| Path::new("."))
    } else {
        root
    };
    path.strip_prefix(base).unwrap_or(path)
}

fn normalize_relative_path(path: &Path) -> PathBuf {
    path.components().collect()
}

fn read_scannable_text(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.contains(&0) {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}
