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
                regex: Regex::new(r"\bAKIA[0-9A-Z]{16}\b")
                    .expect("static AWS access key regex should compile"),
            },
            SecretPattern {
                rule_id: "secret/aws-secret-access-key",
                severity: Severity::Critical,
                cwe: Some("CWE-798"),
                description: "Possible AWS secret access key detected",
                regex: Regex::new(
                    r#"(?i)\baws_secret_access_key\b\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?"#,
                )
                .expect("static AWS secret key regex should compile"),
            },
            SecretPattern {
                rule_id: "secret/github-token",
                severity: Severity::Critical,
                cwe: Some("CWE-798"),
                description: "Possible GitHub personal access token detected",
                regex: Regex::new(r"\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b")
                    .expect("static GitHub token regex should compile"),
            },
            SecretPattern {
                rule_id: "secret/gitlab-token",
                severity: Severity::Critical,
                cwe: Some("CWE-798"),
                description: "Possible GitLab personal access token detected",
                regex: Regex::new(r"\bglpat-[A-Za-z0-9\-_]{20,}\b")
                    .expect("static GitLab token regex should compile"),
            },
            SecretPattern {
                rule_id: "secret/npm-token",
                severity: Severity::High,
                cwe: Some("CWE-798"),
                description: "Possible npm access token detected",
                regex: Regex::new(r"\bnpm_[A-Za-z0-9]{36}\b")
                    .expect("static npm token regex should compile"),
            },
            SecretPattern {
                rule_id: "secret/slack-token",
                severity: Severity::High,
                cwe: Some("CWE-798"),
                description: "Possible Slack token detected",
                regex: Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
                    .expect("static Slack token regex should compile"),
            },
            SecretPattern {
                rule_id: "secret/stripe-live-key",
                severity: Severity::Critical,
                cwe: Some("CWE-798"),
                description: "Possible Stripe live secret key detected",
                regex: Regex::new(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b")
                    .expect("static Stripe key regex should compile"),
            },
            SecretPattern {
                rule_id: "secret/private-key",
                severity: Severity::Critical,
                cwe: Some("CWE-798"),
                description: "Private key material detected",
                regex: Regex::new(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----")
                    .expect("static private key regex should compile"),
            },
        ]
    })
}

pub fn scan_directory(root: &str, max_file_size: u64) -> Vec<Finding> {
    scan_directory_with_config(root, &SecretScanConfig::default(), max_file_size)
}

pub fn scan_directory_with_config(
    root: &str,
    config: &SecretScanConfig,
    max_file_size: u64,
) -> Vec<Finding> {
    scan_directory_with_config_and_notices(root, config, max_file_size).0
}

pub fn scan_directory_with_config_and_notices(
    root: &str,
    config: &SecretScanConfig,
    max_file_size: u64,
) -> (Vec<Finding>, Vec<String>) {
    let root_path = Path::new(root);
    let files: Vec<PathBuf> = if root_path.is_file() {
        vec![root_path.to_path_buf()]
    } else {
        WalkBuilder::new(root)
            .hidden(false)
            .git_ignore(true)
            .build()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_some_and(|ft| ft.is_file()))
            .map(|entry| entry.into_path())
            .collect()
    };

    scan_paths_with_config_and_notices(root_path, &files, config, max_file_size)
}

pub fn scan_paths(paths: &[PathBuf], max_file_size: u64) -> Vec<Finding> {
    scan_paths_with_config(
        Path::new("."),
        paths,
        &SecretScanConfig::default(),
        max_file_size,
    )
}

pub fn scan_paths_with_config(
    root: &Path,
    paths: &[PathBuf],
    config: &SecretScanConfig,
    max_file_size: u64,
) -> Vec<Finding> {
    scan_paths_with_config_and_notices(root, paths, config, max_file_size).0
}

pub fn scan_paths_with_config_and_notices(
    root: &Path,
    paths: &[PathBuf],
    config: &SecretScanConfig,
    max_file_size: u64,
) -> (Vec<Finding>, Vec<String>) {
    let patterns = patterns();
    let mut findings = Vec::new();
    let mut notices = Vec::new();
    let mut line_matches = Vec::new();

    for path in paths {
        if config.should_skip_path(root, path) {
            continue;
        }

        match std::fs::metadata(path) {
            Ok(m) if m.len() > max_file_size => {
                notices.push(format!(
                    "warning: skipping {} ({} bytes exceeds --max-file-size)",
                    path.display(),
                    m.len()
                ));
                continue;
            }
            Err(_) => {
                notices.push(format!(
                    "warning: skipping {} (cannot read metadata)",
                    path.display()
                ));
                continue;
            }
            _ => {}
        }

        let Some(source) = read_scannable_text(path) else {
            continue;
        };

        for (line_idx, line) in source.lines().enumerate() {
            line_matches.clear();
            for pattern in patterns {
                for matched in pattern.regex.find_iter(line) {
                    line_matches.push((pattern, matched.range()));
                }
            }
            if !line_matches
                .iter()
                .any(|(pattern, _)| !config.should_skip_rule(pattern.rule_id))
            {
                continue;
            }

            // Redact every recognized secret, including ignored rules, before
            // sharing a snippet between findings on this line.
            line_matches.sort_by_key(|(_, range)| range.start);
            let mut snippet = String::with_capacity(line.len());
            let mut cursor = 0;
            for (_, range) in &line_matches {
                if range.end <= cursor {
                    continue;
                }
                if range.start >= cursor {
                    snippet.push_str(&line[cursor..range.start]);
                    snippet.push_str("[REDACTED]");
                }
                cursor = range.end;
            }
            snippet.push_str(&line[cursor..]);

            for (pattern, matched) in &line_matches {
                if config.should_skip_rule(pattern.rule_id) {
                    continue;
                }
                findings.push(Finding {
                    rule_id: pattern.rule_id.to_string(),
                    severity: pattern.severity,
                    cwe: pattern.cwe.map(str::to_string),
                    description: pattern.description.to_string(),
                    file: path.display().to_string(),
                    line: line_idx + 1,
                    column: matched.start + 1,
                    end_line: line_idx + 1,
                    end_column: matched.end + 1,
                    snippet: snippet.clone(),
                    source_line: None,
                    source_description: None,
                    sink_line: None,
                    sink_description: None,
                    fix_suggestion: None,
                    sink_start_byte: None,
                    sink_end_byte: None,
                    confidence: crate::default_confidence(),
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
        }
    }

    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
    (findings, notices)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_finding_redacts_all_secrets_on_its_line() {
        let dir = tempfile::tempdir().unwrap();
        let first = ["ghp_", &"a".repeat(36)].concat();
        let second = ["ghp_", &"b".repeat(36)].concat();
        let npm = ["npm_", &"c".repeat(36)].concat();
        let path = dir.path().join("tokens.txt");
        std::fs::write(&path, format!("é tokens: {first}, {second}, {npm}\n")).unwrap();

        let findings = scan_paths(&[path], 1_000_000);
        assert_eq!(findings.len(), 3);
        for finding in findings {
            assert_eq!(
                finding.snippet,
                "é tokens: [REDACTED], [REDACTED], [REDACTED]"
            );
        }
    }

    #[test]
    fn ignored_secret_rules_do_not_expose_neighboring_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let github = ["ghp_", &"a".repeat(36)].concat();
        let npm = ["npm_", &"b".repeat(36)].concat();
        let path = dir.path().join("tokens.txt");
        std::fs::write(&path, format!("{github} {npm}\n")).unwrap();
        let config =
            SecretScanConfig::from_inputs(dir.path(), &[], None, &["secret/npm-token".to_string()])
                .unwrap();

        let findings = scan_paths_with_config(dir.path(), &[path], &config, 1_000_000);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "secret/github-token");
        assert_eq!(findings[0].snippet, "[REDACTED] [REDACTED]");
    }

    #[test]
    fn overlapping_secret_patterns_share_fully_redacted_snippets() {
        let dir = tempfile::tempdir().unwrap();
        let nested = ["glpat-", "npm_", &"a".repeat(36)].concat();
        let path = dir.path().join("tokens.txt");
        std::fs::write(&path, format!("TOKEN=\"{nested}\"\n")).unwrap();

        let findings = scan_paths(&[path], 1_000_000);
        assert_eq!(findings.len(), 2);
        for finding in findings {
            assert_eq!(finding.snippet, "TOKEN=\"[REDACTED]\"");
        }
    }

    /// Issue #401: `scan_directory` must include hidden files such as `.env`.
    #[test]
    fn scan_directory_includes_dotenv() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let github = ["ghp_", "abcdefghijklmnopqrstuvwxyz1234567890"].concat();
        std::fs::write(dir.path().join(".env"), format!("TOKEN={github}\n"))
            .expect("failed to write .env");

        let findings = scan_directory(dir.path().to_str().unwrap(), 1_000_000);
        assert!(
            !findings.is_empty(),
            "scan_directory must detect secrets inside .env"
        );
        assert!(
            findings.iter().any(|f| f.file.contains(".env")),
            "at least one finding should reference .env"
        );
    }

    /// Issue #401: `scan_directory` must descend into hidden directories.
    #[test]
    fn scan_directory_includes_hidden_dirs() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let hidden = dir.path().join(".secrets");
        std::fs::create_dir_all(&hidden).expect("failed to create hidden dir");
        let github = ["ghp_", "abcdefghijklmnopqrstuvwxyz1234567890"].concat();
        std::fs::write(hidden.join("creds.txt"), format!("TOKEN={github}\n"))
            .expect("failed to write creds.txt");

        let findings = scan_directory(dir.path().to_str().unwrap(), 1_000_000);
        assert!(
            !findings.is_empty(),
            "scan_directory must detect secrets inside hidden directories"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.file.contains(".secrets/creds.txt")
                    || f.file.contains(".secrets\\creds.txt")),
            "at least one finding should reference .secrets/creds.txt"
        );
    }
}
