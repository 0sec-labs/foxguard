use crate::cli::{ScanArgs, SecretsArgs, SeverityFilter};
use crate::{Finding, Severity};
use serde::Deserialize;
use serde_yaml::{Mapping, Sequence, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

const CONFIG_NAMES: [&str; 4] = [
    ".foxguard.yml",
    ".foxguard.yaml",
    "foxguard.yml",
    "foxguard.yaml",
];

#[derive(Debug, Clone, Default)]
pub struct FoxguardConfig {
    pub scan: ScanConfig,
    pub secrets: SecretsConfig,
}

#[derive(Debug, Clone, Default)]
pub struct ScanConfig {
    pub rules: Option<String>,
    pub no_builtins: bool,
    pub severity: Option<SeverityFilter>,
    pub baseline: Option<String>,
    pub ignore_rules: Vec<ScanIgnoreRule>,
    /// Per-rule severity overrides applied at finding emit time.
    ///
    /// Keyed by rule id (e.g. `py/no-eval`). Applied before the
    /// `severity` min-filter, so demoting a rule to Low with a
    /// `severity: medium` filter will suppress the finding.
    pub severity_overrides: HashMap<String, Severity>,
}

#[derive(Debug, Clone, Default)]
pub struct SecretsConfig {
    pub baseline: Option<String>,
    pub exclude_paths: Vec<String>,
    pub exclude_path_file: Option<String>,
    pub ignored_rules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanIgnoreRule {
    pub path: String,
    pub rules: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawFoxguardConfig {
    #[serde(default)]
    scan: RawScanConfig,
    #[serde(default)]
    secrets: RawSecretsConfig,
}

#[derive(Debug, Deserialize, Default)]
struct RawScanConfig {
    rules: Option<String>,
    no_builtins: Option<bool>,
    severity: Option<SeverityFilter>,
    baseline: Option<String>,
    #[serde(default)]
    ignore_rules: Vec<RawScanIgnoreRule>,
    /// Invalid severity values surface as yaml parse errors via
    /// `Severity`'s serde derive (rename_all = lowercase), which
    /// satisfies the "loud on invalid" requirement without custom
    /// validation.
    #[serde(default)]
    severity_overrides: HashMap<String, Severity>,
}

#[derive(Debug, Deserialize, Default)]
struct RawScanIgnoreRule {
    path: String,
    #[serde(default)]
    rules: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawSecretsConfig {
    baseline: Option<String>,
    #[serde(default)]
    exclude_paths: Vec<String>,
    exclude_path_file: Option<String>,
    #[serde(default)]
    ignore_rules: Vec<String>,
}

pub fn load_for_scan(
    scan_path: &Path,
    explicit_path: Option<&str>,
) -> Result<Option<FoxguardConfig>, String> {
    let Some(path) = resolve_config_path(scan_path, explicit_path)? else {
        return Ok(None);
    };

    let path = path.canonicalize().unwrap_or_else(|_| path.clone());
    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let allowed_root = resolve_allowed_root(scan_path, config_dir);

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read config {}: {}", path.display(), e))?;
    let raw: RawFoxguardConfig = serde_yaml::from_str(&content)
        .map_err(|e| format!("Failed to parse config {}: {}", path.display(), e))?;

    Ok(Some(FoxguardConfig::from_raw(
        raw,
        config_dir,
        &allowed_root,
    )?))
}

pub fn apply_scan_defaults(scan: &mut ScanArgs, config: Option<&FoxguardConfig>) {
    let Some(config) = config else {
        return;
    };

    if scan.rules.is_none() {
        scan.rules = config.scan.rules.clone();
    }
    if !scan.no_builtins && config.scan.no_builtins {
        scan.no_builtins = true;
    }
    if scan.severity.is_none() {
        scan.severity = config.scan.severity;
    }
    if scan.baseline.is_none() {
        scan.baseline = config.scan.baseline.clone();
    }
}

pub fn apply_secrets_defaults(args: &mut SecretsArgs, config: Option<&FoxguardConfig>) {
    let Some(config) = config else {
        return;
    };

    if args.baseline.is_none() {
        args.baseline = config.secrets.baseline.clone();
    }
    if args.exclude_path_file.is_none() {
        args.exclude_path_file = config.secrets.exclude_path_file.clone();
    }
    args.exclude_paths
        .extend(config.secrets.exclude_paths.clone());
    args.ignored_rules
        .extend(config.secrets.ignored_rules.clone());
}

impl FoxguardConfig {
    fn from_raw(
        raw: RawFoxguardConfig,
        config_dir: &Path,
        allowed_root: &Path,
    ) -> Result<Self, String> {
        let scan_rules = raw
            .scan
            .rules
            .map(|path| resolve_value_path(config_dir, allowed_root, "scan.rules", &path))
            .transpose()?;
        let scan_baseline = raw
            .scan
            .baseline
            .map(|path| resolve_value_path(config_dir, allowed_root, "scan.baseline", &path))
            .transpose()?;
        let scan_ignore_rules = raw
            .scan
            .ignore_rules
            .into_iter()
            .map(|entry| {
                Ok(ScanIgnoreRule {
                    path: resolve_value_path(
                        config_dir,
                        allowed_root,
                        "scan.ignore_rules.path",
                        &entry.path,
                    )?,
                    rules: entry.rules,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let secrets_baseline = raw
            .secrets
            .baseline
            .map(|path| resolve_value_path(config_dir, allowed_root, "secrets.baseline", &path))
            .transpose()?;
        let secrets_exclude_paths = raw
            .secrets
            .exclude_paths
            .into_iter()
            .map(|path| {
                resolve_value_path(config_dir, allowed_root, "secrets.exclude_paths", &path)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let secrets_exclude_path_file = raw
            .secrets
            .exclude_path_file
            .map(|path| {
                resolve_value_path(config_dir, allowed_root, "secrets.exclude_path_file", &path)
            })
            .transpose()?;

        Ok(Self {
            scan: ScanConfig {
                rules: scan_rules,
                no_builtins: raw.scan.no_builtins.unwrap_or(false),
                severity: raw.scan.severity,
                baseline: scan_baseline,
                ignore_rules: scan_ignore_rules,
                severity_overrides: raw.scan.severity_overrides,
            },
            secrets: SecretsConfig {
                baseline: secrets_baseline,
                exclude_paths: secrets_exclude_paths,
                exclude_path_file: secrets_exclude_path_file,
                ignored_rules: raw.secrets.ignore_rules,
            },
        })
    }
}

/// Apply per-rule severity overrides from config to findings.
///
/// Mutates each finding's severity in place if its rule_id is present in
/// the override map. Returns a list of human-readable notices for
/// override rule IDs that do not match any known rule in `known_rule_ids`
/// — callers typically push these onto a warning channel (stderr) so
/// typos surface quickly without a hard failure.
///
/// Applied before the severity min-filter so the filter sees the
/// overridden value. See issue #209.
pub fn apply_severity_overrides(
    findings: &mut [Finding],
    config: Option<&FoxguardConfig>,
    known_rule_ids: &std::collections::HashSet<String>,
) -> Vec<String> {
    let Some(config) = config else {
        return Vec::new();
    };
    let overrides = &config.scan.severity_overrides;
    if overrides.is_empty() {
        return Vec::new();
    }

    for finding in findings.iter_mut() {
        if let Some(new_severity) = overrides.get(&finding.rule_id) {
            finding.severity = *new_severity;
        }
    }

    let mut unknown: Vec<&String> = overrides
        .keys()
        .filter(|id| !known_rule_ids.contains(id.as_str()))
        .collect();
    if unknown.is_empty() {
        return Vec::new();
    }
    unknown.sort();
    vec![format!(
        "warning: severity_overrides references unknown rule id{}: {}",
        if unknown.len() == 1 { "" } else { "s" },
        unknown
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    )]
}

pub fn suppress_with_scan_ignores(
    findings: Vec<Finding>,
    config: Option<&FoxguardConfig>,
) -> Vec<Finding> {
    let Some(config) = config else {
        return findings;
    };
    if config.scan.ignore_rules.is_empty() {
        return findings;
    }

    findings
        .into_iter()
        .filter(|finding| {
            !config.scan.ignore_rules.iter().any(|entry| {
                entry.path == finding.file
                    && entry
                        .rules
                        .iter()
                        .any(|rule_id| rule_id == &finding.rule_id)
            })
        })
        .collect()
}

pub fn editable_config_path(
    scan_path: &Path,
    explicit_path: Option<&str>,
) -> Result<PathBuf, String> {
    if let Some(path) = explicit_path {
        return Ok(PathBuf::from(path));
    }

    if let Some(path) = resolve_config_path(scan_path, explicit_path)? {
        return Ok(path);
    }

    Ok(resolve_scan_root(scan_path).join(".foxguard.yml"))
}

pub fn add_scan_ignore_rule(
    scan_path: &Path,
    explicit_config: Option<&str>,
    finding: &Finding,
) -> Result<(PathBuf, bool), String> {
    let config_path = editable_config_path(scan_path, explicit_config)?;
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let finding_path = Path::new(&finding.file);
    let stored_path = match finding_path.strip_prefix(config_dir) {
        Ok(relative) => relative.display().to_string(),
        Err(_) => finding.file.clone(),
    };

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create config directory '{}': {}",
                parent.display(),
                e
            )
        })?;
    }

    let mut root = if config_path.exists() {
        let content = fs::read_to_string(&config_path)
            .map_err(|e| format!("failed to read config '{}': {}", config_path.display(), e))?;
        if content.trim().is_empty() {
            Value::Mapping(Mapping::new())
        } else {
            serde_yaml::from_str(&content)
                .map_err(|e| format!("failed to parse config '{}': {}", config_path.display(), e))?
        }
    } else {
        Value::Mapping(Mapping::new())
    };

    let mapping = root
        .as_mapping_mut()
        .ok_or_else(|| format!("config '{}' must be a YAML mapping", config_path.display()))?;
    let scan = mapping
        .entry(Value::String("scan".to_string()))
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    let scan_mapping = scan.as_mapping_mut().ok_or_else(|| {
        format!(
            "config '{}' field 'scan' must be a mapping",
            config_path.display()
        )
    })?;
    let ignore_rules = scan_mapping
        .entry(Value::String("ignore_rules".to_string()))
        .or_insert_with(|| Value::Sequence(Sequence::new()));
    let sequence = ignore_rules.as_sequence_mut().ok_or_else(|| {
        format!(
            "config '{}' field 'scan.ignore_rules' must be a list",
            config_path.display()
        )
    })?;

    let mut added = false;
    let mut updated_existing = false;
    for item in sequence.iter_mut() {
        let Some(item_mapping) = item.as_mapping_mut() else {
            continue;
        };
        let path_matches = item_mapping
            .get(Value::String("path".to_string()))
            .and_then(Value::as_str)
            .map(|value| value == stored_path)
            .unwrap_or(false);
        if !path_matches {
            continue;
        }

        let rules_value = item_mapping
            .entry(Value::String("rules".to_string()))
            .or_insert_with(|| Value::Sequence(Sequence::new()));
        let rules = rules_value.as_sequence_mut().ok_or_else(|| {
            format!(
                "config '{}' field 'scan.ignore_rules.rules' must be a list",
                config_path.display()
            )
        })?;

        if rules
            .iter()
            .any(|value| value.as_str() == Some(finding.rule_id.as_str()))
        {
            updated_existing = true;
            break;
        }

        rules.push(Value::String(finding.rule_id.clone()));
        added = true;
        updated_existing = true;
        break;
    }

    if !updated_existing {
        let mut item = Mapping::new();
        item.insert(
            Value::String("path".to_string()),
            Value::String(stored_path),
        );
        item.insert(
            Value::String("rules".to_string()),
            Value::Sequence(vec![Value::String(finding.rule_id.clone())]),
        );
        sequence.push(Value::Mapping(item));
        added = true;
    }

    let content = serde_yaml::to_string(&root).map_err(|e| {
        format!(
            "failed to serialize config '{}': {}",
            config_path.display(),
            e
        )
    })?;
    fs::write(&config_path, content)
        .map_err(|e| format!("failed to write config '{}': {}", config_path.display(), e))?;

    Ok((config_path, added))
}

pub fn add_secrets_ignored_rule(
    scan_path: &Path,
    explicit_config: Option<&str>,
    rule_id: &str,
) -> Result<(PathBuf, bool), String> {
    let config_path = editable_config_path(scan_path, explicit_config)?;

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create config directory '{}': {}",
                parent.display(),
                e
            )
        })?;
    }

    let mut root = if config_path.exists() {
        let content = fs::read_to_string(&config_path)
            .map_err(|e| format!("failed to read config '{}': {}", config_path.display(), e))?;
        if content.trim().is_empty() {
            Value::Mapping(Mapping::new())
        } else {
            serde_yaml::from_str(&content)
                .map_err(|e| format!("failed to parse config '{}': {}", config_path.display(), e))?
        }
    } else {
        Value::Mapping(Mapping::new())
    };

    let mapping = root
        .as_mapping_mut()
        .ok_or_else(|| format!("config '{}' must be a YAML mapping", config_path.display()))?;
    let secrets = mapping
        .entry(Value::String("secrets".to_string()))
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    let secrets_mapping = secrets.as_mapping_mut().ok_or_else(|| {
        format!(
            "config '{}' field 'secrets' must be a mapping",
            config_path.display()
        )
    })?;
    let ignore_rules = secrets_mapping
        .entry(Value::String("ignore_rules".to_string()))
        .or_insert_with(|| Value::Sequence(Sequence::new()));
    let sequence = ignore_rules.as_sequence_mut().ok_or_else(|| {
        format!(
            "config '{}' field 'secrets.ignore_rules' must be a list",
            config_path.display()
        )
    })?;

    let added = if sequence.iter().any(|value| value.as_str() == Some(rule_id)) {
        false
    } else {
        sequence.push(Value::String(rule_id.to_string()));
        true
    };

    let content = serde_yaml::to_string(&root).map_err(|e| {
        format!(
            "failed to serialize config '{}': {}",
            config_path.display(),
            e
        )
    })?;
    fs::write(&config_path, content)
        .map_err(|e| format!("failed to write config '{}': {}", config_path.display(), e))?;

    Ok((config_path, added))
}

fn resolve_config_path(
    scan_path: &Path,
    explicit_path: Option<&str>,
) -> Result<Option<PathBuf>, String> {
    if let Some(path) = explicit_path {
        let path = PathBuf::from(path);
        if !path.exists() {
            return Err(format!("Config path '{}' does not exist", path.display()));
        }
        return Ok(Some(path));
    }

    let start = scan_path
        .canonicalize()
        .unwrap_or_else(|_| scan_path.to_path_buf());
    let start = if start.is_file() {
        start
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        start
    };

    for dir in start.ancestors() {
        for name in CONFIG_NAMES {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Ok(Some(candidate));
            }
        }
    }

    Ok(None)
}

fn resolve_value_path(
    base: &Path,
    allowed_root: &Path,
    field: &str,
    value: &str,
) -> Result<String, String> {
    let joined = if Path::new(value).is_absolute() {
        PathBuf::from(value)
    } else {
        base.join(value)
    };
    let resolved = resolve_path_for_boundary(&joined);

    if !resolved.starts_with(allowed_root) {
        return Err(format!(
            "Config path '{}' for {} escapes the project root {}",
            value,
            field,
            allowed_root.display()
        ));
    }

    Ok(resolved.display().to_string())
}

fn resolve_allowed_root(scan_path: &Path, config_dir: &Path) -> PathBuf {
    let scan_root = resolve_scan_root(scan_path);
    let config_dir = resolve_path_for_boundary(config_dir);

    if scan_root.starts_with(&config_dir) {
        config_dir
    } else {
        scan_root
    }
}

fn resolve_scan_root(scan_path: &Path) -> PathBuf {
    let scan_root = resolve_path_for_boundary(scan_path);
    if scan_root.is_file() {
        scan_root
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        scan_root
    }
}

fn resolve_path_for_boundary(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }

    let absolute = absolutize_path(path);
    for ancestor in absolute.ancestors() {
        if let Ok(canonical_ancestor) = ancestor.canonicalize() {
            let suffix = absolute
                .strip_prefix(ancestor)
                .unwrap_or_else(|_| Path::new(""));
            return normalize_path(&canonical_ancestor.join(suffix));
        }
    }

    normalize_path(&absolute)
}

fn absolutize_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component.as_os_str());
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }

    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    fn write_config(dir: &Path, relative_path: &str, content: &str) -> PathBuf {
        let path = dir.join(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("failed to create config directory");
        }
        fs::write(&path, content).expect("failed to write config");
        path
    }

    #[test]
    fn load_for_scan_rejects_parent_traversal_in_config_paths() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  rules: ../../../etc/passwd\n",
        );

        let err = load_for_scan(repo.path(), None).expect_err("expected traversal to fail");

        assert!(err.contains("scan.rules"), "unexpected error: {err}");
        assert!(
            err.contains("escapes the project root"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_for_scan_rejects_absolute_paths_outside_project_root() {
        let repo = TempDir::new().expect("failed to create temp dir");
        let outside = TempDir::new().expect("failed to create outside temp dir");
        let outside_rules = outside.path().join("rules.yml");
        fs::write(&outside_rules, "rules: []\n").expect("failed to write outside file");

        write_config(
            repo.path(),
            ".foxguard.yml",
            &format!("scan:\n  rules: {}\n", outside_rules.display()),
        );

        let err = load_for_scan(repo.path(), None).expect_err("expected absolute path to fail");

        assert!(err.contains("scan.rules"), "unexpected error: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn load_for_scan_rejects_symlink_escapes() {
        let repo = TempDir::new().expect("failed to create temp dir");
        let outside = TempDir::new().expect("failed to create outside temp dir");
        let outside_baseline = outside.path().join("baseline.json");
        fs::write(&outside_baseline, "[]\n").expect("failed to write outside baseline");
        symlink(&outside_baseline, repo.path().join("baseline.json"))
            .expect("failed to create symlink");

        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  baseline: baseline.json\n",
        );

        let err = load_for_scan(repo.path(), None).expect_err("expected symlink escape to fail");

        assert!(err.contains("scan.baseline"), "unexpected error: {err}");
    }

    #[test]
    fn load_for_scan_allows_paths_within_scan_root_for_nested_explicit_config() {
        let repo = TempDir::new().expect("failed to create temp dir");
        fs::create_dir_all(repo.path().join("fixtures")).expect("failed to create fixture dir");
        let config = write_config(
            repo.path(),
            "config/foxguard.yml",
            "secrets:\n  exclude_paths:\n    - ../fixtures\n",
        );

        let loaded = load_for_scan(repo.path(), Some(config.to_str().expect("non-utf8 path")))
            .expect("failed to load config")
            .expect("expected config");
        let expected = resolve_path_for_boundary(&repo.path().join("fixtures"));

        assert_eq!(
            loaded.secrets.exclude_paths,
            vec![expected.display().to_string()]
        );
    }

    #[test]
    fn load_for_scan_parses_scan_ignore_rules() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  ignore_rules:\n    - path: src/app.py\n      rules:\n        - py/no-command-injection\n",
        );

        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");

        assert_eq!(loaded.scan.ignore_rules.len(), 1);
        assert_eq!(
            loaded.scan.ignore_rules[0].rules,
            vec!["py/no-command-injection"]
        );
    }

    #[test]
    fn add_scan_ignore_rule_creates_or_updates_config() {
        let repo = TempDir::new().expect("failed to create temp dir");
        let finding = Finding {
            rule_id: "py/no-command-injection".to_string(),
            severity: crate::Severity::High,
            cwe: None,
            description: "tainted input reaches command sink".to_string(),
            file: repo.path().join("src/app.py").display().to_string(),
            line: 10,
            column: 5,
            end_line: 10,
            end_column: 20,
            snippet: "os.system(cmd)".to_string(),
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
        };

        let (config_path, added) =
            add_scan_ignore_rule(repo.path(), None, &finding).expect("should write ignore rule");
        assert!(added);
        assert!(config_path.ends_with(".foxguard.yml"));

        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");
        assert_eq!(loaded.scan.ignore_rules.len(), 1);
        assert_eq!(
            loaded.scan.ignore_rules[0].rules,
            vec!["py/no-command-injection"]
        );

        let (_, added_again) =
            add_scan_ignore_rule(repo.path(), None, &finding).expect("should preserve duplicate");
        assert!(!added_again);
    }

    #[test]
    fn add_secrets_ignored_rule_creates_or_updates_config() {
        let repo = TempDir::new().expect("failed to create temp dir");

        let (config_path, added) =
            add_secrets_ignored_rule(repo.path(), None, "secret/github-token")
                .expect("should write secrets ignore rule");
        assert!(added);
        assert!(config_path.ends_with(".foxguard.yml"));

        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");
        assert_eq!(loaded.secrets.ignored_rules, vec!["secret/github-token"]);

        let (_, added_again) = add_secrets_ignored_rule(repo.path(), None, "secret/github-token")
            .expect("should preserve duplicate");
        assert!(!added_again);
    }

    fn finding_with_rule(rule_id: &str, severity: Severity) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity,
            cwe: None,
            description: "test".to_string(),
            file: "src/app.py".to_string(),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 1,
            snippet: "x".to_string(),
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
        }
    }

    #[test]
    fn severity_overrides_single_rule() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  severity_overrides:\n    py/no-eval: low\n",
        );
        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");

        assert_eq!(
            loaded.scan.severity_overrides.get("py/no-eval"),
            Some(&Severity::Low)
        );

        let mut findings = vec![
            finding_with_rule("py/no-eval", Severity::Critical),
            finding_with_rule("py/no-pickle-loads", Severity::High),
        ];
        let known: std::collections::HashSet<String> = ["py/no-eval", "py/no-pickle-loads"]
            .into_iter()
            .map(String::from)
            .collect();
        let warnings = apply_severity_overrides(&mut findings, Some(&loaded), &known);

        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[1].severity, Severity::High);
    }

    #[test]
    fn severity_overrides_multiple_rules() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  severity_overrides:\n    py/no-eval: low\n    py/no-cors-star: critical\n    js/no-hardcoded-secret: high\n",
        );
        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");

        let mut findings = vec![
            finding_with_rule("py/no-eval", Severity::Critical),
            finding_with_rule("py/no-cors-star", Severity::Medium),
            finding_with_rule("js/no-hardcoded-secret", Severity::Low),
        ];
        let known: std::collections::HashSet<String> =
            findings.iter().map(|f| f.rule_id.clone()).collect();
        let warnings = apply_severity_overrides(&mut findings, Some(&loaded), &known);

        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[1].severity, Severity::Critical);
        assert_eq!(findings[2].severity, Severity::High);
    }

    #[test]
    fn severity_overrides_interact_with_min_filter() {
        // Verify the override value is the one the min-filter sees:
        // override to Low + min-filter Medium → finding suppressed.
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  severity_overrides:\n    py/no-eval: low\n",
        );
        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");

        let mut findings = vec![finding_with_rule("py/no-eval", Severity::Critical)];
        let known: std::collections::HashSet<String> =
            std::iter::once("py/no-eval".to_string()).collect();
        let _ = apply_severity_overrides(&mut findings, Some(&loaded), &known);

        // After override the finding is Low; a Medium min-filter should drop it.
        let min = Severity::Medium;
        findings.retain(|f| f.severity >= min);
        assert!(
            findings.is_empty(),
            "override should place finding below min-filter"
        );
    }

    #[test]
    fn severity_overrides_warn_on_unknown_rule_ids() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  severity_overrides:\n    py/no-eval: low\n    py/typo-here: critical\n",
        );
        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");

        let mut findings = vec![finding_with_rule("py/no-eval", Severity::Critical)];
        // Only py/no-eval is a "known" rule; the typo should warn.
        let known: std::collections::HashSet<String> =
            std::iter::once("py/no-eval".to_string()).collect();
        let warnings = apply_severity_overrides(&mut findings, Some(&loaded), &known);

        assert_eq!(warnings.len(), 1, "expected one warning: {warnings:?}");
        assert!(
            warnings[0].contains("py/typo-here"),
            "warning should name the unknown rule: {}",
            warnings[0]
        );
        assert!(
            !warnings[0].contains("py/no-eval"),
            "known rule should not appear in warning: {}",
            warnings[0]
        );
    }

    #[test]
    fn severity_overrides_reject_invalid_value() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  severity_overrides:\n    py/no-eval: banana\n",
        );
        let err = load_for_scan(repo.path(), None).expect_err("expected invalid severity to fail");
        assert!(
            err.contains("Failed to parse config"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn severity_overrides_empty_when_absent() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(repo.path(), ".foxguard.yml", "scan:\n  no_builtins: true\n");
        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");
        assert!(loaded.scan.severity_overrides.is_empty());
    }
}
