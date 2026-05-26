use crate::cli::{ScanArgs, SecretsArgs, SeverityFilter};
use crate::rules::common::{
    set_hardcoded_secret_min_entropy_override, set_hardcoded_secret_min_length_override,
};
use crate::{Finding, Severity};
use regex::Regex;
use serde::Deserialize;
use serde_yaml_ng::{Mapping, Sequence, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

const CONFIG_NAMES: [&str; 4] = [
    ".foxguard.yml",
    ".foxguard.yaml",
    "foxguard.yml",
    "foxguard.yaml",
];

#[derive(Debug, Clone, Default)]
pub struct FoxguardConfig {
    pub project_root: PathBuf,
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
    /// Optional allowlist of rule IDs. When non-empty, only rules whose
    /// `id()` appears in the list are kept in the active registry.
    pub enable_rules: Vec<String>,
    /// Denylist of rule IDs. Rules whose `id()` appears in this list are
    /// removed from the active registry and never execute. Applied after
    /// `enable_rules`, so a rule listed in both lists is disabled.
    pub disable_rules: Vec<String>,
    /// Threshold knobs for built-in pattern rules (refs #210).
    pub thresholds: ScanThresholds,
    /// Minimum confidence (0.0–1.0) to report. Findings whose
    /// `confidence` is strictly below this value are suppressed.
    /// `None` means "no filter" (equivalent to 0.0). See issue #207.
    pub min_confidence: Option<f32>,
    /// Per-rule option map passed to `Rule::configure` at registry build
    /// time. Keys are rule IDs, values are opaque YAML that each rule
    /// parses itself. Unknown rule IDs surface as stderr warnings.
    pub rule_options: HashMap<String, serde_yaml_ng::Value>,
    /// Enable CNSA 2.0 compliance annotations and summary in terminal
    /// output. Mirrors the `--cnsa2` CLI flag. See issue #241 and
    /// [`crate::compliance`].
    pub cnsa2: bool,
    /// Pattern-based suppression rules. Each entry matches findings by
    /// `rule_id` (exact match) and `path_pattern` (regex matched against
    /// the finding's file path). When both conditions match, the finding
    /// is suppressed. Useful for silencing known false positives in test
    /// or fixture directories without a per-file ignore entry.
    pub suppressions: Vec<SuppressionPattern>,
}

/// Tunable thresholds for pattern/heuristic rules.
///
/// See issue #210. Each field is `Option<_>` and `None` means "use the
/// default hardcoded in the rule today" so an empty threshold block is a
/// pure no-op (zero behavior change). Only thresholds that correspond to
/// an *existing* hardcoded constant in the scanner are wired up today;
/// the rest are parsed and validated so users can set them without a
/// schema break when follow-up PRs hook them into the engine.
#[derive(Debug, Clone, Default)]
pub struct ScanThresholds {
    pub secrets: SecretsThresholds,
    pub taint: TaintThresholds,
}

/// Thresholds for `*-hardcoded-secret` rules.
///
/// Both fields are live: `min_length` replaces the previously hardcoded
/// `inner.len() >= 4` check, and `min_entropy` adds a Shannon entropy
/// gate so low-entropy strings like `"test"` or `"changeme"` are skipped.
#[derive(Debug, Clone, Default)]
pub struct SecretsThresholds {
    pub min_length: Option<usize>,
    pub min_entropy: Option<f32>,
}

/// Thresholds for taint-propagation rules.
///
/// `max_hops` filters taint findings by propagation depth. Findings with
/// more hops than `max_hops` are suppressed after scanning. Currently
/// hops are 1 (intra-file direct) or 2 (cross-file).
#[derive(Debug, Clone, Default)]
pub struct TaintThresholds {
    pub max_hops: Option<usize>,
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

/// A pattern-based suppression rule parsed from the `scan.suppressions`
/// config section. Matches findings whose `rule_id` equals `rule_id` and
/// whose file path matches `path_pattern` (a regular expression).
#[derive(Debug, Clone)]
pub struct SuppressionPattern {
    pub rule_id: String,
    pub path_pattern: Regex,
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
    #[serde(default)]
    enable_rules: Vec<String>,
    #[serde(default)]
    disable_rules: Vec<String>,
    /// Threshold knobs. Invalid scalar shapes (e.g. a string in a
    /// numeric field) surface as yaml parse errors so typos fail loudly
    /// at load time rather than silently falling back to defaults.
    #[serde(default)]
    thresholds: RawScanThresholds,
    #[serde(default)]
    min_confidence: Option<f32>,
    #[serde(default)]
    rule_options: HashMap<String, serde_yaml_ng::Value>,
    #[serde(default)]
    cnsa2: Option<bool>,
    #[serde(default)]
    suppressions: Vec<RawSuppressionPattern>,
}

#[derive(Debug, Deserialize, Default)]
struct RawScanThresholds {
    #[serde(default)]
    secrets: RawSecretsThresholds,
    #[serde(default)]
    taint: RawTaintThresholds,
}

#[derive(Debug, Deserialize, Default)]
struct RawSecretsThresholds {
    min_length: Option<usize>,
    min_entropy: Option<f32>,
}

#[derive(Debug, Deserialize, Default)]
struct RawTaintThresholds {
    max_hops: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
struct RawScanIgnoreRule {
    path: String,
    #[serde(default)]
    rules: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawSuppressionPattern {
    rule_id: String,
    path_pattern: String,
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
    let raw: RawFoxguardConfig = serde_yaml_ng::from_str(&content)
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
    if scan.min_confidence.is_none() {
        scan.min_confidence = config.scan.min_confidence;
    }
    if !scan.cnsa2 && config.scan.cnsa2 {
        scan.cnsa2 = true;
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

        let raw_thresholds = raw.scan.thresholds;
        let min_length = raw_thresholds.secrets.min_length;
        if let Some(value) = min_length {
            if value == 0 {
                return Err(
                    "scan.thresholds.secrets.min_length must be >= 1 (0 disables the \
                     rule entirely; use scan.ignore_rules instead)"
                        .to_string(),
                );
            }
        }
        if let Some(value) = raw_thresholds.secrets.min_entropy {
            if !(0.0..=8.0).contains(&value) || value.is_nan() {
                return Err(format!(
                    "scan.thresholds.secrets.min_entropy must be a finite number in \
                     [0.0, 8.0] (got {value})"
                ));
            }
        }
        if let Some(value) = raw_thresholds.taint.max_hops {
            if value == 0 {
                return Err(
                    "scan.thresholds.taint.max_hops must be >= 1 (0 would disable taint \
                     analysis; set scan.no_builtins or use scan.ignore_rules instead)"
                        .to_string(),
                );
            }
        }
        let thresholds = ScanThresholds {
            secrets: SecretsThresholds {
                min_length,
                min_entropy: raw_thresholds.secrets.min_entropy,
            },
            taint: TaintThresholds {
                max_hops: raw_thresholds.taint.max_hops,
            },
        };

        let suppressions = raw
            .scan
            .suppressions
            .into_iter()
            .map(|entry| {
                let pattern = Regex::new(&entry.path_pattern).map_err(|e| {
                    format!(
                        "scan.suppressions: invalid path_pattern '{}': {}",
                        entry.path_pattern, e
                    )
                })?;
                Ok(SuppressionPattern {
                    rule_id: entry.rule_id,
                    path_pattern: pattern,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        Ok(Self {
            project_root: allowed_root.to_path_buf(),
            scan: ScanConfig {
                rules: scan_rules,
                no_builtins: raw.scan.no_builtins.unwrap_or(false),
                severity: raw.scan.severity,
                baseline: scan_baseline,
                ignore_rules: scan_ignore_rules,
                severity_overrides: raw.scan.severity_overrides,
                enable_rules: raw.scan.enable_rules,
                disable_rules: raw.scan.disable_rules,
                thresholds,
                min_confidence: raw.scan.min_confidence,
                rule_options: raw.scan.rule_options,
                cnsa2: raw.scan.cnsa2.unwrap_or(false),
                suppressions,
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
    identity_root: &Path,
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
            let finding_path_key =
                crate::path_identity::finding_path_key(identity_root, &finding.file);
            !config.scan.ignore_rules.iter().any(|entry| {
                crate::path_identity::stored_path_key(identity_root, &entry.path)
                    == finding_path_key
                    && entry
                        .rules
                        .iter()
                        .any(|rule_id| rule_id == &finding.rule_id)
            })
        })
        .collect()
}

/// Suppress findings that match any pattern-based suppression rule from
/// `scan.suppressions` in the config. A finding is suppressed when its
/// `rule_id` matches the suppression's `rule_id` exactly and its file
/// path matches the suppression's `path_pattern` regex.
pub fn suppress_with_patterns(
    findings: Vec<Finding>,
    config: Option<&FoxguardConfig>,
) -> Vec<Finding> {
    let Some(config) = config else {
        return findings;
    };
    if config.scan.suppressions.is_empty() {
        return findings;
    }

    findings
        .into_iter()
        .filter(|finding| {
            !config.scan.suppressions.iter().any(|suppression| {
                suppression.rule_id == finding.rule_id
                    && suppression.path_pattern.is_match(&finding.file)
            })
        })
        .collect()
}

/// Install any [`ScanThresholds`] overrides from the loaded config into the
/// scanner's process-wide state. Idempotent: calling with a fresh config
/// overwrites any previous override, so repeated scans in the same
/// process (e.g. the TUI) cannot leak a stale value.
pub fn apply_scan_thresholds(config: Option<&FoxguardConfig>) {
    let min_length = config.and_then(|cfg| cfg.scan.thresholds.secrets.min_length);
    set_hardcoded_secret_min_length_override(min_length);

    let min_entropy = config.and_then(|cfg| cfg.scan.thresholds.secrets.min_entropy);
    set_hardcoded_secret_min_entropy_override(min_entropy);
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

    Ok(crate::path_identity::resolve_scan_root(scan_path).join(".foxguard.yml"))
}

pub fn add_scan_ignore_rule(
    scan_path: &Path,
    explicit_config: Option<&str>,
    finding: &Finding,
) -> Result<(PathBuf, bool), String> {
    let config_path = editable_config_path(scan_path, explicit_config)?;
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let allowed_root = resolve_allowed_root(scan_path, config_dir);
    let stored_path = crate::path_identity::finding_path_key(&allowed_root, &finding.file);

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
            serde_yaml_ng::from_str(&content)
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
            .map(|value| crate::path_identity::stored_path_key(&allowed_root, value) == stored_path)
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

    let content = serde_yaml_ng::to_string(&root).map_err(|e| {
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

/// Write `scan.severity_overrides[<rule_id>]: <severity>` into the editable
/// config file for `scan_path`, creating the file/structure if necessary.
///
/// Returns `(config_path, previous_severity)`. `previous_severity` is
/// `Some(prev)` when the rule already had a different override (which this
/// function replaces), `None` when the rule is new to the map. An unchanged
/// override is not rewritten: the file is left untouched and `Ok((path,
/// None))` is returned.
///
/// Used by the TUI triage menu as a non-destructive alternative to
/// `ignore_rules` — operators can dial a noisy rule down to `low` instead
/// of silencing it entirely.
pub fn add_severity_override_to_config(
    scan_path: &Path,
    explicit_config: Option<&str>,
    rule_id: &str,
    severity: Severity,
) -> Result<(PathBuf, Option<Severity>), String> {
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
            serde_yaml_ng::from_str(&content)
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
    let overrides = scan_mapping
        .entry(Value::String("severity_overrides".to_string()))
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    let overrides_mapping = overrides.as_mapping_mut().ok_or_else(|| {
        format!(
            "config '{}' field 'scan.severity_overrides' must be a mapping",
            config_path.display()
        )
    })?;

    let key = Value::String(rule_id.to_string());
    let new_value = Value::String(severity_yaml_name(severity).to_string());
    let previous = overrides_mapping
        .get(&key)
        .and_then(Value::as_str)
        .and_then(parse_severity_yaml_name);
    if previous == Some(severity) {
        return Ok((config_path, None));
    }
    overrides_mapping.insert(key, new_value);

    let content = serde_yaml_ng::to_string(&root).map_err(|e| {
        format!(
            "failed to serialize config '{}': {}",
            config_path.display(),
            e
        )
    })?;
    fs::write(&config_path, content)
        .map_err(|e| format!("failed to write config '{}': {}", config_path.display(), e))?;

    Ok((config_path, previous))
}

/// Append `rule_id` to `scan.disable_rules` in the editable config, creating
/// the file/structure if necessary. Returns `(config_path, added)` where
/// `added` is `false` when the rule was already in the list (the file is
/// left untouched in that case).
pub fn add_disabled_rule_to_config(
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
            serde_yaml_ng::from_str(&content)
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
    let disable_rules = scan_mapping
        .entry(Value::String("disable_rules".to_string()))
        .or_insert_with(|| Value::Sequence(Sequence::new()));
    let sequence = disable_rules.as_sequence_mut().ok_or_else(|| {
        format!(
            "config '{}' field 'scan.disable_rules' must be a list",
            config_path.display()
        )
    })?;

    if sequence.iter().any(|value| value.as_str() == Some(rule_id)) {
        return Ok((config_path, false));
    }

    sequence.push(Value::String(rule_id.to_string()));

    let content = serde_yaml_ng::to_string(&root).map_err(|e| {
        format!(
            "failed to serialize config '{}': {}",
            config_path.display(),
            e
        )
    })?;
    fs::write(&config_path, content)
        .map_err(|e| format!("failed to write config '{}': {}", config_path.display(), e))?;

    Ok((config_path, true))
}

/// Check whether `rule_id` is already listed in `scan.disable_rules` for the
/// resolved config file. Returns `Ok(false)` when no config file exists.
/// The TUI uses this to grey out the "Disable rule globally" action when
/// it would be a no-op.
pub fn is_rule_disabled_in_config(
    scan_path: &Path,
    explicit_config: Option<&str>,
    rule_id: &str,
) -> Result<bool, String> {
    let Some(path) = resolve_config_path(scan_path, explicit_config)? else {
        return Ok(false);
    };
    let content = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read config '{}': {}", path.display(), e))?;
    if content.trim().is_empty() {
        return Ok(false);
    }
    let value: Value = serde_yaml_ng::from_str(&content)
        .map_err(|e| format!("failed to parse config '{}': {}", path.display(), e))?;
    let Some(disable_rules) = value
        .get("scan")
        .and_then(|scan| scan.get("disable_rules"))
        .and_then(Value::as_sequence)
    else {
        return Ok(false);
    };
    Ok(disable_rules
        .iter()
        .any(|item| item.as_str() == Some(rule_id)))
}

/// Look up the current `scan.severity_overrides[rule_id]` value in the
/// resolved config file, if any. Returns `Ok(None)` when no config exists,
/// the rule is not in the map, or the stored value isn't a valid severity.
pub fn current_severity_override(
    scan_path: &Path,
    explicit_config: Option<&str>,
    rule_id: &str,
) -> Result<Option<Severity>, String> {
    let Some(path) = resolve_config_path(scan_path, explicit_config)? else {
        return Ok(None);
    };
    let content = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read config '{}': {}", path.display(), e))?;
    if content.trim().is_empty() {
        return Ok(None);
    }
    let value: Value = serde_yaml_ng::from_str(&content)
        .map_err(|e| format!("failed to parse config '{}': {}", path.display(), e))?;
    Ok(value
        .get("scan")
        .and_then(|scan| scan.get("severity_overrides"))
        .and_then(|overrides| overrides.get(rule_id))
        .and_then(Value::as_str)
        .and_then(parse_severity_yaml_name))
}

fn severity_yaml_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn parse_severity_yaml_name(value: &str) -> Option<Severity> {
    match value {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
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
            serde_yaml_ng::from_str(&content)
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

    let content = serde_yaml_ng::to_string(&root).map_err(|e| {
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
    let resolved = crate::path_identity::resolve_path_for_boundary(&joined);

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
    let scan_root = crate::path_identity::resolve_scan_root(scan_path);
    let config_dir = crate::path_identity::resolve_path_for_boundary(config_dir);

    if scan_root.starts_with(&config_dir) {
        config_dir
    } else {
        scan_root
    }
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

    fn finding_at(path: &Path) -> Finding {
        Finding {
            rule_id: "py/no-command-injection".to_string(),
            severity: crate::Severity::High,
            cwe: None,
            description: "tainted input reaches command sink".to_string(),
            file: path.display().to_string(),
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
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
            dep_name: None,
        }
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
        let expected =
            crate::path_identity::resolve_path_for_boundary(&repo.path().join("fixtures"));

        assert_eq!(
            loaded.secrets.exclude_paths,
            vec![expected.display().to_string()]
        );
    }

    #[test]
    fn load_for_scan_parses_enable_and_disable_rules() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  enable_rules:\n    - py/no-eval\n    - js/no-xss\n  disable_rules:\n    - go/no-ssrf\n",
        );

        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");

        assert_eq!(
            loaded.scan.enable_rules,
            vec!["py/no-eval".to_string(), "js/no-xss".to_string()]
        );
        assert_eq!(loaded.scan.disable_rules, vec!["go/no-ssrf".to_string()]);
    }

    #[test]
    fn load_for_scan_defaults_enable_and_disable_rules_to_empty() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(repo.path(), ".foxguard.yml", "scan:\n  severity: high\n");

        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");

        assert!(loaded.scan.enable_rules.is_empty());
        assert!(loaded.scan.disable_rules.is_empty());
    }

    #[test]
    fn load_for_scan_parses_min_confidence() {
        // `scan.min_confidence` is optional. When supplied, it's stored
        // as a raw f32 in [0.0, 1.0] that the scan pipeline uses to drop
        // low-confidence findings before they reach reporting.
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  min_confidence: 0.8\n",
        );

        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");

        assert_eq!(loaded.scan.min_confidence, Some(0.8));
    }

    #[test]
    fn load_for_scan_defaults_min_confidence_to_none() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(repo.path(), ".foxguard.yml", "scan:\n  severity: high\n");

        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");

        assert!(loaded.scan.min_confidence.is_none());
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
        let finding = finding_at(&repo.path().join("src/app.py"));

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
    fn add_scan_ignore_rule_merges_legacy_absolute_path_entry() {
        let repo = TempDir::new().expect("failed to create temp dir");
        let app_path = repo.path().join("src/app.py");
        write_config(
            repo.path(),
            ".foxguard.yml",
            &format!(
                "scan:\n  ignore_rules:\n    - path: {}\n      rules:\n        - py/no-sql-injection\n",
                app_path.display()
            ),
        );
        let finding = finding_at(&app_path);

        let (_, added) =
            add_scan_ignore_rule(repo.path(), None, &finding).expect("should update ignore rule");

        assert!(added);
        let content =
            fs::read_to_string(repo.path().join(".foxguard.yml")).expect("failed to read config");
        let value: Value = serde_yaml_ng::from_str(&content).expect("failed to parse config");
        let ignore_rules = value
            .get("scan")
            .and_then(|scan| scan.get("ignore_rules"))
            .and_then(Value::as_sequence)
            .expect("missing ignore_rules");
        assert_eq!(
            ignore_rules.len(),
            1,
            "expected existing legacy path entry to be updated"
        );
        let rules = ignore_rules[0]
            .get("rules")
            .and_then(Value::as_sequence)
            .expect("missing rules");
        assert!(
            rules
                .iter()
                .any(|rule| rule.as_str() == Some("py/no-command-injection")),
            "expected new rule to be merged into existing path entry"
        );
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
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
            dep_name: None,
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

    // ── scan.thresholds.* (issue #210) ────────────────────────────────────

    #[test]
    fn thresholds_default_empty_when_absent() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(repo.path(), ".foxguard.yml", "scan:\n  no_builtins: true\n");
        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");
        assert!(loaded.scan.thresholds.secrets.min_length.is_none());
        assert!(loaded.scan.thresholds.secrets.min_entropy.is_none());
        assert!(loaded.scan.thresholds.taint.max_hops.is_none());
    }

    #[test]
    fn thresholds_parse_secrets_min_length() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  thresholds:\n    secrets:\n      min_length: 12\n",
        );
        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");
        assert_eq!(loaded.scan.thresholds.secrets.min_length, Some(12));
    }

    #[test]
    fn thresholds_parse_secrets_min_entropy() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  thresholds:\n    secrets:\n      min_entropy: 3.5\n",
        );
        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");
        assert_eq!(loaded.scan.thresholds.secrets.min_entropy, Some(3.5));
    }

    #[test]
    fn thresholds_parse_taint_max_hops() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  thresholds:\n    taint:\n      max_hops: 8\n",
        );
        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");
        assert_eq!(loaded.scan.thresholds.taint.max_hops, Some(8));
    }

    #[test]
    fn thresholds_reject_zero_secrets_min_length() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  thresholds:\n    secrets:\n      min_length: 0\n",
        );
        let err = load_for_scan(repo.path(), None).expect_err("expected validation error");
        assert!(err.contains("min_length"), "unexpected error: {err}");
    }

    #[test]
    fn thresholds_reject_zero_taint_max_hops() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  thresholds:\n    taint:\n      max_hops: 0\n",
        );
        let err = load_for_scan(repo.path(), None).expect_err("expected validation error");
        assert!(err.contains("max_hops"), "unexpected error: {err}");
    }

    #[test]
    fn thresholds_reject_out_of_range_min_entropy() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  thresholds:\n    secrets:\n      min_entropy: 20.0\n",
        );
        let err = load_for_scan(repo.path(), None).expect_err("expected validation error");
        assert!(err.contains("min_entropy"), "unexpected error: {err}");
    }

    #[test]
    fn thresholds_reject_invalid_types() {
        // `min_length` is a `usize`; yaml string fails to parse at deserialize
        // time, which is exactly the "loud on invalid" behavior we want.
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  thresholds:\n    secrets:\n      min_length: not-a-number\n",
        );
        let err = load_for_scan(repo.path(), None).expect_err("expected parse error");
        assert!(
            err.contains("Failed to parse config"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn apply_scan_thresholds_installs_and_resets_min_length_override() {
        use crate::rules::common::hardcoded_secret_min_length;

        // Baseline: default value when no config present.
        apply_scan_thresholds(None);
        assert_eq!(hardcoded_secret_min_length(), 4);

        // Override via loaded config.
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  thresholds:\n    secrets:\n      min_length: 9\n",
        );
        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");
        apply_scan_thresholds(Some(&loaded));
        assert_eq!(hardcoded_secret_min_length(), 9);

        // Re-applying a config without the override resets to the default,
        // so repeated scans in the same process (TUI) cannot leak state.
        let repo2 = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo2.path(),
            ".foxguard.yml",
            "scan:\n  no_builtins: true\n",
        );
        let fresh = load_for_scan(repo2.path(), None)
            .expect("failed to load config")
            .expect("expected config");
        apply_scan_thresholds(Some(&fresh));
        assert_eq!(hardcoded_secret_min_length(), 4);
    }

    // ── TUI triage helpers: severity override + disable rule writers ──────

    #[test]
    fn add_severity_override_creates_config_and_records_previous() {
        let repo = TempDir::new().expect("failed to create temp dir");

        let (path, previous) =
            add_severity_override_to_config(repo.path(), None, "py/no-eval", Severity::Low)
                .expect("should write severity override");
        assert!(path.ends_with(".foxguard.yml"));
        assert!(previous.is_none(), "no prior override should exist");

        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");
        assert_eq!(
            loaded.scan.severity_overrides.get("py/no-eval"),
            Some(&Severity::Low)
        );

        // Replacing with a different severity returns the previous one.
        let (_, previous_again) =
            add_severity_override_to_config(repo.path(), None, "py/no-eval", Severity::Medium)
                .expect("should replace severity override");
        assert_eq!(previous_again, Some(Severity::Low));

        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");
        assert_eq!(
            loaded.scan.severity_overrides.get("py/no-eval"),
            Some(&Severity::Medium)
        );
    }

    #[test]
    fn add_severity_override_is_noop_when_value_unchanged() {
        let repo = TempDir::new().expect("failed to create temp dir");
        add_severity_override_to_config(repo.path(), None, "py/no-eval", Severity::Low)
            .expect("first write");

        let (_, previous) =
            add_severity_override_to_config(repo.path(), None, "py/no-eval", Severity::Low)
                .expect("second write");
        assert!(
            previous.is_none(),
            "unchanged override should report no previous"
        );
    }

    #[test]
    fn current_severity_override_reads_existing_value() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  severity_overrides:\n    py/no-eval: high\n",
        );

        assert_eq!(
            current_severity_override(repo.path(), None, "py/no-eval")
                .expect("should read override"),
            Some(Severity::High)
        );
        assert_eq!(
            current_severity_override(repo.path(), None, "py/unrelated")
                .expect("should return None"),
            None
        );
    }

    #[test]
    fn add_disabled_rule_appends_to_disable_rules() {
        let repo = TempDir::new().expect("failed to create temp dir");

        let (path, added) =
            add_disabled_rule_to_config(repo.path(), None, "py/no-eval").expect("should write");
        assert!(path.ends_with(".foxguard.yml"));
        assert!(added);

        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");
        assert_eq!(loaded.scan.disable_rules, vec!["py/no-eval".to_string()]);

        // Second invocation is a no-op.
        let (_, added_again) =
            add_disabled_rule_to_config(repo.path(), None, "py/no-eval").expect("second write");
        assert!(!added_again);
    }

    #[test]
    fn is_rule_disabled_in_config_reports_membership() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  disable_rules:\n    - py/no-eval\n",
        );

        assert!(is_rule_disabled_in_config(repo.path(), None, "py/no-eval")
            .expect("should probe config"));
        assert!(
            !is_rule_disabled_in_config(repo.path(), None, "py/no-pickle-loads")
                .expect("should probe config")
        );
    }

    #[test]
    fn is_rule_disabled_in_config_returns_false_when_no_config() {
        let repo = TempDir::new().expect("failed to create temp dir");
        assert!(!is_rule_disabled_in_config(repo.path(), None, "py/no-eval")
            .expect("should probe missing config"));
    }

    // ── scan.rule_options ────────────────────────────────────────────────

    #[test]
    fn rule_options_round_trip() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  rule_options:\n    py/no-eval:\n      max_depth: 5\n    js/no-eval:\n      enabled: true\n",
        );
        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");

        assert_eq!(loaded.scan.rule_options.len(), 2);
        assert!(loaded.scan.rule_options.contains_key("py/no-eval"));
        assert!(loaded.scan.rule_options.contains_key("js/no-eval"));
        // Values are opaque YAML — verify they survived the round-trip.
        let py_opts = &loaded.scan.rule_options["py/no-eval"];
        assert_eq!(py_opts["max_depth"], serde_yaml_ng::Value::from(5));
    }

    #[test]
    fn rule_options_defaults_to_empty() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(repo.path(), ".foxguard.yml", "scan:\n  severity: high\n");
        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");
        assert!(loaded.scan.rule_options.is_empty());
    }

    // ── scan.suppressions (pattern-based suppression) ───────────────────

    #[test]
    fn suppressions_parse_rule_id_and_path_pattern() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  suppressions:\n    - rule_id: js/no-eval\n      path_pattern: \".*test.*\"\n    - rule_id: py/no-hardcoded-secret\n      path_pattern: \".*fixtures.*\"\n",
        );

        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");

        assert_eq!(loaded.scan.suppressions.len(), 2);
        assert_eq!(loaded.scan.suppressions[0].rule_id, "js/no-eval");
        assert!(loaded.scan.suppressions[0]
            .path_pattern
            .is_match("src/test_app.js"));
        assert!(!loaded.scan.suppressions[0]
            .path_pattern
            .is_match("src/app.js"));
        assert_eq!(
            loaded.scan.suppressions[1].rule_id,
            "py/no-hardcoded-secret"
        );
        assert!(loaded.scan.suppressions[1]
            .path_pattern
            .is_match("tests/fixtures/secret.py"));
    }

    #[test]
    fn suppressions_defaults_to_empty() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(repo.path(), ".foxguard.yml", "scan:\n  severity: high\n");
        let loaded = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");
        assert!(loaded.scan.suppressions.is_empty());
    }

    #[test]
    fn suppressions_reject_invalid_regex() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  suppressions:\n    - rule_id: js/no-eval\n      path_pattern: \"*invalid[\"\n",
        );
        let err = load_for_scan(repo.path(), None).expect_err("expected regex parse error");
        assert!(err.contains("scan.suppressions"), "unexpected error: {err}");
        assert!(
            err.contains("invalid path_pattern"),
            "unexpected error: {err}"
        );
    }

    fn finding_with_rule_and_file(rule_id: &str, file: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::High,
            cwe: None,
            description: "test".to_string(),
            file: file.to_string(),
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
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
            dep_name: None,
        }
    }

    #[test]
    fn suppress_with_patterns_filters_matching_findings() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  suppressions:\n    - rule_id: js/no-eval\n      path_pattern: \".*test.*\"\n",
        );
        let config = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");

        let findings = vec![
            finding_with_rule_and_file("js/no-eval", "src/test_app.js"),
            finding_with_rule_and_file("js/no-eval", "src/app.js"),
            finding_with_rule_and_file("py/no-eval", "src/test_app.py"),
        ];

        let filtered = suppress_with_patterns(findings, Some(&config));

        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].file, "src/app.js");
        assert_eq!(filtered[1].file, "src/test_app.py");
    }

    #[test]
    fn suppress_with_patterns_no_config_returns_all() {
        let findings = vec![
            finding_with_rule_and_file("js/no-eval", "src/test_app.js"),
            finding_with_rule_and_file("js/no-eval", "src/app.js"),
        ];

        let filtered = suppress_with_patterns(findings, None);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn suppress_with_patterns_empty_suppressions_returns_all() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(repo.path(), ".foxguard.yml", "scan:\n  severity: high\n");
        let config = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");

        let findings = vec![finding_with_rule_and_file("js/no-eval", "src/test_app.js")];

        let filtered = suppress_with_patterns(findings, Some(&config));
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn suppress_with_patterns_requires_both_rule_id_and_path_match() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  suppressions:\n    - rule_id: js/no-eval\n      path_pattern: \".*test.*\"\n",
        );
        let config = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");

        // Rule matches but path doesn't
        let findings_wrong_path = vec![finding_with_rule_and_file(
            "js/no-eval",
            "src/production.js",
        )];
        let filtered = suppress_with_patterns(findings_wrong_path, Some(&config));
        assert_eq!(filtered.len(), 1, "path mismatch should not suppress");

        // Path matches but rule doesn't
        let findings_wrong_rule = vec![finding_with_rule_and_file("py/no-eval", "src/test_app.py")];
        let filtered = suppress_with_patterns(findings_wrong_rule, Some(&config));
        assert_eq!(filtered.len(), 1, "rule mismatch should not suppress");

        // Both match
        let findings_match = vec![finding_with_rule_and_file("js/no-eval", "src/test_app.js")];
        let filtered = suppress_with_patterns(findings_match, Some(&config));
        assert_eq!(filtered.len(), 0, "both match should suppress");
    }

    #[test]
    fn suppress_with_patterns_multiple_rules() {
        let repo = TempDir::new().expect("failed to create temp dir");
        write_config(
            repo.path(),
            ".foxguard.yml",
            "scan:\n  suppressions:\n    - rule_id: js/no-eval\n      path_pattern: \".*test.*\"\n    - rule_id: py/no-hardcoded-secret\n      path_pattern: \".*fixtures.*\"\n",
        );
        let config = load_for_scan(repo.path(), None)
            .expect("failed to load config")
            .expect("expected config");

        let findings = vec![
            finding_with_rule_and_file("js/no-eval", "src/test_app.js"),
            finding_with_rule_and_file("py/no-hardcoded-secret", "tests/fixtures/creds.py"),
            finding_with_rule_and_file("py/no-hardcoded-secret", "src/app.py"),
            finding_with_rule_and_file("js/no-eval", "src/main.js"),
        ];

        let filtered = suppress_with_patterns(findings, Some(&config));
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].rule_id, "py/no-hardcoded-secret");
        assert_eq!(filtered[0].file, "src/app.py");
        assert_eq!(filtered[1].rule_id, "js/no-eval");
        assert_eq!(filtered[1].file, "src/main.js");
    }
}
