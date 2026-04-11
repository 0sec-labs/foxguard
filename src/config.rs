use crate::cli::{ScanArgs, SecretsArgs, SeverityFilter};
use serde::Deserialize;
use std::path::{Path, PathBuf};

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
    pub max_file_size: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct SecretsConfig {
    pub baseline: Option<String>,
    pub exclude_paths: Vec<String>,
    pub exclude_path_file: Option<String>,
    pub ignored_rules: Vec<String>,
    pub max_file_size: Option<u64>,
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
    max_file_size: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
struct RawSecretsConfig {
    baseline: Option<String>,
    #[serde(default)]
    exclude_paths: Vec<String>,
    exclude_path_file: Option<String>,
    #[serde(default)]
    ignore_rules: Vec<String>,
    max_file_size: Option<u64>,
}

pub fn load_for_scan(
    scan_path: &Path,
    explicit_path: Option<&str>,
) -> Result<Option<FoxguardConfig>, String> {
    let Some(path) = resolve_config_path(scan_path, explicit_path)? else {
        return Ok(None);
    };

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read config {}: {}", path.display(), e))?;
    let raw: RawFoxguardConfig = serde_yml::from_str(&content)
        .map_err(|e| format!("Failed to parse config {}: {}", path.display(), e))?;

    Ok(Some(FoxguardConfig::from_raw(
        raw,
        path.parent().unwrap_or_else(|| Path::new(".")),
    )))
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
    if scan.max_file_size.is_none() {
        scan.max_file_size = config.scan.max_file_size;
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
    if args.max_file_size.is_none() {
        args.max_file_size = config.secrets.max_file_size;
    }
}

impl FoxguardConfig {
    fn from_raw(raw: RawFoxguardConfig, config_dir: &Path) -> Self {
        Self {
            scan: ScanConfig {
                rules: raw
                    .scan
                    .rules
                    .map(|path| resolve_value_path(config_dir, &path)),
                no_builtins: raw.scan.no_builtins.unwrap_or(false),
                severity: raw.scan.severity,
                baseline: raw
                    .scan
                    .baseline
                    .map(|path| resolve_value_path(config_dir, &path)),
                max_file_size: raw.scan.max_file_size,
            },
            secrets: SecretsConfig {
                baseline: raw
                    .secrets
                    .baseline
                    .map(|path| resolve_value_path(config_dir, &path)),
                exclude_paths: raw
                    .secrets
                    .exclude_paths
                    .into_iter()
                    .map(|path| resolve_value_path(config_dir, &path))
                    .collect(),
                exclude_path_file: raw
                    .secrets
                    .exclude_path_file
                    .map(|path| resolve_value_path(config_dir, &path)),
                ignored_rules: raw.secrets.ignore_rules,
                max_file_size: raw.secrets.max_file_size,
            },
        }
    }
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

    let home = std::env::var("HOME").ok().map(PathBuf::from);

    for dir in start.ancestors() {
        for name in CONFIG_NAMES {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Ok(Some(candidate));
            }
        }

        // Stop at repository root
        if dir.join(".git").exists() {
            break;
        }

        // Don't walk past the user's home directory
        if let Some(ref home) = home {
            if dir == home.as_path() {
                break;
            }
        }
    }

    Ok(None)
}

fn resolve_value_path(base: &Path, value: &str) -> String {
    let path = Path::new(value);
    if path.is_absolute() {
        return path.display().to_string();
    }
    let joined = base.join(path);
    joined
        .canonicalize()
        .unwrap_or(joined)
        .display()
        .to_string()
}
