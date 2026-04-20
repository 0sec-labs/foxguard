use crate::baseline::{load_baseline, suppress_with_baseline, write_baseline};
use crate::cli::{DiffArgs, OutputFormat, ScanArgs, SecretsArgs, TuiArgs};
use crate::config::{
    apply_scan_defaults, apply_scan_thresholds, apply_secrets_defaults, apply_severity_overrides,
    load_for_scan, suppress_with_scan_ignores,
};
use crate::diff::run_diff_with_warnings;
use crate::engine::{
    scan_directory_with_notices, scan_paths_with_root_with_notices, PathExcludeMatcher, ScanResult,
};
use crate::git::changed_files;
use crate::rules::semgrep_compat::load_semgrep_rules;
use crate::rules::RuleRegistry;
use crate::secrets::{
    scan_directory_with_config_and_notices, scan_paths_with_config_and_notices, SecretScanConfig,
};
use crate::Finding;
use std::path::{Path, PathBuf};

pub struct ScanExecution {
    pub args: ScanArgs,
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub duration: std::time::Duration,
    pub notices: Vec<String>,
}

pub struct SecretsExecution {
    pub args: SecretsArgs,
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub duration: std::time::Duration,
    pub notices: Vec<String>,
}

pub struct DiffExecution {
    pub args: DiffArgs,
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub duration: std::time::Duration,
    pub total_current: usize,
    pub existing_count: usize,
    pub notices: Vec<String>,
}

pub struct DiffSummary {
    pub target: String,
    pub total_current: usize,
    pub existing_count: usize,
}

pub enum TuiMode {
    Scan,
    Diff { target: String },
    Secrets,
}

pub struct TuiExecution {
    pub mode: TuiMode,
    pub path: String,
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub duration: std::time::Duration,
    pub explain: bool,
    pub diff_summary: Option<DiffSummary>,
    pub notices: Vec<String>,
}

pub fn resolve_scan_args(scan: &ScanArgs) -> Result<ScanArgs, String> {
    let mut scan = scan.clone();
    let config = load_for_scan(Path::new(&scan.path), scan.config.as_deref())?;
    apply_scan_defaults(&mut scan, config.as_ref());
    Ok(scan)
}

pub fn resolve_secrets_args(args: &SecretsArgs) -> Result<SecretsArgs, String> {
    let mut args = args.clone();
    let config = load_for_scan(Path::new(&args.path), args.config.as_deref())?;
    apply_secrets_defaults(&mut args, config.as_ref());
    Ok(args)
}

pub fn scan_findings(scan: &ScanArgs) -> Result<ScanResult, String> {
    let execution = execute_scan(scan)?;
    Ok(ScanResult {
        findings: execution.findings,
        files_scanned: execution.files_scanned,
        duration: execution.duration,
    })
}

pub fn execute_scan(scan: &ScanArgs) -> Result<ScanExecution, String> {
    let scan = resolve_scan_args(scan)?;
    let config = load_for_scan(Path::new(&scan.path), scan.config.as_deref())?;
    validate_root_path(&scan.path)?;
    validate_rules_path(scan.rules.as_deref())?;

    // Install any `scan.thresholds.*` overrides into process-wide state
    // before the rules run. Must happen after config load and before
    // `scan_directory_with_notices` dispatches parallel rule execution.
    apply_scan_thresholds(config.as_ref());

    let mut registry = build_registry(scan.no_builtins, scan.rules.as_deref())?;
    if let Some(ref config) = config {
        if !config.scan.rule_options.is_empty() {
            let warnings = registry.configure_rules(&config.scan.rule_options)?;
            for w in &warnings {
                eprintln!("warning: {}", w);
            }
        }
    }
    let excludes = PathExcludeMatcher::new(&scan.exclude)?;
    let targets = collect_changed_targets(&scan.path, scan.changed)?;

    // In PQ mode, filter to only PQ-related rules
    let pq_enable: Vec<String>;
    let rule_filter_unknown = if scan.pq_mode {
        pq_enable = registry
            .all_rules()
            .iter()
            .map(|r| r.id().to_string())
            .filter(|id| is_pq_rule_id(id))
            .collect();
        if pq_enable.is_empty() {
            eprintln!(
                "Warning: no PQ rules registered in this build. \
                 Install a version with post-quantum crypto rules to use 'foxguard pqc'."
            );
        }
        registry.apply_rule_filter(&pq_enable, &[])
    } else if let Some(config) = config.as_ref() {
        registry.apply_rule_filter(&config.scan.enable_rules, &config.scan.disable_rules)
    } else {
        registry.apply_rule_filter(&[], &[])
    };

    let (result, mut notices) = if let Some(files) = targets {
        scan_paths_with_root_with_notices(
            Path::new(&scan.path),
            &files,
            &registry,
            scan.max_file_size,
            Some(&excludes),
        )
    } else {
        scan_directory_with_notices(&scan.path, &registry, scan.max_file_size, Some(&excludes))
    };

    if !rule_filter_unknown.is_empty() {
        notices.insert(
            0,
            format!(
                "Warning: unknown rule id{} in config (enable_rules/disable_rules): {}",
                if rule_filter_unknown.len() == 1 {
                    ""
                } else {
                    "s"
                },
                rule_filter_unknown.join(", ")
            ),
        );
    }

    let files_scanned = result.files_scanned;
    let duration = result.duration;
    let mut findings = result.findings;

    let known_rule_ids = collect_rule_ids(&registry);
    let override_warnings =
        apply_severity_overrides(&mut findings, config.as_ref(), &known_rule_ids);
    notices.extend(override_warnings);

    if let Some(min_conf) = scan.min_confidence {
        findings.retain(|f| f.confidence >= min_conf);
    }

    // Filter taint findings exceeding max_hops threshold
    if let Some(ref cfg) = config {
        if let Some(max) = cfg.scan.thresholds.taint.max_hops {
            findings.retain(|f| f.taint_hops.is_none_or(|h| (h as usize) <= max));
        }
    }

    if let Some(ref min_severity) = scan.severity {
        let min = min_severity.to_severity();
        findings.retain(|f| f.severity >= min);
    }

    findings = suppress_with_scan_ignores(findings, config.as_ref());

    if let Some(ref path) = scan.write_baseline {
        write_baseline(Path::new(path), &findings)?;
        notices.push(format!("Wrote baseline to {}", path));
    }

    let baseline = match scan.baseline.as_ref() {
        Some(path) => load_baseline(Path::new(path))?,
        None => None,
    };

    findings = suppress_with_baseline(findings, baseline.as_ref());

    if files_scanned == 0 {
        notices.push(
            "Warning: no files with supported extensions found. Supported: .js, .ts, .py, .go, .rb, .java, .php, .rs, .cs, .swift, .kt"
                .to_string(),
        );
    }

    Ok(ScanExecution {
        args: scan,
        findings,
        files_scanned,
        duration,
        notices,
    })
}

pub fn execute_secrets(args: &SecretsArgs) -> Result<SecretsExecution, String> {
    let args = resolve_secrets_args(args)?;
    validate_root_path(&args.path)?;

    let scan_path = Path::new(&args.path);
    let config = SecretScanConfig::from_inputs(
        scan_path,
        &args.exclude_paths,
        args.exclude_path_file.as_deref().map(Path::new),
        &args.ignored_rules,
    )?;

    let (mut findings, mut notices, files_scanned, duration) =
        match collect_changed_targets(&args.path, args.changed)? {
            Some(files) => {
                let file_count = files.len();
                let started = std::time::Instant::now();
                let (findings, notices) = scan_paths_with_config_and_notices(
                    scan_path,
                    &files,
                    &config,
                    args.max_file_size,
                );
                (findings, notices, file_count, started.elapsed())
            }
            None => {
                let started = std::time::Instant::now();
                let (findings, notices) =
                    scan_directory_with_config_and_notices(&args.path, &config, args.max_file_size);
                let files_scanned = count_secret_files(scan_path);
                (findings, notices, files_scanned, started.elapsed())
            }
        };

    if let Some(ref path) = args.write_baseline {
        write_baseline(Path::new(path), &findings)?;
        notices.push(format!("Wrote secrets baseline to {}", path));
    }

    let baseline = match args.baseline.as_ref() {
        Some(path) => load_baseline(Path::new(path))?,
        None => None,
    };
    findings = suppress_with_baseline(findings, baseline.as_ref());

    Ok(SecretsExecution {
        args,
        findings,
        files_scanned,
        duration,
        notices,
    })
}

pub fn execute_diff(args: &DiffArgs) -> Result<DiffExecution, String> {
    validate_root_path(&args.path)?;
    let config = load_for_scan(Path::new(&args.path), None)?;
    apply_scan_thresholds(config.as_ref());
    let mut registry = build_registry(args.no_builtins, args.rules.as_deref())?;
    let rule_filter_unknown = if let Some(config) = config.as_ref() {
        registry.apply_rule_filter(&config.scan.enable_rules, &config.scan.disable_rules)
    } else {
        registry.apply_rule_filter(&[], &[])
    };
    let ((scan_result, mut diff_result), mut notices) =
        run_diff_with_warnings(&args.path, &args.target, &registry, args.max_file_size)?;

    if !rule_filter_unknown.is_empty() {
        notices.insert(
            0,
            format!(
                "Warning: unknown rule id{} in config (enable_rules/disable_rules): {}",
                if rule_filter_unknown.len() == 1 {
                    ""
                } else {
                    "s"
                },
                rule_filter_unknown.join(", ")
            ),
        );
    }

    let known_rule_ids = collect_rule_ids(&registry);
    let override_warnings = apply_severity_overrides(
        &mut diff_result.new_findings,
        config.as_ref(),
        &known_rule_ids,
    );
    notices.extend(override_warnings);

    if let Some(ref min_severity) = args.severity {
        let min = min_severity.to_severity();
        diff_result.new_findings.retain(|f| f.severity >= min);
    }

    diff_result.new_findings =
        suppress_with_scan_ignores(diff_result.new_findings, config.as_ref());

    notices.push(format!(
        "foxguard diff vs {}: {} new issue{} ({} total, {} existing)",
        args.target,
        diff_result.new_findings.len(),
        if diff_result.new_findings.len() == 1 {
            ""
        } else {
            "s"
        },
        diff_result.total_current,
        diff_result.existing_count
    ));

    Ok(DiffExecution {
        args: args.clone(),
        findings: diff_result.new_findings,
        files_scanned: scan_result.files_scanned,
        duration: scan_result.duration,
        total_current: diff_result.total_current,
        existing_count: diff_result.existing_count,
        notices,
    })
}

pub fn execute_tui(args: &TuiArgs) -> Result<TuiExecution, String> {
    if args.secrets {
        let result = execute_secrets(&tui_secrets_args(args))?;
        return Ok(TuiExecution {
            mode: TuiMode::Secrets,
            path: result.args.path.clone(),
            findings: result.findings,
            files_scanned: result.files_scanned,
            duration: result.duration,
            explain: false,
            diff_summary: None,
            notices: result.notices,
        });
    }

    if let Some(target) = args.diff.as_ref() {
        let result = execute_diff(&tui_diff_args(args, target))?;
        return Ok(TuiExecution {
            mode: TuiMode::Diff {
                target: result.args.target.clone(),
            },
            path: result.args.path.clone(),
            findings: result.findings,
            files_scanned: result.files_scanned,
            duration: result.duration,
            explain: args.explain,
            diff_summary: Some(DiffSummary {
                target: result.args.target,
                total_current: result.total_current,
                existing_count: result.existing_count,
            }),
            notices: result.notices,
        });
    }

    let result = execute_scan(&tui_scan_args(args))?;
    Ok(TuiExecution {
        mode: TuiMode::Scan,
        path: result.args.path.clone(),
        findings: result.findings,
        files_scanned: result.files_scanned,
        duration: result.duration,
        explain: result.args.explain,
        diff_summary: None,
        notices: result.notices,
    })
}

fn tui_scan_args(args: &TuiArgs) -> ScanArgs {
    ScanArgs {
        path: args.path.clone(),
        config: args.config.clone(),
        format: OutputFormat::Terminal,
        severity: args.severity,
        rules: args.rules.clone(),
        no_builtins: args.no_builtins,
        changed: args.changed,
        exclude: args.exclude.clone(),
        baseline: args.baseline.clone(),
        write_baseline: None,
        explain: args.explain,
        github_pr: None,
        quiet: false,
        max_file_size: args.max_file_size,
        fix: false,
        show_confidence: false,
        min_confidence: None,
        pq_mode: false,
    }
}

fn tui_diff_args(args: &TuiArgs, target: &str) -> DiffArgs {
    DiffArgs {
        target: target.to_string(),
        path: args.path.clone(),
        format: OutputFormat::Terminal,
        severity: args.severity,
        rules: args.rules.clone(),
        no_builtins: args.no_builtins,
        max_file_size: args.max_file_size,
    }
}

fn tui_secrets_args(args: &TuiArgs) -> SecretsArgs {
    SecretsArgs {
        path: args.path.clone(),
        config: args.config.clone(),
        format: OutputFormat::Terminal,
        changed: args.changed,
        baseline: args.baseline.clone(),
        write_baseline: None,
        exclude_paths: Vec::new(),
        exclude_path_file: None,
        ignored_rules: Vec::new(),
        max_file_size: args.max_file_size,
    }
}

fn collect_rule_ids(registry: &RuleRegistry) -> std::collections::HashSet<String> {
    registry
        .all_rules()
        .iter()
        .map(|rule| rule.id().to_string())
        .collect()
}

fn build_registry(no_builtins: bool, rules: Option<&str>) -> Result<RuleRegistry, String> {
    validate_rules_path(rules)?;

    let mut registry = if no_builtins {
        RuleRegistry::empty()
    } else {
        RuleRegistry::new()
    };

    if let Some(rules_path) = rules {
        let semgrep_rules = load_semgrep_rules(Path::new(rules_path));
        for rule in semgrep_rules {
            registry.register(rule);
        }
    }

    Ok(registry)
}

fn validate_root_path(path: &str) -> Result<(), String> {
    if !Path::new(path).exists() {
        return Err(format!("path '{}' does not exist", path));
    }
    Ok(())
}

fn validate_rules_path(rules: Option<&str>) -> Result<(), String> {
    if let Some(rules_path) = rules {
        let path = Path::new(rules_path);
        if !path.exists() {
            return Err(format!("rules path '{}' does not exist", rules_path));
        }
    }

    Ok(())
}

/// Returns `true` if the rule ID belongs to the PQ audit rule set.
fn is_pq_rule_id(id: &str) -> bool {
    id.contains("pq-vulnerable")
        || id.contains("hardcoded-crypto-algorithm")
        || (id.starts_with("config/") && (id.contains("tls") || id.contains("dockerfile")))
}

fn collect_changed_targets(path: &str, changed: bool) -> Result<Option<Vec<PathBuf>>, String> {
    if !changed {
        return Ok(None);
    }

    let scan_root = Path::new(path);
    let files =
        changed_files(scan_root).map_err(|e| format!("failed to resolve changed files: {}", e))?;
    Ok(Some(files))
}

fn count_secret_files(scan_path: &Path) -> usize {
    if scan_path.is_file() {
        return 1;
    }

    ignore::WalkBuilder::new(scan_path)
        .hidden(true)
        .git_ignore(true)
        .build()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_some_and(|ft| ft.is_file()))
        .count()
}
