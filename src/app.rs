use crate::baseline::{load_baseline, suppress_with_baseline_at_root, write_baseline_at_root};
use crate::cli::{DiffArgs, OutputFormat, ScanArgs, SecretsArgs, TuiArgs};
use crate::config::{
    apply_scan_defaults, apply_secrets_defaults, apply_severity_overrides, load_for_scan,
    secret_scan_thresholds, suppress_with_patterns, suppress_with_scan_ignores, FoxguardConfig,
};
use crate::deps::{scan_dependency_vulnerabilities, DependencyScanOptions};
use crate::diff::run_diff_with_coccinelle_warnings;
use crate::engine::{
    coccinelle, codeql, scan_directory_with_notices, scan_paths_with_root_with_notices,
    PathExcludeMatcher, ScanResult, ScanStats,
};
use crate::git::changed_files;
use crate::rules::semgrep_compat::load_semgrep_rules;
use crate::rules::RuleRegistry;
use crate::secrets::{
    scan_directory_with_config_and_notices, scan_paths_with_config_and_notices, SecretScanConfig,
};
use crate::Finding;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct ScanExecution {
    pub args: ScanArgs,
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub stats: ScanStats,
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
        stats: execution.stats,
        duration: execution.duration,
    })
}

pub fn scan_findings_resolved(scan: ScanArgs) -> Result<ScanResult, String> {
    let execution = execute_scan_resolved(scan)?;
    Ok(ScanResult {
        findings: execution.findings,
        files_scanned: execution.files_scanned,
        stats: execution.stats,
        duration: execution.duration,
    })
}

pub fn execute_scan(scan: &ScanArgs) -> Result<ScanExecution, String> {
    execute_scan_resolved(resolve_scan_args(scan)?)
}

fn execute_scan_resolved(scan: ScanArgs) -> Result<ScanExecution, String> {
    let config = load_for_scan(Path::new(&scan.path), scan.config.as_deref())?;
    validate_root_path(&scan.path)?;
    validate_rules_path(scan.rules.as_deref())?;
    let identity_root = finding_identity_root(Path::new(&scan.path), config.as_ref());

    let mut registry = build_registry(scan.no_builtins, scan.rules.as_deref())?;
    registry.set_secret_thresholds(secret_scan_thresholds(config.as_ref()));
    let (mut coccinelle_rules, mut coccinelle_notices) = match scan.rules.as_deref() {
        Some(rules_path) => coccinelle::load_coccinelle_rules(Path::new(rules_path)),
        None => (Vec::new(), Vec::new()),
    };
    let (mut codeql_rules, mut codeql_notices) = match scan.rules.as_deref() {
        Some(rules_path) => codeql::load_codeql_rules(Path::new(rules_path)),
        None => (Vec::new(), Vec::new()),
    };
    if let Some(ref config) = config {
        if !config.scan.rule_options.is_empty() {
            let warnings = registry.configure_rules(&config.scan.rule_options)?;
            for w in &warnings {
                eprintln!("warning: {}", w);
            }
        }
    }
    let excludes = PathExcludeMatcher::new(&scan.exclude)?;
    let targets = if let Some(list_file) = scan.changed_files_from.as_deref() {
        // Explicit changed-file list (e.g. from the GitHub App): scan only
        // these paths but keep `scan.path` as the analysis root so cross-file
        // taint context is preserved. Precedence over the change-mode flags.
        Some(resolve_changed_files_from(&scan.path, list_file)?)
    } else {
        collect_changed_targets(&scan.path, scan.changes.selection())?
    };
    let coccinelle_rule_ids = coccinelle::rule_ids(&coccinelle_rules);
    let codeql_rule_ids = codeql::rule_ids(&codeql_rules);

    // In PQ mode, filter to only PQ-related rules
    let pq_enable: Vec<String>;
    let rule_filter_unknown = if scan.pq_mode {
        pq_enable = collect_pq_rule_ids(&registry, &coccinelle_rule_ids, &codeql_rule_ids);
        if pq_enable.is_empty() {
            eprintln!(
                "Warning: no PQ rules registered in this build. \
                 Install a version with post-quantum crypto rules to use 'foxguard pqc'."
            );
        }
        coccinelle::apply_rule_filter(&mut coccinelle_rules, &pq_enable, &[]);
        codeql::apply_rule_filter(&mut codeql_rules, &pq_enable, &[]);
        let external_rule_ids = external_rule_ids(&coccinelle_rule_ids, &codeql_rule_ids);
        registry.apply_rule_filter_with_known(&pq_enable, &[], &external_rule_ids)
    } else if let Some(config) = config.as_ref() {
        coccinelle::apply_rule_filter(
            &mut coccinelle_rules,
            &config.scan.enable_rules,
            &config.scan.disable_rules,
        );
        codeql::apply_rule_filter(
            &mut codeql_rules,
            &config.scan.enable_rules,
            &config.scan.disable_rules,
        );
        let external_rule_ids = external_rule_ids(&coccinelle_rule_ids, &codeql_rule_ids);
        registry.apply_rule_filter_with_known(
            &config.scan.enable_rules,
            &config.scan.disable_rules,
            &external_rule_ids,
        )
    } else {
        let external_rule_ids = external_rule_ids(&coccinelle_rule_ids, &codeql_rule_ids);
        registry.apply_rule_filter_with_known(&[], &[], &external_rule_ids)
    };

    let scan_started = std::time::Instant::now();
    let sca_only = scan.sca
        && registry.all_rules().is_empty()
        && coccinelle_rules.is_empty()
        && codeql_rules.is_empty();
    let (result, mut notices) = if sca_only {
        (
            ScanResult {
                findings: Vec::new(),
                files_scanned: 0,
                stats: ScanStats::default(),
                duration: std::time::Duration::default(),
            },
            Vec::new(),
        )
    } else if let Some(files) = targets.as_ref() {
        scan_paths_with_root_with_notices(
            Path::new(&scan.path),
            files,
            &registry,
            scan.max_file_size,
            Some(&excludes),
        )
    } else {
        scan_directory_with_notices(&scan.path, &registry, scan.max_file_size, Some(&excludes))
    };
    notices.append(&mut coccinelle_notices);
    notices.append(&mut codeql_notices);

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

    let mut files_scanned = result.files_scanned;
    let stats = result.stats;
    let mut findings = result.findings;
    let mut coccinelle_candidate_files = 0;
    let mut codeql_candidate_rules = 0;

    if !coccinelle_rules.is_empty() {
        let coccinelle_result = if let Some(files) = targets.as_ref() {
            coccinelle::scan_paths_with_notices(
                Path::new(&scan.path),
                files,
                &coccinelle_rules,
                scan.max_file_size,
                Some(&excludes),
            )
        } else {
            coccinelle::scan_path_with_notices(
                Path::new(&scan.path),
                &coccinelle_rules,
                scan.max_file_size,
                Some(&excludes),
            )
        };
        coccinelle_candidate_files = coccinelle_result.candidate_files;
        files_scanned += coccinelle_result.files_scanned;
        notices.extend(coccinelle_result.notices);
        findings.extend(coccinelle_result.findings);
        findings.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then(a.line.cmp(&b.line))
                .then(a.column.cmp(&b.column))
                .then(a.rule_id.cmp(&b.rule_id))
        });
    }
    if !codeql_rules.is_empty() {
        let codeql_result = codeql::scan_with_notices_for_target(
            &codeql_rules,
            scan.codeql_db.as_deref().map(Path::new),
            Some(Path::new(&scan.path)),
        );
        codeql_candidate_rules = codeql_result.candidate_rules;
        files_scanned += codeql_result.files_scanned;
        notices.extend(codeql_result.notices);
        findings.extend(codeql_result.findings);
        findings.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then(a.line.cmp(&b.line))
                .then(a.column.cmp(&b.column))
                .then(a.rule_id.cmp(&b.rule_id))
        });
    }

    if scan.sca {
        let sca_options = DependencyScanOptions {
            offline: scan.sca_offline,
            advisory_db: scan.sca_db.as_ref().map(PathBuf::from),
            cache_path: scan.sca_cache.as_ref().map(PathBuf::from),
        };
        let sca_result = scan_dependency_vulnerabilities(
            Path::new(&scan.path),
            targets.as_deref(),
            Some(&excludes),
            scan.max_file_size,
            &sca_options,
        )?;
        files_scanned += sca_result.files_scanned;
        notices.extend(sca_result.notices);
        findings.extend(sca_result.findings);
        findings.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then(a.line.cmp(&b.line))
                .then(a.column.cmp(&b.column))
                .then(a.rule_id.cmp(&b.rule_id))
        });
    }

    // PQ audit: also open the ACTUAL cryptographic material in the repo
    // (X.509 certs and keys) and emit real crypto findings. This is only run
    // for `foxguard pqc` (pq_mode); it complements the pattern-matching rules
    // by parsing the deployed certs/keys directly. Defensive: never crashes on
    // malformed material — bad files are skipped.
    if scan.pq_mode {
        let cert_result = crate::certscan::scan_certificates(
            Path::new(&scan.path),
            Path::new(&scan.path),
            Some(&excludes),
        );
        files_scanned += cert_result.files_scanned;
        notices.extend(cert_result.notices);
        findings.extend(cert_result.findings);
        findings.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then(a.line.cmp(&b.line))
                .then(a.column.cmp(&b.column))
                .then(a.rule_id.cmp(&b.rule_id))
        });
    }

    let duration = scan_started.elapsed();
    append_scan_stats_notice(&mut notices, &stats);

    // CNSA 2.0 deadline annotation. Runs regardless of the `--cnsa2`
    // opt-in flag because SARIF always carries the field in `properties`
    // — it's metadata. The flag only controls terminal surface (see
    // `src/main.rs`).
    crate::compliance::annotate_cnsa2_deadlines(&mut findings, &registry);

    let mut known_rule_ids = collect_rule_ids(&registry, &coccinelle_rules, &codeql_rules);
    if scan.sca {
        known_rule_ids.insert(crate::deps::OSV_RULE_ID.to_string());
    }
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

    findings = suppress_with_scan_ignores(findings, config.as_ref(), &identity_root);
    findings = suppress_with_patterns(findings, config.as_ref());

    if let Some(ref path) = scan.write_baseline {
        write_baseline_at_root(Path::new(path), &findings, &identity_root)?;
        notices.push(format!("Wrote baseline to {}", path));
    }

    let baseline = match scan.baseline.as_ref() {
        Some(path) => load_baseline(Path::new(path))?,
        None => None,
    };

    findings = suppress_with_baseline_at_root(findings, baseline.as_ref(), &identity_root);

    if files_scanned == 0 && coccinelle_candidate_files == 0 && codeql_candidate_rules == 0 {
        if stats.files_discovered == 0 {
            let supported = if coccinelle_rules.is_empty() {
                ".js, .ts, .py, .go, .rb, .java, .php, .rs, .cs, .swift, .kt, .hs"
            } else {
                ".js, .ts, .py, .go, .rb, .java, .php, .rs, .cs, .swift, .kt, .hs, .c, .h"
            };
            notices.push(format!("Warning: no files found. Supported: {supported}"));
        } else {
            notices.push(
                "Warning: no files were scanned. See skipped-file summary for reasons.".to_string(),
            );
        }
    }

    Ok(ScanExecution {
        args: scan,
        findings,
        files_scanned,
        stats,
        duration,
        notices,
    })
}

pub fn execute_secrets(args: &SecretsArgs) -> Result<SecretsExecution, String> {
    let args = resolve_secrets_args(args)?;
    let config_for_identity = load_for_scan(Path::new(&args.path), args.config.as_deref())?;
    let identity_root = finding_identity_root(Path::new(&args.path), config_for_identity.as_ref());
    validate_root_path(&args.path)?;

    let scan_path = Path::new(&args.path);
    let config = SecretScanConfig::from_inputs(
        scan_path,
        &args.exclude_paths,
        args.exclude_path_file.as_deref().map(Path::new),
        &args.ignored_rules,
    )?;

    let (mut findings, mut notices, files_scanned, duration) =
        match collect_changed_targets(&args.path, args.changes.selection())? {
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
        write_baseline_at_root(Path::new(path), &findings, &identity_root)?;
        notices.push(format!("Wrote secrets baseline to {}", path));
    }

    let baseline = match args.baseline.as_ref() {
        Some(path) => load_baseline(Path::new(path))?,
        None => None,
    };
    findings = suppress_with_baseline_at_root(findings, baseline.as_ref(), &identity_root);

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
    let config = load_for_scan(Path::new(&args.path), args.config.as_deref())?;
    let identity_root = finding_identity_root(Path::new(&args.path), config.as_ref());
    let config_scan = config.as_ref().map(|config| &config.scan);
    let rules_path = args
        .rules
        .as_deref()
        .or_else(|| config_scan.and_then(|scan_config| scan_config.rules.as_deref()));
    let no_builtins = args.no_builtins
        || config_scan
            .map(|scan_config| scan_config.no_builtins)
            .unwrap_or(false);
    let min_severity = args
        .severity
        .or_else(|| config_scan.and_then(|scan_config| scan_config.severity));
    let min_confidence = config_scan.and_then(|scan_config| scan_config.min_confidence);
    let mut registry = build_registry(no_builtins, rules_path)?;
    registry.set_secret_thresholds(secret_scan_thresholds(config.as_ref()));
    let (mut coccinelle_rules, mut coccinelle_notices) = match rules_path {
        Some(rules_path) => coccinelle::load_coccinelle_rules(Path::new(rules_path)),
        None => (Vec::new(), Vec::new()),
    };
    let coccinelle_rule_ids = coccinelle::rule_ids(&coccinelle_rules);
    let rule_filter_unknown = if let Some(config) = config.as_ref() {
        coccinelle::apply_rule_filter(
            &mut coccinelle_rules,
            &config.scan.enable_rules,
            &config.scan.disable_rules,
        );
        registry.apply_rule_filter_with_known(
            &config.scan.enable_rules,
            &config.scan.disable_rules,
            &coccinelle_rule_ids,
        )
    } else {
        registry.apply_rule_filter_with_known(&[], &[], &coccinelle_rule_ids)
    };
    let ((scan_result, mut diff_result), mut notices) = run_diff_with_coccinelle_warnings(
        &args.path,
        &args.target,
        &registry,
        &coccinelle_rules,
        args.max_file_size,
    )?;
    notices.append(&mut coccinelle_notices);
    append_scan_stats_notice(&mut notices, &scan_result.stats);

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

    // Annotate CNSA 2.0 deadlines on the new findings surfaced by this diff.
    crate::compliance::annotate_cnsa2_deadlines(&mut diff_result.new_findings, &registry);

    let known_rule_ids = collect_rule_ids(&registry, &coccinelle_rules, &[]);
    let override_warnings = apply_severity_overrides(
        &mut diff_result.new_findings,
        config.as_ref(),
        &known_rule_ids,
    );
    notices.extend(override_warnings);

    if let Some(min_conf) = min_confidence {
        diff_result
            .new_findings
            .retain(|f| f.confidence >= min_conf);
    }

    if let Some(min_severity) = min_severity {
        let min = min_severity.to_severity();
        diff_result.new_findings.retain(|f| f.severity >= min);
    }

    diff_result.new_findings =
        suppress_with_scan_ignores(diff_result.new_findings, config.as_ref(), &identity_root);
    diff_result.new_findings = suppress_with_patterns(diff_result.new_findings, config.as_ref());

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

fn append_scan_stats_notice(notices: &mut Vec<String>, stats: &ScanStats) {
    if let Some(summary) = stats.skipped_summary() {
        notices.push(format!(
            "Skipped {} file{}: {}.",
            stats.files_skipped,
            if stats.files_skipped == 1 { "" } else { "s" },
            summary
        ));
    }
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
        codeql_db: None,
        changes: args.changes.clone(),
        changed_files_from: None,
        exclude: args.exclude.clone(),
        baseline: args.baseline.clone(),
        write_baseline: None,
        explain: args.explain,
        github_pr: None,
        quiet: false,
        output: None,
        max_file_size: args.max_file_size,
        fix: false,
        show_confidence: false,
        min_confidence: None,
        pq_mode: args.pq_mode,
        sca: false,
        sca_offline: false,
        sca_db: None,
        sca_cache: None,
        cnsa2: args.pq_mode,
    }
}

fn tui_diff_args(args: &TuiArgs, target: &str) -> DiffArgs {
    DiffArgs {
        target: target.to_string(),
        path: args.path.clone(),
        format: OutputFormat::Terminal,
        severity: args.severity,
        config: args.config.clone(),
        rules: args.rules.clone(),
        no_builtins: args.no_builtins,
        output: None,
        github_pr: None,
        max_file_size: args.max_file_size,
    }
}

fn tui_secrets_args(args: &TuiArgs) -> SecretsArgs {
    SecretsArgs {
        path: args.path.clone(),
        config: args.config.clone(),
        format: OutputFormat::Terminal,
        changes: args.changes.clone(),
        baseline: args.baseline.clone(),
        write_baseline: None,
        exclude_paths: Vec::new(),
        exclude_path_file: None,
        ignored_rules: Vec::new(),
        output: None,
        max_file_size: args.max_file_size,
    }
}

fn collect_rule_ids(
    registry: &RuleRegistry,
    coccinelle_rules: &[coccinelle::CoccinelleRule],
    codeql_rules: &[codeql::CodeQlRule],
) -> HashSet<String> {
    let mut ids: HashSet<String> = registry
        .all_rules()
        .iter()
        .map(|rule| rule.id().to_string())
        .collect();
    ids.extend(coccinelle_rules.iter().map(|rule| rule.id().to_string()));
    ids.extend(codeql_rules.iter().map(|rule| rule.id().to_string()));
    ids
}

fn finding_identity_root(scan_path: &Path, config: Option<&FoxguardConfig>) -> PathBuf {
    crate::path_identity::project_root(
        scan_path,
        config.map(|config| config.project_root.as_path()),
    )
}

fn collect_pq_rule_ids(
    registry: &RuleRegistry,
    coccinelle_rule_ids: &HashSet<String>,
    codeql_rule_ids: &HashSet<String>,
) -> Vec<String> {
    let mut ids: Vec<String> = registry
        .all_rules()
        .iter()
        .map(|rule| rule.id().to_string())
        .filter(|id| is_pq_rule_id(id))
        .collect();

    for id in coccinelle_rule_ids {
        if is_pq_rule_id(id) && !ids.iter().any(|existing| existing == id) {
            ids.push(id.clone());
        }
    }
    for id in codeql_rule_ids {
        if is_pq_rule_id(id) && !ids.iter().any(|existing| existing == id) {
            ids.push(id.clone());
        }
    }

    ids
}

fn external_rule_ids(
    coccinelle_rule_ids: &HashSet<String>,
    codeql_rule_ids: &HashSet<String>,
) -> HashSet<String> {
    let mut ids = coccinelle_rule_ids.clone();
    ids.extend(codeql_rule_ids.iter().cloned());
    ids
}

fn build_registry(no_builtins: bool, rules: Option<&str>) -> Result<RuleRegistry, String> {
    validate_rules_path(rules)?;

    // `RuleRegistry::new()` registers both the hand-written Rust rules and
    // the bundled YAML rule packs (currently `rules/kernel/dirty-frag-class/`)
    // embedded into the binary at compile time. `--no-builtins` therefore
    // suppresses BOTH sources — anyone passing it gets nothing unless they
    // also pass `--rules <path>`. We deliberately do not expose a separate
    // `--no-bundled-rules` flag: there is no current use case for "Rust core
    // only, no shipped YAML". Add one only when someone hits that need.
    let mut registry = if no_builtins {
        RuleRegistry::empty()
    } else {
        RuleRegistry::new()
    };

    // `--rules <path>` still loads additional external packs on top of the
    // bundled set; semantics unchanged.
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
        // Informational post-quantum-ready detectors: the migration-target
        // side of the audit. Included so `foxguard pqc` activates them (they
        // are opt-in and therefore dormant in a normal scan).
        || id.contains("pq-ready")
        || id.contains("hardcoded-crypto-algorithm")
        || id == "config/dockerfile-insecure-tls-env"
}

fn collect_changed_targets(
    path: &str,
    selection: Option<crate::git::ChangeSelection>,
) -> Result<Option<Vec<PathBuf>>, String> {
    let Some(selection) = selection else {
        return Ok(None);
    };

    let scan_root = Path::new(path);
    let files = changed_files(scan_root, selection)
        .map_err(|e| format!("failed to resolve changed files: {}", e))?;
    Ok(Some(files))
}

/// Resolve an explicit changed-file list (newline-delimited, repo-root-relative
/// paths) into scan targets rooted at `scan_path`. Blank lines and comments
/// (`#`) are ignored, and paths that no longer exist on disk (e.g. files a PR
/// deleted) are skipped. Returned paths are kept relative to `scan_path` so the
/// exclude matcher sees repo-root-relative paths. An empty resolved list is a
/// valid result: the caller scans nothing and reports zero findings rather than
/// falling back to a full-tree scan.
fn resolve_changed_files_from(scan_path: &str, list_file: &str) -> Result<Vec<PathBuf>, String> {
    let contents = std::fs::read_to_string(list_file)
        .map_err(|e| format!("failed to read changed-files list '{}': {}", list_file, e))?;

    let root = Path::new(scan_path);
    let mut files = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let candidate = root.join(line);
        // A PR can delete files; skip anything that is not a present file so we
        // never error out or scan phantom paths.
        if candidate.is_file() {
            files.push(candidate);
        }
    }
    Ok(files)
}

fn count_secret_files(scan_path: &Path) -> usize {
    if scan_path.is_file() {
        return 1;
    }

    ignore::WalkBuilder::new(scan_path)
        .hidden(false)
        .git_ignore(true)
        .build()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_some_and(|ft| ft.is_file()))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_rule_ids_include_coccinelle_rules() {
        let registry = RuleRegistry::empty();
        let coccinelle_rule_ids = HashSet::from([
            "kernel/pq-vulnerable-cocci".to_string(),
            "kernel/non-pq-cocci".to_string(),
        ]);

        let ids = collect_pq_rule_ids(&registry, &coccinelle_rule_ids, &HashSet::new());

        assert!(ids.contains(&"kernel/pq-vulnerable-cocci".to_string()));
        assert!(!ids.contains(&"kernel/non-pq-cocci".to_string()));
    }

    #[test]
    fn resolve_changed_files_from_skips_missing_and_comments() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::write(root.join("a.py"), "print(1)\n").unwrap();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::write(root.join("sub").join("b.py"), "print(2)\n").unwrap();

        let list = root.join("changed.txt");
        std::fs::write(&list, "# comment\n\na.py\nsub/b.py\ndeleted/gone.py\n").unwrap();

        let files = resolve_changed_files_from(root.to_str().unwrap(), list.to_str().unwrap())
            .expect("resolve");

        // Existing files resolve (rooted at scan path); the missing/deleted
        // path and the comment/blank lines are dropped.
        assert_eq!(files.len(), 2, "got {files:?}");
        assert!(files.contains(&root.join("a.py")));
        assert!(files.contains(&root.join("sub").join("b.py")));
    }

    #[test]
    fn resolve_changed_files_from_empty_list_is_empty_not_full_tree() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::write(root.join("a.py"), "print(1)\n").unwrap();
        let list = root.join("changed.txt");
        std::fs::write(&list, "\n  \n# only comments\n").unwrap();

        let files = resolve_changed_files_from(root.to_str().unwrap(), list.to_str().unwrap())
            .expect("resolve");
        assert!(
            files.is_empty(),
            "empty list must not fall back to full tree; got {files:?}"
        );
    }
}
