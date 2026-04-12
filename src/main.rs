use clap::Parser;
use foxguard::baseline::{load_baseline, suppress_with_baseline, write_baseline};
use foxguard::cli::{BaselineArgs, Cli, Command, InitArgs, OutputFormat, ScanArgs, SecretsArgs};
use foxguard::config::{apply_scan_defaults, apply_secrets_defaults, load_for_scan};
use foxguard::engine::{scan_directory, scan_paths_with_root, ScanResult};
use foxguard::git::changed_files;
use foxguard::rules::semgrep_compat::load_semgrep_rules;
use foxguard::rules::RuleRegistry;
use foxguard::secrets::{
    scan_directory_with_config as scan_secrets_directory,
    scan_paths_with_config as scan_secrets_paths, SecretScanConfig,
};
use std::path::{Path, PathBuf};

fn main() {
    let cli = Cli::parse();

    // Show banner for terminal output (not JSON/SARIF, not quiet mode)
    if matches!(cli.scan.format, OutputFormat::Terminal) && !cli.scan.quiet {
        foxguard::report::terminal::print_banner();
    }
    let exit_code = match cli.command {
        Some(Command::Init(args)) => run_init(&args),
        Some(Command::Baseline(args)) => run_baseline(&args),
        Some(Command::Secrets(args)) => run_secrets(&args),
        None => run_scan(&cli.scan),
    };

    std::process::exit(exit_code);
}

fn resolve_scan_args(scan: &ScanArgs) -> Result<ScanArgs, i32> {
    let mut scan = scan.clone();
    let config = match load_for_scan(Path::new(&scan.path), scan.config.as_deref()) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(2);
        }
    };
    apply_scan_defaults(&mut scan, config.as_ref());
    Ok(scan)
}

fn resolve_secrets_args(args: &SecretsArgs) -> Result<SecretsArgs, i32> {
    let mut args = args.clone();
    let config = match load_for_scan(Path::new(&args.path), args.config.as_deref()) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(2);
        }
    };
    apply_secrets_defaults(&mut args, config.as_ref());
    Ok(args)
}

fn build_registry(scan: &ScanArgs) -> RuleRegistry {
    let mut registry = if scan.no_builtins {
        RuleRegistry::empty()
    } else {
        RuleRegistry::new()
    };

    if let Some(ref rules_path) = scan.rules {
        let path = Path::new(rules_path);
        let semgrep_rules = load_semgrep_rules(path);
        let count = semgrep_rules.len();
        for rule in semgrep_rules {
            registry.register(rule);
        }
        if count > 0 {
            eprintln!("Loaded {} Semgrep rule(s) from {}", count, rules_path);
        }
    }

    registry
}

fn validate_scan_inputs(scan: &ScanArgs) -> Result<(), i32> {
    let scan_path = Path::new(&scan.path);
    if !scan_path.exists() {
        eprintln!("Error: path '{}' does not exist", scan.path);
        return Err(2);
    }

    if let Some(ref rules_path) = scan.rules {
        let path = Path::new(rules_path);
        if !path.exists() {
            eprintln!("Error: rules path '{}' does not exist", rules_path);
            return Err(2);
        }
    }

    Ok(())
}

fn collect_changed_targets(path: &str, changed: bool) -> Result<Option<Vec<PathBuf>>, i32> {
    if !changed {
        return Ok(None);
    }

    let scan_root = Path::new(path);
    let files = changed_files(scan_root).map_err(|e| {
        eprintln!("Error: failed to resolve changed files: {}", e);
        2
    })?;

    Ok(Some(files))
}

fn scan_findings(scan: &ScanArgs) -> Result<ScanResult, i32> {
    validate_scan_inputs(scan)?;

    let registry = build_registry(scan);
    let targets = collect_changed_targets(&scan.path, scan.changed)?;

    let mut result = if let Some(files) = targets {
        scan_paths_with_root(Path::new(&scan.path), &files, &registry, scan.max_file_size)
    } else {
        scan_directory(&scan.path, &registry, scan.max_file_size)
    };

    // Filter by severity if specified
    if let Some(ref min_severity) = scan.severity {
        let min = min_severity.to_severity();
        result.findings.retain(|f| f.severity >= min);
    }

    Ok(result)
}

fn run_scan(scan: &ScanArgs) -> i32 {
    let scan = match resolve_scan_args(scan) {
        Ok(scan) => scan,
        Err(code) => return code,
    };

    let result = match scan_findings(&scan) {
        Ok(result) => result,
        Err(code) => return code,
    };

    let files_scanned = result.files_scanned;
    let duration = result.duration;
    let mut findings = result.findings;

    if let Some(ref path) = scan.write_baseline {
        if let Err(e) = write_baseline(Path::new(path), &findings) {
            eprintln!("Error: {}", e);
            return 2;
        }
        eprintln!("Wrote baseline to {}", path);
    }

    let baseline = match scan.baseline.as_ref() {
        Some(path) => match load_baseline(Path::new(path)) {
            Ok(baseline) => baseline,
            Err(e) => {
                eprintln!("Error: {}", e);
                return 2;
            }
        },
        None => None,
    };

    findings = suppress_with_baseline(findings, baseline.as_ref());

    if files_scanned == 0 {
        eprintln!(
            "Warning: no files with supported extensions found. Supported: .js, .ts, .py, .go, .rb, .java, .php, .rs, .cs, .swift, .kt"
        );
    }

    match scan.format {
        OutputFormat::Terminal => {
            if !scan.quiet {
                foxguard::report::terminal::clear_banner();
                foxguard::report::terminal::print_findings_with_options(
                    &findings,
                    files_scanned,
                    duration,
                    scan.explain,
                );
            }
        }
        OutputFormat::Json => foxguard::report::json::print_json(&findings),
        OutputFormat::Sarif => foxguard::report::sarif::print_sarif(&findings),
    }

    // Post inline PR review comments if --github-pr is set (best-effort)
    if let Some(pr_number) = scan.github_pr {
        let scan_root = Path::new(&scan.path);
        if let Err(e) =
            foxguard::report::github_pr::post_pr_review(&findings, pr_number, Some(scan_root))
        {
            eprintln!("Warning: failed to post PR review: {}", e);
        }
    }

    if !findings.is_empty() {
        return 1;
    }

    0
}

fn run_baseline(args: &BaselineArgs) -> i32 {
    let mut scan = match resolve_scan_args(&args.scan) {
        Ok(scan) => scan,
        Err(code) => return code,
    };
    scan.write_baseline = None;
    scan.baseline = None;

    let result = match scan_findings(&scan) {
        Ok(result) => result,
        Err(code) => return code,
    };

    if let Err(e) = write_baseline(Path::new(&args.output), &result.findings) {
        eprintln!("Error: {}", e);
        return 2;
    }

    eprintln!(
        "Wrote baseline with {} finding(s) to {}",
        result.findings.len(),
        args.output
    );
    0
}

fn run_secrets(args: &SecretsArgs) -> i32 {
    let args = match resolve_secrets_args(args) {
        Ok(args) => args,
        Err(code) => return code,
    };

    let scan_path = Path::new(&args.path);
    if !scan_path.exists() {
        eprintln!("Error: path '{}' does not exist", args.path);
        return 2;
    }

    let config = match SecretScanConfig::from_inputs(
        scan_path,
        &args.exclude_paths,
        args.exclude_path_file.as_deref().map(Path::new),
        &args.ignored_rules,
    ) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {}", e);
            return 2;
        }
    };

    let targets = match collect_changed_targets(&args.path, args.changed) {
        Ok(targets) => targets,
        Err(code) => return code,
    };

    let mut findings = if let Some(files) = targets {
        scan_secrets_paths(scan_path, &files, &config, args.max_file_size)
    } else {
        scan_secrets_directory(&args.path, &config, args.max_file_size)
    };

    if let Some(ref path) = args.write_baseline {
        if let Err(e) = write_baseline(Path::new(path), &findings) {
            eprintln!("Error: {}", e);
            return 2;
        }
        eprintln!("Wrote secrets baseline to {}", path);
    }

    let baseline = match args.baseline.as_ref() {
        Some(path) => match load_baseline(Path::new(path)) {
            Ok(baseline) => baseline,
            Err(e) => {
                eprintln!("Error: {}", e);
                return 2;
            }
        },
        None => None,
    };

    findings = suppress_with_baseline(findings, baseline.as_ref());

    match args.format {
        OutputFormat::Terminal => {
            foxguard::report::terminal::print_findings(&findings, 0, std::time::Duration::ZERO);
        }
        OutputFormat::Json => foxguard::report::json::print_json(&findings),
        OutputFormat::Sarif => foxguard::report::sarif::print_sarif(&findings),
    }

    if !findings.is_empty() {
        return 1;
    }

    0
}

fn run_init(args: &InitArgs) -> i32 {
    let repo_root = Path::new(&args.path);
    if !repo_root.exists() {
        eprintln!("Error: path '{}' does not exist", args.path);
        return 2;
    }

    let hook_path = repo_root.join(&args.hook_path);
    if hook_path.exists() && !args.force {
        eprintln!(
            "Error: hook '{}' already exists; rerun with --force to overwrite",
            hook_path.display()
        );
        return 2;
    }

    if let Some(parent) = hook_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!(
                "Error: failed to create hook directory '{}': {}",
                parent.display(),
                e
            );
            return 2;
        }
    }

    let config_path = repo_root.join(&args.config_path);
    let config_created = match ensure_init_config(args, &config_path) {
        Ok(created) => created,
        Err(e) => {
            eprintln!("Error: {}", e);
            return 2;
        }
    };

    let config = match load_for_scan(repo_root, Some(config_path.to_string_lossy().as_ref())) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {}", e);
            return 2;
        }
    };

    let hook_contents = build_init_hook(args, config.as_ref(), config_created);

    if let Err(e) = std::fs::write(&hook_path, hook_contents) {
        eprintln!(
            "Error: failed to write hook '{}': {}",
            hook_path.display(),
            e
        );
        return 2;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = match std::fs::metadata(&hook_path) {
            Ok(meta) => meta.permissions(),
            Err(e) => {
                eprintln!(
                    "Error: failed to read hook metadata '{}': {}",
                    hook_path.display(),
                    e
                );
                return 2;
            }
        };
        perms.set_mode(0o755);
        if let Err(e) = std::fs::set_permissions(&hook_path, perms) {
            eprintln!(
                "Error: failed to mark hook executable '{}': {}",
                hook_path.display(),
                e
            );
            return 2;
        }
    }

    if !args.no_baseline {
        let baseline_args = BaselineArgs {
            scan: ScanArgs {
                path: args.path.clone(),
                config: None,
                format: OutputFormat::Json,
                severity: None,
                rules: None,
                no_builtins: false,
                changed: false,
                baseline: None,
                write_baseline: None,
                explain: false,
                github_pr: None,
                quiet: false,
                max_file_size: 1_048_576,
            },
            output: repo_root.join(&args.baseline).display().to_string(),
        };

        let code = run_baseline(&baseline_args);
        if code != 0 {
            return code;
        }

        let secrets_args = SecretsArgs {
            path: args.path.clone(),
            config: None,
            format: OutputFormat::Json,
            changed: false,
            baseline: None,
            write_baseline: Some(repo_root.join(&args.secrets_baseline).display().to_string()),
            exclude_paths: Vec::new(),
            exclude_path_file: None,
            ignored_rules: Vec::new(),
            max_file_size: 1_048_576,
        };

        let code = run_secrets(&secrets_args);
        if code != 0 && code != 1 {
            return code;
        }
    }

    if config_created {
        eprintln!("Wrote starter config to {}", config_path.display());
    }
    eprintln!("Installed pre-commit hook at {}", hook_path.display());
    0
}

fn ensure_init_config(args: &InitArgs, config_path: &Path) -> Result<bool, String> {
    if config_path.exists() {
        return Ok(false);
    }

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create config directory '{}': {}",
                parent.display(),
                e
            )
        })?;
    }

    let contents = if args.no_baseline {
        "scan: {}\nsecrets: {}\n".to_string()
    } else {
        format!(
            "scan:\n  baseline: {}\n\nsecrets:\n  baseline: {}\n",
            args.baseline, args.secrets_baseline
        )
    };

    std::fs::write(config_path, contents)
        .map_err(|e| format!("failed to write config '{}': {}", config_path.display(), e))?;

    Ok(true)
}

fn build_init_hook(
    args: &InitArgs,
    config: Option<&foxguard::config::FoxguardConfig>,
    config_created: bool,
) -> String {
    let uses_config_baselines = args.no_baseline
        || config_created
        || config
            .map(|config| config.scan.baseline.is_some() && config.secrets.baseline.is_some())
            .unwrap_or(false);

    if uses_config_baselines {
        format!(
            "#!/usr/bin/env sh\nset -eu\nfoxguard --config \"{}\" --changed\nfoxguard secrets --config \"{}\" --changed\n",
            args.config_path, args.config_path
        )
    } else {
        format!(
            "#!/usr/bin/env sh\nset -eu\nfoxguard --config \"{}\" --changed --baseline \"{}\"\nfoxguard secrets --config \"{}\" --changed --baseline \"{}\"\n",
            args.config_path, args.baseline, args.config_path, args.secrets_baseline
        )
    }
}
