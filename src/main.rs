use clap::Parser;
use foxguard::app::{
    execute_diff, execute_scan, execute_secrets, resolve_scan_args as resolve_app_scan_args,
    scan_findings,
};
use foxguard::baseline::write_baseline;
use foxguard::cli::{
    BaselineArgs, Cli, Command, DiffArgs, InitArgs, OutputFormat, PqcArgs, ScanArgs, SecretsArgs,
    TuiArgs,
};
use foxguard::config::load_for_scan;
use foxguard::tui::run_scan_tui;
use std::path::Path;

fn main() {
    let cli = Cli::parse();

    if cli.command.is_none() && matches!(cli.scan.format, OutputFormat::Terminal) && !cli.scan.quiet
    {
        foxguard::report::terminal::print_banner();
    }
    let exit_code = match cli.command {
        Some(Command::Init(args)) => run_init(&args),
        Some(Command::Baseline(args)) => run_baseline(&args),
        Some(Command::Secrets(args)) => run_secrets(&args),
        Some(Command::Diff(args)) => run_diff_cmd(&args),
        Some(Command::Tui(args)) => run_tui(&args),
        Some(Command::Pqc(args)) => run_pqc(&args),
        None => run_scan(&cli.scan),
    };

    std::process::exit(exit_code);
}

fn run_pqc(args: &PqcArgs) -> i32 {
    let scan = args.to_scan_args();
    run_scan(&scan)
}

fn run_scan(scan: &ScanArgs) -> i32 {
    let result = match execute_scan(scan) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("Error: {}", error);
            return 2;
        }
    };

    for notice in &result.notices {
        eprintln!("{}", notice);
    }

    // Apply auto-fixes if --fix is set
    if scan.fix && !result.findings.is_empty() {
        let files_fixed = foxguard::fix::apply_all_fixes(&result.findings, &scan.path);
        if files_fixed > 0 {
            eprintln!("Fixed findings in {} file(s)", files_fixed);
        }
    }

    match result.args.format {
        OutputFormat::Terminal => {
            if !result.args.quiet {
                foxguard::report::terminal::clear_banner();
                foxguard::report::terminal::print_findings_full(
                    &result.findings,
                    result.files_scanned,
                    result.duration,
                    foxguard::report::terminal::ReportOptions {
                        explain: result.args.explain,
                        show_confidence: result.args.show_confidence,
                        cnsa2: result.args.cnsa2,
                    },
                );
            }
        }
        OutputFormat::Json => foxguard::report::json::print_json(&result.findings),
        OutputFormat::Sarif => foxguard::report::sarif::print_sarif(&result.findings),
        OutputFormat::Cbom => foxguard::report::cbom::print_cbom(&result.findings),
    }

    if let Some(pr_number) = result.args.github_pr {
        let scan_root = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        if let Err(e) = foxguard::report::github_pr::post_pr_review(
            &result.findings,
            pr_number,
            Some(&scan_root),
        ) {
            eprintln!("Warning: failed to post PR review: {}", e);
        }
    }

    if !result.findings.is_empty() {
        return 1;
    }

    0
}

fn run_baseline(args: &BaselineArgs) -> i32 {
    let mut scan = match resolve_app_scan_args(&args.scan) {
        Ok(scan) => scan,
        Err(error) => {
            eprintln!("Error: {}", error);
            return 2;
        }
    };
    scan.write_baseline = None;
    scan.baseline = None;

    let result = match scan_findings(&scan) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("Error: {}", error);
            return 2;
        }
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

fn run_tui(args: &TuiArgs) -> i32 {
    match run_scan_tui(args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("Error: {}", error);
            2
        }
    }
}

fn run_secrets(args: &SecretsArgs) -> i32 {
    let result = match execute_secrets(args) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("Error: {}", error);
            return 2;
        }
    };

    for notice in &result.notices {
        eprintln!("{}", notice);
    }

    match result.args.format {
        OutputFormat::Terminal => {
            foxguard::report::terminal::print_findings(
                &result.findings,
                result.files_scanned,
                result.duration,
            );
        }
        OutputFormat::Json => foxguard::report::json::print_json(&result.findings),
        OutputFormat::Sarif => foxguard::report::sarif::print_sarif(&result.findings),
        OutputFormat::Cbom => foxguard::report::cbom::print_cbom(&result.findings),
    }

    if !result.findings.is_empty() {
        return 1;
    }

    0
}

fn run_diff_cmd(args: &DiffArgs) -> i32 {
    let result = match execute_diff(args) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("Error: {}", error);
            return 2;
        }
    };

    for notice in &result.notices {
        eprintln!("{}", notice);
    }

    let new_count = result.findings.len();

    match result.args.format {
        OutputFormat::Terminal => {
            foxguard::report::terminal::print_findings(
                &result.findings,
                result.files_scanned,
                result.duration,
            );
        }
        OutputFormat::Json => foxguard::report::json::print_json(&result.findings),
        OutputFormat::Sarif => foxguard::report::sarif::print_sarif(&result.findings),
        OutputFormat::Cbom => foxguard::report::cbom::print_cbom(&result.findings),
    }

    if new_count > 0 {
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
                exclude: Vec::new(),
                baseline: None,
                write_baseline: None,
                explain: false,
                fix: false,
                github_pr: None,
                quiet: false,
                max_file_size: 1_048_576,
                show_confidence: false,
                min_confidence: None,
                pq_mode: false,
                cnsa2: false,
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
