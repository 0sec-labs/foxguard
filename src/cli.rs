use crate::git::ChangeSelection;
use clap::{Args, Parser, Subcommand};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, clap::ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Terminal,
    Json,
    Sarif,
    Cbom,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityFilter {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Args, Debug, Clone, Default)]
pub struct ChangeModeArgs {
    /// Scan changed files only (legacy: staged first, then unstaged/untracked)
    #[arg(long, default_value_t = false, conflicts_with_all = ["staged", "unstaged", "all_changes"])]
    pub changed: bool,

    /// Scan staged changes only
    #[arg(long, default_value_t = false, conflicts_with_all = ["changed", "unstaged", "all_changes"])]
    pub staged: bool,

    /// Scan unstaged tracked changes and untracked files only
    #[arg(long, default_value_t = false, conflicts_with_all = ["changed", "staged", "all_changes"])]
    pub unstaged: bool,

    /// Scan staged, unstaged tracked, and untracked changes
    #[arg(long = "all-changes", default_value_t = false, conflicts_with_all = ["changed", "staged", "unstaged"])]
    pub all_changes: bool,
}

impl ChangeModeArgs {
    pub fn selection(&self) -> Option<ChangeSelection> {
        if self.changed {
            Some(ChangeSelection::Legacy)
        } else if self.staged {
            Some(ChangeSelection::Staged)
        } else if self.unstaged {
            Some(ChangeSelection::Unstaged)
        } else if self.all_changes {
            Some(ChangeSelection::All)
        } else {
            None
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct ScanArgs {
    /// Path to scan
    #[arg(default_value = ".")]
    pub path: String,

    /// Path to foxguard config file
    #[arg(long)]
    pub config: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "terminal")]
    pub format: OutputFormat,

    /// Minimum severity to report
    #[arg(short, long, value_enum)]
    pub severity: Option<SeverityFilter>,

    /// Path to external YAML rule file or directory
    #[arg(short, long)]
    pub rules: Option<String>,

    /// Pre-built CodeQL database for external `engine: codeql` rules.
    /// When omitted, foxguard auto-builds an ephemeral database against the
    /// scan target if the `codeql` CLI is on PATH.
    #[arg(long = "codeql-db")]
    pub codeql_db: Option<String>,

    /// Disable built-in rules and run only external rules loaded via --rules
    #[arg(long, default_value_t = false)]
    pub no_builtins: bool,

    #[command(flatten)]
    pub changes: ChangeModeArgs,

    /// Exclude scan-relative paths by glob or prefix (repeatable)
    #[arg(long)]
    pub exclude: Vec<String>,

    /// Apply a baseline file to suppress known findings
    #[arg(long)]
    pub baseline: Option<String>,

    /// Write the current findings to a baseline file
    #[arg(long)]
    pub write_baseline: Option<String>,

    /// Show source-to-sink dataflow traces on taint findings
    #[arg(long, default_value_t = false)]
    pub explain: bool,

    /// Auto-fix supported taint findings (writes changes to disk)
    #[arg(long, default_value_t = false)]
    pub fix: bool,

    /// Post findings as inline review comments on a GitHub PR
    #[arg(long)]
    pub github_pr: Option<u64>,

    /// Suppress terminal output (exit code still reflects findings)
    #[arg(short, long)]
    pub quiet: bool,

    /// Write machine-readable output to a file instead of stdout
    #[arg(long)]
    pub output: Option<String>,

    /// Maximum file size in bytes to scan (default: 1 MB)
    #[arg(long, default_value_t = 1_048_576)]
    pub max_file_size: u64,

    /// Show per-finding confidence scores in terminal output
    #[arg(long, default_value_t = false)]
    pub show_confidence: bool,

    /// Minimum confidence (0.0–1.0) to report. Findings below this
    /// threshold are suppressed. Defaults to 0.0 (report all).
    #[arg(long)]
    pub min_confidence: Option<f32>,

    /// Internal: set by the `pqc` subcommand to filter to PQ rules only.
    #[arg(hide = true, long, default_value_t = false)]
    pub pq_mode: bool,

    /// Query OSV for dependency vulnerabilities in supported lockfiles.
    #[arg(long, default_value_t = false)]
    pub sca: bool,

    /// Do not query OSV over the network; use --sca-db or --sca-cache only.
    #[arg(long, default_value_t = false)]
    pub sca_offline: bool,

    /// Local OSV advisory JSON/JSONL file or directory for offline SCA runs.
    #[arg(long)]
    pub sca_db: Option<String>,

    /// Read/write an OSV query cache for dependency vulnerability scanning.
    #[arg(long)]
    pub sca_cache: Option<String>,

    /// Emit CNSA 2.0 compliance annotations on crypto-related findings and
    /// a migration-readiness summary block in terminal output (issue #241).
    ///
    /// When disabled (the default), the scan pipeline still exposes the
    /// `cnsa2Deadline` field on every applicable finding in SARIF
    /// `properties` for downstream tooling, but the terminal reporter
    /// stays silent and no summary block is printed. Also settable via
    /// `scan.cnsa2 = true` in `.foxguard.yml`.
    #[arg(long, default_value_t = false)]
    pub cnsa2: bool,
}

#[derive(Args, Debug, Clone)]
pub struct InitArgs {
    /// Repository path where the hook should be installed
    #[arg(long, default_value = ".")]
    pub path: String,

    /// Config file path relative to the repo
    #[arg(long, default_value = ".foxguard.yml")]
    pub config_path: String,

    /// Hook file path relative to the repo
    #[arg(long, default_value = ".git/hooks/pre-commit")]
    pub hook_path: String,

    /// Baseline path relative to the repo
    #[arg(long, default_value = ".foxguard/baseline.json")]
    pub baseline: String,

    /// Secrets baseline path relative to the repo
    #[arg(long, default_value = ".foxguard/secrets-baseline.json")]
    pub secrets_baseline: String,

    /// Do not create an initial baseline file
    #[arg(long, default_value_t = false)]
    pub no_baseline: bool,

    /// Overwrite an existing hook file
    #[arg(long, default_value_t = false)]
    pub force: bool,
}

#[derive(Args, Debug, Clone)]
pub struct BaselineArgs {
    #[command(flatten)]
    pub scan: BaselineScanArgs,

    /// Output path for the baseline file
    #[arg(long, default_value = ".foxguard/baseline.json")]
    pub output: String,
}

#[derive(Args, Debug, Clone)]
pub struct BaselineScanArgs {
    /// Path to scan
    #[arg(default_value = ".")]
    pub path: String,

    /// Path to foxguard config file
    #[arg(long)]
    pub config: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "terminal")]
    pub format: OutputFormat,

    /// Minimum severity to report
    #[arg(short, long, value_enum)]
    pub severity: Option<SeverityFilter>,

    /// Path to Semgrep YAML rule file or directory
    #[arg(short, long)]
    pub rules: Option<String>,

    /// Pre-built CodeQL database for external `engine: codeql` rules.
    /// When omitted, foxguard auto-builds an ephemeral database against the
    /// scan target if the `codeql` CLI is on PATH.
    #[arg(long = "codeql-db")]
    pub codeql_db: Option<String>,

    /// Disable built-in rules and run only external rules loaded via --rules
    #[arg(long, default_value_t = false)]
    pub no_builtins: bool,

    #[command(flatten)]
    pub changes: ChangeModeArgs,

    /// Exclude scan-relative paths by glob or prefix (repeatable)
    #[arg(long)]
    pub exclude: Vec<String>,

    /// Apply a baseline file to suppress known findings
    #[arg(long)]
    pub baseline: Option<String>,

    /// Write the current findings to a baseline file
    #[arg(long)]
    pub write_baseline: Option<String>,

    /// Show source-to-sink dataflow traces on taint findings
    #[arg(long, default_value_t = false)]
    pub explain: bool,

    /// Auto-fix supported taint findings (writes changes to disk)
    #[arg(long, default_value_t = false)]
    pub fix: bool,

    /// Post findings as inline review comments on a GitHub PR
    #[arg(long)]
    pub github_pr: Option<u64>,

    /// Suppress terminal output (exit code still reflects findings)
    #[arg(short, long)]
    pub quiet: bool,

    /// Maximum file size in bytes to scan (default: 1 MB)
    #[arg(long, default_value_t = 1_048_576)]
    pub max_file_size: u64,

    /// Show per-finding confidence scores in terminal output
    #[arg(long, default_value_t = false)]
    pub show_confidence: bool,

    /// Minimum confidence (0.0–1.0) to report. Findings below this
    /// threshold are suppressed. Defaults to 0.0 (report all).
    #[arg(long)]
    pub min_confidence: Option<f32>,

    /// Internal: set by the `pqc` subcommand to filter to PQ rules only.
    #[arg(hide = true, long, default_value_t = false)]
    pub pq_mode: bool,

    /// Query OSV for dependency vulnerabilities in supported lockfiles.
    #[arg(long, default_value_t = false)]
    pub sca: bool,

    /// Do not query OSV over the network; use --sca-db or --sca-cache only.
    #[arg(long, default_value_t = false)]
    pub sca_offline: bool,

    /// Local OSV advisory JSON/JSONL file or directory for offline SCA runs.
    #[arg(long)]
    pub sca_db: Option<String>,

    /// Read/write an OSV query cache for dependency vulnerability scanning.
    #[arg(long)]
    pub sca_cache: Option<String>,

    /// Emit CNSA 2.0 compliance annotations on crypto-related findings and
    /// a migration-readiness summary block in terminal output (issue #241).
    #[arg(long, default_value_t = false)]
    pub cnsa2: bool,
}

#[derive(Args, Debug, Clone)]
pub struct SecretsArgs {
    /// Path to scan
    #[arg(default_value = ".")]
    pub path: String,

    /// Path to foxguard config file
    #[arg(long)]
    pub config: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "terminal")]
    pub format: OutputFormat,

    #[command(flatten)]
    pub changes: ChangeModeArgs,

    /// Apply a baseline file to suppress known findings
    #[arg(long)]
    pub baseline: Option<String>,

    /// Write the current findings to a baseline file
    #[arg(long)]
    pub write_baseline: Option<String>,

    /// Write machine-readable output to a file instead of stdout
    #[arg(long)]
    pub output: Option<String>,

    /// Exclude a file or directory prefix from secrets scanning (repeatable)
    #[arg(long = "exclude-path")]
    pub exclude_paths: Vec<String>,

    /// Load excluded file or directory prefixes from a newline-delimited file
    #[arg(long)]
    pub exclude_path_file: Option<String>,

    /// Ignore a specific built-in secrets rule ID (repeatable)
    #[arg(long = "ignore-rule")]
    pub ignored_rules: Vec<String>,

    /// Maximum file size in bytes to scan (default: 1 MB)
    #[arg(long, default_value_t = 1_048_576)]
    pub max_file_size: u64,
}

#[derive(Args, Debug, Clone)]
pub struct DiffArgs {
    /// Target branch to compare against (e.g., "main", "origin/main")
    #[arg()]
    pub target: String,

    /// Path to scan
    #[arg(default_value = ".")]
    pub path: String,

    /// Path to foxguard config file
    #[arg(long)]
    pub config: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "terminal")]
    pub format: OutputFormat,

    /// Minimum severity to report
    #[arg(short, long, value_enum)]
    pub severity: Option<SeverityFilter>,

    /// Path to external YAML rule file or directory
    #[arg(short, long)]
    pub rules: Option<String>,

    /// Disable built-in rules and run only external rules loaded via --rules
    #[arg(long, default_value_t = false)]
    pub no_builtins: bool,

    /// Write machine-readable output to a file instead of stdout
    #[arg(long)]
    pub output: Option<String>,

    /// Post findings as inline review comments on a GitHub PR
    #[arg(long)]
    pub github_pr: Option<u64>,

    /// Maximum file size in bytes to scan (default: 1 MB)
    #[arg(long, default_value_t = 1_048_576)]
    pub max_file_size: u64,
}

#[derive(Args, Debug, Clone)]
pub struct TuiArgs {
    /// Path to scan
    #[arg(default_value = ".")]
    pub path: String,

    /// Path to foxguard config file
    #[arg(long)]
    pub config: Option<String>,

    /// Minimum severity to report
    #[arg(short, long, value_enum)]
    pub severity: Option<SeverityFilter>,

    /// Path to external YAML rule file or directory
    #[arg(short, long)]
    pub rules: Option<String>,

    /// Disable built-in rules and run only external rules loaded via --rules
    #[arg(long, default_value_t = false)]
    pub no_builtins: bool,

    #[command(flatten)]
    pub changes: ChangeModeArgs,

    /// Exclude scan-relative paths by glob or prefix (repeatable)
    #[arg(long)]
    pub exclude: Vec<String>,

    /// Apply a baseline file to suppress known findings
    #[arg(long)]
    pub baseline: Option<String>,

    /// Show only new findings compared to a target branch
    #[arg(long, value_name = "TARGET", conflicts_with = "secrets")]
    pub diff: Option<String>,

    /// Scan repositories and changed files for common secrets
    #[arg(long, default_value_t = false, conflicts_with = "diff")]
    pub secrets: bool,

    /// Show source-to-sink dataflow traces in the detail pane when available
    #[arg(long, default_value_t = false)]
    pub explain: bool,

    /// Maximum file size in bytes to scan (default: 1 MB)
    #[arg(long, default_value_t = 1_048_576)]
    pub max_file_size: u64,

    /// Start the launcher focused on the post-quantum crypto audit mode.
    /// Not exposed via clap — set programmatically when invoking the TUI
    /// from the `pqc` subcommand or other PQ-specific entry points.
    #[arg(skip)]
    pub pq_mode: bool,
}

#[derive(Args, Debug, Clone)]
pub struct PqcArgs {
    /// Path to scan
    #[arg(default_value = ".")]
    pub path: String,

    /// Path to foxguard config file
    #[arg(long)]
    pub config: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "terminal")]
    pub format: OutputFormat,

    /// Minimum severity to report
    #[arg(short, long, value_enum)]
    pub severity: Option<SeverityFilter>,

    #[command(flatten)]
    pub changes: ChangeModeArgs,

    /// Exclude scan-relative paths by glob or prefix (repeatable)
    #[arg(long)]
    pub exclude: Vec<String>,

    /// Show source-to-sink dataflow traces on taint findings
    #[arg(long, default_value_t = false)]
    pub explain: bool,

    /// Suppress terminal output (exit code still reflects findings)
    #[arg(short, long)]
    pub quiet: bool,

    /// Maximum file size in bytes to scan (default: 1 MB)
    #[arg(long, default_value_t = 1_048_576)]
    pub max_file_size: u64,

    /// Post findings as inline review comments on a GitHub PR
    #[arg(long)]
    pub github_pr: Option<u64>,

    /// Write machine-readable output to a file instead of stdout
    #[arg(long)]
    pub output: Option<String>,

    /// Apply a baseline file to suppress known findings
    #[arg(long)]
    pub baseline: Option<String>,

    /// Show per-finding confidence scores in terminal output
    #[arg(long, default_value_t = false)]
    pub show_confidence: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ScaArgs {
    /// Path to scan
    #[arg(default_value = ".")]
    pub path: String,

    /// Path to foxguard config file
    #[arg(long)]
    pub config: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "terminal")]
    pub format: OutputFormat,

    /// Minimum severity to report
    #[arg(short, long, value_enum)]
    pub severity: Option<SeverityFilter>,

    #[command(flatten)]
    pub changes: ChangeModeArgs,

    /// Exclude scan-relative paths by glob or prefix (repeatable)
    #[arg(long)]
    pub exclude: Vec<String>,

    /// Apply a baseline file to suppress known findings
    #[arg(long)]
    pub baseline: Option<String>,

    /// Suppress terminal output (exit code still reflects findings)
    #[arg(short, long)]
    pub quiet: bool,

    /// Maximum file size in bytes to scan (default: 1 MB)
    #[arg(long, default_value_t = 1_048_576)]
    pub max_file_size: u64,

    /// Post findings as inline review comments on a GitHub PR
    #[arg(long)]
    pub github_pr: Option<u64>,

    /// Write machine-readable output to a file instead of stdout
    #[arg(long)]
    pub output: Option<String>,

    /// Show per-finding confidence scores in terminal output
    #[arg(long, default_value_t = false)]
    pub show_confidence: bool,

    /// Minimum confidence (0.0–1.0) to report. Findings below this
    /// threshold are suppressed. Defaults to 0.0 (report all).
    #[arg(long)]
    pub min_confidence: Option<f32>,

    /// Do not query OSV over the network; use --sca-db or --sca-cache only.
    #[arg(long, default_value_t = false)]
    pub sca_offline: bool,

    /// Local OSV advisory JSON/JSONL file or directory for offline SCA runs.
    #[arg(long)]
    pub sca_db: Option<String>,

    /// Read/write an OSV query cache for dependency vulnerability scanning.
    #[arg(long)]
    pub sca_cache: Option<String>,
}

impl PqcArgs {
    /// Convert to `ScanArgs` with `pq_mode` enabled.
    pub fn to_scan_args(&self) -> ScanArgs {
        ScanArgs {
            path: self.path.clone(),
            config: self.config.clone(),
            format: self.format,
            severity: self.severity,
            rules: None,
            codeql_db: None,
            no_builtins: false,
            changes: self.changes.clone(),
            exclude: self.exclude.clone(),
            baseline: self.baseline.clone(),
            write_baseline: None,
            explain: self.explain,
            fix: false,
            github_pr: self.github_pr,
            quiet: self.quiet,
            output: self.output.clone(),
            max_file_size: self.max_file_size,
            show_confidence: self.show_confidence,
            min_confidence: None,
            pq_mode: true,
            sca: false,
            sca_offline: false,
            sca_db: None,
            sca_cache: None,
            // `pqc` subcommand always shows CNSA 2.0 context — that's
            // exactly the audience for that command.
            cnsa2: true,
        }
    }
}

impl ScaArgs {
    /// Convert to `ScanArgs` with dependency vulnerability scanning enabled.
    pub fn to_scan_args(&self) -> ScanArgs {
        ScanArgs {
            path: self.path.clone(),
            config: self.config.clone(),
            format: self.format,
            severity: self.severity,
            rules: None,
            codeql_db: None,
            no_builtins: true,
            changes: self.changes.clone(),
            exclude: self.exclude.clone(),
            baseline: self.baseline.clone(),
            write_baseline: None,
            explain: false,
            fix: false,
            github_pr: self.github_pr,
            quiet: self.quiet,
            output: self.output.clone(),
            max_file_size: self.max_file_size,
            show_confidence: self.show_confidence,
            min_confidence: self.min_confidence,
            pq_mode: false,
            sca: true,
            sca_offline: self.sca_offline,
            sca_db: self.sca_db.clone(),
            sca_cache: self.sca_cache.clone(),
            cnsa2: false,
        }
    }
}

impl BaselineScanArgs {
    pub fn to_scan_args(&self) -> ScanArgs {
        ScanArgs {
            path: self.path.clone(),
            config: self.config.clone(),
            format: self.format,
            severity: self.severity,
            rules: self.rules.clone(),
            codeql_db: self.codeql_db.clone(),
            no_builtins: self.no_builtins,
            changes: self.changes.clone(),
            exclude: self.exclude.clone(),
            baseline: self.baseline.clone(),
            write_baseline: self.write_baseline.clone(),
            explain: self.explain,
            fix: self.fix,
            github_pr: self.github_pr,
            quiet: self.quiet,
            output: None,
            max_file_size: self.max_file_size,
            show_confidence: self.show_confidence,
            min_confidence: self.min_confidence,
            pq_mode: self.pq_mode,
            sca: self.sca,
            sca_offline: self.sca_offline,
            sca_db: self.sca_db.clone(),
            sca_cache: self.sca_cache.clone(),
            cnsa2: self.cnsa2,
        }
    }
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Install a pre-commit hook for local foxguard runs
    Init(InitArgs),
    /// Generate a baseline file from current findings
    Baseline(BaselineArgs),
    /// Scan repositories and changed files for common secrets
    Secrets(SecretsArgs),
    /// Show only new findings compared to a target branch
    Diff(DiffArgs),
    /// Explore scan findings in the interactive terminal TUI
    Tui(TuiArgs),
    /// Post-quantum cryptography audit — scan for quantum-vulnerable algorithms
    Pqc(PqcArgs),
    /// Dependency vulnerability audit using OSV
    Sca(ScaArgs),
}

#[derive(Parser, Debug)]
#[command(
    name = "foxguard",
    about = "Fast local security guard for changed files, built-in rules, and external YAML",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub scan: ScanArgs,
}

impl SeverityFilter {
    pub fn to_severity(&self) -> crate::Severity {
        match self {
            SeverityFilter::Low => crate::Severity::Low,
            SeverityFilter::Medium => crate::Severity::Medium,
            SeverityFilter::High => crate::Severity::High,
            SeverityFilter::Critical => crate::Severity::Critical,
        }
    }
}
