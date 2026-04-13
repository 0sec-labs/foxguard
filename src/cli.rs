use clap::{Args, Parser, Subcommand};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, clap::ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Terminal,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityFilter {
    Low,
    Medium,
    High,
    Critical,
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

    /// Path to Semgrep YAML rule file or directory
    #[arg(short, long)]
    pub rules: Option<String>,

    /// Disable built-in rules and run only external rules loaded via --rules
    #[arg(long, default_value_t = false)]
    pub no_builtins: bool,

    /// Scan changed files only (staged first, then unstaged)
    #[arg(long, default_value_t = false)]
    pub changed: bool,

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

    /// Post findings as inline review comments on a GitHub PR
    #[arg(long)]
    pub github_pr: Option<u64>,

    /// Suppress terminal output (exit code still reflects findings)
    #[arg(short, long)]
    pub quiet: bool,

    /// Maximum file size in bytes to scan (default: 1 MB)
    #[arg(long, default_value_t = 1_048_576)]
    pub max_file_size: u64,
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
    pub scan: ScanArgs,

    /// Output path for the baseline file
    #[arg(long, default_value = ".foxguard/baseline.json")]
    pub output: String,
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

    /// Scan changed files only (staged first, then unstaged)
    #[arg(long, default_value_t = false)]
    pub changed: bool,

    /// Apply a baseline file to suppress known findings
    #[arg(long)]
    pub baseline: Option<String>,

    /// Write the current findings to a baseline file
    #[arg(long)]
    pub write_baseline: Option<String>,

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

    /// Output format
    #[arg(short, long, value_enum, default_value = "terminal")]
    pub format: OutputFormat,

    /// Minimum severity to report
    #[arg(short, long, value_enum)]
    pub severity: Option<SeverityFilter>,

    /// Path to Semgrep YAML rule file or directory
    #[arg(short, long)]
    pub rules: Option<String>,

    /// Disable built-in rules and run only external rules loaded via --rules
    #[arg(long, default_value_t = false)]
    pub no_builtins: bool,

    /// Maximum file size in bytes to scan (default: 1 MB)
    #[arg(long, default_value_t = 1_048_576)]
    pub max_file_size: u64,
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
}

#[derive(Parser, Debug)]
#[command(
    name = "foxguard",
    about = "Fast local security guard for changed files, built-in rules, and Semgrep-compatible YAML",
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
