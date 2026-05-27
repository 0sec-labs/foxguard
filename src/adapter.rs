use crate::app::{execute_diff, execute_scan, execute_secrets};
use crate::cli::{ChangeModeArgs, DiffArgs, OutputFormat, ScanArgs, SecretsArgs, SeverityFilter};
use crate::{Finding, Severity};
use serde::{Deserialize, Serialize};

pub const ADAPTER_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterCommand {
    ScanFile,
    ScanWorkspace,
    Diff,
    Secrets,
    Pqc,
    Explain,
    Suppress,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterChangeMode {
    #[default]
    None,
    Changed,
    Staged,
    Unstaged,
    AllChanges,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterSuppressionKind {
    Inline,
    Config,
    Baseline,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdapterFindingRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterRequest {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub command: AdapterCommand,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<String>,
    #[serde(default)]
    pub no_builtins: bool,
    #[serde(default)]
    pub change_mode: AdapterChangeMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<String>,
    #[serde(default)]
    pub explain: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_file_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_confidence: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding: Option<AdapterFindingRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppression: Option<AdapterSuppressionKind>,
}

impl AdapterRequest {
    pub fn new(command: AdapterCommand) -> Self {
        Self {
            schema_version: ADAPTER_SCHEMA_VERSION.to_string(),
            request_id: None,
            command,
            path: None,
            workspace_root: None,
            base: None,
            severity: None,
            config: None,
            rules: None,
            no_builtins: false,
            change_mode: AdapterChangeMode::None,
            exclude: Vec::new(),
            baseline: None,
            explain: false,
            max_file_size: None,
            min_confidence: None,
            finding: None,
            suppression: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdapterSeverityCounts {
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterSummary {
    pub findings_total: usize,
    pub files_scanned: usize,
    pub duration_ms: u128,
    pub by_severity: AdapterSeverityCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterDiffSummary {
    pub base: String,
    pub total_current: usize,
    pub existing_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterSuppressionSuggestion {
    pub kind: AdapterSuppressionKind,
    pub rule_id: String,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterResponse {
    pub schema_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub command: Option<AdapterCommand>,
    pub ok: bool,
    pub exit_code: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<AdapterSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notices: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<AdapterDiffSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression: Option<AdapterSuppressionSuggestion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn execute_adapter_request(request: AdapterRequest) -> AdapterResponse {
    match request.command {
        AdapterCommand::ScanFile => scan_file_response(&request),
        AdapterCommand::ScanWorkspace => scan_workspace_response(&request),
        AdapterCommand::Diff => diff_response(&request),
        AdapterCommand::Secrets => secrets_response(&request),
        AdapterCommand::Pqc => pqc_response(&request),
        AdapterCommand::Explain => explain_response(&request),
        AdapterCommand::Suppress => suppress_response(&request),
    }
}

pub fn adapter_error_response(
    request_id: Option<String>,
    command: Option<AdapterCommand>,
    error: impl Into<String>,
) -> AdapterResponse {
    AdapterResponse {
        schema_version: ADAPTER_SCHEMA_VERSION.to_string(),
        request_id,
        command,
        ok: false,
        exit_code: 2,
        summary: None,
        findings: Vec::new(),
        notices: Vec::new(),
        diff: None,
        suppression: None,
        error: Some(error.into()),
    }
}

fn scan_file_response(request: &AdapterRequest) -> AdapterResponse {
    let Some(path) = request.path.as_deref() else {
        return request_error(request, "scan-file requires path");
    };
    run_scan_response(
        request,
        resolve_workspace_path(path, request.workspace_root.as_deref()),
        false,
    )
}

fn scan_workspace_response(request: &AdapterRequest) -> AdapterResponse {
    let path = request
        .path
        .as_deref()
        .or(request.workspace_root.as_deref())
        .unwrap_or(".");
    run_scan_response(
        request,
        resolve_workspace_path(path, request.workspace_root.as_deref()),
        false,
    )
}

fn pqc_response(request: &AdapterRequest) -> AdapterResponse {
    let path = request
        .path
        .as_deref()
        .or(request.workspace_root.as_deref())
        .unwrap_or(".");
    run_scan_response(
        request,
        resolve_workspace_path(path, request.workspace_root.as_deref()),
        true,
    )
}

fn explain_response(request: &AdapterRequest) -> AdapterResponse {
    let Some(path) = request
        .path
        .as_deref()
        .or(request.workspace_root.as_deref())
    else {
        return request_error(request, "explain requires path or workspace_root");
    };
    let mut scan = scan_args(
        request,
        resolve_workspace_path(path, request.workspace_root.as_deref()),
        false,
    );
    scan.explain = true;
    match execute_scan(&scan) {
        Ok(result) => {
            let findings = select_findings(result.findings, request.finding.as_ref());
            let summary = summarize(&findings, result.files_scanned, result.duration);
            success_response(
                request,
                findings_exit_code(&findings),
                Some(summary),
                findings,
                result.notices,
                None,
                None,
            )
        }
        Err(error) => request_error(request, error),
    }
}

fn run_scan_response(request: &AdapterRequest, path: String, pq_mode: bool) -> AdapterResponse {
    let scan = scan_args(request, path, pq_mode);
    match execute_scan(&scan) {
        Ok(result) => {
            let summary = summarize(&result.findings, result.files_scanned, result.duration);
            let exit_code = findings_exit_code(&result.findings);
            success_response(
                request,
                exit_code,
                Some(summary),
                result.findings,
                result.notices,
                None,
                None,
            )
        }
        Err(error) => request_error(request, error),
    }
}

fn secrets_response(request: &AdapterRequest) -> AdapterResponse {
    let path = request
        .path
        .as_deref()
        .or(request.workspace_root.as_deref())
        .unwrap_or(".");
    let args = SecretsArgs {
        path: resolve_workspace_path(path, request.workspace_root.as_deref()),
        config: resolve_optional_workspace_path(
            request.config.as_deref(),
            request.workspace_root.as_deref(),
        ),
        format: OutputFormat::Json,
        changes: change_mode_args(request.change_mode),
        baseline: resolve_optional_workspace_path(
            request.baseline.as_deref(),
            request.workspace_root.as_deref(),
        ),
        write_baseline: None,
        output: None,
        exclude_paths: request.exclude.clone(),
        exclude_path_file: None,
        ignored_rules: Vec::new(),
        max_file_size: max_file_size(request),
    };
    match execute_secrets(&args) {
        Ok(result) => {
            let summary = summarize(&result.findings, result.files_scanned, result.duration);
            let exit_code = findings_exit_code(&result.findings);
            success_response(
                request,
                exit_code,
                Some(summary),
                result.findings,
                result.notices,
                None,
                None,
            )
        }
        Err(error) => request_error(request, error),
    }
}

fn diff_response(request: &AdapterRequest) -> AdapterResponse {
    let path = request
        .path
        .as_deref()
        .or(request.workspace_root.as_deref())
        .unwrap_or(".");
    let base = request.base.clone().unwrap_or_else(|| "main".to_string());
    let args = DiffArgs {
        target: base.clone(),
        path: resolve_workspace_path(path, request.workspace_root.as_deref()),
        config: resolve_optional_workspace_path(
            request.config.as_deref(),
            request.workspace_root.as_deref(),
        ),
        format: OutputFormat::Json,
        severity: request.severity.map(severity_filter),
        rules: resolve_optional_workspace_path(
            request.rules.as_deref(),
            request.workspace_root.as_deref(),
        ),
        no_builtins: request.no_builtins,
        output: None,
        github_pr: None,
        max_file_size: max_file_size(request),
    };
    match execute_diff(&args) {
        Ok(result) => {
            let summary = summarize(&result.findings, result.files_scanned, result.duration);
            let exit_code = findings_exit_code(&result.findings);
            let diff = AdapterDiffSummary {
                base,
                total_current: result.total_current,
                existing_count: result.existing_count,
            };
            success_response(
                request,
                exit_code,
                Some(summary),
                result.findings,
                result.notices,
                Some(diff),
                None,
            )
        }
        Err(error) => request_error(request, error),
    }
}

fn suppress_response(request: &AdapterRequest) -> AdapterResponse {
    let Some(finding) = request.finding.as_ref() else {
        return request_error(request, "suppress requires finding");
    };
    let Some(rule_id) = finding.rule_id.as_deref() else {
        return request_error(request, "suppress requires finding.rule_id");
    };
    let file = finding
        .file
        .as_deref()
        .or(request.path.as_deref())
        .unwrap_or(".");
    let kind = request
        .suppression
        .unwrap_or(AdapterSuppressionKind::Inline);
    let suggestion = suppression_suggestion(kind, rule_id, file, finding.line);

    success_response(
        request,
        0,
        None,
        Vec::new(),
        Vec::new(),
        None,
        Some(suggestion),
    )
}

fn scan_args(request: &AdapterRequest, path: String, pq_mode: bool) -> ScanArgs {
    ScanArgs {
        path,
        config: resolve_optional_workspace_path(
            request.config.as_deref(),
            request.workspace_root.as_deref(),
        ),
        format: OutputFormat::Json,
        severity: request.severity.map(severity_filter),
        rules: resolve_optional_workspace_path(
            request.rules.as_deref(),
            request.workspace_root.as_deref(),
        ),
        codeql_db: None,
        no_builtins: request.no_builtins,
        changes: change_mode_args(request.change_mode),
        exclude: request.exclude.clone(),
        baseline: resolve_optional_workspace_path(
            request.baseline.as_deref(),
            request.workspace_root.as_deref(),
        ),
        write_baseline: None,
        explain: request.explain || pq_mode,
        fix: false,
        github_pr: None,
        quiet: true,
        output: None,
        max_file_size: max_file_size(request),
        show_confidence: false,
        min_confidence: request.min_confidence,
        pq_mode,
        cnsa2: pq_mode,
    }
}

fn success_response(
    request: &AdapterRequest,
    exit_code: u8,
    summary: Option<AdapterSummary>,
    findings: Vec<Finding>,
    notices: Vec<String>,
    diff: Option<AdapterDiffSummary>,
    suppression: Option<AdapterSuppressionSuggestion>,
) -> AdapterResponse {
    AdapterResponse {
        schema_version: ADAPTER_SCHEMA_VERSION.to_string(),
        request_id: request.request_id.clone(),
        command: Some(request.command),
        ok: true,
        exit_code,
        summary,
        findings,
        notices,
        diff,
        suppression,
        error: None,
    }
}

fn request_error(request: &AdapterRequest, error: impl Into<String>) -> AdapterResponse {
    adapter_error_response(
        Some(request.request_id.clone()).flatten(),
        Some(request.command),
        error,
    )
}

fn summarize(
    findings: &[Finding],
    files_scanned: usize,
    duration: std::time::Duration,
) -> AdapterSummary {
    let mut by_severity = AdapterSeverityCounts::default();
    for finding in findings {
        match finding.severity {
            Severity::Low => by_severity.low += 1,
            Severity::Medium => by_severity.medium += 1,
            Severity::High => by_severity.high += 1,
            Severity::Critical => by_severity.critical += 1,
        }
    }
    AdapterSummary {
        findings_total: findings.len(),
        files_scanned,
        duration_ms: duration.as_millis(),
        by_severity,
    }
}

fn select_findings(findings: Vec<Finding>, selector: Option<&AdapterFindingRef>) -> Vec<Finding> {
    let Some(selector) = selector else {
        return findings;
    };
    findings
        .into_iter()
        .filter(|finding| {
            selector
                .rule_id
                .as_ref()
                .is_none_or(|rule_id| &finding.rule_id == rule_id)
                && selector
                    .file
                    .as_ref()
                    .is_none_or(|file| finding.file == *file || finding.file.ends_with(file))
                && selector.line.is_none_or(|line| finding.line == line)
                && selector
                    .column
                    .is_none_or(|column| finding.column == column)
        })
        .collect()
}

fn suppression_suggestion(
    kind: AdapterSuppressionKind,
    rule_id: &str,
    file: &str,
    line: Option<usize>,
) -> AdapterSuppressionSuggestion {
    let (snippet, config_snippet, command) = match kind {
        AdapterSuppressionKind::Inline => (
            Some(format!(
                "{} foxguard: ignore[{rule_id}]",
                comment_prefix_for_path(file)
            )),
            None,
            None,
        ),
        AdapterSuppressionKind::Config => (
            None,
            Some(format!(
                "scan:\n  ignore_rules:\n    - path: {file}\n      rules:\n        - {rule_id}\n"
            )),
            None,
        ),
        AdapterSuppressionKind::Baseline => (
            None,
            None,
            Some(format!(
                "foxguard baseline --output .foxguard/baseline.json {file}"
            )),
        ),
    };

    AdapterSuppressionSuggestion {
        kind,
        rule_id: rule_id.to_string(),
        file: file.to_string(),
        line,
        snippet,
        config_snippet,
        command,
    }
}

fn findings_exit_code(findings: &[Finding]) -> u8 {
    if findings.is_empty() {
        0
    } else {
        1
    }
}

fn severity_filter(severity: Severity) -> SeverityFilter {
    match severity {
        Severity::Low => SeverityFilter::Low,
        Severity::Medium => SeverityFilter::Medium,
        Severity::High => SeverityFilter::High,
        Severity::Critical => SeverityFilter::Critical,
    }
}

fn change_mode_args(mode: AdapterChangeMode) -> ChangeModeArgs {
    ChangeModeArgs {
        changed: matches!(mode, AdapterChangeMode::Changed),
        staged: matches!(mode, AdapterChangeMode::Staged),
        unstaged: matches!(mode, AdapterChangeMode::Unstaged),
        all_changes: matches!(mode, AdapterChangeMode::AllChanges),
    }
}

fn max_file_size(request: &AdapterRequest) -> u64 {
    request.max_file_size.unwrap_or(1_048_576)
}

fn default_schema_version() -> String {
    ADAPTER_SCHEMA_VERSION.to_string()
}

fn resolve_optional_workspace_path(
    path: Option<&str>,
    workspace_root: Option<&str>,
) -> Option<String> {
    path.map(|path| resolve_workspace_path(path, workspace_root))
}

fn resolve_workspace_path(path: &str, workspace_root: Option<&str>) -> String {
    if path == "." {
        return workspace_root
            .filter(|root| !root.is_empty())
            .unwrap_or(".")
            .to_string();
    }
    if is_absolute_path(path) {
        return path.to_string();
    }
    let Some(root) = workspace_root else {
        return path.to_string();
    };
    if root == "." || root.is_empty() {
        return path.to_string();
    }
    format!(
        "{}/{}",
        root.trim_end_matches(['/', '\\']),
        path.trim_start_matches("./")
    )
}

fn is_absolute_path(path: &str) -> bool {
    path.starts_with('/') || path.as_bytes().get(1).is_some_and(|byte| *byte == b':')
}

fn comment_prefix_for_path(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    let extension = lower.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("");
    match extension {
        "py" | "pyw" | "rb" | "rake" | "yml" | "yaml" | "sh" | "bash" | "zsh" => "#",
        _ => "//",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn must<T, E: std::fmt::Display>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{error}"),
        }
    }

    #[test]
    fn adapter_request_uses_stable_kebab_case_command_names() {
        let value = json!({
            "command": "scan-file",
            "request_id": "abc",
            "path": "src/app.py",
            "severity": "medium",
            "change_mode": "staged"
        });

        let request: AdapterRequest = must(serde_json::from_value(value));
        assert_eq!(request.command, AdapterCommand::ScanFile);
        assert_eq!(request.request_id.as_deref(), Some("abc"));
        assert_eq!(request.severity, Some(Severity::Medium));
        assert_eq!(request.change_mode, AdapterChangeMode::Staged);

        let encoded = must(serde_json::to_value(&request));
        assert_eq!(encoded["command"].as_str(), Some("scan-file"));
        assert_eq!(
            encoded["schema_version"].as_str(),
            Some(ADAPTER_SCHEMA_VERSION)
        );
    }

    #[test]
    fn scan_file_request_reports_findings_with_summary() {
        let temp = must(tempfile::tempdir());
        let file = temp.path().join("app.py");
        if let Err(error) = std::fs::write(&file, "password = \"supersecret123\"\nDEBUG = True\n") {
            panic!("{error}");
        }

        let mut request = AdapterRequest::new(AdapterCommand::ScanFile);
        request.path = Some(file.to_string_lossy().into_owned());
        request.severity = Some(Severity::Medium);

        let response = execute_adapter_request(request);
        assert!(
            response.ok,
            "unexpected adapter error: {:?}",
            response.error
        );
        assert_eq!(response.exit_code, 1);
        assert!(response.findings.iter().any(|finding| {
            finding.rule_id == "py/no-hardcoded-secret" || finding.rule_id == "py/no-debug-true"
        }));
        let Some(summary) = response.summary else {
            panic!("missing summary");
        };
        assert_eq!(summary.findings_total, response.findings.len());
        assert_eq!(summary.files_scanned, 1);
    }

    #[test]
    fn suppress_request_returns_inline_snippet() {
        let mut request = AdapterRequest::new(AdapterCommand::Suppress);
        request.finding = Some(AdapterFindingRef {
            rule_id: Some("py/no-eval".to_string()),
            file: Some("src/app.py".to_string()),
            line: Some(12),
            column: None,
        });
        request.suppression = Some(AdapterSuppressionKind::Inline);

        let response = execute_adapter_request(request);
        assert!(
            response.ok,
            "unexpected adapter error: {:?}",
            response.error
        );
        let Some(suppression) = response.suppression else {
            panic!("missing suppression");
        };
        assert_eq!(suppression.kind, AdapterSuppressionKind::Inline);
        assert_eq!(
            suppression.snippet.as_deref(),
            Some("# foxguard: ignore[py/no-eval]")
        );
        assert_eq!(suppression.line, Some(12));
    }
}
