use crate::diff::{diff_findings, DiffResult};
use crate::{Finding, Severity};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use serde_yaml_ng::Value as YamlValue;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

#[derive(Debug, Clone)]
pub struct CodeQlRule {
    pub id: String,
    pub message: String,
    pub severity: Severity,
    pub cwe: Option<String>,
    query: PathBuf,
    database: Option<PathBuf>,
}

pub struct CodeQlScanResult {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub candidate_rules: usize,
    pub notices: Vec<String>,
}

pub struct CodeQlDiffScanResult {
    findings: Vec<CodeQlDiffFinding>,
    namespaces_by_rule: HashMap<String, HashSet<String>>,
    pub files_scanned: usize,
}

#[derive(Clone)]
struct CodeQlDiffFinding {
    finding: Finding,
    comparison_path: String,
    identity: String,
    has_fingerprint: bool,
}

struct CodeQlArtifactPath {
    display_path: String,
    comparison_path: String,
}

struct ParsedCodeQlDiffFindings {
    findings: Vec<CodeQlDiffFinding>,
    namespaces: HashSet<String>,
}

#[derive(Debug, Deserialize)]
struct CodeQlRuleYaml {
    id: String,
    #[serde(default)]
    engine: Option<String>,
    message: String,
    severity: FlexibleSeverity,
    #[serde(default)]
    metadata: Option<CodeQlMetadata>,
    query: String,
    #[serde(default)]
    database: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CodeQlMetadata {
    cwe: Option<CweValue>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CweValue {
    Single(String),
    List(Vec<String>),
}

#[derive(Debug)]
struct FlexibleSeverity(Severity);

impl<'de> Deserialize<'de> for FlexibleSeverity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        let severity = match raw.to_ascii_lowercase().as_str() {
            "critical" | "error" => Severity::Critical,
            "high" | "warning" => Severity::High,
            "medium" | "info" => Severity::Medium,
            "low" => Severity::Low,
            other => {
                return Err(serde::de::Error::custom(format!(
                    "unsupported CodeQL severity '{}'",
                    other
                )))
            }
        };
        Ok(Self(severity))
    }
}

impl CodeQlRule {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn query_path(&self) -> &Path {
        &self.query
    }
}

pub fn rule_ids(rules: &[CodeQlRule]) -> HashSet<String> {
    rules.iter().map(|rule| rule.id.clone()).collect()
}

pub fn apply_rule_filter(rules: &mut Vec<CodeQlRule>, enable: &[String], disable: &[String]) {
    if !enable.is_empty() {
        let enable_set: HashSet<&str> = enable.iter().map(|id| id.as_str()).collect();
        rules.retain(|rule| enable_set.contains(rule.id()));
    }

    if !disable.is_empty() {
        let disable_set: HashSet<&str> = disable.iter().map(|id| id.as_str()).collect();
        rules.retain(|rule| !disable_set.contains(rule.id()));
    }
}

pub fn load_codeql_rules(path: &Path) -> (Vec<CodeQlRule>, Vec<String>) {
    let mut rules = Vec::new();
    let mut notices = Vec::new();

    if path.is_file() {
        match parse_codeql_file(path) {
            Ok((parsed, mut parsed_notices)) => {
                rules.extend(parsed);
                notices.append(&mut parsed_notices);
            }
            Err(error) => notices.push(format!("Warning: {}", error)),
        }
    } else if path.is_dir() {
        let walker = walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry.file_type().is_file()
                    && matches!(
                        entry.path().extension().and_then(|ext| ext.to_str()),
                        Some("yaml" | "yml")
                    )
            });

        for entry in walker {
            match parse_codeql_file(entry.path()) {
                Ok((parsed, mut parsed_notices)) => {
                    rules.extend(parsed);
                    notices.append(&mut parsed_notices);
                }
                Err(error) => notices.push(format!("Warning: {}", error)),
            }
        }
    }

    (rules, notices)
}

/// Load CodeQL rules for a paired database diff.
///
/// A diff cannot safely treat an unloadable rule set as zero findings, so this
/// strict variant turns parser notices, missing queries, and an empty CodeQL
/// rule selection into errors. The regular one-tree scan keeps its existing
/// warn-and-skip behavior through [`load_codeql_rules`].
pub fn load_codeql_rules_for_diff(path: &Path) -> Result<Vec<CodeQlRule>, String> {
    let mut rules = Vec::new();
    for rule_file in strict_codeql_rule_files(path)? {
        let (parsed, notices) = parse_codeql_file(&rule_file).map_err(|error| {
            format!(
                "CodeQL diff failed to load rules from {}: {}",
                rule_file.display(),
                error
            )
        })?;
        if !notices.is_empty() {
            return Err(format!(
                "CodeQL diff failed to load rules from {}: {}",
                rule_file.display(),
                notices.join("; ")
            ));
        }
        rules.extend(parsed);
    }

    if rules.is_empty() {
        return Err(format!(
            "CodeQL diff requires at least one engine: codeql rule in {}",
            path.display()
        ));
    }
    for rule in &rules {
        if !rule.query.is_file() {
            return Err(format!(
                "CodeQL diff failed to load rule '{}': query {} does not exist",
                rule.id,
                rule.query.display()
            ));
        }
    }

    Ok(rules)
}

fn strict_codeql_rule_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !path.is_dir() {
        return Err(format!(
            "CodeQL diff failed to load rules: {} does not exist",
            path.display()
        ));
    }

    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(path) {
        let entry = entry.map_err(|error| {
            format!(
                "CodeQL diff failed to traverse rules under {}: {}",
                path.display(),
                error
            )
        })?;
        if entry.file_type().is_file()
            && matches!(
                entry.path().extension().and_then(|ext| ext.to_str()),
                Some("yaml" | "yml")
            )
        {
            files.push(entry.into_path());
        }
    }
    files.sort();
    Ok(files)
}

pub fn parse_codeql_file(path: &Path) -> Result<(Vec<CodeQlRule>, Vec<String>), String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    let raw_doc: YamlValue = serde_yaml_ng::from_str(&content)
        .map_err(|e| format!("Failed to parse YAML {}: {}", path.display(), e))?;

    let Some(raw_rules) = raw_doc.get("rules").and_then(YamlValue::as_sequence) else {
        return Ok((Vec::new(), Vec::new()));
    };

    let mut rules = Vec::new();
    let mut notices = Vec::new();
    for (index, raw_rule) in raw_rules.iter().enumerate() {
        if !is_codeql_rule(raw_rule) {
            continue;
        }

        let rule_position = index + 1;
        let raw_id = raw_rule
            .get("id")
            .and_then(YamlValue::as_str)
            .unwrap_or("<unknown>");
        let yaml: CodeQlRuleYaml = match serde_yaml_ng::from_value(raw_rule.clone()) {
            Ok(yaml) => yaml,
            Err(error) => {
                notices.push(format!(
                    "Warning: CodeQL rule '{}' in {} at rule {} skipped: {}",
                    raw_id,
                    path.display(),
                    rule_position,
                    error
                ));
                continue;
            }
        };

        let engine = yaml.engine.as_deref().unwrap_or_default();
        if !engine.eq_ignore_ascii_case("codeql") {
            continue;
        }

        let query = resolve_relative_path(path, &yaml.query);
        let database = yaml
            .database
            .as_deref()
            .and_then(resolve_database_value)
            .map(|database| resolve_relative_path(path, &database));
        let cwe = yaml
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.cwe.as_ref())
            .and_then(extract_cwe);

        rules.push(CodeQlRule {
            id: yaml.id,
            message: yaml.message,
            severity: yaml.severity.0,
            cwe,
            query,
            database,
        });
    }

    Ok((rules, notices))
}

pub fn scan_with_notices(rules: &[CodeQlRule], cli_database: Option<&Path>) -> CodeQlScanResult {
    scan_with_notices_for_target(rules, cli_database, None)
}

/// Run CodeQL rules against one explicitly supplied, prebuilt database.
///
/// Unlike the regular scan path, this never consults a rule-level database,
/// environment variable, or auto-build fallback. A configured diff must use
/// exactly the paired base/head databases supplied by the caller. Failure to
/// run every rule returns an error so callers cannot compare a partial result
/// set as though it were a clean delta.
pub fn scan_prebuilt_database(
    rules: &[CodeQlRule],
    database: &Path,
) -> Result<CodeQlDiffScanResult, String> {
    if rules.is_empty() {
        return Ok(CodeQlDiffScanResult {
            findings: Vec::new(),
            namespaces_by_rule: HashMap::new(),
            files_scanned: 0,
        });
    }

    probe_codeql().map_err(|error| {
        format!(
            "CodeQL diff skipped: {}; install CodeQL (`codeql`) to compare configured databases",
            error
        )
    })?;
    let source_roots = codeql_database_source_roots(database)?;

    let mut findings = Vec::new();
    let mut namespaces_by_rule = HashMap::new();
    for rule in rules {
        let sarif = run_codeql_database_analyze(database, &rule.query).map_err(|error| {
            format!(
                "CodeQL diff failed: rule '{}' against {}: {}",
                rule.id,
                database.display(),
                error
            )
        })?;
        let parsed = parse_sarif_diff_findings(rule, &sarif, &source_roots).map_err(|error| {
            format!(
                "CodeQL diff failed: rule '{}' against {} produced invalid SARIF: {}",
                rule.id,
                database.display(),
                error
            )
        })?;
        if !parsed.namespaces.is_empty() {
            namespaces_by_rule
                .entry(rule.id.clone())
                .or_insert_with(HashSet::new)
                .extend(parsed.namespaces);
        }
        findings.extend(parsed.findings);
    }

    findings.sort_by(|a, b| {
        a.finding
            .file
            .cmp(&b.finding.file)
            .then(a.finding.line.cmp(&b.finding.line))
            .then(a.finding.column.cmp(&b.finding.column))
            .then(a.finding.rule_id.cmp(&b.finding.rule_id))
    });

    Ok(CodeQlDiffScanResult {
        findings,
        namespaces_by_rule,
        files_scanned: 1,
    })
}

/// Compare paired CodeQL result sets using the normal diff comparator while
/// retaining SARIF-derived finding identities and display snippets.
pub fn diff_prebuilt_database_findings(
    current: CodeQlDiffScanResult,
    base: CodeQlDiffScanResult,
) -> Result<DiffResult, String> {
    validate_codeql_namespace_compatibility(&current.namespaces_by_rule, &base.namespaces_by_rule)?;
    let current = deduplicate_codeql_diff_findings(current.findings);
    let base = deduplicate_codeql_diff_findings(base.findings);
    let mut originals = HashMap::new();
    let current_for_comparison = current
        .into_iter()
        .map(|finding| {
            let key = codeql_diff_key(
                &finding.finding.rule_id,
                &finding.comparison_path,
                &finding.identity,
            );
            let mut comparison = finding.finding.clone();
            comparison.file = finding.comparison_path;
            comparison.snippet = finding.identity;
            originals.insert(key, finding.finding);
            comparison
        })
        .collect();
    let base_for_comparison = base
        .into_iter()
        .map(|finding| {
            let mut comparison = finding.finding;
            comparison.file = finding.comparison_path;
            comparison.snippet = finding.identity;
            comparison
        })
        .collect();
    let mut result = diff_findings(current_for_comparison, base_for_comparison);

    for finding in &mut result.new_findings {
        if let Some(original) = originals.remove(&codeql_diff_key(
            &finding.rule_id,
            &finding.file,
            &finding.snippet,
        )) {
            *finding = original;
        }
    }

    Ok(result)
}

fn validate_codeql_namespace_compatibility(
    current: &HashMap<String, HashSet<String>>,
    base: &HashMap<String, HashSet<String>>,
) -> Result<(), String> {
    if current == base {
        return Ok(());
    }
    Err(
        "paired CodeQL databases have incompatible multi-base uriBaseId namespaces; unable to map them safely"
            .to_string(),
    )
}

fn deduplicate_codeql_diff_findings(findings: Vec<CodeQlDiffFinding>) -> Vec<CodeQlDiffFinding> {
    let mut seen = HashSet::new();
    findings
        .into_iter()
        .filter(|finding| {
            seen.insert(codeql_diff_key(
                &finding.finding.rule_id,
                &finding.comparison_path,
                &finding.identity,
            ))
        })
        .collect()
}

fn codeql_diff_key(
    rule_id: &str,
    comparison_path: &str,
    identity: &str,
) -> (String, String, String) {
    (
        rule_id.to_string(),
        comparison_path.replace('\\', "/"),
        identity.to_string(),
    )
}

/// Run loaded CodeQL rules against the provided target.
///
/// Database selection order (per rule):
/// 1. The rule's explicit `database` field.
/// 2. `cli_database` (from `--codeql-db`).
/// 3. `FOXGUARD_CODEQL_DB` environment variable.
/// 4. If `codeql` is on PATH and `scan_target` is set, an ephemeral database
///    is created via `codeql database create --language=<lang> --source-root=
///    <scan_target>` and reused for every rule that needs the same language.
///    Temp DBs auto-clean when the function returns.
///
/// If `codeql` is absent, all CodeQL rules are skipped with a single notice
/// — the rest of the scan continues.
pub fn scan_with_notices_for_target(
    rules: &[CodeQlRule],
    cli_database: Option<&Path>,
    scan_target: Option<&Path>,
) -> CodeQlScanResult {
    let candidate_rules = rules.len();
    if rules.is_empty() {
        return CodeQlScanResult {
            findings: Vec::new(),
            files_scanned: 0,
            candidate_rules,
            notices: Vec::new(),
        };
    }

    let mut findings = Vec::new();
    let mut notices = Vec::new();

    // Resolve a database for every rule, falling back to an auto-built DB
    // when neither rule-level, CLI, nor env values are available. We probe
    // for `codeql` lazily to avoid forking when no auto-DB would be built.
    let codeql_available = probe_codeql();
    let auto_db_allowed = scan_target.is_some() && codeql_available.is_ok();
    let mut auto_databases: HashMap<String, TempDir> = HashMap::new();
    let mut runnable_rules: Vec<(&CodeQlRule, PathBuf)> = Vec::new();

    for rule in rules {
        if let Some(database) = explicit_rule_database(rule, cli_database) {
            runnable_rules.push((rule, database));
            continue;
        }

        if !auto_db_allowed {
            // Preserve the original notice when we can't auto-build a DB so
            // existing users with no scan-target plumbing still see a clear
            // pointer at --codeql-db / FOXGUARD_CODEQL_DB.
            notices.push(format!(
                "Warning: CodeQL rule '{}' skipped: no database configured; set rule database, --codeql-db, or FOXGUARD_CODEQL_DB",
                rule.id
            ));
            continue;
        }

        let scan_target = scan_target.expect("checked by auto_db_allowed");
        let language = match infer_query_language(rule, scan_target) {
            Some(language) => language,
            None => {
                notices.push(format!(
                    "Warning: CodeQL rule '{}' skipped: could not infer query language; add an `import <lang>` line to {} or set --codeql-db",
                    rule.id,
                    rule.query.display()
                ));
                continue;
            }
        };

        // Build at most one DB per language, reused across rules.
        if !auto_databases.contains_key(&language) {
            match build_auto_database(scan_target, &language) {
                Ok(tempdir) => {
                    auto_databases.insert(language.clone(), tempdir);
                }
                Err(error) => {
                    notices.push(format!(
                        "Warning: CodeQL rule '{}' skipped: failed to auto-build {} database for {}: {}",
                        rule.id,
                        language,
                        scan_target.display(),
                        error
                    ));
                    continue;
                }
            }
        }

        let database = auto_databases
            .get(&language)
            .expect("just inserted")
            .path()
            .join("db");
        runnable_rules.push((rule, database));
    }

    if runnable_rules.is_empty() {
        return CodeQlScanResult {
            findings,
            files_scanned: 0,
            candidate_rules,
            notices,
        };
    }

    if let Err(error) = codeql_available {
        // Some rules had explicit databases but codeql itself is missing —
        // we still skip them with a clear message instead of silently
        // pretending success.
        return CodeQlScanResult {
            findings: Vec::new(),
            files_scanned: 0,
            candidate_rules,
            notices: vec![format!(
                "Warning: CodeQL engine skipped: {}; install CodeQL (`codeql`) to run engine: codeql rules",
                error
            )],
        };
    }

    let mut scanned_databases = HashSet::new();
    for (rule, database) in runnable_rules {
        match run_codeql_database_analyze(database.as_path(), &rule.query) {
            Ok(sarif) => {
                scanned_databases.insert(database);
                findings.extend(parse_sarif_findings(rule, &sarif));
            }
            Err(error) => notices.push(format!(
                "Warning: CodeQL rule '{}' failed: {}",
                rule.id, error
            )),
        }
    }

    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
            .then(a.rule_id.cmp(&b.rule_id))
    });

    let result = CodeQlScanResult {
        findings,
        files_scanned: scanned_databases.len(),
        candidate_rules,
        notices,
    };
    // `auto_databases` drops here, cleaning up the temp DBs we built.
    drop(auto_databases);
    result
}

fn run_codeql_database_analyze(database: &Path, query: &Path) -> Result<String, String> {
    use crate::engine::process::{wait_with_output_timeout, TimedOutput};

    let output = tempfile::NamedTempFile::new()
        .map_err(|e| format!("failed to create temporary SARIF output: {}", e))?;
    let output_path = output.path().to_path_buf();
    drop(output);
    let mut output_arg = OsString::from("--output=");
    output_arg.push(output_path.as_os_str());

    let timeout = codeql_timeout();
    let child = Command::new("codeql")
        .arg("database")
        .arg("analyze")
        .arg(database)
        .arg(query)
        .arg("--format=sarif-latest")
        .arg(output_arg)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to run codeql: {}", e))?;

    let result = wait_with_output_timeout(child, timeout)
        .map_err(|e| format!("failed to wait for codeql: {}", e))?;

    match result {
        TimedOutput::TimedOut { .. } => {
            Err(format!("codeql timed out after {}s", timeout.as_secs()))
        }
        TimedOutput::Finished(ref output) if !output.status.success() => {
            let message = process_message(&output.stdout, &output.stderr);
            if message.is_empty() {
                Err("codeql exited without output".to_string())
            } else {
                Err(message)
            }
        }
        TimedOutput::Finished(_) => std::fs::read_to_string(&output_path).map_err(|e| {
            format!(
                "failed to read CodeQL SARIF output {}: {}",
                output_path.display(),
                e
            )
        }),
    }
}

fn parse_sarif_findings(rule: &CodeQlRule, sarif: &str) -> Vec<Finding> {
    let Ok(root) = serde_json::from_str::<JsonValue>(sarif) else {
        return Vec::new();
    };

    root.get("runs")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .flat_map(|run| {
            run.get("results")
                .and_then(JsonValue::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|result| {
            normalized_finding_from_sarif_result(
                rule,
                result,
                CodeQlSnippetSource::LiveCheckout,
                None,
            )
            .ok()
            .flatten()
        })
        .map(|finding| finding.finding)
        .collect()
}

fn parse_sarif_diff_findings(
    rule: &CodeQlRule,
    sarif: &str,
    source_roots: &[PathBuf],
) -> Result<ParsedCodeQlDiffFindings, String> {
    const SUPPORTED_SARIF_VERSION: &str = "2.1.0";

    let root: JsonValue =
        serde_json::from_str(sarif).map_err(|error| format!("invalid JSON: {error}"))?;
    let version = root
        .get("version")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| "missing SARIF version".to_string())?;
    if version != SUPPORTED_SARIF_VERSION {
        return Err(format!(
            "unsupported SARIF version '{version}'; expected {SUPPORTED_SARIF_VERSION}"
        ));
    }
    let runs = root
        .get("runs")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| "missing SARIF runs array".to_string())?;
    if runs.is_empty() {
        return Err("SARIF runs array is empty".to_string());
    }

    let mut findings = Vec::new();
    let mut namespaces = HashSet::new();
    for (run_index, run) in runs.iter().enumerate() {
        let results = sarif_run_results(run, run_index + 1)?;
        let resolver = CodeQlSarifPathResolver::from_run(run, source_roots)
            .map_err(|error| format!("SARIF run {}: {error}", run_index + 1))?;
        namespaces.extend(resolver.comparison_namespaces().iter().cloned());
        for (result_index, result) in results.iter().enumerate() {
            let finding = normalized_finding_from_sarif_result(
                rule,
                result,
                CodeQlSnippetSource::Sarif,
                Some(&resolver),
            )
            .map_err(|error| {
                format!(
                    "SARIF result {} in run {} has an unsafe artifact path: {error}",
                    result_index + 1,
                    run_index + 1
                )
            })?
            .ok_or_else(|| {
                format!(
                    "SARIF result {} in run {} lacks a physical location",
                    result_index + 1,
                    run_index + 1
                )
            })?;
            findings.push(finding);
        }
    }

    Ok(ParsedCodeQlDiffFindings {
        findings: assign_fallback_occurrences(findings),
        namespaces,
    })
}

fn sarif_run_results(run: &JsonValue, run_index: usize) -> Result<&Vec<JsonValue>, String> {
    let tool = run
        .get("tool")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| format!("SARIF run {run_index} lacks a tool object"))?;
    let driver = tool
        .get("driver")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| format!("SARIF run {run_index} lacks a tool driver object"))?;
    if driver
        .get("name")
        .and_then(JsonValue::as_str)
        .is_none_or(|name| name.trim().is_empty())
    {
        return Err(format!("SARIF run {run_index} has a driver without a name"));
    }

    run.get("results")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| format!("SARIF run {run_index} has a missing or non-array results field"))
}

#[derive(Clone, Copy)]
enum CodeQlSnippetSource {
    LiveCheckout,
    Sarif,
}

fn normalized_finding_from_sarif_result(
    rule: &CodeQlRule,
    result: &JsonValue,
    snippet_source: CodeQlSnippetSource,
    path_resolver: Option<&CodeQlSarifPathResolver>,
) -> Result<Option<CodeQlDiffFinding>, String> {
    let Some(physical) = result
        .get("locations")
        .and_then(JsonValue::as_array)
        .and_then(|locations| locations.first())
        .and_then(|location| location.get("physicalLocation"))
    else {
        return Ok(None);
    };
    let Some(artifact_location) = physical.get("artifactLocation") else {
        return Ok(None);
    };
    let Some(uri) = artifact_location.get("uri").and_then(JsonValue::as_str) else {
        return Ok(None);
    };
    let CodeQlArtifactPath {
        display_path: file,
        comparison_path,
    } = match path_resolver {
        Some(resolver) => resolver.normalize_artifact_location(artifact_location)?,
        None => {
            let file = normalize_sarif_uri(uri);
            CodeQlArtifactPath {
                comparison_path: single_root_comparison_path(&file),
                display_path: file,
            }
        }
    };
    let region = physical.get("region");
    let line = region
        .and_then(|region| region.get("startLine"))
        .and_then(JsonValue::as_u64)
        .unwrap_or(1) as usize;
    let column = region
        .and_then(|region| region.get("startColumn"))
        .and_then(JsonValue::as_u64)
        .unwrap_or(1) as usize;
    let end_line = region
        .and_then(|region| region.get("endLine"))
        .and_then(JsonValue::as_u64)
        .unwrap_or(line as u64) as usize;
    let message = result
        .get("message")
        .and_then(|message| message.get("text"))
        .and_then(JsonValue::as_str)
        .filter(|message| !message.trim().is_empty())
        .unwrap_or(&rule.message);
    let sarif_snippet = region
        .and_then(|region| region.get("snippet"))
        .and_then(|snippet| snippet.get("text"))
        .and_then(JsonValue::as_str)
        .filter(|snippet| !snippet.trim().is_empty())
        .map(str::to_string);
    let snippet = match snippet_source {
        CodeQlSnippetSource::LiveCheckout => snippet_for_path(&file, line),
        CodeQlSnippetSource::Sarif => sarif_snippet.clone().unwrap_or_default(),
    };
    let end_column = region
        .and_then(|region| region.get("endColumn"))
        .and_then(JsonValue::as_u64)
        .map(|column| column as usize)
        .unwrap_or_else(|| column + snippet.chars().count().max(1));
    let (identity, has_fingerprint) = sarif_finding_identity(
        result,
        sarif_snippet.as_deref(),
        message,
        line,
        column,
        end_line,
        end_column,
    );

    Ok(Some(CodeQlDiffFinding {
        finding: Finding {
            rule_id: rule.id.clone(),
            severity: rule.severity,
            cwe: rule.cwe.clone(),
            description: message.to_string(),
            file,
            line,
            column,
            end_line,
            end_column,
            snippet,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: 0.8,
            taint_hops: None,
            tags: vec!["codeql".to_string()],
            crypto_algorithm: None,
            cnsa2_deadline: None,
            dep_name: None,
            dep_version: None,
            dep_ecosystem: None,
            dep_purl: None,
            dep_vulnerability_id: None,
            dep_fixed_version: None,
            dep_source: None,
            dep_vulnerability_severity: None,
            dep_path: vec![],
            crypto_material: None,
        },
        comparison_path,
        identity,
        has_fingerprint,
    }))
}

struct CodeQlSarifPathResolver {
    uri_bases: HashMap<String, PathBuf>,
    source_roots: Vec<PathBuf>,
    comparison_namespaces: HashSet<String>,
}

impl CodeQlSarifPathResolver {
    fn from_run(run: &JsonValue, source_roots: &[PathBuf]) -> Result<Self, String> {
        let mut uri_bases = HashMap::new();
        if let Some(original_uri_base_ids) = run.get("originalUriBaseIds") {
            let original_uri_base_ids = original_uri_base_ids
                .as_object()
                .ok_or_else(|| "originalUriBaseIds must be an object".to_string())?;
            for (id, location) in original_uri_base_ids {
                let uri = location
                    .get("uri")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| format!("originalUriBaseIds.{id} lacks a URI"))?;
                let (path, is_absolute) = sarif_uri_path(uri)?;
                if !is_absolute {
                    return Err(format!(
                        "originalUriBaseIds.{id} is not an absolute file URI"
                    ));
                }
                uri_bases.insert(id.clone(), normalize_absolute_path(&path)?);
            }
        }

        let mut source_roots = source_roots
            .iter()
            .map(|root| normalize_absolute_path(root))
            .collect::<Result<Vec<_>, _>>()?;
        source_roots.sort();
        source_roots.dedup();
        let comparison_namespaces = if uri_bases.values().cloned().collect::<HashSet<_>>().len() > 1
        {
            uri_bases.keys().cloned().collect()
        } else {
            HashSet::new()
        };
        Ok(Self {
            uri_bases,
            source_roots,
            comparison_namespaces,
        })
    }

    fn comparison_namespaces(&self) -> &HashSet<String> {
        &self.comparison_namespaces
    }

    fn normalize_artifact_location(
        &self,
        artifact_location: &JsonValue,
    ) -> Result<CodeQlArtifactPath, String> {
        let uri = artifact_location
            .get("uri")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| "artifact location lacks a URI".to_string())?;
        let (path, is_absolute) = sarif_uri_path(uri)?;

        match artifact_location.get("uriBaseId") {
            Some(JsonValue::String(uri_base_id)) => {
                let root = self.uri_bases.get(uri_base_id).ok_or_else(|| {
                    format!("artifact references unknown uriBaseId '{uri_base_id}'")
                })?;
                let display_path = if is_absolute {
                    stable_path_under_root(&path, root)?
                } else {
                    stable_relative_path(&path)?
                };
                let comparison_path = if self.comparison_namespaces.contains(uri_base_id) {
                    uri_base_comparison_path(uri_base_id, &display_path)
                } else {
                    single_root_comparison_path(&display_path)
                };
                Ok(CodeQlArtifactPath {
                    comparison_path,
                    display_path,
                })
            }
            Some(_) => Err("artifact uriBaseId must be a string".to_string()),
            None => {
                if self.source_roots.len() > 1 {
                    return Err(
                        "artifact path has multiple CodeQL source roots without a uriBaseId"
                            .to_string(),
                    );
                }
                let display_path = if is_absolute {
                    stable_path_under_source_root(&path, &self.source_roots)?
                } else {
                    stable_relative_path(&path)?
                };
                Ok(CodeQlArtifactPath {
                    comparison_path: single_root_comparison_path(&display_path),
                    display_path,
                })
            }
        }
    }
}

fn uri_base_comparison_path(uri_base_id: &str, display_path: &str) -> String {
    let mut namespace = String::with_capacity(uri_base_id.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in uri_base_id.bytes() {
        namespace.push(HEX[(byte >> 4) as usize] as char);
        namespace.push(HEX[(byte & 0x0f) as usize] as char);
    }
    format!("codeql-uri-base/{namespace}/{display_path}")
}

fn single_root_comparison_path(display_path: &str) -> String {
    format!("codeql-single-root/{display_path}")
}

fn codeql_database_source_roots(database: &Path) -> Result<Vec<PathBuf>, String> {
    let metadata_path = database.join("codeql-database.yml");
    if !metadata_path.exists() {
        return Ok(Vec::new());
    }
    if !metadata_path.is_file() {
        return Err(format!(
            "CodeQL database metadata {} is not a file",
            metadata_path.display()
        ));
    }

    let content = std::fs::read_to_string(&metadata_path).map_err(|error| {
        format!(
            "failed to read CodeQL database metadata {}: {error}",
            metadata_path.display()
        )
    })?;
    let metadata: YamlValue = serde_yaml_ng::from_str(&content).map_err(|error| {
        format!(
            "failed to parse CodeQL database metadata {}: {error}",
            metadata_path.display()
        )
    })?;

    let mut source_roots = Vec::new();
    for key in [
        "sourceLocationPrefix",
        "sourceLocationPrefixes",
        "sourceRoot",
    ] {
        let Some(value) = metadata.get(key) else {
            continue;
        };
        if let Some(value) = value.as_str() {
            add_codeql_source_root(&mut source_roots, key, value)?;
        } else if let Some(values) = value.as_sequence() {
            for value in values {
                let value = value.as_str().ok_or_else(|| {
                    format!(
                        "CodeQL database metadata {} has a non-string {key} entry",
                        metadata_path.display()
                    )
                })?;
                add_codeql_source_root(&mut source_roots, key, value)?;
            }
        } else if !matches!(value, YamlValue::Null) {
            return Err(format!(
                "CodeQL database metadata {} has an invalid {key} value",
                metadata_path.display()
            ));
        }
    }
    source_roots.sort();
    source_roots.dedup();
    Ok(source_roots)
}

fn add_codeql_source_root(
    source_roots: &mut Vec<PathBuf>,
    key: &str,
    value: &str,
) -> Result<(), String> {
    let (path, is_absolute) =
        sarif_uri_path(value).map_err(|error| format!("invalid {key} value '{value}': {error}"))?;
    if !is_absolute {
        return Err(format!("{key} value '{value}' is not an absolute path"));
    }
    source_roots.push(normalize_absolute_path(&path)?);
    Ok(())
}

fn sarif_uri_path(uri: &str) -> Result<(PathBuf, bool), String> {
    let decoded = decode_sarif_uri(uri)?;
    let path = if let Some(uri) = decoded.strip_prefix("file://") {
        if uri.starts_with('/') {
            uri.to_string()
        } else if let Some(uri) = uri.strip_prefix("localhost/") {
            format!("/{uri}")
        } else {
            return Err(format!("unsupported non-local file URI '{uri}'"));
        }
    } else {
        if decoded.contains("://") {
            return Err(format!("unsupported artifact URI '{uri}'"));
        }
        decoded
    };

    if looks_like_windows_absolute_path(&path) {
        return Err(format!(
            "cannot safely normalize Windows artifact path '{path}' on this platform"
        ));
    }
    let path = PathBuf::from(path);
    Ok((path.clone(), path.is_absolute()))
}

fn decode_sarif_uri(uri: &str) -> Result<String, String> {
    let bytes = uri.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(format!("invalid percent escape in URI '{uri}'"));
        }
        let high = decode_hex(bytes[index + 1])
            .ok_or_else(|| format!("invalid percent escape in URI '{uri}'"))?;
        let low = decode_hex(bytes[index + 2])
            .ok_or_else(|| format!("invalid percent escape in URI '{uri}'"))?;
        decoded.push(high << 4 | low);
        index += 3;
    }
    String::from_utf8(decoded).map_err(|_| format!("URI '{uri}' is not valid UTF-8"))
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn looks_like_windows_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

fn normalize_absolute_path(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("path {} is not absolute", path.display()));
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(format!("path {} escapes its root", path.display()));
                }
            }
            Component::Normal(component) => normalized.push(component),
        }
    }
    Ok(normalized)
}

fn stable_path_under_source_root(path: &Path, source_roots: &[PathBuf]) -> Result<String, String> {
    let path = normalize_absolute_path(path)?;
    let mut matching_roots = Vec::new();
    for root in source_roots {
        let root = normalize_absolute_path(root)?;
        if path.strip_prefix(&root).is_ok() {
            matching_roots.push(root);
        }
    }
    matching_roots.sort();
    matching_roots.dedup();
    let Some(longest_root) = matching_roots
        .iter()
        .max_by_key(|root| root.components().count())
    else {
        return Err(format!(
            "absolute artifact path {} has no matching CodeQL source root",
            path.display()
        ));
    };
    let longest_count = longest_root.components().count();
    if matching_roots
        .iter()
        .filter(|root| root.components().count() == longest_count)
        .count()
        != 1
    {
        return Err(format!(
            "absolute artifact path {} has ambiguous CodeQL source roots",
            path.display()
        ));
    }
    stable_path_under_root(&path, longest_root)
}

fn stable_path_under_root(path: &Path, root: &Path) -> Result<String, String> {
    let path = normalize_absolute_path(path)?;
    let root = normalize_absolute_path(root)?;
    let relative = path.strip_prefix(&root).map_err(|_| {
        format!(
            "artifact path {} is outside {}",
            path.display(),
            root.display()
        )
    })?;
    stable_relative_path(relative)
}

fn stable_relative_path(path: &Path) -> Result<String, String> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => {
                components.push(component.to_string_lossy().into_owned())
            }
            Component::ParentDir => {
                if components.pop().is_none() {
                    return Err(format!(
                        "relative artifact path {} escapes its root",
                        path.display()
                    ));
                }
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(format!(
                    "artifact path {} is not repository-relative",
                    path.display()
                ))
            }
        }
    }
    if components.is_empty() {
        return Err("artifact path does not identify a source file".to_string());
    }
    Ok(components.join("/"))
}

fn sarif_finding_identity(
    result: &JsonValue,
    snippet: Option<&str>,
    message: &str,
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
) -> (String, bool) {
    if let Some(fingerprint) = sarif_fingerprint(result) {
        return (format!("fingerprint:{fingerprint}"), true);
    }
    if let Some(snippet) = snippet {
        return (format!("snippet:{}", snippet.trim()), false);
    }
    (
        format!(
            "location:{line}:{column}:{end_line}:{end_column}:{}",
            message.trim()
        ),
        false,
    )
}

fn sarif_fingerprint(result: &JsonValue) -> Option<String> {
    for field in ["partialFingerprints", "fingerprints"] {
        let Some(fingerprints) = result.get(field).and_then(JsonValue::as_object) else {
            continue;
        };
        for name in [
            "primaryLocationLineHash",
            "primaryLocationStartColumnFingerprint",
            "primaryLocationEndColumnFingerprint",
        ] {
            if let Some(value) = fingerprints.get(name).and_then(JsonValue::as_str) {
                return Some(format!("{field}:{name}:{value}"));
            }
        }
        let mut values: Vec<_> = fingerprints
            .iter()
            .filter_map(|(name, value)| value.as_str().map(|value| (name, value)))
            .collect();
        values.sort_unstable_by_key(|(name, _)| *name);
        if let Some((name, value)) = values.into_iter().next() {
            return Some(format!("{field}:{name}:{value}"));
        }
    }
    None
}

fn assign_fallback_occurrences(mut findings: Vec<CodeQlDiffFinding>) -> Vec<CodeQlDiffFinding> {
    let mut occurrences = HashMap::new();
    for finding in &mut findings {
        if finding.has_fingerprint {
            continue;
        }
        let key = codeql_diff_key(
            &finding.finding.rule_id,
            &finding.comparison_path,
            &finding.identity,
        );
        let occurrence = occurrences.entry(key).or_insert(0usize);
        *occurrence += 1;
        finding.identity = format!("{}#{occurrence}", finding.identity);
    }
    findings
}

/// Resolve a pre-existing database for the rule — rule-level field, then
/// `--codeql-db`, then `FOXGUARD_CODEQL_DB`. Returns `None` when none of those
/// are set; callers may then decide whether to auto-build one.
fn explicit_rule_database(rule: &CodeQlRule, cli_database: Option<&Path>) -> Option<PathBuf> {
    rule.database
        .clone()
        .or_else(|| cli_database.map(Path::to_path_buf))
        .or_else(|| std::env::var("FOXGUARD_CODEQL_DB").ok().map(PathBuf::from))
}

/// Best-effort detection of the CodeQL language family a query targets.
///
/// Priority:
/// 1. Top-level `import <lang>` in the `.ql` file (handles `cpp`, `python`,
///    `javascript`, `java`, `go`, `csharp`, `ruby`, `swift`).
/// 2. Source-root fallback: pick the language family with the most matching
///    files in `scan_target`. Used when the query imports a library qlpack
///    that doesn't start with the language name.
fn infer_query_language(rule: &CodeQlRule, scan_target: &Path) -> Option<String> {
    if let Some(language) = language_from_query_imports(&rule.query) {
        return Some(language);
    }
    language_from_source_root(scan_target)
}

fn language_from_query_imports(query: &Path) -> Option<String> {
    let content = std::fs::read_to_string(query).ok()?;
    for raw in content.lines() {
        let line = raw.trim();
        let Some(rest) = line.strip_prefix("import ") else {
            continue;
        };
        let token = rest
            .split(|c: char| c.is_whitespace() || c == '/' || c == '.' || c == ';')
            .next()
            .unwrap_or("")
            .trim();
        let language = match token {
            "cpp" => "cpp",
            "python" => "python",
            "javascript" => "javascript",
            "java" => "java",
            "go" => "go",
            "csharp" => "csharp",
            "ruby" => "ruby",
            "swift" => "swift",
            _ => continue,
        };
        return Some(language.to_string());
    }
    None
}

fn language_from_source_root(scan_target: &Path) -> Option<String> {
    let mut counts: HashMap<&'static str, usize> = HashMap::new();
    let walker = walkdir::WalkDir::new(scan_target)
        .max_depth(6)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file());
    for entry in walker {
        let ext = match entry.path().extension().and_then(|e| e.to_str()) {
            Some(ext) => ext.to_ascii_lowercase(),
            None => continue,
        };
        let language = match ext.as_str() {
            "c" | "cc" | "cpp" | "cxx" | "h" | "hpp" => "cpp",
            "py" => "python",
            "js" | "jsx" | "ts" | "tsx" => "javascript",
            "java" => "java",
            "go" => "go",
            "cs" => "csharp",
            "rb" => "ruby",
            "swift" => "swift",
            _ => continue,
        };
        *counts.entry(language).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(language, _)| language.to_string())
}

/// Drive `codeql database create` against the scan target, returning a
/// `TempDir` whose `path().join("db")` is the resulting database. Dropping
/// the returned handle removes the temp tree.
fn build_auto_database(scan_target: &Path, language: &str) -> Result<TempDir, String> {
    use crate::engine::process::{wait_with_output_timeout, TimedOutput};

    let parent = TempDir::new().map_err(|e| format!("failed to create codeql temp dir: {}", e))?;
    let db_path = parent.path().join("db");
    let mut language_arg = OsString::from("--language=");
    language_arg.push(language);
    let mut source_arg = OsString::from("--source-root=");
    source_arg.push(scan_target.as_os_str());

    let timeout = codeql_create_timeout();
    let child = Command::new("codeql")
        .arg("database")
        .arg("create")
        .arg(&db_path)
        .arg(language_arg)
        .arg(source_arg)
        .arg("--overwrite")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn codeql: {}", e))?;

    let result = wait_with_output_timeout(child, timeout)
        .map_err(|e| format!("failed to wait for codeql: {}", e))?;

    match result {
        TimedOutput::TimedOut { .. } => Err(format!(
            "codeql database create timed out after {}s",
            timeout.as_secs()
        )),
        TimedOutput::Finished(ref output) if !output.status.success() => {
            let message = process_message(&output.stdout, &output.stderr);
            if message.is_empty() {
                Err("codeql database create exited without output".to_string())
            } else {
                Err(message)
            }
        }
        TimedOutput::Finished(_) => Ok(parent),
    }
}

fn codeql_create_timeout() -> Duration {
    let secs = std::env::var("FOXGUARD_CODEQL_CREATE_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(900);
    Duration::from_secs(secs)
}

fn resolve_database_value(value: &str) -> Option<String> {
    if value == "${FOXGUARD_CODEQL_DB}" {
        std::env::var("FOXGUARD_CODEQL_DB").ok()
    } else {
        Some(value.to_string())
    }
}

fn resolve_relative_path(rule_file: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        rule_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(path)
    }
}

fn extract_cwe(cwe: &CweValue) -> Option<String> {
    match cwe {
        CweValue::Single(cwe) => Some(cwe.clone()),
        CweValue::List(cwes) => cwes.first().cloned(),
    }
}

fn probe_codeql() -> Result<(), String> {
    match Command::new("codeql").arg("--version").output() {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let message = stderr.trim();
            if message.is_empty() {
                Err("codeql --version failed".to_string())
            } else {
                Err(message.to_string())
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err("codeql not found on PATH".to_string())
        }
        Err(e) => Err(format!("failed to run codeql --version: {}", e)),
    }
}

fn codeql_timeout() -> Duration {
    let secs = std::env::var("FOXGUARD_CODEQL_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(300);
    Duration::from_secs(secs)
}

fn process_message(stdout: &[u8], stderr: &[u8]) -> String {
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else if stdout.trim().is_empty() {
        stderr.trim().to_string()
    } else {
        format!("{}\n{}", stdout.trim(), stderr.trim())
    }
}

fn normalize_sarif_uri(uri: &str) -> String {
    uri.strip_prefix("file://")
        .unwrap_or(uri)
        .replace("%20", " ")
}

fn snippet_for_path(path: &str, line: usize) -> String {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|source| {
            source
                .lines()
                .nth(line.saturating_sub(1))
                .map(str::to_string)
        })
        .unwrap_or_default()
}

fn is_codeql_rule(raw_rule: &YamlValue) -> bool {
    raw_rule
        .get("engine")
        .and_then(YamlValue::as_str)
        .is_some_and(|engine| engine.eq_ignore_ascii_case("codeql"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn sample_rule() -> CodeQlRule {
        CodeQlRule {
            id: "kernel/codeql-test".to_string(),
            message: "query matched".to_string(),
            severity: Severity::High,
            cwe: Some("CWE-362".to_string()),
            query: PathBuf::from("query.ql"),
            database: None,
        }
    }

    #[test]
    fn parses_codeql_yaml_rule() {
        let mut file = match NamedTempFile::new() {
            Ok(file) => file,
            Err(error) => panic!("failed to create temp file: {error}"),
        };
        if let Err(error) = file.write_all(
            br#"
rules:
  - id: kernel/codeql-test
    engine: codeql
    severity: WARNING
    message: query matched
    metadata:
      cwe: [CWE-362]
    query: queries/test.ql
"#,
        ) {
            panic!("failed to write temp rule file: {error}");
        }

        let parsed = parse_codeql_file(file.path());
        let (rules, notices) = match parsed {
            Ok(parsed) => parsed,
            Err(error) => panic!("failed to parse CodeQL rule: {error}"),
        };

        assert!(notices.is_empty());
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "kernel/codeql-test");
        assert_eq!(rules[0].severity, Severity::High);
        assert_eq!(rules[0].cwe.as_deref(), Some("CWE-362"));
        assert!(rules[0].query.ends_with("queries/test.ql"));
    }

    #[test]
    fn skips_malformed_codeql_rule_with_notice() {
        let mut file = match NamedTempFile::new() {
            Ok(file) => file,
            Err(error) => panic!("failed to create temp file: {error}"),
        };
        if let Err(error) = file.write_all(
            br#"
rules:
  - id: kernel/good-codeql
    engine: codeql
    severity: high
    message: good
    query: good.ql
  - id: kernel/bad-codeql
    engine: codeql
    severity: nope
    message: bad
    query: bad.ql
"#,
        ) {
            panic!("failed to write temp rule file: {error}");
        }

        let parsed = parse_codeql_file(file.path());
        let (rules, notices) = match parsed {
            Ok(parsed) => parsed,
            Err(error) => panic!("failed to parse CodeQL rule file: {error}"),
        };

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "kernel/good-codeql");
        assert_eq!(notices.len(), 1);
        assert!(notices[0].contains("kernel/bad-codeql"));
        assert!(notices[0].contains("rule 2"));
    }

    #[test]
    fn strict_diff_loader_rejects_missing_rule_path() {
        let directory = TempDir::new().expect("tempdir");
        let missing = directory.path().join("missing-rules");

        let error = load_codeql_rules_for_diff(&missing).expect_err("missing path must fail");

        assert!(error.contains("does not exist"), "{error}");
    }

    #[test]
    fn missing_database_emits_notice_without_findings() {
        let result = scan_with_notices(&[sample_rule()], None);

        assert!(result.findings.is_empty());
        assert_eq!(result.candidate_rules, 1);
        assert_eq!(result.notices.len(), 1);
        assert!(result.notices[0].contains("no database configured"));
    }

    #[test]
    fn auto_db_skipped_cleanly_when_codeql_absent() {
        // Force PATH to a directory that definitely does not contain a
        // `codeql` binary, then exercise the auto-DB path. We expect the
        // legacy "no database configured" notice (same as missing-target),
        // not a crash.
        let empty_path = TempDir::new().expect("tempdir for empty PATH");
        let scan_target = TempDir::new().expect("tempdir for scan target");

        let prev_path = std::env::var_os("PATH");
        // Safety: the test process is single-threaded for env mutation; we
        // restore the original PATH before returning. If a future test
        // parallelism change makes this flaky, move to a serial-test crate.
        std::env::set_var("PATH", empty_path.path());
        let prev_db = std::env::var_os("FOXGUARD_CODEQL_DB");
        std::env::remove_var("FOXGUARD_CODEQL_DB");

        let result = scan_with_notices_for_target(&[sample_rule()], None, Some(scan_target.path()));

        // Restore env before asserting so a failure doesn't poison sibling
        // tests.
        match prev_path {
            Some(value) => std::env::set_var("PATH", value),
            None => std::env::remove_var("PATH"),
        }
        if let Some(value) = prev_db {
            std::env::set_var("FOXGUARD_CODEQL_DB", value);
        }

        assert!(result.findings.is_empty());
        assert_eq!(result.candidate_rules, 1);
        assert_eq!(result.notices.len(), 1);
        // When codeql is absent we fall back to the legacy "configure a DB"
        // notice — auto-build isn't possible, so the user is pointed at the
        // explicit-DB flags.
        assert!(
            result.notices[0].contains("no database configured"),
            "expected legacy notice, got: {}",
            result.notices[0]
        );
    }

    #[test]
    fn infers_cpp_from_query_import() {
        let mut file = NamedTempFile::new().expect("temp .ql");
        file.write_all(
            br#"/**
 * @id cpp/foo
 */
import cpp

from Function f
select f
"#,
        )
        .unwrap();
        let language = language_from_query_imports(file.path());
        assert_eq!(language.as_deref(), Some("cpp"));
    }

    #[test]
    fn infers_python_from_query_import() {
        let mut file = NamedTempFile::new().expect("temp .ql");
        file.write_all(b"import python\nfrom Foo f select f\n")
            .unwrap();
        let language = language_from_query_imports(file.path());
        assert_eq!(language.as_deref(), Some("python"));
    }

    #[test]
    fn infers_cpp_from_source_root_extensions() {
        let dir = TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join("a.c"), "int main(){}\n").unwrap();
        std::fs::write(dir.path().join("b.h"), "#define X 1\n").unwrap();
        std::fs::write(dir.path().join("readme.md"), "ignored").unwrap();
        let language = language_from_source_root(dir.path());
        assert_eq!(language.as_deref(), Some("cpp"));
    }

    /// End-to-end auto-DB run. Requires `codeql` on PATH plus the
    /// `codeql/cpp-all` library pack installed; CI runners don't have these
    /// so it stays `#[ignore]`'d. Run locally with:
    ///   cargo test --test-threads=1 -- --ignored codeql_auto_database_runs_end_to_end
    #[test]
    #[ignore = "requires codeql CLI and cpp-all qlpack on host"]
    fn codeql_auto_database_runs_end_to_end() {
        if probe_codeql().is_err() {
            eprintln!("codeql not on PATH — nothing to verify");
            return;
        }
        let source = TempDir::new().expect("source tempdir");
        std::fs::write(
            source.path().join("main.c"),
            "int main(void) { return 0; }\n",
        )
        .unwrap();

        let query_dir = TempDir::new().expect("query tempdir");
        let query_path = query_dir.path().join("trivial.ql");
        std::fs::write(
            &query_path,
            r#"/**
 * @name Trivial
 * @id cpp/trivial
 * @kind problem
 * @problem.severity warning
 */
import cpp

from Function f
where f.hasName("main")
select f, "found main"
"#,
        )
        .unwrap();

        let rule = CodeQlRule {
            id: "test/trivial".to_string(),
            message: "trivial".to_string(),
            severity: Severity::Medium,
            cwe: None,
            query: query_path,
            database: None,
        };

        let result = scan_with_notices_for_target(&[rule], None, Some(source.path()));
        assert!(
            !result.findings.is_empty() || result.notices.is_empty(),
            "expected findings or zero notices, got notices: {:?}",
            result.notices
        );
    }

    #[test]
    fn parses_sarif_result_into_finding() {
        let sarif = r#"
{
  "version": "2.1.0",
  "runs": [
    {
      "results": [
        {
          "ruleId": "external/id",
          "message": { "text": "CodeQL found this" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/file%20name.c" },
                "region": { "startLine": 7, "startColumn": 3, "endLine": 7, "endColumn": 11 }
              }
            }
          ]
        }
      ]
    }
  ]
}
"#;

        let findings = parse_sarif_findings(&sample_rule(), sarif);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "kernel/codeql-test");
        assert_eq!(findings[0].file, "src/file name.c");
        assert_eq!(findings[0].line, 7);
        assert_eq!(findings[0].column, 3);
        assert_eq!(findings[0].end_column, 11);
        assert_eq!(findings[0].description, "CodeQL found this");
        assert_eq!(findings[0].tags, vec!["codeql".to_string()]);
    }

    #[test]
    fn paired_sarif_resolves_uri_base_id_to_repo_relative_path() {
        let sarif = r#"
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "CodeQL" } },
      "originalUriBaseIds": {
        "SRCROOT": { "uri": "file:///tmp/base/" }
      },
      "results": [
        {
          "message": { "text": "CodeQL found this" },
          "partialFingerprints": { "primaryLocationLineHash": "stable" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/file.c", "uriBaseId": "SRCROOT" },
                "region": { "startLine": 7, "startColumn": 3 }
              }
            }
          ]
        }
      ]
    }
  ]
}
"#;

        let parsed =
            parse_sarif_diff_findings(&sample_rule(), sarif, &[]).expect("valid paired SARIF");

        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].finding.file, "src/file.c");
        assert_eq!(
            parsed.findings[0].comparison_path,
            "codeql-single-root/src/file.c"
        );
        assert!(parsed.namespaces.is_empty());
    }

    #[test]
    fn paired_sarif_rejects_multiple_source_roots_without_a_uri_base_id() {
        let sarif = r#"
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "CodeQL" } },
      "results": [
        {
          "message": { "text": "CodeQL found this" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/file.c" },
                "region": { "startLine": 7, "startColumn": 3 }
              }
            }
          ]
        }
      ]
    }
  ]
}
"#;
        let source_roots = vec![
            PathBuf::from("/tmp/base/pkg-a"),
            PathBuf::from("/tmp/base/pkg-b"),
        ];

        let error = match parse_sarif_diff_findings(&sample_rule(), sarif, &source_roots) {
            Ok(_) => panic!("multiple anonymous source roots must fail"),
            Err(error) => error,
        };

        assert!(error.contains("multiple CodeQL source roots without a uriBaseId"));
    }
}
