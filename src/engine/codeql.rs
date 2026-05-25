use crate::{Finding, Severity};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use serde_yaml_ng::Value as YamlValue;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use wait_timeout::ChildExt;

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
    let output = tempfile::NamedTempFile::new()
        .map_err(|e| format!("failed to create temporary SARIF output: {}", e))?;
    let output_path = output.path().to_path_buf();
    drop(output);
    let mut output_arg = OsString::from("--output=");
    output_arg.push(output_path.as_os_str());

    let timeout = codeql_timeout();
    let mut child = Command::new("codeql")
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

    let status = match child
        .wait_timeout(timeout)
        .map_err(|e| format!("failed to wait for codeql: {}", e))?
    {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("codeql timed out after {}s", timeout.as_secs()));
        }
    };

    let mut stdout = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        pipe.read_to_end(&mut stdout)
            .map_err(|e| format!("failed to read codeql stdout: {}", e))?;
    }
    let mut stderr = Vec::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_end(&mut stderr)
            .map_err(|e| format!("failed to read codeql stderr: {}", e))?;
    }

    if !status.success() {
        let message = process_message(&stdout, &stderr);
        return if message.is_empty() {
            Err("codeql exited without output".to_string())
        } else {
            Err(message)
        };
    }

    std::fs::read_to_string(&output_path).map_err(|e| {
        format!(
            "failed to read CodeQL SARIF output {}: {}",
            output_path.display(),
            e
        )
    })
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
        .filter_map(|result| finding_from_sarif_result(rule, result))
        .collect()
}

fn finding_from_sarif_result(rule: &CodeQlRule, result: &JsonValue) -> Option<Finding> {
    let physical = result
        .get("locations")?
        .as_array()?
        .first()?
        .get("physicalLocation")?;
    let uri = physical
        .get("artifactLocation")?
        .get("uri")?
        .as_str()
        .unwrap_or("<unknown>");
    let file = normalize_sarif_uri(uri);
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
    let snippet = snippet_for_path(&file, line);
    let end_column = region
        .and_then(|region| region.get("endColumn"))
        .and_then(JsonValue::as_u64)
        .map(|column| column as usize)
        .unwrap_or_else(|| column + snippet.chars().count().max(1));

    Some(Finding {
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
    })
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
    let parent = TempDir::new().map_err(|e| format!("failed to create codeql temp dir: {}", e))?;
    let db_path = parent.path().join("db");
    let mut language_arg = OsString::from("--language=");
    language_arg.push(language);
    let mut source_arg = OsString::from("--source-root=");
    source_arg.push(scan_target.as_os_str());

    let timeout = codeql_create_timeout();
    let mut child = Command::new("codeql")
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

    let status = match child
        .wait_timeout(timeout)
        .map_err(|e| format!("failed to wait for codeql: {}", e))?
    {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "codeql database create timed out after {}s",
                timeout.as_secs()
            ));
        }
    };

    let mut stdout = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        pipe.read_to_end(&mut stdout).ok();
    }
    let mut stderr = Vec::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_end(&mut stderr).ok();
    }

    if !status.success() {
        let message = process_message(&stdout, &stderr);
        return if message.is_empty() {
            Err("codeql database create exited without output".to_string())
        } else {
            Err(message)
        };
    }

    Ok(parent)
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
}
