use crate::engine::scanner::PathExcludeMatcher;
use crate::rules::common::get_source_line;
use crate::{Finding, Severity};
use ignore::WalkBuilder;
use regex::Regex;
use serde::Deserialize;
use serde_yaml_ng::Value as YamlValue;
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct CoccinelleRule {
    pub id: String,
    pub message: String,
    pub severity: Severity,
    pub cwe: Option<String>,
    script: String,
    languages: Vec<String>,
}

pub struct CoccinelleScanResult {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub candidate_files: usize,
    pub notices: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CoccinelleRuleYaml {
    id: String,
    #[serde(default)]
    engine: Option<String>,
    message: String,
    severity: FlexibleSeverity,
    #[serde(default)]
    languages: Vec<String>,
    #[serde(default)]
    metadata: Option<CoccinelleMetadata>,
    #[serde(default)]
    script: Option<String>,
    #[serde(default)]
    script_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CoccinelleMetadata {
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
                    "unsupported Coccinelle severity '{}'",
                    other
                )))
            }
        };
        Ok(Self(severity))
    }
}

impl CoccinelleRule {
    pub fn id(&self) -> &str {
        &self.id
    }

    fn applies_to_c(&self) -> bool {
        self.languages.is_empty()
            || self.languages.iter().any(|lang| {
                matches!(
                    lang.to_ascii_lowercase().as_str(),
                    "c" | "cocci" | "coccinelle"
                )
            })
    }
}

pub fn rule_ids(rules: &[CoccinelleRule]) -> HashSet<String> {
    rules.iter().map(|rule| rule.id.clone()).collect()
}

pub fn apply_rule_filter(rules: &mut Vec<CoccinelleRule>, enable: &[String], disable: &[String]) {
    if !enable.is_empty() {
        let enable_set: HashSet<&str> = enable.iter().map(|id| id.as_str()).collect();
        rules.retain(|rule| enable_set.contains(rule.id()));
    }

    if !disable.is_empty() {
        let disable_set: HashSet<&str> = disable.iter().map(|id| id.as_str()).collect();
        rules.retain(|rule| !disable_set.contains(rule.id()));
    }
}

pub fn load_coccinelle_rules(path: &Path) -> (Vec<CoccinelleRule>, Vec<String>) {
    let mut rules = Vec::new();
    let mut notices = Vec::new();

    if path.is_file() {
        match parse_coccinelle_file(path) {
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
            match parse_coccinelle_file(entry.path()) {
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

pub fn parse_coccinelle_file(path: &Path) -> Result<(Vec<CoccinelleRule>, Vec<String>), String> {
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
        if !is_coccinelle_rule(raw_rule) {
            continue;
        }

        let rule_position = index + 1;
        let raw_id = raw_rule
            .get("id")
            .and_then(YamlValue::as_str)
            .unwrap_or("<unknown>");
        let yaml: CoccinelleRuleYaml = match serde_yaml_ng::from_value(raw_rule.clone()) {
            Ok(yaml) => yaml,
            Err(error) => {
                notices.push(format!(
                    "Warning: Coccinelle rule '{}' in {} at rule {} skipped: {}",
                    raw_id,
                    path.display(),
                    rule_position,
                    error
                ));
                continue;
            }
        };

        let engine = yaml.engine.as_deref().unwrap_or_default();
        if !engine.eq_ignore_ascii_case("coccinelle") {
            continue;
        }

        let script = match resolve_script(path, &yaml) {
            Ok(script) => script,
            Err(error) => {
                notices.push(format!(
                    "Warning: Coccinelle rule '{}' in {} at rule {} skipped: {}",
                    yaml.id,
                    path.display(),
                    rule_position,
                    error
                ));
                continue;
            }
        };
        let cwe = yaml
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.cwe.as_ref())
            .and_then(extract_cwe);

        rules.push(CoccinelleRule {
            id: yaml.id,
            message: yaml.message,
            severity: yaml.severity.0,
            cwe,
            script,
            languages: yaml.languages,
        });
    }

    Ok((rules, notices))
}

pub fn scan_path_with_notices(
    root: &Path,
    rules: &[CoccinelleRule],
    max_file_size: u64,
    excludes: Option<&PathExcludeMatcher>,
) -> CoccinelleScanResult {
    let scan_root = scan_root(root);
    let candidates = collect_c_files(root, scan_root, max_file_size, excludes);
    scan_candidates(scan_root, candidates, rules)
}

pub fn scan_paths_with_notices(
    root: &Path,
    paths: &[PathBuf],
    rules: &[CoccinelleRule],
    max_file_size: u64,
    excludes: Option<&PathExcludeMatcher>,
) -> CoccinelleScanResult {
    let scan_root = scan_root(root);
    let candidates = paths
        .iter()
        .filter(|path| is_c_file(path))
        .filter(|path| {
            !excludes
                .is_some_and(|matcher| matcher.is_excluded(&relative_scan_path(scan_root, path)))
        })
        .filter_map(|path| {
            if std::fs::metadata(path).ok()?.len() > max_file_size {
                return None;
            }
            Some(path.clone())
        })
        .collect();
    scan_candidates(scan_root, candidates, rules)
}

fn scan_candidates(
    scan_root: &Path,
    candidates: Vec<PathBuf>,
    rules: &[CoccinelleRule],
) -> CoccinelleScanResult {
    let candidate_files = candidates.len();
    let active_rules: Vec<&CoccinelleRule> =
        rules.iter().filter(|rule| rule.applies_to_c()).collect();

    if active_rules.is_empty() || candidates.is_empty() {
        return CoccinelleScanResult {
            findings: Vec::new(),
            files_scanned: 0,
            candidate_files,
            notices: Vec::new(),
        };
    }

    if let Err(error) = probe_spatch() {
        return CoccinelleScanResult {
            findings: Vec::new(),
            files_scanned: 0,
            candidate_files,
            notices: vec![format!(
                "Warning: Coccinelle engine skipped: {}; install Coccinelle (`spatch`) to run engine: coccinelle rules",
                error
            )],
        };
    }

    let mut findings = Vec::new();
    let mut notices = Vec::new();
    let mut scanned_files = HashSet::new();

    for rule in active_rules {
        let mut temp_rule = match tempfile::NamedTempFile::new() {
            Ok(file) => file,
            Err(e) => {
                notices.push(format!(
                    "Warning: Coccinelle rule '{}' skipped: failed to create temp file: {}",
                    rule.id, e
                ));
                continue;
            }
        };

        if let Err(e) = temp_rule.write_all(rule.script.as_bytes()) {
            notices.push(format!(
                "Warning: Coccinelle rule '{}' skipped: failed to write SmPL temp file: {}",
                rule.id, e
            ));
            continue;
        }

        for path in &candidates {
            match run_spatch(temp_rule.path(), path) {
                Ok(output) => {
                    scanned_files.insert(path.clone());
                    findings.extend(parse_spatch_output(rule, path, scan_root, &output));
                }
                Err(error) => notices.push(format!(
                    "Warning: Coccinelle rule '{}' failed on {}: {}",
                    rule.id,
                    path.display(),
                    error
                )),
            }
        }
    }

    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
            .then(a.rule_id.cmp(&b.rule_id))
    });

    CoccinelleScanResult {
        findings,
        files_scanned: scanned_files.len(),
        candidate_files,
        notices,
    }
}

fn run_spatch(script_path: &Path, target: &Path) -> Result<String, String> {
    use crate::engine::process::{wait_with_output_timeout, TimedOutput};

    let timeout = spatch_timeout();
    let child = Command::new("spatch")
        .arg("--very-quiet")
        .arg("--sp-file")
        .arg(script_path)
        .arg(target)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to run spatch: {}", e))?;

    let result = wait_with_output_timeout(child, timeout)
        .map_err(|e| format!("failed to wait for spatch: {}", e))?;

    let (status_ok, raw_stdout, raw_stderr) = match result {
        TimedOutput::TimedOut { .. } => {
            return Err(format!("spatch timed out after {}s", timeout.as_secs()));
        }
        TimedOutput::Finished(output) => (output.status.success(), output.stdout, output.stderr),
    };

    let stdout = String::from_utf8_lossy(&raw_stdout);
    let stderr = String::from_utf8_lossy(&raw_stderr);
    let combined = if stderr.trim().is_empty() {
        stdout.to_string()
    } else if stdout.trim().is_empty() {
        stderr.to_string()
    } else {
        format!("{stdout}\n{stderr}")
    };

    if status_ok
        || combined.contains("\n@@ ")
        || combined.starts_with("@@ ")
        || combined.contains("\n--- ")
        || combined.starts_with("--- ")
    {
        Ok(combined)
    } else {
        let message = combined.trim();
        if message.is_empty() {
            Err("spatch exited without output".to_string())
        } else {
            Err(message.to_string())
        }
    }
}

fn spatch_timeout() -> Duration {
    let secs = std::env::var("FOXGUARD_SPATCH_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(60);
    Duration::from_secs(secs)
}

fn probe_spatch() -> Result<(), String> {
    match Command::new("spatch").arg("--version").output() {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let message = stderr.trim();
            if message.is_empty() {
                Err("spatch --version failed".to_string())
            } else {
                Err(message.to_string())
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err("spatch not found on PATH".to_string())
        }
        Err(e) => Err(format!("failed to run spatch --version: {}", e)),
    }
}

fn parse_spatch_output(
    rule: &CoccinelleRule,
    target: &Path,
    scan_root: &Path,
    output: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    let source = std::fs::read_to_string(target).unwrap_or_default();
    let line_starts = line_start_offsets(&source);

    for line in diff_hunk_lines(output) {
        if seen.insert(line) {
            findings.push(make_finding(
                rule,
                target,
                scan_root,
                line,
                &source,
                &line_starts,
            ));
        }
    }

    if findings.is_empty() {
        for line in file_line_matches(output, target) {
            if seen.insert(line) {
                findings.push(make_finding(
                    rule,
                    target,
                    scan_root,
                    line,
                    &source,
                    &line_starts,
                ));
            }
        }
    }

    findings
}

fn diff_hunk_lines(output: &str) -> Vec<usize> {
    static HUNK_RE: OnceLock<Regex> = OnceLock::new();
    let hunk_re = HUNK_RE.get_or_init(|| {
        Regex::new(r"^@@\s+-(?P<line>\d+)(?:,\d+)?\s+\+(?:\d+)(?:,\d+)?\s+@@")
            .expect("invalid Coccinelle hunk regex")
    });
    static CONTEXT_HUNK_RE: OnceLock<Regex> = OnceLock::new();
    let context_hunk_re = CONTEXT_HUNK_RE.get_or_init(|| {
        Regex::new(r"^\*\*\*\s+(?P<line>\d+)(?:,\d+)?\s+\*\*\*\*")
            .expect("invalid Coccinelle context hunk regex")
    });

    output
        .lines()
        .filter_map(|line| {
            hunk_re
                .captures(line)
                .or_else(|| context_hunk_re.captures(line))
                .and_then(|captures| captures.name("line"))
                .and_then(|line| line.as_str().parse::<usize>().ok())
        })
        .collect()
}

fn file_line_matches(output: &str, target: &Path) -> Vec<usize> {
    static FILE_LINE_RE: OnceLock<Regex> = OnceLock::new();
    let file_line_re = FILE_LINE_RE.get_or_init(|| {
        Regex::new(r"(?m)^(?P<file>[^:\n]+):(?P<line>\d+)(?::\d+)?:")
            .expect("invalid Coccinelle file-line regex")
    });
    let target_name = target.file_name().and_then(|name| name.to_str());

    file_line_re
        .captures_iter(output)
        .filter_map(|captures| {
            let file = captures.name("file")?.as_str();
            if target_name.is_some_and(|name| file.ends_with(name)) || target.ends_with(file) {
                captures.name("line")?.as_str().parse::<usize>().ok()
            } else {
                None
            }
        })
        .collect()
}

fn make_finding(
    rule: &CoccinelleRule,
    target: &Path,
    scan_root: &Path,
    line: usize,
    source: &str,
    line_starts: &[usize],
) -> Finding {
    let line_start = byte_offset_for_line(line_starts, source.len(), line);
    let snippet = get_source_line(source, line_start);
    let column = 1;
    let end_column = snippet.chars().count().max(1) + 1;

    Finding {
        rule_id: rule.id.clone(),
        severity: rule.severity,
        cwe: rule.cwe.clone(),
        description: rule.message.clone(),
        file: display_scan_path(scan_root, target),
        line,
        column,
        end_line: line,
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
        tags: vec![],
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
    }
}

fn line_start_offsets(source: &str) -> Vec<usize> {
    let mut offsets = vec![0];
    for (idx, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            offsets.push(idx + 1);
        }
    }
    offsets
}

fn byte_offset_for_line(line_starts: &[usize], source_len: usize, line: usize) -> usize {
    line_starts
        .get(line.saturating_sub(1))
        .copied()
        .unwrap_or(source_len)
}

fn collect_c_files(
    root: &Path,
    scan_root: &Path,
    max_file_size: u64,
    excludes: Option<&PathExcludeMatcher>,
) -> Vec<PathBuf> {
    if root.is_file() {
        if is_c_file(root)
            && !excludes
                .is_some_and(|matcher| matcher.is_excluded(&relative_scan_path(scan_root, root)))
            && std::fs::metadata(root).is_ok_and(|metadata| metadata.len() <= max_file_size)
        {
            return vec![root.to_path_buf()];
        }
        return Vec::new();
    }

    WalkBuilder::new(root)
        .follow_links(false)
        .hidden(true)
        .git_ignore(true)
        .build()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_some_and(|ft| ft.is_file()))
        .map(|entry| entry.into_path())
        .filter(|path| is_c_file(path))
        .filter(|path| {
            !excludes
                .is_some_and(|matcher| matcher.is_excluded(&relative_scan_path(scan_root, path)))
        })
        .filter(|path| {
            std::fs::metadata(path).is_ok_and(|metadata| metadata.len() <= max_file_size)
        })
        .collect()
}

fn is_c_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("c" | "h")
    )
}

fn scan_root(path: &Path) -> &Path {
    if path.is_file() {
        path.parent().unwrap_or_else(|| Path::new("."))
    } else {
        path
    }
}

fn relative_scan_path(scan_root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(scan_root).unwrap_or(path).to_path_buf()
}

fn display_scan_path(scan_root: &Path, path: &Path) -> String {
    path.strip_prefix(scan_root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn is_coccinelle_rule(raw_rule: &YamlValue) -> bool {
    raw_rule
        .get("engine")
        .and_then(YamlValue::as_str)
        .is_some_and(|engine| engine.eq_ignore_ascii_case("coccinelle"))
}

fn resolve_script(path: &Path, yaml: &CoccinelleRuleYaml) -> Result<String, String> {
    match (&yaml.script, &yaml.script_path) {
        (Some(script), None) => Ok(script.clone()),
        (None, Some(script_path)) => {
            let script_path = resolve_script_path(path, script_path);
            std::fs::read_to_string(&script_path).map_err(|e| {
                format!(
                    "Failed to read Coccinelle script_path {}: {}",
                    script_path.display(),
                    e
                )
            })
        }
        (Some(_), Some(_)) => Err(format!(
            "Coccinelle rule '{}' in {} must use either script or script_path, not both",
            yaml.id,
            path.display()
        )),
        (None, None) => Err(format!(
            "Coccinelle rule '{}' in {} is missing script or script_path",
            yaml.id,
            path.display()
        )),
    }
}

fn resolve_script_path(rule_file: &Path, script_path: &str) -> PathBuf {
    let path = Path::new(script_path);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn sample_rule() -> CoccinelleRule {
        CoccinelleRule {
            id: "kernel/test-cocci".to_string(),
            message: "missing guard".to_string(),
            severity: Severity::High,
            cwe: Some("CWE-362".to_string()),
            script: "@@\n@@\n".to_string(),
            languages: vec!["c".to_string()],
        }
    }

    #[test]
    fn parses_coccinelle_yaml_rule() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(
            br#"
rules:
  - id: kernel/test-cocci
    engine: coccinelle
    severity: high
    languages: [c]
    message: missing guard
    metadata:
      cwe: CWE-362
    script: |
      @@
      @@
"#,
        )
        .unwrap();

        let (rules, notices) = parse_coccinelle_file(file.path()).unwrap();
        assert!(notices.is_empty());
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "kernel/test-cocci");
        assert_eq!(rules[0].severity, Severity::High);
        assert_eq!(rules[0].cwe.as_deref(), Some("CWE-362"));
    }

    #[test]
    fn skips_malformed_coccinelle_rule_with_notice() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(
            br#"
rules:
  - id: kernel/good-cocci
    engine: coccinelle
    severity: high
    message: good
    script: |
      @@
      @@
  - id: kernel/bad-cocci
    engine: coccinelle
    severity: unknown
    message: bad
    script: |
      @@
      @@
  - id: kernel/second-good-cocci
    engine: coccinelle
    severity: low
    message: second good
    script: |
      @@
      @@
"#,
        )
        .unwrap();

        let (rules, notices) = parse_coccinelle_file(file.path()).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "kernel/good-cocci");
        assert_eq!(rules[1].id, "kernel/second-good-cocci");
        assert_eq!(notices.len(), 1);
        assert!(notices[0].contains("kernel/bad-cocci"));
        assert!(notices[0].contains("rule 2"));
    }

    #[test]
    fn parses_unified_diff_hunk_as_finding_line() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("vulnerable.c");
        std::fs::write(
            &target,
            "int f(void) {\n  int ok = 0;\n  crypto_aead_decrypt(skb);\n}\n",
        )
        .unwrap();

        let output = format!(
            "--- {}\n+++ /tmp/cocci-output\n@@ -3,7 +3,7 @@\n",
            target.display()
        );
        let findings = parse_spatch_output(&sample_rule(), &target, dir.path(), &output);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 3);
        assert!(findings[0].snippet.contains("crypto_aead_decrypt"));
        assert_eq!(findings[0].file, "vulnerable.c");
    }

    #[test]
    fn parses_context_diff_hunk_as_finding_line() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("vulnerable.c");
        std::fs::write(
            &target,
            "int f(void) {\n  int ok = 0;\n  crypto_aead_decrypt(skb);\n}\n",
        )
        .unwrap();

        let output = format!(
            "*** {}\n--- /tmp/cocci-output\n***************\n*** 3,7 ****\n",
            target.display()
        );
        let findings = parse_spatch_output(&sample_rule(), &target, dir.path(), &output);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 3);
        assert!(findings[0].snippet.contains("crypto_aead_decrypt"));
    }
}
