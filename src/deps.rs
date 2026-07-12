use crate::engine::PathExcludeMatcher;
use crate::{Finding, Severity};
use ignore::WalkBuilder;
use pep440_rs::Version as Pep440Version;
use semver::Version as SemverVersion;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

pub const OSV_RULE_ID: &str = "manifest/osv-vulnerable-dep";

const OSV_API_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const OSV_SOURCE: &str = "OSV";
const OSV_CWE: &str = "CWE-937";

#[derive(Debug, Clone, Default)]
pub struct DependencyScanOptions {
    pub offline: bool,
    pub advisory_db: Option<PathBuf>,
    pub cache_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct DependencyScanResult {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub notices: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockfileKind {
    Cargo,
    Requirements,
    Poetry,
    Pipfile,
    Pnpm,
    PackageLock,
}

#[derive(Debug, Clone)]
struct PackageRef {
    ecosystem: String,
    name: String,
    display_name: String,
    version: String,
    purl: String,
    file: String,
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
    snippet: String,
    dep_path: Vec<String>,
}

impl PackageRef {
    fn key(&self) -> String {
        package_key(&self.ecosystem, &self.name, &self.version)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OsvCache {
    schema_version: u8,
    entries: BTreeMap<String, Vec<OsvVulnerability>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OsvPackage {
    name: Option<String>,
    ecosystem: Option<String>,
    purl: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
    limit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OsvRange {
    #[serde(rename = "type")]
    range_type: Option<String>,
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OsvAffected {
    package: Option<OsvPackage>,
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: Option<String>,
    score: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OsvVulnerability {
    id: String,
    aliases: Option<Vec<String>>,
    summary: Option<String>,
    details: Option<String>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    database_specific: Option<Value>,
}

#[derive(Debug, Serialize)]
struct OsvQueryBatchRequest {
    queries: Vec<OsvQuery>,
}

#[derive(Debug, Serialize)]
struct OsvQuery {
    version: String,
    package: OsvQueryPackage,
}

#[derive(Debug, Serialize)]
struct OsvQueryPackage {
    name: String,
    ecosystem: String,
    purl: String,
}

#[derive(Debug, Deserialize)]
struct OsvQueryBatchResponse {
    #[serde(default)]
    results: Vec<OsvQueryResult>,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResult {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Clone)]
struct Span {
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
    snippet: String,
}

pub fn scan_dependency_vulnerabilities(
    root: &Path,
    explicit_paths: Option<&[PathBuf]>,
    excludes: Option<&PathExcludeMatcher>,
    max_file_size: u64,
    options: &DependencyScanOptions,
) -> Result<DependencyScanResult, String> {
    let mut notices = Vec::new();
    let lockfiles = collect_lockfiles(root, explicit_paths, excludes);
    let mut packages = Vec::new();
    let mut files_scanned = 0usize;

    for path in lockfiles {
        match fs::metadata(&path) {
            Ok(metadata) if metadata.len() > max_file_size => {
                notices.push(format!(
                    "SCA: skipped {} ({} bytes exceeds max-file-size {})",
                    path.display(),
                    metadata.len(),
                    max_file_size
                ));
                continue;
            }
            Err(error) => {
                notices.push(format!(
                    "SCA: skipped {} (metadata error: {})",
                    path.display(),
                    error
                ));
                continue;
            }
            _ => {}
        }

        let source = match fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) => {
                notices.push(format!(
                    "SCA: skipped {} (read error: {})",
                    path.display(),
                    error
                ));
                continue;
            }
        };
        files_scanned += 1;
        packages.extend(parse_lockfile_packages(&source, &path));
    }

    let unique_packages = unique_packages(&packages);
    if unique_packages.is_empty() {
        if files_scanned > 0 {
            notices.push(
                "SCA: no pinned third-party dependencies found in supported lockfiles".to_string(),
            );
        }
        return Ok(DependencyScanResult {
            findings: Vec::new(),
            files_scanned,
            notices,
        });
    }

    let vulnerabilities_by_package = vulnerability_source(&unique_packages, options, &mut notices)?;
    let findings = packages
        .iter()
        .flat_map(|package| {
            // Local vulnerability map lookup; no outbound request is made here.
            // foxguard: ignore[rs/no-ssrf]
            vulnerabilities_by_package
                .get(&package.key())
                .into_iter()
                .flatten()
                .map(|vuln| finding_for_vulnerability(package, vuln))
        })
        .collect();

    Ok(DependencyScanResult {
        findings,
        files_scanned,
        notices,
    })
}

fn vulnerability_source(
    packages: &[PackageRef],
    options: &DependencyScanOptions,
    notices: &mut Vec<String>,
) -> Result<BTreeMap<String, Vec<OsvVulnerability>>, String> {
    if let Some(path) = options.advisory_db.as_ref() {
        let advisories = load_advisory_db(path)?;
        notices.push(format!(
            "SCA: using local OSV advisory database {}",
            path.display()
        ));
        return Ok(match_local_advisories(packages, &advisories));
    }

    if options.offline {
        if let Some(path) = options.cache_path.as_ref() {
            if path.exists() {
                notices.push(format!("SCA: using OSV cache {}", path.display()));
                return read_cache_entries(path, packages);
            }
        }
        notices.push(
            "SCA: offline mode has no advisory database/cache; vulnerability lookup skipped"
                .to_string(),
        );
        return Ok(BTreeMap::new());
    }

    match query_osv(packages) {
        Ok(entries) => {
            if let Some(path) = options.cache_path.as_ref() {
                write_cache_entries(path, &entries)?;
                notices.push(format!("SCA: wrote OSV cache {}", path.display()));
            }
            Ok(entries)
        }
        Err(error) => {
            if let Some(path) = options.cache_path.as_ref() {
                if path.exists() {
                    notices.push(format!(
                        "SCA: OSV query failed ({}); using cache {}",
                        error,
                        path.display()
                    ));
                    return read_cache_entries(path, packages);
                }
            }
            notices.push(format!(
                "SCA: OSV query failed; vulnerability lookup skipped ({error})"
            ));
            Ok(BTreeMap::new())
        }
    }
}

fn collect_lockfiles(
    root: &Path,
    explicit_paths: Option<&[PathBuf]>,
    excludes: Option<&PathExcludeMatcher>,
) -> Vec<PathBuf> {
    let scan_root = if root.is_file() {
        root.parent().unwrap_or_else(|| Path::new("."))
    } else {
        root
    };
    let mut files = Vec::new();

    if let Some(paths) = explicit_paths {
        for path in paths {
            push_lockfile(path.clone(), scan_root, excludes, &mut files);
        }
        return files;
    }

    if root.is_file() {
        push_lockfile(root.to_path_buf(), scan_root, excludes, &mut files);
        return files;
    }

    for entry in WalkBuilder::new(root)
        .follow_links(false)
        .hidden(true)
        .git_ignore(true)
        .build()
        .filter_map(Result::ok)
    {
        if entry.file_type().is_some_and(|ft| ft.is_file()) {
            push_lockfile(entry.into_path(), scan_root, excludes, &mut files);
        }
    }

    files
}

fn push_lockfile(
    path: PathBuf,
    scan_root: &Path,
    excludes: Option<&PathExcludeMatcher>,
    files: &mut Vec<PathBuf>,
) {
    if lockfile_kind(&path).is_none() {
        return;
    }
    let relative = path.strip_prefix(scan_root).unwrap_or(&path);
    if excludes.is_some_and(|matcher| matcher.is_excluded(relative)) {
        return;
    }
    files.push(path);
}

fn lockfile_kind(path: &Path) -> Option<LockfileKind> {
    match path.file_name().and_then(|name| name.to_str())? {
        "Cargo.lock" => Some(LockfileKind::Cargo),
        "requirements.txt" => Some(LockfileKind::Requirements),
        "poetry.lock" => Some(LockfileKind::Poetry),
        "Pipfile.lock" => Some(LockfileKind::Pipfile),
        "pnpm-lock.yaml" => Some(LockfileKind::Pnpm),
        "package-lock.json" => Some(LockfileKind::PackageLock),
        _ => None,
    }
}

fn parse_lockfile_packages(source: &str, path: &Path) -> Vec<PackageRef> {
    match lockfile_kind(path) {
        Some(LockfileKind::Cargo) => parse_cargo_lock(source, path),
        Some(LockfileKind::Requirements) => parse_requirements_txt(source, path),
        Some(LockfileKind::Poetry) => parse_poetry_lock(source, path),
        Some(LockfileKind::Pipfile) => parse_pipfile_lock(source, path),
        Some(LockfileKind::Pnpm) => parse_pnpm_lock(source, path),
        Some(LockfileKind::PackageLock) => parse_package_lock(source, path),
        None => Vec::new(),
    }
}

fn parse_cargo_lock(source: &str, path: &Path) -> Vec<PackageRef> {
    let Ok(doc) = source.parse::<toml::Value>() else {
        return Vec::new();
    };
    let Some(packages) = doc.get("package").and_then(|value| value.as_array()) else {
        return Vec::new();
    };

    packages
        .iter()
        .filter_map(|pkg| {
            let source_value = pkg.get("source").and_then(|value| value.as_str())?;
            if !source_value.contains("crates.io-index") {
                return None;
            }
            let name = pkg.get("name").and_then(|value| value.as_str())?;
            let version = pkg.get("version").and_then(|value| value.as_str())?;
            let name_pat = format!("name = \"{name}\"");
            let version_pat = format!("version = \"{version}\"");
            let (start, end) = find_name_version_offset(source, &name_pat, &version_pat)
                .unwrap_or_else(|| (0, name_pat.len().min(source.len())));
            Some(package_ref(
                "crates.io",
                name,
                version,
                source,
                path,
                start,
                end,
            ))
        })
        .collect()
}

fn parse_requirements_txt(source: &str, path: &Path) -> Vec<PackageRef> {
    let mut packages = Vec::new();
    let mut byte_offset = 0usize;

    for line in source.lines() {
        let line_start = byte_offset;
        let line_end = line_start + line.len();
        byte_offset = advance_line_offset(source, line_end);

        let Some((name, version)) = parse_pinned_requirement(line) else {
            continue;
        };
        packages.push(package_ref(
            "PyPI", &name, &version, source, path, line_start, line_end,
        ));
    }

    packages
}

fn parse_poetry_lock(source: &str, path: &Path) -> Vec<PackageRef> {
    let Ok(doc) = source.parse::<toml::Value>() else {
        return Vec::new();
    };
    let Some(packages) = doc.get("package").and_then(|value| value.as_array()) else {
        return Vec::new();
    };

    packages
        .iter()
        .filter_map(|pkg| {
            let name = pkg.get("name").and_then(|value| value.as_str())?;
            let version = pkg.get("version").and_then(|value| value.as_str())?;
            let name_pat = format!("name = \"{name}\"");
            let version_pat = format!("version = \"{version}\"");
            let (start, end) = find_name_version_offset(source, &name_pat, &version_pat)
                .unwrap_or_else(|| find_pattern_span(source, &name_pat));
            Some(package_ref("PyPI", name, version, source, path, start, end))
        })
        .collect()
}

fn parse_pipfile_lock(source: &str, path: &Path) -> Vec<PackageRef> {
    let Ok(doc) = serde_json::from_str::<Value>(source) else {
        return Vec::new();
    };
    let mut packages = Vec::new();
    let mut seen = HashSet::new();

    for section in ["default", "develop"] {
        // Local Pipfile.lock object lookup; no outbound request is made here.
        // foxguard: ignore[rs/no-ssrf]
        let Some(deps) = doc.get(section).and_then(|value| value.as_object()) else {
            continue;
        };
        for (name, metadata) in deps {
            let Some(version) = metadata
                .get("version")
                .and_then(|value| value.as_str())
                .map(normalize_pipfile_version)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            if !seen.insert((name.clone(), version.clone())) {
                continue;
            }
            let key_pat = format!("\"{name}\"");
            let (start, end) = find_pattern_span(source, &key_pat);
            packages.push(package_ref(
                "PyPI", name, &version, source, path, start, end,
            ));
        }
    }

    packages
}

fn parse_pnpm_lock(source: &str, path: &Path) -> Vec<PackageRef> {
    let Ok(doc) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(source) else {
        return Vec::new();
    };
    let Some(packages) = doc.get("packages").and_then(|value| value.as_mapping()) else {
        return Vec::new();
    };

    packages
        .keys()
        .filter_map(|key| {
            let key = key.as_str()?;
            let (name, version) = parse_pnpm_package_key(key)?;
            let (start, end) = find_pattern_span(source, key);
            Some(package_ref(
                "npm", &name, &version, source, path, start, end,
            ))
        })
        .collect()
}

fn parse_package_lock(source: &str, path: &Path) -> Vec<PackageRef> {
    let Ok(doc) = serde_json::from_str::<Value>(source) else {
        return Vec::new();
    };
    let mut packages = Vec::new();
    let mut seen = HashSet::new();

    if let Some(package_map) = doc.get("packages").and_then(|value| value.as_object()) {
        for (key, metadata) in package_map {
            if key.is_empty() {
                continue;
            }
            let Some(name) = npm_name_from_package_lock_key(key) else {
                continue;
            };
            let Some(version) = metadata.get("version").and_then(|value| value.as_str()) else {
                continue;
            };
            if !seen.insert((name.to_string(), version.to_string())) {
                continue;
            }
            let key_pat = format!("\"{key}\"");
            let (start, end) = find_pattern_span(source, &key_pat);
            packages.push(package_ref("npm", name, version, source, path, start, end));
        }
        return packages;
    }

    if let Some(deps) = doc.get("dependencies").and_then(|value| value.as_object()) {
        collect_package_lock_v1_deps(source, path, deps, &mut seen, &mut packages);
    }

    packages
}

fn collect_package_lock_v1_deps(
    source: &str,
    path: &Path,
    deps: &serde_json::Map<String, Value>,
    seen: &mut HashSet<(String, String)>,
    packages: &mut Vec<PackageRef>,
) {
    for (name, metadata) in deps {
        if let Some(version) = metadata.get("version").and_then(|value| value.as_str()) {
            if seen.insert((name.clone(), version.to_string())) {
                let key_pat = format!("\"{name}\"");
                let (start, end) = find_pattern_span(source, &key_pat);
                packages.push(package_ref("npm", name, version, source, path, start, end));
            }
        }
        if let Some(nested) = metadata
            .get("dependencies")
            .and_then(|value| value.as_object())
        {
            collect_package_lock_v1_deps(source, path, nested, seen, packages);
        }
    }
}

fn package_ref(
    ecosystem: &str,
    display_name: &str,
    version: &str,
    source: &str,
    path: &Path,
    start: usize,
    end: usize,
) -> PackageRef {
    let name = normalize_package_name(ecosystem, display_name);
    let purl = package_purl(ecosystem, &name, version);
    let span = span_for_offsets(source, start, end);
    let dep_path = vec![format!("{display_name}@{version}")];
    PackageRef {
        ecosystem: ecosystem.to_string(),
        name,
        display_name: display_name.to_string(),
        version: version.to_string(),
        purl,
        file: path.display().to_string(),
        line: span.line,
        column: span.column,
        end_line: span.end_line,
        end_column: span.end_column,
        snippet: span.snippet,
        dep_path,
    }
}

fn normalize_package_name(ecosystem: &str, name: &str) -> String {
    match ecosystem {
        "PyPI" => normalize_pypi_name(name),
        "npm" | "crates.io" => name.to_ascii_lowercase(),
        _ => name.to_string(),
    }
}

fn normalize_pypi_name(name: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in name.chars().flat_map(char::to_lowercase) {
        let is_sep = matches!(ch, '-' | '_' | '.');
        if is_sep {
            if !last_dash {
                out.push('-');
                last_dash = true;
            }
        } else {
            out.push(ch);
            last_dash = false;
        }
    }
    out.trim_matches('-').to_string()
}

fn package_purl(ecosystem: &str, name: &str, version: &str) -> String {
    match ecosystem {
        "crates.io" => format!("pkg:cargo/{name}@{version}"),
        "PyPI" => format!("pkg:pypi/{name}@{version}"),
        "npm" if name.starts_with('@') => {
            let encoded = name.replacen('@', "%40", 1);
            format!("pkg:npm/{encoded}@{version}")
        }
        "npm" => format!("pkg:npm/{name}@{version}"),
        _ => format!("pkg:generic/{name}@{version}"),
    }
}

fn parse_pinned_requirement(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with('-')
        || trimmed.starts_with("git+")
        || trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
    {
        return None;
    }

    let before_marker = trimmed.split(';').next().unwrap_or(trimmed).trim();
    let before_comment = before_marker
        .split('#')
        .next()
        .unwrap_or(before_marker)
        .trim();
    let (name_part, version_part) = before_comment.split_once("==")?;
    let name = extract_pip_package_name(name_part.trim()).to_string();
    let version = version_part
        .trim()
        .split(',')
        .next()
        .unwrap_or(version_part)
        .trim()
        .to_string();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

fn extract_pip_package_name(value: &str) -> &str {
    let end = value
        .find(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' && ch != '.')
        .unwrap_or(value.len());
    &value[..end]
}

fn normalize_pipfile_version(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('=')
        .trim()
        .trim_matches('"')
        .to_string()
}

fn parse_pnpm_package_key(key: &str) -> Option<(String, String)> {
    let stripped = key.strip_prefix('/').unwrap_or(key);
    let without_peers = stripped.split('(').next().unwrap_or(stripped);
    let at = without_peers.rfind('@')?;
    if at == 0 {
        return None;
    }
    let name = &without_peers[..at];
    let version = &without_peers[at + 1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

fn npm_name_from_package_lock_key(key: &str) -> Option<&str> {
    key.rsplit_once("node_modules/")
        .map(|(_, name)| name)
        .filter(|name| !name.is_empty())
}

fn unique_packages(packages: &[PackageRef]) -> Vec<PackageRef> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for package in packages {
        if seen.insert(package.key()) {
            unique.push(package.clone());
        }
    }
    unique
}

fn query_osv(packages: &[PackageRef]) -> Result<BTreeMap<String, Vec<OsvVulnerability>>, String> {
    let request = OsvQueryBatchRequest {
        queries: packages
            .iter()
            .map(|package| OsvQuery {
                version: package.version.clone(),
                package: OsvQueryPackage {
                    name: package.name.clone(),
                    ecosystem: package.ecosystem.clone(),
                    purl: package.purl.clone(),
                },
            })
            .collect(),
    };

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent(format!("foxguard/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        // Fixed OSV API endpoint, not user-controlled.
        .post(OSV_API_BATCH_URL) // foxguard: ignore[rs/no-ssrf]
        .json(&request)
        .send()
        .map_err(|error| error.to_string())?;

    if !response.status().is_success() {
        return Err(format!("OSV returned HTTP {}", response.status()));
    }

    let batch: OsvQueryBatchResponse = response.json().map_err(|error| error.to_string())?;
    let mut entries = BTreeMap::new();
    for (package, result) in packages.iter().zip(batch.results) {
        entries.insert(package.key(), result.vulns);
    }
    Ok(entries)
}

fn load_advisory_db(path: &Path) -> Result<Vec<OsvVulnerability>, String> {
    let mut advisories = Vec::new();
    if path.is_dir() {
        for entry in WalkBuilder::new(path)
            .follow_links(false)
            .hidden(false)
            .git_ignore(false)
            .build()
            .filter_map(Result::ok)
        {
            if !entry.file_type().is_some_and(|ft| ft.is_file()) {
                continue;
            }
            let path = entry.path();
            let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
                continue;
            };
            if !matches!(ext, "json" | "jsonl") {
                continue;
            }
            let content = fs::read_to_string(path)
                .map_err(|error| format!("failed to read OSV db {}: {}", path.display(), error))?;
            advisories.extend(parse_advisory_content(&content, path)?);
        }
    } else {
        let content = fs::read_to_string(path)
            .map_err(|error| format!("failed to read OSV db {}: {}", path.display(), error))?;
        advisories.extend(parse_advisory_content(&content, path)?);
    }
    Ok(advisories)
}

fn parse_advisory_content(content: &str, path: &Path) -> Result<Vec<OsvVulnerability>, String> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if path.extension().and_then(|ext| ext.to_str()) == Some("jsonl") {
        return trimmed
            .lines()
            .map(|line| {
                serde_json::from_str::<OsvVulnerability>(line).map_err(|error| {
                    format!("failed to parse OSV JSONL {}: {}", path.display(), error)
                })
            })
            .collect();
    }

    let value: Value = serde_json::from_str(trimmed)
        .map_err(|error| format!("failed to parse OSV db {}: {}", path.display(), error))?;

    if value.is_array() {
        return serde_json::from_value::<Vec<OsvVulnerability>>(value)
            .map_err(|error| format!("failed to decode OSV db {}: {}", path.display(), error));
    }

    if value.get("results").is_some() {
        let response = serde_json::from_value::<OsvQueryBatchResponse>(value)
            .map_err(|error| format!("failed to decode OSV cache {}: {}", path.display(), error))?;
        return Ok(response
            .results
            .into_iter()
            .flat_map(|result| result.vulns)
            .collect());
    }

    if let Some(vulns) = value.get("vulns") {
        return serde_json::from_value::<Vec<OsvVulnerability>>(vulns.clone())
            .map_err(|error| format!("failed to decode OSV vulns {}: {}", path.display(), error));
    }

    serde_json::from_value::<OsvVulnerability>(value)
        .map(|vuln| vec![vuln])
        .map_err(|error| {
            format!(
                "failed to decode OSV advisory {}: {}",
                path.display(),
                error
            )
        })
}

fn match_local_advisories(
    packages: &[PackageRef],
    advisories: &[OsvVulnerability],
) -> BTreeMap<String, Vec<OsvVulnerability>> {
    let mut entries = BTreeMap::new();
    for package in packages {
        let vulns = advisories
            .iter()
            .filter(|vuln| matches_advisory(package, vuln))
            .cloned()
            .collect::<Vec<_>>();
        entries.insert(package.key(), vulns);
    }
    entries
}

fn matches_advisory(package: &PackageRef, vuln: &OsvVulnerability) -> bool {
    vuln.affected.iter().any(|affected| {
        affected_package_matches(package, affected) && affected_version_matches(package, affected)
    })
}

fn affected_package_matches(package: &PackageRef, affected: &OsvAffected) -> bool {
    let Some(osv_package) = affected.package.as_ref() else {
        return false;
    };
    if osv_package
        .purl
        .as_deref()
        .is_some_and(|purl| purl == package.purl)
    {
        return true;
    }
    let ecosystem_matches = osv_package
        .ecosystem
        .as_deref()
        .is_some_and(|ecosystem| ecosystems_equal(ecosystem, &package.ecosystem));
    let Some(name) = osv_package.name.as_deref() else {
        return false;
    };
    ecosystem_matches && normalize_package_name(&package.ecosystem, name) == package.name
}

fn affected_version_matches(package: &PackageRef, affected: &OsvAffected) -> bool {
    if affected
        .versions
        .iter()
        .any(|version| version_matches(package, version))
    {
        return true;
    }

    if affected.ranges.is_empty() {
        return affected.versions.is_empty();
    }

    affected
        .ranges
        .iter()
        .any(|range| version_in_range(package, range))
}

fn version_matches(package: &PackageRef, advisory_version: &str) -> bool {
    compare_versions_for_package(package, None, advisory_version)
        .map_or(package.version == advisory_version, |ordering| {
            ordering == Ordering::Equal
        })
}

fn version_in_range(package: &PackageRef, range: &OsvRange) -> bool {
    if !version_before_limits(package, range) {
        return false;
    }

    let mut vulnerable = false;
    for event in &range.events {
        if let Some(introduced) = event.introduced.as_deref() {
            if introduced == "0"
                || compare_versions_for_package(package, range.range_type.as_deref(), introduced)
                    .is_some_and(|ordering| ordering != Ordering::Less)
            {
                vulnerable = true;
            }
        }
        if let Some(fixed) = event.fixed.as_deref() {
            if compare_versions_for_package(package, range.range_type.as_deref(), fixed)
                .is_some_and(|ordering| ordering != Ordering::Less)
            {
                vulnerable = false;
            }
        }
        if let Some(last_affected) = event.last_affected.as_deref() {
            if compare_versions_for_package(package, range.range_type.as_deref(), last_affected)
                .is_some_and(|ordering| ordering == Ordering::Greater)
            {
                vulnerable = false;
            }
        }
    }
    vulnerable
}

fn version_before_limits(package: &PackageRef, range: &OsvRange) -> bool {
    let mut saw_limit = false;
    for event in &range.events {
        let Some(limit) = event.limit.as_deref() else {
            continue;
        };
        saw_limit = true;
        if compare_versions_for_package(package, range.range_type.as_deref(), limit)
            .is_some_and(|ordering| ordering == Ordering::Less)
        {
            return true;
        }
    }
    !saw_limit
}

fn first_fixed_version(package: &PackageRef, vuln: &OsvVulnerability) -> Option<String> {
    let mut fallback = None;
    for affected in vuln
        .affected
        .iter()
        .filter(|affected| affected_package_matches(package, affected))
        .filter(|affected| affected_version_matches(package, affected))
    {
        for range in &affected.ranges {
            let fixed = range.events.iter().find_map(|event| event.fixed.clone());
            if fallback.is_none() {
                fallback = fixed.clone();
            }
            if version_in_range(package, range) {
                return fixed;
            }
        }
    }
    fallback
}

fn finding_for_vulnerability(package: &PackageRef, vuln: &OsvVulnerability) -> Finding {
    let fixed_version = first_fixed_version(package, vuln);
    let advisory_severity = advisory_severity_text(vuln);
    let severity = advisory_severity
        .as_deref()
        .map(severity_from_text)
        .unwrap_or(Severity::Medium);
    let title = vuln
        .summary
        .as_deref()
        .or(vuln.details.as_deref())
        .unwrap_or("known dependency vulnerability");
    let fixed_text = fixed_version
        .as_ref()
        .map(|version| format!("; fixed in {version}"))
        .unwrap_or_default();
    let description = format!(
        "Dependency `{}` {} is affected by {}: {}{}",
        package.display_name, package.version, vuln.id, title, fixed_text
    );

    Finding {
        rule_id: OSV_RULE_ID.to_string(),
        severity,
        cwe: Some(OSV_CWE.to_string()),
        description,
        file: package.file.clone(),
        line: package.line,
        column: package.column,
        end_line: package.end_line,
        end_column: package.end_column,
        snippet: package.snippet.clone(),
        source_line: None,
        source_description: None,
        sink_line: None,
        sink_description: None,
        fix_suggestion: fixed_version
            .as_ref()
            .map(|version| format!("Upgrade `{}` to {version} or later", package.display_name)),
        sink_start_byte: None,
        sink_end_byte: None,
        confidence: crate::default_confidence(),
        taint_hops: None,
        tags: vec![
            "SCA".to_string(),
            OSV_SOURCE.to_string(),
            package.ecosystem.clone(),
        ],
        crypto_algorithm: None,
        cnsa2_deadline: None,
        dep_name: Some(package.display_name.clone()),
        dep_version: Some(package.version.clone()),
        dep_ecosystem: Some(package.ecosystem.clone()),
        dep_purl: Some(package.purl.clone()),
        dep_vulnerability_id: Some(vuln.id.clone()),
        dep_fixed_version: fixed_version,
        dep_source: Some(OSV_SOURCE.to_string()),
        dep_vulnerability_severity: advisory_severity,
        dep_path: package.dep_path.clone(),
        crypto_material: None,
    }
}

fn advisory_severity_text(vuln: &OsvVulnerability) -> Option<String> {
    if let Some(severity) = vuln
        .database_specific
        .as_ref()
        .and_then(|value| value.get("severity"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
    {
        return Some(severity.to_string());
    }

    vuln.severity.iter().find_map(|severity| {
        severity.score.as_ref().map(|score| {
            if let Some(kind) = severity.severity_type.as_deref() {
                format!("{kind}:{score}")
            } else {
                score.clone()
            }
        })
    })
}

fn severity_from_text(value: &str) -> Severity {
    let upper = value.trim().to_ascii_uppercase();
    if upper.contains("CRITICAL") {
        return Severity::Critical;
    }
    if upper.contains("HIGH") {
        return Severity::High;
    }
    if upper.contains("MODERATE") || upper.contains("MEDIUM") {
        return Severity::Medium;
    }
    if upper.contains("LOW") {
        return Severity::Low;
    }

    let numeric = value
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .find_map(|part| part.parse::<f32>().ok());
    match numeric {
        Some(score) if score >= 9.0 => Severity::Critical,
        Some(score) if score >= 7.0 => Severity::High,
        Some(score) if score >= 4.0 => Severity::Medium,
        Some(_) => Severity::Low,
        None => Severity::Medium,
    }
}

fn read_cache_entries(
    path: &Path,
    packages: &[PackageRef],
) -> Result<BTreeMap<String, Vec<OsvVulnerability>>, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read OSV cache {}: {}", path.display(), error))?;
    let cache: OsvCache = serde_json::from_str(&content)
        .map_err(|error| format!("failed to parse OSV cache {}: {}", path.display(), error))?;

    let mut entries = BTreeMap::new();
    for package in packages {
        entries.insert(
            package.key(),
            // Local cache lookup by normalized package key; no outbound request is made here.
            // foxguard: ignore[rs/no-ssrf]
            cache
                .entries
                .get(&package.key())
                .cloned()
                .unwrap_or_default(),
        );
    }
    Ok(entries)
}

fn write_cache_entries(
    path: &Path,
    entries: &BTreeMap<String, Vec<OsvVulnerability>>,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create OSV cache directory {}: {}",
                    parent.display(),
                    error
                )
            })?;
        }
    }

    let cache = OsvCache {
        schema_version: 1,
        entries: entries.clone(),
    };
    let content = serde_json::to_string_pretty(&cache)
        .map_err(|error| format!("failed to serialize OSV cache: {error}"))?;
    fs::write(path, content)
        .map_err(|error| format!("failed to write OSV cache {}: {}", path.display(), error))
}

fn package_key(ecosystem: &str, name: &str, version: &str) -> String {
    format!("{ecosystem}|{name}|{version}")
}

fn ecosystems_equal(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
        || (left.eq_ignore_ascii_case("crates.io") && right.eq_ignore_ascii_case("cargo"))
        || (left.eq_ignore_ascii_case("cargo") && right.eq_ignore_ascii_case("crates.io"))
}

fn compare_versions_for_package(
    package: &PackageRef,
    range_type: Option<&str>,
    advisory_version: &str,
) -> Option<Ordering> {
    compare_versions(
        &package.ecosystem,
        range_type,
        &package.version,
        advisory_version,
    )
}

fn compare_versions(
    ecosystem: &str,
    range_type: Option<&str>,
    left: &str,
    right: &str,
) -> Option<Ordering> {
    match range_type {
        Some(range_type) if range_type.eq_ignore_ascii_case("GIT") => None,
        Some(range_type) if range_type.eq_ignore_ascii_case("SEMVER") => {
            compare_semver_versions(left, right)
        }
        Some(range_type) if range_type.eq_ignore_ascii_case("ECOSYSTEM") => {
            compare_ecosystem_versions(ecosystem, left, right)
        }
        _ => compare_ecosystem_versions(ecosystem, left, right),
    }
}

fn compare_ecosystem_versions(ecosystem: &str, left: &str, right: &str) -> Option<Ordering> {
    if ecosystem.eq_ignore_ascii_case("PyPI") {
        return compare_pep440_versions(left, right);
    }
    if ecosystem.eq_ignore_ascii_case("npm")
        || ecosystem.eq_ignore_ascii_case("crates.io")
        || ecosystem.eq_ignore_ascii_case("cargo")
    {
        return compare_semver_versions(left, right);
    }
    None
}

fn compare_pep440_versions(left: &str, right: &str) -> Option<Ordering> {
    Some(
        Pep440Version::from_str(left)
            .ok()?
            .cmp(&Pep440Version::from_str(right).ok()?),
    )
}

fn compare_semver_versions(left: &str, right: &str) -> Option<Ordering> {
    Some(parse_relaxed_semver(left)?.cmp(&parse_relaxed_semver(right)?))
}

fn parse_relaxed_semver(value: &str) -> Option<SemverVersion> {
    let value = value.trim();
    SemverVersion::parse(value).ok().or_else(|| {
        let value = value.strip_prefix('v').unwrap_or(value);
        let suffix_start = value.find(['-', '+']).unwrap_or(value.len());
        let (core, suffix) = value.split_at(suffix_start);
        let mut parts = core.split('.').collect::<Vec<_>>();
        if parts.is_empty()
            || parts.len() > 3
            || parts
                .iter()
                .any(|part| part.is_empty() || !part.chars().all(|ch| ch.is_ascii_digit()))
        {
            return None;
        }
        while parts.len() < 3 {
            parts.push("0");
        }
        SemverVersion::parse(&format!("{}{}", parts.join("."), suffix)).ok()
    })
}

fn find_name_version_offset(source: &str, name_pat: &str, ver_pat: &str) -> Option<(usize, usize)> {
    let mut search_from = 0;
    while let Some(pos) = source[search_from..].find(name_pat) {
        let abs = search_from + pos;
        let after_name = abs + name_pat.len();
        let rest = &source[after_name..];
        if rest.starts_with('\n') || rest.starts_with("\r\n") {
            let ver_start = after_name + if rest.starts_with("\r\n") { 2 } else { 1 };
            if source[ver_start..].starts_with(ver_pat) {
                return Some((abs, ver_start + ver_pat.len()));
            }
        }
        search_from = abs + 1;
    }
    None
}

fn find_pattern_span(source: &str, pattern: &str) -> (usize, usize) {
    source
        .find(pattern)
        .map(|offset| (offset, offset + pattern.len()))
        .unwrap_or((0, pattern.len().min(source.len())))
}

fn span_for_offsets(source: &str, start: usize, end: usize) -> Span {
    let start = start.min(source.len());
    let end = end.min(source.len());
    let line = source[..start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let line_start = source[..start].rfind('\n').map_or(0, |idx| idx + 1);
    let column = source[line_start..start].chars().count() + 1;
    let end_line = source[..end].bytes().filter(|byte| *byte == b'\n').count() + 1;
    let end_line_start = source[..end].rfind('\n').map_or(0, |idx| idx + 1);
    let end_column = source[end_line_start..end].chars().count() + 1;
    let snippet_end = source[end..]
        .find('\n')
        .map(|idx| end + idx)
        .unwrap_or(source.len());
    let snippet_start = source[..start].rfind('\n').map_or(0, |idx| idx + 1);
    let snippet = source[snippet_start..snippet_end]
        .trim_end_matches('\r')
        .to_string();
    Span {
        line,
        column,
        end_line,
        end_column,
        snippet,
    }
}

fn advance_line_offset(source: &str, line_end: usize) -> usize {
    let bytes = source.as_bytes();
    if line_end >= bytes.len() {
        return line_end;
    }
    if bytes[line_end] == b'\r' {
        if line_end + 1 < bytes.len() && bytes[line_end + 1] == b'\n' {
            return line_end + 2;
        }
        return line_end + 1;
    }
    if bytes[line_end] == b'\n' {
        return line_end + 1;
    }
    line_end
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vuln(ecosystem: &str, name: &str, version: &str) -> OsvVulnerability {
        OsvVulnerability {
            id: "GHSA-test-0000".to_string(),
            summary: Some("test advisory".to_string()),
            affected: vec![OsvAffected {
                package: Some(OsvPackage {
                    name: Some(name.to_string()),
                    ecosystem: Some(ecosystem.to_string()),
                    purl: None,
                }),
                versions: vec![version.to_string()],
                ranges: vec![OsvRange {
                    events: vec![
                        OsvEvent {
                            introduced: Some("0".to_string()),
                            ..OsvEvent::default()
                        },
                        OsvEvent {
                            fixed: Some("9.9.9".to_string()),
                            ..OsvEvent::default()
                        },
                    ],
                    ..OsvRange::default()
                }],
            }],
            database_specific: Some(serde_json::json!({ "severity": "HIGH" })),
            ..OsvVulnerability::default()
        }
    }

    #[test]
    fn parses_supported_lockfiles() {
        assert_eq!(
            parse_cargo_lock(
                "[[package]]\nname = \"rsa\"\nversion = \"0.9.6\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
                Path::new("Cargo.lock")
            )[0]
                .purl,
            "pkg:cargo/rsa@0.9.6"
        );
        assert_eq!(
            parse_requirements_txt("Django==5.0\nrequests>=2\n", Path::new("requirements.txt"))[0]
                .name,
            "django"
        );
        assert_eq!(
            parse_poetry_lock(
                "[[package]]\nname = \"python-rsa\"\nversion = \"4.9\"\n",
                Path::new("poetry.lock")
            )[0]
            .name,
            "python-rsa"
        );
        assert_eq!(
            parse_pipfile_lock(
                "{\"default\":{\"cryptography\":{\"version\":\"==41.0.7\"}}}",
                Path::new("Pipfile.lock")
            )[0]
            .version,
            "41.0.7"
        );
        assert_eq!(
            parse_pnpm_lock(
                "packages:\n  elliptic@6.5.4:\n    resolution: {}\n",
                Path::new("pnpm-lock.yaml")
            )[0]
            .purl,
            "pkg:npm/elliptic@6.5.4"
        );
        assert_eq!(
            parse_package_lock(
                "{\"packages\":{\"node_modules/elliptic\":{\"version\":\"6.5.4\"}}}",
                Path::new("package-lock.json")
            )[0]
            .name,
            "elliptic"
        );
    }

    #[test]
    fn local_advisory_matching_uses_ecosystem_name_and_version() {
        let package = parse_package_lock(
            "{\"packages\":{\"node_modules/elliptic\":{\"version\":\"6.5.4\"}}}",
            Path::new("package-lock.json"),
        )
        .pop()
        .unwrap();
        let entries = match_local_advisories(
            std::slice::from_ref(&package),
            &[vuln("npm", "elliptic", "6.5.4")],
        );
        assert_eq!(entries[&package.key()].len(), 1);
        let finding = finding_for_vulnerability(&package, &entries[&package.key()][0]);
        assert_eq!(finding.dep_name.as_deref(), Some("elliptic"));
        assert_eq!(finding.dep_version.as_deref(), Some("6.5.4"));
        assert_eq!(finding.dep_ecosystem.as_deref(), Some("npm"));
        assert_eq!(finding.dep_fixed_version.as_deref(), Some("9.9.9"));
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn range_matching_respects_fixed_event() {
        let range = OsvRange {
            range_type: Some("SEMVER".to_string()),
            events: vec![
                OsvEvent {
                    introduced: Some("1.0.0".to_string()),
                    ..OsvEvent::default()
                },
                OsvEvent {
                    fixed: Some("1.2.0".to_string()),
                    ..OsvEvent::default()
                },
            ],
        };
        let matching = package_ref(
            "crates.io",
            "demo",
            "1.1.9",
            "demo = 1.1.9\n",
            Path::new("Cargo.lock"),
            0,
            12,
        );
        let fixed = package_ref(
            "crates.io",
            "demo",
            "1.2.0",
            "demo = 1.2.0\n",
            Path::new("Cargo.lock"),
            0,
            12,
        );
        assert!(version_in_range(&matching, &range));
        assert!(!version_in_range(&fixed, &range));
    }

    #[test]
    fn pypi_prerelease_range_matches_before_final_release() {
        let package = package_ref(
            "PyPI",
            "mypkg",
            "1.0.0rc1",
            "mypkg==1.0.0rc1\n",
            Path::new("requirements.txt"),
            0,
            16,
        );
        let affected = OsvAffected {
            package: Some(OsvPackage {
                name: Some("mypkg".to_string()),
                ecosystem: Some("PyPI".to_string()),
                purl: None,
            }),
            ranges: vec![OsvRange {
                range_type: Some("ECOSYSTEM".to_string()),
                events: vec![
                    OsvEvent {
                        introduced: Some("0".to_string()),
                        ..OsvEvent::default()
                    },
                    OsvEvent {
                        fixed: Some("1.0.0".to_string()),
                        ..OsvEvent::default()
                    },
                ],
            }],
            ..OsvAffected::default()
        };

        assert!(affected_version_matches(&package, &affected));
    }

    #[test]
    fn pypi_exact_versions_use_pep440_equality() {
        let package = package_ref(
            "PyPI",
            "mypkg",
            "1.0",
            "mypkg==1.0\n",
            Path::new("requirements.txt"),
            0,
            10,
        );
        let affected = OsvAffected {
            package: Some(OsvPackage {
                name: Some("mypkg".to_string()),
                ecosystem: Some("PyPI".to_string()),
                purl: None,
            }),
            versions: vec!["1.0.0".to_string()],
            ..OsvAffected::default()
        };

        assert!(affected_version_matches(&package, &affected));
    }

    #[test]
    fn semver_prerelease_range_matches_before_final_release() {
        let package = package_ref(
            "npm",
            "demo",
            "1.0.0-rc.1",
            "demo@1.0.0-rc.1\n",
            Path::new("package-lock.json"),
            0,
            15,
        );
        let affected = OsvAffected {
            package: Some(OsvPackage {
                name: Some("demo".to_string()),
                ecosystem: Some("npm".to_string()),
                purl: None,
            }),
            ranges: vec![OsvRange {
                range_type: Some("SEMVER".to_string()),
                events: vec![
                    OsvEvent {
                        introduced: Some("0".to_string()),
                        ..OsvEvent::default()
                    },
                    OsvEvent {
                        fixed: Some("1.0.0".to_string()),
                        ..OsvEvent::default()
                    },
                ],
            }],
            ..OsvAffected::default()
        };

        assert!(affected_version_matches(&package, &affected));
    }

    #[test]
    fn range_matching_respects_limit_event() {
        let range = OsvRange {
            range_type: Some("SEMVER".to_string()),
            events: vec![
                OsvEvent {
                    introduced: Some("1.0.0".to_string()),
                    ..OsvEvent::default()
                },
                OsvEvent {
                    limit: Some("2.0.0".to_string()),
                    ..OsvEvent::default()
                },
            ],
        };
        let inside = package_ref(
            "crates.io",
            "demo",
            "1.5.0",
            "demo = 1.5.0\n",
            Path::new("Cargo.lock"),
            0,
            12,
        );
        let at_limit = package_ref(
            "crates.io",
            "demo",
            "2.0.0",
            "demo = 2.0.0\n",
            Path::new("Cargo.lock"),
            0,
            12,
        );

        assert!(version_in_range(&inside, &range));
        assert!(!version_in_range(&at_limit, &range));
    }

    #[test]
    fn first_fixed_version_uses_matching_range() {
        let package = package_ref(
            "npm",
            "demo",
            "3.1.0",
            "demo@3.1.0\n",
            Path::new("package-lock.json"),
            0,
            10,
        );
        let vuln = OsvVulnerability {
            id: "GHSA-test-0001".to_string(),
            affected: vec![OsvAffected {
                package: Some(OsvPackage {
                    name: Some("demo".to_string()),
                    ecosystem: Some("npm".to_string()),
                    purl: None,
                }),
                ranges: vec![
                    OsvRange {
                        range_type: Some("SEMVER".to_string()),
                        events: vec![
                            OsvEvent {
                                introduced: Some("1.0.0".to_string()),
                                ..OsvEvent::default()
                            },
                            OsvEvent {
                                fixed: Some("1.2.0".to_string()),
                                ..OsvEvent::default()
                            },
                        ],
                    },
                    OsvRange {
                        range_type: Some("SEMVER".to_string()),
                        events: vec![
                            OsvEvent {
                                introduced: Some("3.0.0".to_string()),
                                ..OsvEvent::default()
                            },
                            OsvEvent {
                                fixed: Some("3.2.5".to_string()),
                                ..OsvEvent::default()
                            },
                        ],
                    },
                ],
                ..OsvAffected::default()
            }],
            ..OsvVulnerability::default()
        };

        assert_eq!(
            first_fixed_version(&package, &vuln).as_deref(),
            Some("3.2.5")
        );
    }
}
