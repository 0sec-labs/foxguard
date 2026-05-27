use crate::cli::{DiffArgs, OutputFormat, ScanArgs, SecretsArgs};
use crate::report::json::{
    build_json_report, JsonConfigMetadata, JsonReportMetadata, JsonTargetMetadata,
};
use crate::Finding;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const CONFIG_NAMES: [&str; 4] = [
    ".foxguard.yml",
    ".foxguard.yaml",
    "foxguard.yml",
    "foxguard.yaml",
];

pub fn emit_scan_report(
    findings: &[Finding],
    args: &ScanArgs,
    files_scanned: usize,
    duration: Duration,
) -> Result<(), String> {
    match args.format {
        OutputFormat::Terminal => validate_terminal_output_path(args.output.as_deref()),
        OutputFormat::Json => emit_json(
            findings,
            args.output.as_deref(),
            JsonReportMetadata {
                command: if args.pq_mode {
                    "pqc"
                } else if args.sca && args.no_builtins {
                    "sca"
                } else {
                    "scan"
                },
                config: config_metadata(&args.path, args.config.as_deref()),
                target: JsonTargetMetadata {
                    path: &args.path,
                    kind: target_kind(&args.path),
                    changed_only: args.changes.selection().is_some(),
                    files_scanned,
                    diff_base: None,
                },
                duration,
            },
        ),
        OutputFormat::Sarif => emit_sarif(findings, args.output.as_deref()),
        OutputFormat::Cbom => emit_cbom(findings, args.output.as_deref()),
    }
}

pub fn emit_secrets_report(
    findings: &[Finding],
    args: &SecretsArgs,
    files_scanned: usize,
    duration: Duration,
) -> Result<(), String> {
    match args.format {
        OutputFormat::Terminal => validate_terminal_output_path(args.output.as_deref()),
        OutputFormat::Json => emit_json(
            findings,
            args.output.as_deref(),
            JsonReportMetadata {
                command: "secrets",
                config: config_metadata(&args.path, args.config.as_deref()),
                target: JsonTargetMetadata {
                    path: &args.path,
                    kind: target_kind(&args.path),
                    changed_only: args.changes.selection().is_some(),
                    files_scanned,
                    diff_base: None,
                },
                duration,
            },
        ),
        OutputFormat::Sarif => emit_sarif(findings, args.output.as_deref()),
        OutputFormat::Cbom => emit_cbom(findings, args.output.as_deref()),
    }
}

pub fn emit_diff_report(
    findings: &[Finding],
    args: &DiffArgs,
    files_scanned: usize,
    duration: Duration,
) -> Result<(), String> {
    match args.format {
        OutputFormat::Terminal => validate_terminal_output_path(args.output.as_deref()),
        OutputFormat::Json => emit_json(
            findings,
            args.output.as_deref(),
            JsonReportMetadata {
                command: "diff",
                config: config_metadata(&args.path, None),
                target: JsonTargetMetadata {
                    path: &args.path,
                    kind: target_kind(&args.path),
                    changed_only: false,
                    files_scanned,
                    diff_base: Some(&args.target),
                },
                duration,
            },
        ),
        OutputFormat::Sarif => emit_sarif(findings, args.output.as_deref()),
        OutputFormat::Cbom => emit_cbom(findings, args.output.as_deref()),
    }
}

fn emit_json(
    findings: &[Finding],
    output_path: Option<&str>,
    metadata: JsonReportMetadata<'_>,
) -> Result<(), String> {
    let report = build_json_report(findings, metadata);
    let content = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("Failed to serialize JSON report: {e}"))?;
    write_report(&content, output_path, "JSON")
}

fn emit_sarif(findings: &[Finding], output_path: Option<&str>) -> Result<(), String> {
    let sarif = crate::report::sarif::build_sarif(findings);
    let content = serde_json::to_string_pretty(&sarif)
        .map_err(|e| format!("Failed to serialize SARIF: {e}"))?;
    write_report(&content, output_path, "SARIF")
}

fn emit_cbom(findings: &[Finding], output_path: Option<&str>) -> Result<(), String> {
    let (cbom, empty_but_findings_present) = crate::report::cbom::build_cbom(findings);

    if empty_but_findings_present {
        eprintln!(
            "Warning: no cryptographic findings detected; CBOM is empty. \
             Use 'foxguard pqc' to scan for quantum-vulnerable cryptography."
        );
    }

    let content = serde_json::to_string_pretty(&cbom)
        .map_err(|e| format!("Failed to serialize CBOM: {e}"))?;
    write_report(&content, output_path, "CBOM")
}

fn write_report(content: &str, output_path: Option<&str>, label: &str) -> Result<(), String> {
    match output_path {
        Some(path) => {
            let path = Path::new(path);
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent).map_err(|e| {
                        format!(
                            "Failed to create output directory '{}': {}",
                            parent.display(),
                            e
                        )
                    })?;
                }
            }
            fs::write(path, content).map_err(|e| {
                format!(
                    "Failed to write {} report to '{}': {}",
                    label,
                    path.display(),
                    e
                )
            })?;
            eprintln!("Wrote {} report to {}", label, path.display());
            Ok(())
        }
        None => {
            println!("{content}");
            Ok(())
        }
    }
}

fn validate_terminal_output_path(output_path: Option<&str>) -> Result<(), String> {
    if output_path.is_some() {
        return Err("--output requires a machine-readable format".to_string());
    }
    Ok(())
}

fn config_metadata(scan_path: &str, explicit_path: Option<&str>) -> JsonConfigMetadata {
    if let Some(path) = explicit_path {
        return JsonConfigMetadata {
            source: "explicit",
            path: Some(normalize_path(Path::new(path))),
        };
    }

    match discover_config_path(Path::new(scan_path)) {
        Some(path) => JsonConfigMetadata {
            source: "discovered",
            path: Some(normalize_path(&path)),
        },
        None => JsonConfigMetadata {
            source: "none",
            path: None,
        },
    }
}

fn discover_config_path(scan_path: &Path) -> Option<PathBuf> {
    let start = scan_path
        .canonicalize()
        .unwrap_or_else(|_| scan_path.to_path_buf());
    let start = if start.is_file() {
        start
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        start
    };

    for dir in start.ancestors() {
        for name in CONFIG_NAMES {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    None
}

fn normalize_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

fn target_kind(path: &str) -> &'static str {
    let path = Path::new(path);
    if path.is_file() {
        "file"
    } else if path.is_dir() {
        "directory"
    } else {
        "path"
    }
}
