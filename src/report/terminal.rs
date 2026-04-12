use crate::{Finding, Severity};
use colored::Colorize;
use std::path::Path;

const MAX_SNIPPET_WIDTH: usize = 120;

pub fn print_banner() {
    // Print on same line so we can overwrite with clear_banner
    eprint!(
        "\r  {} {} {} ",
        "foxguard".truecolor(245, 158, 11).bold(),
        format!("v{}", env!("CARGO_PKG_VERSION")).dimmed(),
        "\u{00b7} scanning...".dimmed(),
    );
}

pub fn clear_banner() {
    // Clear the scanning line and move cursor back
    eprint!("\r{}\r", " ".repeat(60));
}

/// Shorten a file path for display. If the path is absolute and starts with
/// the current working directory, strip the prefix to show a relative path.
fn display_path(path: &str) -> String {
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(rel) = Path::new(path).strip_prefix(&cwd) {
            return rel.display().to_string();
        }
    }
    // If it's still long, show just the last 3 components
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > 4 {
        format!(".../{}", parts[parts.len() - 3..].join("/"))
    } else {
        path.to_string()
    }
}

pub fn print_findings(findings: &[Finding], files_scanned: usize, duration: std::time::Duration) {
    print_findings_with_options(findings, files_scanned, duration, false);
}

pub fn print_findings_with_options(
    findings: &[Finding],
    files_scanned: usize,
    duration: std::time::Duration,
    explain: bool,
) {
    if findings.is_empty() {
        if files_scanned > 0 {
            println!(
                "\n  {} Scanned {} files in {:.2}s.\n",
                "\u{2714}".green(),
                files_scanned,
                duration.as_secs_f64(),
            );
        } else {
            println!("\n  {} No security issues found.\n", "\u{2714}".green());
        }
        return;
    }

    // Group by file
    let mut by_file: Vec<(&str, Vec<&Finding>)> = Vec::new();
    let mut current_file = "";
    for f in findings {
        if f.file != current_file {
            current_file = &f.file;
            by_file.push((&f.file, Vec::new()));
        }
        by_file.last_mut().unwrap().1.push(f);
    }

    println!();

    for (file, file_findings) in &by_file {
        let count = file_findings.len();
        let label = if count == 1 { "issue" } else { "issues" };
        let short_path = display_path(file);
        println!(
            "  {} {} {}",
            short_path.bold(),
            "\u{00b7}".dimmed(),
            format!("{count} {label}").dimmed(),
        );
        println!();

        for f in file_findings {
            print_finding(f, explain);
        }
        println!();
    }

    print_summary(findings, files_scanned, duration);
}

fn severity_badge(severity: Severity) -> colored::ColoredString {
    match severity {
        Severity::Critical => " CRITICAL ".on_truecolor(130, 50, 180).white().bold(),
        Severity::High => " HIGH ".on_red().white().bold(),
        Severity::Medium => " MEDIUM ".on_yellow().black().bold(),
        Severity::Low => " LOW ".on_blue().white().bold(),
    }
}

fn severity_accent(severity: Severity) -> colored::ColoredString {
    match severity {
        Severity::Critical => "\u{2588}".truecolor(130, 50, 180),
        Severity::High => "\u{2588}".red(),
        Severity::Medium => "\u{2588}".yellow(),
        Severity::Low => "\u{2588}".blue(),
    }
}

fn truncate_snippet(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed.len() <= MAX_SNIPPET_WIDTH {
        return trimmed.to_string();
    }
    let mut end = MAX_SNIPPET_WIDTH;
    while end > 0 && !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &trimmed[..end])
}

fn print_finding(f: &Finding, explain: bool) {
    let accent = severity_accent(f.severity);
    let badge = severity_badge(f.severity);
    let cwe = f
        .cwe
        .as_ref()
        .map(|c| format!(" ({c})"))
        .unwrap_or_default();

    // Line 1: badge + description (the main thing you read)
    println!("    {accent} {badge} {}", f.description,);

    // Line 2: rule ID + CWE + location (secondary info, dimmed)
    println!(
        "    {accent}   {}{}  {}",
        f.rule_id.cyan().dimmed(),
        cwe.dimmed(),
        format!("line {}:{}", f.line, f.column).dimmed(),
    );

    // Code snippet (recessed further)
    if !f.snippet.is_empty() {
        for line in f.snippet.lines() {
            let truncated = truncate_snippet(line);
            println!("    {accent}   {}", truncated.dimmed());
        }
    }

    // Source/sink trace
    if explain {
        if let (Some(src_line), Some(src_desc)) = (f.source_line, f.source_description.as_ref()) {
            let src_path = display_path(&f.file);
            println!(
                "    {accent} {} {}:{}  {}",
                "source \u{2192}".yellow(),
                src_path.dimmed(),
                src_line.to_string().dimmed(),
                src_desc,
            );
        }
        if let (Some(snk_line), Some(snk_desc)) = (f.sink_line, f.sink_description.as_ref()) {
            let snk_path = display_path(&f.file);
            println!(
                "    {accent} {} {}:{}  {}",
                "sink   \u{2192}".red(),
                snk_path.dimmed(),
                snk_line.to_string().dimmed(),
                snk_desc,
            );
        }
    }

    // Fix suggestion
    if let Some(fix) = f.fix_suggestion.as_ref() {
        println!("    {accent} {} {}", "Fix:".green().bold(), fix);
    }

    // Blank line between findings
    println!();
}

fn print_summary(findings: &[Finding], files_scanned: usize, duration: std::time::Duration) {
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();

    let mut badges = Vec::new();
    if critical > 0 {
        badges.push(format!(
            "{}",
            format!(" {critical} critical ")
                .on_truecolor(130, 50, 180)
                .white()
                .bold()
        ));
    }
    if high > 0 {
        badges.push(format!(
            "{}",
            format!(" {high} high ").on_red().white().bold()
        ));
    }
    if medium > 0 {
        badges.push(format!(
            "{}",
            format!(" {medium} medium ").on_yellow().black().bold()
        ));
    }
    if low > 0 {
        badges.push(format!(
            "{}",
            format!(" {low} low ").on_blue().white().bold()
        ));
    }

    let total = findings.len();
    let secs = duration.as_secs_f64();

    println!("  {}", "\u{2500}".repeat(50).dimmed());
    println!();
    println!(
        "  {} {}  {}",
        format!("{total}").bold(),
        "issues".dimmed(),
        format!("{files_scanned} files \u{00b7} {secs:.2}s").dimmed(),
    );
    println!();
    println!("  {}", badges.join("  "));
    println!();
}
