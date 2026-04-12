use crate::{Finding, Severity};
use colored::Colorize;

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
                "{}  Scanned {} files in {:.2}s",
                "No security issues found.".green().bold(),
                files_scanned.to_string().bold(),
                duration.as_secs_f64(),
            );
        } else {
            println!("{}", "No security issues found.".green().bold());
        }
        return;
    }

    let mut current_file = String::new();

    for f in findings {
        if f.file != current_file {
            current_file = f.file.clone();
            println!("\n{}", current_file.bold().underline());
        }

        let severity_str = match f.severity {
            Severity::Critical => format!(" {} ", "CRITICAL").on_red().white().bold(),
            Severity::High => format!(" {} ", "HIGH").on_red().white().bold(),
            Severity::Medium => format!(" {} ", "MEDIUM").on_yellow().black().bold(),
            Severity::Low => format!(" {} ", "LOW").on_blue().white().bold(),
        };

        let cwe = f
            .cwe
            .as_ref()
            .map(|c| format!(" ({})", c))
            .unwrap_or_default();

        println!(
            "  {}:{} {} {}{} {}",
            f.line.to_string().dimmed(),
            f.column.to_string().dimmed(),
            severity_str,
            f.rule_id.cyan(),
            cwe.dimmed(),
            f.description,
        );

        if !f.snippet.is_empty() {
            for line in f.snippet.lines() {
                println!("    {}", line.dimmed());
            }
        }

        // When --explain is active, print source/sink trace for taint findings
        if explain {
            if let (Some(src_line), Some(src_desc)) = (f.source_line, f.source_description.as_ref())
            {
                println!(
                    "    {} {} {}:{}   {}",
                    "source".yellow().bold(),
                    "\u{2192}".dimmed(),
                    f.file.dimmed(),
                    src_line.to_string().dimmed(),
                    src_desc,
                );
            }
            if let (Some(snk_line), Some(snk_desc)) = (f.sink_line, f.sink_description.as_ref()) {
                println!(
                    "    {} {} {}:{}   {}",
                    "sink  ".yellow().bold(),
                    "\u{2192}".dimmed(),
                    f.file.dimmed(),
                    snk_line.to_string().dimmed(),
                    snk_desc,
                );
            }
            if let Some(fix) = f.fix_suggestion.as_ref() {
                println!("  {} {}", "Fix:".green().bold(), fix);
            }
        }
    }

    // Summary
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

    let stats = if files_scanned > 0 {
        format!(
            " in {} files ({:.2}s)",
            files_scanned,
            duration.as_secs_f64()
        )
    } else {
        String::new()
    };

    println!(
        "\n{} {}{}: {} critical, {} high, {} medium, {} low",
        "WARNING".yellow(),
        format!("{} issues", findings.len()).bold(),
        stats.dimmed(),
        critical.to_string().red().bold(),
        high.to_string().red(),
        medium.to_string().yellow(),
        low.to_string().blue(),
    );
}
