//! Terminal rendering for Semgrep import migration-readiness reports.

use crate::rules::semgrep_readiness::{
    SemgrepMigrationDisposition, SemgrepMigrationReadinessReport,
};

/// Render a deterministic human-readable migration-readiness report.
///
/// The summary aggregates by both normalized source language and stable reason
/// code before listing the one-record-per-source-rule inventory.
pub fn render_terminal(report: &SemgrepMigrationReadinessReport) -> String {
    let totals = report.total_by_disposition();
    let exact = count(&totals, SemgrepMigrationDisposition::Exact);
    let degraded = count(&totals, SemgrepMigrationDisposition::Degraded);
    let skipped = count(&totals, SemgrepMigrationDisposition::Skipped);

    let mut output = format!(
        "Semgrep migration readiness (schema {})\n\
         Rules: {}  exact: {}  degraded: {}  skipped: {}\n\n\
         By language:\n",
        report.schema_version,
        report.records.len(),
        exact,
        degraded,
        skipped,
    );
    for (language, language_totals) in report.total_by_language() {
        output.push_str(&format!(
            "  {}: exact={} degraded={} skipped={}\n",
            language,
            count(&language_totals, SemgrepMigrationDisposition::Exact),
            count(&language_totals, SemgrepMigrationDisposition::Degraded),
            count(&language_totals, SemgrepMigrationDisposition::Skipped),
        ));
    }

    output.push_str("\nBy reason:\n");
    for (reason, total) in report.total_by_reason() {
        output.push_str(&format!("  {}: {}\n", reason, total));
    }

    output.push_str("\nRecords:\n");
    for record in &report.records {
        output.push_str(&format!(
            "  {}  {}  {}  {}\n",
            record.source_id, record.language, record.disposition, record.reason_code
        ));
    }
    output
}

fn count(
    totals: &std::collections::BTreeMap<SemgrepMigrationDisposition, usize>,
    disposition: SemgrepMigrationDisposition,
) -> usize {
    totals.get(&disposition).copied().unwrap_or_default()
}
