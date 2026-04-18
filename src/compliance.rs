use crate::Finding;

/// Map a PQ-related rule ID to its CNSA 2.0 compliance deadline.
///
/// Returns `None` for non-PQ rules. Deadlines follow the NSA CNSA 2.0
/// timeline:
/// - `"2027-01"` — Jan 2027: all new NSS systems must use quantum-resistant
///   algorithms (key exchange / encryption)
/// - `"2030-12"` — Dec 2030: all deployed software using quantum-resistant
///   signatures
/// - `"2035"` — full transition complete (general / config rules)
pub fn cnsa2_deadline_for_rule(rule_id: &str) -> Option<&'static str> {
    // Key exchange / encryption — earliest deadline
    if rule_id.contains("pq-vulnerable") {
        // Distinguish by description context would be ideal, but rule_id
        // alone doesn't tell us key-exchange vs signature. Use the earlier
        // deadline since key exchange is the primary concern.
        return Some("2027-01");
    }

    // Crypto agility rules — general migration timeline
    if rule_id.contains("hardcoded-crypto-algorithm") {
        return Some("2035");
    }

    // Config file TLS rules — need TLSv1.3 for PQ key exchange
    if rule_id.starts_with("config/") && rule_id.contains("tls") {
        return Some("2027-01");
    }

    // Dockerfile TLS verification — not directly PQ but security hygiene
    if rule_id.contains("dockerfile-insecure-tls") {
        return Some("2035");
    }

    None
}

/// Annotate findings with CNSA 2.0 deadlines based on rule ID.
pub fn annotate_cnsa2_deadlines(findings: &mut [Finding]) {
    for finding in findings.iter_mut() {
        finding.cnsa2_deadline = cnsa2_deadline_for_rule(&finding.rule_id).map(|s| s.to_string());
    }
}

/// PQ migration readiness level (1–5), inspired by Meta's framework.
#[derive(Debug, Clone)]
pub struct PqMigrationLevel {
    pub level: u8,
    pub label: &'static str,
    pub pq_finding_count: usize,
    pub agility_finding_count: usize,
}

/// Compute the PQ migration readiness level from scan findings.
///
/// Levels:
/// - 5 PQ-Enabled: no PQ-vulnerable findings
/// - 4 PQ-Hardened: only crypto agility findings (no direct PQ vulnerability)
/// - 3 PQ-Ready: few PQ-vulnerable findings (≤ 5)
/// - 2 PQ-Aware: PQ findings exist (we're scanning)
/// - 1 PQ-Unaware: not assessed (no PQ rules matched — codebase may not use crypto)
pub fn compute_pq_migration_level(findings: &[Finding]) -> Option<PqMigrationLevel> {
    let pq_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.cnsa2_deadline.is_some() && !f.rule_id.contains("hardcoded-crypto-algorithm"))
        .collect();

    let agility_findings = findings
        .iter()
        .filter(|f| f.rule_id.contains("hardcoded-crypto-algorithm"))
        .count();

    let pq_count = pq_findings.len();

    // If no PQ-related findings at all, don't report a level
    if pq_count == 0 && agility_findings == 0 {
        return None;
    }

    let (level, label) = if pq_count == 0 && agility_findings == 0 {
        (5, "PQ-Enabled")
    } else if pq_count == 0 && agility_findings > 0 {
        (4, "PQ-Hardened")
    } else if pq_count <= 5 {
        (3, "PQ-Ready")
    } else {
        (2, "PQ-Aware")
    };

    Some(PqMigrationLevel {
        level,
        label,
        pq_finding_count: pq_count,
        agility_finding_count: agility_findings,
    })
}
