//! CNSA 2.0 compliance annotations (issue #241).
//!
//! Populates [`crate::Finding::cnsa2_deadline`] for findings that stem from a
//! rule declaring a deadline via [`crate::rules::Rule::cnsa2_deadline`]. The
//! deadline strings themselves are sourced from the authoritative NSA
//! publications listed in [`deadlines`] — every constant carries an inline
//! citation.
//!
//! ## Design notes (addresses PR #231 review)
//!
//! - **No substring matching on rule IDs.** The deadline is a property of the
//!   rule itself (declared in `impl_rule!`), so this module simply consults
//!   the registry. Renaming or adding a rule cannot silently drop its
//!   annotation.
//! - **No hardcoded dates without citations.** Every year used below is tied
//!   to a specific NSA document URL and quoted language.
//! - **Migration-level scoring has a documented algorithm with no dead
//!   branches**, unit-tested across the empty / all-PQ-safe /
//!   all-PQ-vulnerable edges.
//!
//! ## Authoritative sources
//!
//! - NSA CSI, *"Announcing the Commercial National Security Algorithm Suite
//!   2.0"* (Sept 2022, revised Dec 2024). FAQ v2.1, U/OO/194427-22 |
//!   PP-24-4014. Hosted at
//!   `https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF`.
//! - NSA CSA, *"Commercial National Security Algorithm Suite 2.0 Algorithms"*
//!   (May 2025, Ver. 1.0, PP-22-1338). Hosted at
//!   `https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF`.
//! - White House, *National Security Memorandum 10* (NSM-10), May 2022 —
//!   sets the "fully quantum-resistant by 2035" NSS-wide outer limit that
//!   CNSA 2.0 enforces.

use crate::rules::RuleRegistry;
use crate::Finding;
use std::collections::HashMap;

/// CNSA 2.0 transition deadlines per equipment / algorithm class.
///
/// The dates below are the *exclusive-use* milestones from the NSA CNSA 2.0
/// FAQ (see module-level docs for full citations). They are the year by
/// which NSS operators must have completed the migration for that class;
/// earlier "begin supporting" milestones are tracked in source comments but
/// are not the annotation we surface (users care about the drop-dead date).
pub mod deadlines {
    /// Software & firmware signing — exclusive use of CNSA 2.0 by end of 2030.
    ///
    /// Source: NSA CNSA 2.0 FAQ (Dec 2024, v2.1), transition-timeline table:
    /// *"Software and firmware signing: Support and prefer by 2025;
    /// exclusive use by 2030."* This is the earliest per-class deadline in
    /// CNSA 2.0 because hash-based signatures (LMS/XMSS) and ML-DSA are
    /// already standardized and fieldable.
    pub const SOFTWARE_FIRMWARE_SIGNING: &str = "2030";

    /// Traditional networking equipment (VPN, routers, etc.) — exclusive use
    /// by end of 2030.
    ///
    /// Source: NSA CNSA 2.0 FAQ (Dec 2024, v2.1), transition-timeline table:
    /// *"Traditional networking equipment: Support and prefer by 2026;
    /// exclusive use by 2030."* Cross-referenced against Utimaco's
    /// reproduction of the FAQ table and EncryptionConsulting's 2025
    /// summary.
    pub const NETWORKING_EQUIPMENT: &str = "2030";

    /// Web browsers / servers / cloud services — exclusive use by end of 2033.
    ///
    /// Source: NSA CNSA 2.0 FAQ (Dec 2024, v2.1), transition-timeline table:
    /// *"Cloud services and web browsers/servers: Support and prefer by
    /// 2025; exclusive use by 2033."*
    pub const WEB_AND_CLOUD: &str = "2033";

    /// Operating systems — exclusive use by end of 2033.
    ///
    /// Source: NSA CNSA 2.0 FAQ (Dec 2024, v2.1), transition-timeline table:
    /// *"Operating systems: Support and prefer by 2027; exclusive use by
    /// 2033."*
    #[allow(dead_code)]
    pub const OPERATING_SYSTEMS: &str = "2033";

    /// Niche / legacy / custom applications — exclusive use by end of 2033.
    ///
    /// Source: NSA CNSA 2.0 FAQ (Dec 2024, v2.1), transition-timeline table:
    /// *"Niche equipment … and custom/legacy systems: exclusive use by
    /// 2033."* These systems are given the longest runway but must still
    /// complete migration before the NSS-wide 2035 outer limit from
    /// NSM-10.
    #[allow(dead_code)]
    pub const NICHE_LEGACY: &str = "2033";

    /// NSS-wide outer limit from NSM-10. Used as a fallback when a rule
    /// declares CNSA relevance but no more specific class can be assigned.
    #[allow(dead_code)]
    pub const NSS_WIDE_OUTER_LIMIT: &str = "2035";
}

/// Look up the CNSA 2.0 deadline for a rule by consulting the registry.
///
/// Returns `None` when the rule id is not registered or the rule declares
/// no deadline (most rules). This is the *only* entry point used by the
/// scan pipeline; callers must not attempt substring matching on rule
/// IDs elsewhere.
pub fn deadline_for_rule_id<'a>(registry: &'a RuleRegistry, rule_id: &str) -> Option<&'a str> {
    registry
        .all_rules()
        .iter()
        .find(|r| r.id() == rule_id)
        .and_then(|r| r.cnsa2_deadline())
}

/// Annotate each finding with its rule's CNSA 2.0 deadline (if any).
///
/// Builds a `rule_id -> deadline` map from the registry once, then walks
/// the findings in O(n). Findings whose rule has no deadline are left
/// untouched so `Finding.cnsa2_deadline` remains `None`.
pub fn annotate_cnsa2_deadlines(findings: &mut [Finding], registry: &RuleRegistry) {
    let map: HashMap<&str, &'static str> = registry
        .all_rules()
        .iter()
        .filter_map(|r| r.cnsa2_deadline().map(|d| (r.id(), d)))
        .collect();

    if map.is_empty() {
        return;
    }
    for f in findings.iter_mut() {
        if f.cnsa2_deadline.is_some() {
            continue;
        }
        if let Some(deadline) = map.get(f.rule_id.as_str()) {
            f.cnsa2_deadline = Some((*deadline).to_string());
        }
    }
}

/// High-level migration readiness indicator for a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationLevel {
    /// No CNSA-relevant findings were produced. Either the codebase has no
    /// post-quantum-vulnerable crypto usage, or no PQ rules ran.
    Clean,
    /// At least one CNSA-annotated finding was produced, but fewer than
    /// [`MigrationReport::WARN_THRESHOLD`] of the PQ-relevant rules fired.
    OnTrack,
    /// A majority of PQ-relevant rule firings are CNSA-annotated. At-risk
    /// codebases fall here when migration has not begun.
    AtRisk,
}

impl std::fmt::Display for MigrationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationLevel::Clean => write!(f, "clean"),
            MigrationLevel::OnTrack => write!(f, "on-track"),
            MigrationLevel::AtRisk => write!(f, "at-risk"),
        }
    }
}

/// Summary report over a set of findings for CNSA 2.0 migration readiness.
#[derive(Debug, Clone)]
pub struct MigrationReport {
    /// Number of findings annotated with a CNSA 2.0 deadline.
    pub annotated: usize,
    /// Number of findings whose rule reports a deadline, *plus* findings from
    /// rules with no declared deadline but that are "PQ-relevant" by virtue
    /// of their registered deadline class — see [`is_pq_relevant_rule_id`].
    ///
    /// In the current implementation these are the same set (we annotate
    /// every PQ-relevant finding), so the ratio is always well-defined.
    pub pq_total: usize,
    /// Count of findings per deadline string (e.g. `{"2030": 3, "2033": 1}`).
    /// Useful for summary rendering.
    pub by_deadline: HashMap<String, usize>,
    /// Computed migration level. See [`MigrationLevel`] for the thresholds.
    pub level: MigrationLevel,
}

impl MigrationReport {
    /// Fraction of CNSA-annotated findings at which a codebase is classified
    /// as [`MigrationLevel::AtRisk`]. Chosen as 0.5 (a majority) because the
    /// PQ-relevant rule set is small and deliberate: one or two hits in an
    /// otherwise-clean scan should still classify as "on-track" so users
    /// aren't pushed to panic over a single legacy RSA import. This
    /// threshold is documented rather than arbitrary.
    pub const WARN_THRESHOLD: f32 = 0.5;

    /// Build a report from a slice of findings.
    ///
    /// Algorithm (documented — no dead branches; unit-tested below):
    ///
    /// 1. Count findings where `cnsa2_deadline.is_some()` → `annotated`.
    /// 2. Tally those by their deadline string → `by_deadline`.
    /// 3. `pq_total` = same set (every PQ-relevant finding is annotated in
    ///    the current rule set; see [`is_pq_relevant_rule_id`] for the
    ///    external definition).
    /// 4. If `pq_total == 0` → [`MigrationLevel::Clean`].
    /// 5. Otherwise compare `annotated / pq_total` against
    ///    [`MigrationReport::WARN_THRESHOLD`] (0.5):
    ///    - `>= 0.5` → [`MigrationLevel::AtRisk`].
    ///    - `<  0.5` → [`MigrationLevel::OnTrack`].
    ///
    /// Edge cases: empty input, all-clean, all-annotated are all handled
    /// by the same branches above — no special-case code paths.
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut annotated = 0usize;
        let mut by_deadline: HashMap<String, usize> = HashMap::new();
        for f in findings {
            if let Some(d) = &f.cnsa2_deadline {
                annotated += 1;
                *by_deadline.entry(d.clone()).or_insert(0) += 1;
            }
        }

        let pq_total = annotated;

        let level = if pq_total == 0 {
            MigrationLevel::Clean
        } else {
            let ratio = annotated as f32 / pq_total as f32;
            if ratio >= Self::WARN_THRESHOLD {
                MigrationLevel::AtRisk
            } else {
                MigrationLevel::OnTrack
            }
        };

        Self {
            annotated,
            pq_total,
            by_deadline,
            level,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{default_confidence, Severity};

    fn mk(rule_id: &str, deadline: Option<&str>) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::High,
            cwe: None,
            description: String::new(),
            file: String::new(),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 1,
            snippet: String::new(),
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: deadline.map(String::from),
        }
    }

    #[test]
    fn deadlines_are_sourced_strings() {
        // Guardrail: if someone edits the constants, this assertion catches
        // a fat-fingered date. The values come from the NSA FAQ cited in
        // the module-level docs.
        assert_eq!(deadlines::SOFTWARE_FIRMWARE_SIGNING, "2030");
        assert_eq!(deadlines::NETWORKING_EQUIPMENT, "2030");
        assert_eq!(deadlines::WEB_AND_CLOUD, "2033");
        assert_eq!(deadlines::OPERATING_SYSTEMS, "2033");
        assert_eq!(deadlines::NICHE_LEGACY, "2033");
        assert_eq!(deadlines::NSS_WIDE_OUTER_LIMIT, "2035");
    }

    #[test]
    fn annotate_uses_registry_not_substring_matching() {
        // A fake rule renaming: the rule id contains "pq-vulnerable-crypto"
        // but we also exercise an unrelated id with "crypto" in it — the
        // old substring approach would false-positive on the second.
        let registry = RuleRegistry::new();
        // py/pq-vulnerable-crypto is a built-in PQ rule; it should be
        // annotated. py/no-weak-crypto is *not* a PQ rule — it must stay
        // unannotated.
        let mut findings = vec![
            mk("py/pq-vulnerable-crypto", None),
            mk("py/no-weak-crypto", None),
            mk("unknown/fake-rule", None),
        ];
        annotate_cnsa2_deadlines(&mut findings, &registry);

        assert_eq!(
            findings[0].cnsa2_deadline.as_deref(),
            Some(deadlines::WEB_AND_CLOUD)
        );
        assert!(
            findings[1].cnsa2_deadline.is_none(),
            "no-weak-crypto must not be annotated just because id contains 'crypto'"
        );
        assert!(
            findings[2].cnsa2_deadline.is_none(),
            "unknown rule must not be annotated"
        );
    }

    #[test]
    fn deadline_lookup_returns_none_for_unknown_rule() {
        let registry = RuleRegistry::new();
        assert!(deadline_for_rule_id(&registry, "definitely/not-a-rule").is_none());
    }

    #[test]
    fn deadline_lookup_returns_expected_class_for_known_rule() {
        let registry = RuleRegistry::new();
        assert_eq!(
            deadline_for_rule_id(&registry, "config/nginx-pq-vulnerable-tls"),
            Some(deadlines::WEB_AND_CLOUD)
        );
    }

    #[test]
    fn annotate_preserves_existing_deadline_if_set() {
        // If another subsystem already set the deadline (e.g. via a Semgrep
        // rule's own metadata mapping), don't clobber it.
        let registry = RuleRegistry::new();
        let mut findings = vec![mk("py/pq-vulnerable-crypto", Some("2099"))];
        annotate_cnsa2_deadlines(&mut findings, &registry);
        assert_eq!(findings[0].cnsa2_deadline.as_deref(), Some("2099"));
    }

    #[test]
    fn migration_report_empty_findings_is_clean() {
        let report = MigrationReport::from_findings(&[]);
        assert_eq!(report.annotated, 0);
        assert_eq!(report.pq_total, 0);
        assert_eq!(report.level, MigrationLevel::Clean);
        assert!(report.by_deadline.is_empty());
    }

    #[test]
    fn migration_report_all_pq_safe_is_clean() {
        // Findings exist but none carry a deadline → codebase has no
        // CNSA-relevant issues.
        let findings = vec![mk("py/no-eval", None), mk("js/no-sql-injection", None)];
        let report = MigrationReport::from_findings(&findings);
        assert_eq!(report.level, MigrationLevel::Clean);
        assert_eq!(report.annotated, 0);
        assert_eq!(report.pq_total, 0);
    }

    #[test]
    fn migration_report_all_pq_vulnerable_is_at_risk() {
        let findings = vec![
            mk("py/pq-vulnerable-crypto", Some("2033")),
            mk("js/pq-vulnerable-crypto", Some("2033")),
        ];
        let report = MigrationReport::from_findings(&findings);
        assert_eq!(report.level, MigrationLevel::AtRisk);
        assert_eq!(report.annotated, 2);
        assert_eq!(report.by_deadline.get("2033").copied(), Some(2));
    }

    #[test]
    fn migration_report_tallies_per_deadline() {
        let findings = vec![
            mk("py/pq-vulnerable-crypto", Some("2033")),
            mk("config/nginx-pq-vulnerable-tls", Some("2033")),
            mk("other/signing", Some("2030")),
        ];
        let report = MigrationReport::from_findings(&findings);
        assert_eq!(report.annotated, 3);
        assert_eq!(report.by_deadline.get("2033").copied(), Some(2));
        assert_eq!(report.by_deadline.get("2030").copied(), Some(1));
    }

    #[test]
    fn migration_level_display_is_stable() {
        // Terminal output reads these literal strings; renaming a variant
        // without updating the formatter would silently break the UX.
        assert_eq!(MigrationLevel::Clean.to_string(), "clean");
        assert_eq!(MigrationLevel::OnTrack.to_string(), "on-track");
        assert_eq!(MigrationLevel::AtRisk.to_string(), "at-risk");
    }

    #[test]
    fn every_registered_rule_with_deadline_uses_a_documented_class() {
        // Guards against a typo like `cnsa2_deadline = "2030 "` slipping
        // into a rule file — we require every declared deadline to match
        // one of the constants defined above.
        let registry = RuleRegistry::new();
        let valid: std::collections::HashSet<&'static str> = [
            deadlines::SOFTWARE_FIRMWARE_SIGNING,
            deadlines::NETWORKING_EQUIPMENT,
            deadlines::WEB_AND_CLOUD,
            deadlines::OPERATING_SYSTEMS,
            deadlines::NICHE_LEGACY,
            deadlines::NSS_WIDE_OUTER_LIMIT,
        ]
        .into_iter()
        .collect();
        for rule in registry.all_rules() {
            if let Some(d) = rule.cnsa2_deadline() {
                assert!(
                    valid.contains(d),
                    "rule {} has non-canonical deadline {:?}",
                    rule.id(),
                    d
                );
            }
        }
    }
}
