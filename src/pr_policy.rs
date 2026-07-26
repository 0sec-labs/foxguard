use crate::{Finding, Severity};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// Stable identifier for the first PR-security-policy contract.
pub const PR_SECURITY_POLICY_V1: &str = "v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum PrSecurityPolicyVersion {
    #[serde(rename = "v1")]
    #[value(name = "v1")]
    V1,
}

impl Default for PrSecurityPolicyVersion {
    fn default() -> Self {
        Self::V1
    }
}

impl std::fmt::Display for PrSecurityPolicyVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(PR_SECURITY_POLICY_V1)
    }
}

/// The set of findings a v1 policy evaluates.
///
/// V1 deliberately evaluates the complete result of a PR scan. This is the
/// only scope every current surface can derive identically; a future policy
/// version can add a diff-specific scope without changing this contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum PrSecurityPolicyScope {
    #[serde(rename = "repository")]
    #[value(name = "repository")]
    Repository,
}

impl Default for PrSecurityPolicyScope {
    fn default() -> Self {
        Self::Repository
    }
}

impl std::fmt::Display for PrSecurityPolicyScope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("repository")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum PrBlockingThreshold {
    #[serde(rename = "none")]
    #[value(name = "none")]
    None,
    #[serde(rename = "low")]
    #[value(name = "low")]
    Low,
    #[serde(rename = "medium")]
    #[value(name = "medium")]
    Medium,
    #[serde(rename = "high")]
    #[value(name = "high")]
    High,
    #[serde(rename = "critical")]
    #[value(name = "critical")]
    Critical,
}

impl PrBlockingThreshold {
    pub fn severity(self) -> Option<Severity> {
        match self {
            Self::None => None,
            Self::Low => Some(Severity::Low),
            Self::Medium => Some(Severity::Medium),
            Self::High => Some(Severity::High),
            Self::Critical => Some(Severity::Critical),
        }
    }
}

impl Default for PrBlockingThreshold {
    fn default() -> Self {
        Self::High
    }
}

impl std::fmt::Display for PrBlockingThreshold {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        })
    }
}

/// Optional policy values from `.foxguard.yml` or a surface adapter.
///
/// Later inputs override earlier inputs. Keeping the optional wire shape
/// separate from [`PrSecurityPolicy`] makes the resolved defaults explicit in
/// every emitted result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrSecurityPolicyInput {
    pub version: Option<PrSecurityPolicyVersion>,
    pub scope: Option<PrSecurityPolicyScope>,
    pub reporting_threshold: Option<Severity>,
    pub blocking_threshold: Option<PrBlockingThreshold>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrSecurityPolicy {
    pub version: PrSecurityPolicyVersion,
    pub scope: PrSecurityPolicyScope,
    pub reporting_threshold: Severity,
    pub blocking_threshold: PrBlockingThreshold,
}

impl Default for PrSecurityPolicy {
    fn default() -> Self {
        Self {
            version: PrSecurityPolicyVersion::V1,
            scope: PrSecurityPolicyScope::Repository,
            reporting_threshold: Severity::Medium,
            blocking_threshold: PrBlockingThreshold::High,
        }
    }
}

/// Resolve configuration and surface overrides into the one policy evaluated by
/// every PR surface. Surface values win over repository configuration.
pub fn resolve(
    configured: Option<&PrSecurityPolicyInput>,
    overrides: &PrSecurityPolicyInput,
) -> Result<PrSecurityPolicy, String> {
    let defaults = PrSecurityPolicy::default();
    let version = overrides
        .version
        .or_else(|| configured.and_then(|policy| policy.version))
        .unwrap_or(defaults.version);
    let scope = overrides
        .scope
        .or_else(|| configured.and_then(|policy| policy.scope))
        .unwrap_or(defaults.scope);
    let reporting_threshold = overrides
        .reporting_threshold
        .or_else(|| configured.and_then(|policy| policy.reporting_threshold))
        .unwrap_or(defaults.reporting_threshold);
    let blocking_threshold = overrides
        .blocking_threshold
        .or_else(|| configured.and_then(|policy| policy.blocking_threshold))
        .unwrap_or(defaults.blocking_threshold);

    if let Some(blocking) = blocking_threshold.severity() {
        if blocking < reporting_threshold {
            return Err(format!(
                "pr_security_policy.blocking_threshold ({blocking}) must be at least \
                 pr_security_policy.reporting_threshold ({reporting_threshold})"
            ));
        }
    }

    Ok(PrSecurityPolicy {
        version,
        scope,
        reporting_threshold,
        blocking_threshold,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrPolicyDecision {
    #[serde(rename = "pass")]
    Pass,
    #[serde(rename = "neutral")]
    Neutral,
    #[serde(rename = "fail")]
    Fail,
}

impl PrPolicyDecision {
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Pass | Self::Neutral => 0,
            Self::Fail => 1,
        }
    }

    pub fn github_check_conclusion(self) -> &'static str {
        match self {
            Self::Pass => "success",
            Self::Neutral => "neutral",
            Self::Fail => "failure",
        }
    }
}

impl std::fmt::Display for PrPolicyDecision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Pass => "pass",
            Self::Neutral => "neutral",
            Self::Fail => "fail",
        })
    }
}

/// Machine-readable result exposed by CLI JSON output, Action outputs, and the
/// GitHub App check-run summary. Findings themselves remain in the normal
/// report/transport payload, preserving the existing finding schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrPolicyReport {
    pub version: PrSecurityPolicyVersion,
    pub scope: PrSecurityPolicyScope,
    pub reporting_threshold: Severity,
    pub blocking_threshold: PrBlockingThreshold,
    pub decision: PrPolicyDecision,
    pub scoped_findings: usize,
    pub included_findings: usize,
    pub blocking_findings: usize,
}

/// Why a policy request did not produce a v1 repository decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrPolicyNotEvaluatedReason {
    ChangedOnlyScan,
    PartialScan,
    DiffScan,
    ChangedFilesFallback,
}

impl std::fmt::Display for PrPolicyNotEvaluatedReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ChangedOnlyScan => "the scan was limited to changed files",
            Self::PartialScan => "the scan did not cover a repository root",
            Self::DiffScan => "the scan produced only diff findings",
            Self::ChangedFilesFallback => {
                "the full-repository scan timed out and used a changed-files fallback"
            }
        })
    }
}

/// Explicit status for a requested policy that cannot evaluate a complete
/// repository finding set. This is not a policy report and has no decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrPolicyNotEvaluated {
    pub version: PrSecurityPolicyVersion,
    pub requested_scope: PrSecurityPolicyScope,
    pub reporting_threshold: Severity,
    pub blocking_threshold: PrBlockingThreshold,
    pub reason: PrPolicyNotEvaluatedReason,
}

impl PrPolicyNotEvaluated {
    pub fn new(policy: PrSecurityPolicy, reason: PrPolicyNotEvaluatedReason) -> Self {
        Self {
            version: policy.version,
            requested_scope: policy.scope,
            reporting_threshold: policy.reporting_threshold,
            blocking_threshold: policy.blocking_threshold,
            reason,
        }
    }
}

impl std::fmt::Display for PrPolicyNotEvaluated {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "PR security policy {} was not evaluated: {}. No repository-scope policy decision was made.",
            self.version, self.reason
        )
    }
}

/// Result of evaluating a complete repository finding set. `findings` is the
/// exact reporting set every policy decision surface must use.
#[derive(Debug, Clone)]
pub struct PrPolicyEvaluation {
    pub findings: Vec<Finding>,
    report: PrPolicyReport,
}

impl PrPolicyEvaluation {
    pub fn report(&self) -> &PrPolicyReport {
        &self.report
    }
}

/// Evaluate one already-resolved complete repository scan result.
///
/// Callers MUST use [`PrPolicyNotEvaluated`] instead when their input is a
/// diff, changed-file subset, or other partial result. V1's repository scope
/// means all input findings are in scope. Findings below the reporting
/// threshold are omitted. A clean reporting set passes; a reportable set that
/// contains no blocking finding is neutral; otherwise the policy fails.
pub fn evaluate(policy: PrSecurityPolicy, findings: Vec<Finding>) -> PrPolicyEvaluation {
    let scoped_findings = findings.len();
    let findings: Vec<Finding> = findings
        .into_iter()
        .filter(|finding| finding.severity >= policy.reporting_threshold)
        .collect();
    let blocking_findings = match policy.blocking_threshold.severity() {
        Some(threshold) => findings
            .iter()
            .filter(|finding| finding.severity >= threshold)
            .count(),
        None => 0,
    };
    let decision = if findings.is_empty() {
        PrPolicyDecision::Pass
    } else if blocking_findings > 0 {
        PrPolicyDecision::Fail
    } else {
        PrPolicyDecision::Neutral
    };
    let report = PrPolicyReport {
        version: policy.version,
        scope: policy.scope,
        reporting_threshold: policy.reporting_threshold,
        blocking_threshold: policy.blocking_threshold,
        decision,
        scoped_findings,
        included_findings: findings.len(),
        blocking_findings,
    };

    PrPolicyEvaluation { findings, report }
}

/// Write an evaluated or explicitly not-evaluated policy result for the CLI
/// `--pr-policy-output` contract.
pub fn write_pr_policy_result<T: Serialize>(
    output: Option<&str>,
    result: &T,
) -> Result<(), String> {
    let Some(path) = output else {
        return Ok(());
    };

    let content = serde_json::to_string_pretty(result)
        .map_err(|error| format!("failed to serialize PR policy result: {error}"))?;
    std::fs::write(path, content)
        .map_err(|error| format!("failed to write PR policy result '{path}': {error}"))
}

#[cfg(test)]
pub(crate) mod contract_fixture {
    use super::*;

    #[derive(Deserialize)]
    struct Fixture {
        policy: PrSecurityPolicy,
        findings: Vec<Severity>,
        expected: Expected,
    }

    #[derive(Deserialize)]
    struct Expected {
        scoped_findings: usize,
        included_findings: usize,
        blocking_findings: usize,
        decision: PrPolicyDecision,
    }

    pub(crate) fn mixed_v1() -> (PrSecurityPolicy, Vec<Finding>, PrPolicyReport) {
        let fixture: Fixture =
            serde_json::from_str(include_str!("../tests/fixtures/pr-policy-v1-mixed.json"))
                .expect("valid shared PR policy fixture");
        let findings = fixture
            .findings
            .into_iter()
            .enumerate()
            .map(|(index, severity)| finding(severity, index + 1))
            .collect();
        (
            fixture.policy,
            findings,
            PrPolicyReport {
                version: fixture.policy.version,
                scope: fixture.policy.scope,
                reporting_threshold: fixture.policy.reporting_threshold,
                blocking_threshold: fixture.policy.blocking_threshold,
                decision: fixture.expected.decision,
                scoped_findings: fixture.expected.scoped_findings,
                included_findings: fixture.expected.included_findings,
                blocking_findings: fixture.expected.blocking_findings,
            },
        )
    }

    fn finding(severity: Severity, line: usize) -> Finding {
        Finding {
            rule_id: format!("fixture/{severity}"),
            severity,
            cwe: None,
            description: "fixture finding".to_string(),
            file: "src/app.rs".to_string(),
            line,
            column: 1,
            end_line: line,
            end_column: 1,
            snippet: String::new(),
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: 1.0,
            taint_hops: None,
            tags: Vec::new(),
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
            dep_path: Vec::new(),
            crypto_material: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Severity) -> Finding {
        Finding {
            rule_id: format!("test/{severity}"),
            severity,
            cwe: None,
            description: "test finding".to_string(),
            file: "src/app.rs".to_string(),
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
            confidence: 1.0,
            taint_hops: None,
            tags: Vec::new(),
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
            dep_path: Vec::new(),
            crypto_material: None,
        }
    }

    #[test]
    fn v1_defaults_are_explicit_and_stable() {
        let policy = PrSecurityPolicy::default();
        assert_eq!(policy.version.to_string(), PR_SECURITY_POLICY_V1);
        assert_eq!(policy.scope, PrSecurityPolicyScope::Repository);
        assert_eq!(policy.reporting_threshold, Severity::Medium);
        assert_eq!(policy.blocking_threshold, PrBlockingThreshold::High);
    }

    #[test]
    fn resolver_applies_surface_overrides_and_validates_threshold_order() {
        let configured = PrSecurityPolicyInput {
            reporting_threshold: Some(Severity::Low),
            blocking_threshold: Some(PrBlockingThreshold::Medium),
            ..PrSecurityPolicyInput::default()
        };
        let overrides = PrSecurityPolicyInput {
            blocking_threshold: Some(PrBlockingThreshold::High),
            ..PrSecurityPolicyInput::default()
        };
        let policy = resolve(Some(&configured), &overrides).expect("valid policy");
        assert_eq!(policy.reporting_threshold, Severity::Low);
        assert_eq!(policy.blocking_threshold, PrBlockingThreshold::High);

        let invalid = PrSecurityPolicyInput {
            reporting_threshold: Some(Severity::High),
            blocking_threshold: Some(PrBlockingThreshold::Medium),
            ..PrSecurityPolicyInput::default()
        };
        assert!(resolve(Some(&invalid), &PrSecurityPolicyInput::default()).is_err());
    }

    #[test]
    fn evaluation_filters_reports_and_distinguishes_all_decisions() {
        let policy = PrSecurityPolicy::default();
        let failed = evaluate(
            policy,
            vec![
                finding(Severity::Low),
                finding(Severity::Medium),
                finding(Severity::High),
            ],
        );
        assert_eq!(failed.findings.len(), 2);
        assert_eq!(failed.report().decision, PrPolicyDecision::Fail);

        let neutral = evaluate(
            policy,
            vec![finding(Severity::Low), finding(Severity::Medium)],
        );
        assert_eq!(neutral.report().decision, PrPolicyDecision::Neutral);

        let passed = evaluate(policy, vec![finding(Severity::Low)]);
        assert_eq!(passed.report().decision, PrPolicyDecision::Pass);
    }

    #[test]
    fn no_blocking_threshold_reports_without_failing() {
        let policy = PrSecurityPolicy {
            blocking_threshold: PrBlockingThreshold::None,
            ..PrSecurityPolicy::default()
        };
        let evaluation = evaluate(policy, vec![finding(Severity::High)]);

        assert_eq!(evaluation.report().included_findings, 1);
        assert_eq!(evaluation.report().blocking_findings, 0);
        assert_eq!(evaluation.report().decision, PrPolicyDecision::Neutral);
    }

    #[test]
    fn shared_mixed_fixture_matches_v1_contract() {
        let (policy, findings, expected) = contract_fixture::mixed_v1();
        let evaluation = evaluate(policy, findings);

        assert_eq!(evaluation.report(), &expected);
        assert_eq!(evaluation.findings.len(), expected.included_findings);
    }

    #[test]
    fn cli_pr_policy_output_matches_shared_mixed_policy_contract() {
        let (policy, findings, expected) = contract_fixture::mixed_v1();
        let evaluation = evaluate(policy, findings);
        let temp = tempfile::tempdir().expect("temporary output directory");
        let output = temp.path().join("policy.json");

        write_pr_policy_result(output.to_str(), evaluation.report())
            .expect("write CLI policy output");

        let written: PrPolicyReport =
            serde_json::from_str(&std::fs::read_to_string(output).expect("read CLI policy output"))
                .expect("parse CLI policy output");
        assert_eq!(written, expected);
    }
}
