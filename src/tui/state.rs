use super::resolve_finding_path;
use super::widgets::{
    adjust_scroll, available_open_focuses, compare_findings_by, finding_review_key, scan_root_path,
    LOADING_SHIMMER_CYCLE,
};
use super::WorkerMessage;
use crate::app::{TuiExecution, TuiMode};
use crate::cli::TuiArgs;
use crate::config::load_for_scan;
use crate::{Finding, Severity};
use ratatui::layout::Rect;
use ratatui::text::{Line, Text};
use ratatui::widgets::ListState;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::time::Instant;

pub(super) struct TuiApp {
    pub(super) request: TuiArgs,
    pub(super) result: Option<TuiExecution>,
    pub(super) error: Option<String>,
    pub(super) show_launch: bool,
    pub(super) launch_mode: LaunchMode,
    pub(super) launch_diff_target: String,
    pub(super) scanning: bool,
    pub(super) loading_tick: usize,
    pub(super) search_mode: bool,
    pub(super) search_query: String,
    pub(super) min_severity: Option<Severity>,
    /// Session-only lower bound on [`Finding::confidence`]. Cycled via the
    /// `c` keybind (feature C). This filters already-emitted findings in
    /// the UI; it is intentionally independent from the `scan.min_confidence`
    /// config field (which filters at scan time) and from `--show-confidence`
    /// (which only controls non-TUI rendering of the score).
    pub(super) session_min_confidence: f32,
    /// Selected sort order for the findings list. Defaults to the
    /// legacy severity-desc ordering; cycled via `Shift+C` (feature B).
    pub(super) sort_mode: SortMode,
    pub(super) selected: usize,
    pub(super) list_state: ListState,
    pub(super) list_area: Rect,
    pub(super) hover_index: Option<usize>,
    pub(super) show_notices: bool,
    pub(super) show_help: bool,
    /// When on, a CNSA 2.0 migration-readiness strip is drawn at the bottom
    /// of the main scan body. Toggled by `Shift+N` (see `handle_key`). Chose
    /// `Shift+N` instead of the issue's suggested `Shift+C` because the
    /// latter is already bound to `cycle_sort_mode` (feature B) — `Shift+N`
    /// reads as "cNsa" and keeps both toggles available.
    pub(super) show_compliance_panel: bool,
    pub(super) runtime_notices: Vec<String>,
    pub(super) active_request_id: u64,
    pub(super) next_request_id: u64,
    pub(super) scan_started_at: Instant,
    pub(super) detail_scroll: u16,
    pub(super) notices_scroll: u16,
    pub(super) source_context_cache: Option<SourceContextCache>,
    pub(super) open_focus: OpenFocus,
    pub(super) action_menu: Option<ActionMenu>,
    pub(super) export_menu: Option<ExportMenu>,
    pub(super) severity_picker: Option<SeverityPicker>,
    pub(super) review_states: HashMap<String, ReviewState>,
}

impl TuiApp {
    pub(super) fn new(request: TuiArgs) -> Self {
        let mut request = request;
        request.explain = true;
        Self {
            show_launch: true,
            launch_mode: LaunchMode::from_args(&request),
            launch_diff_target: request.diff.clone().unwrap_or_else(|| "main".to_string()),
            request,
            result: None,
            error: None,
            scanning: false,
            loading_tick: 0,
            search_mode: false,
            search_query: String::new(),
            min_severity: None,
            session_min_confidence: 0.0,
            sort_mode: SortMode::default(),
            selected: 0,
            list_state: ListState::default(),
            list_area: Rect::default(),
            hover_index: None,
            show_notices: true,
            show_help: false,
            show_compliance_panel: false,
            runtime_notices: Vec::new(),
            active_request_id: 0,
            next_request_id: 1,
            scan_started_at: Instant::now(),
            detail_scroll: 0,
            notices_scroll: 0,
            source_context_cache: None,
            open_focus: OpenFocus::Finding,
            action_menu: None,
            export_menu: None,
            severity_picker: None,
            review_states: HashMap::new(),
        }
    }

    pub(super) fn begin_scan(&mut self) -> u64 {
        self.apply_launch_selection();
        self.error = None;
        self.result = None;
        self.selected = 0;
        self.list_state = ListState::default();
        self.hover_index = None;
        self.scanning = true;
        self.show_launch = false;
        self.show_help = false;
        self.runtime_notices.clear();
        self.scan_started_at = Instant::now();
        self.detail_scroll = 0;
        self.notices_scroll = 0;
        self.source_context_cache = None;
        self.open_focus = OpenFocus::Finding;
        self.action_menu = None;
        self.severity_picker = None;
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        self.active_request_id = request_id;
        request_id
    }

    pub(super) fn apply_launch_selection(&mut self) {
        match self.launch_mode {
            LaunchMode::Scan => {
                self.request.secrets = false;
                self.request.diff = None;
                self.request.pq_mode = false;
            }
            LaunchMode::Diff => {
                self.request.secrets = false;
                self.request.diff = Some(self.launch_diff_target.trim().to_string());
                self.request.pq_mode = false;
            }
            LaunchMode::Secrets => {
                self.request.secrets = true;
                self.request.diff = None;
                self.request.pq_mode = false;
            }
            LaunchMode::Pqc => {
                self.request.secrets = false;
                self.request.diff = None;
                self.request.pq_mode = true;
            }
        }
    }

    pub(super) fn handle_worker_messages(&mut self, rx: &Receiver<WorkerMessage>) {
        while let Ok(message) = rx.try_recv() {
            match message {
                WorkerMessage::Scan { request_id, result } => {
                    if request_id != self.active_request_id {
                        continue;
                    }

                    self.scanning = false;
                    match result {
                        Ok(result) => {
                            self.error = None;
                            self.result = Some(result);
                            self.source_context_cache = None;
                            self.normalize_open_focus();
                            self.clamp_selection();
                        }
                        Err(error) => {
                            self.result = None;
                            self.error = Some(error);
                        }
                    }
                }
                WorkerMessage::SourceContext {
                    request_id,
                    key,
                    lines,
                } => {
                    if request_id != self.active_request_id {
                        continue;
                    }

                    if matches!(
                        self.source_context_cache.as_ref(),
                        Some(SourceContextCache::Loading { key: pending }) if *pending == key
                    ) {
                        self.source_context_cache = Some(SourceContextCache::Ready { key, lines });
                    }
                }
            }
        }
    }

    pub(super) fn prepare_source_context_load(
        &mut self,
    ) -> Option<(u64, SourceContextCacheKey, Finding)> {
        if self.request.secrets {
            return None;
        }

        let finding = self.selected_finding()?.clone();
        let key = SourceContextCacheKey::from_finding(&self.request.path, &finding);

        match self.source_context_cache.as_ref() {
            Some(SourceContextCache::Ready {
                key: cached_key, ..
            })
            | Some(SourceContextCache::Loading { key: cached_key })
                if *cached_key == key =>
            {
                return None;
            }
            _ => {}
        }

        self.source_context_cache = Some(SourceContextCache::Loading { key: key.clone() });
        Some((self.active_request_id, key, finding))
    }
}

impl TuiApp {
    pub(super) fn review_state_for(&self, finding: &Finding) -> Option<ReviewState> {
        self.review_states
            .get(&finding_review_key(finding))
            .copied()
    }

    pub(super) fn move_selection(&mut self, delta: isize) {
        let filtered = self.filtered_indices();
        let previous = self.selected;
        if filtered.is_empty() {
            self.selected = 0;
            return;
        }

        let len = filtered.len() as isize;
        let next = (self.selected as isize + delta).clamp(0, len - 1);
        self.selected = next as usize;
        if self.selected != previous {
            self.detail_scroll = 0;
            self.source_context_cache = None;
            self.normalize_open_focus();
        }
    }

    pub(super) fn select_filtered_index(&mut self, index: usize) {
        let filtered_len = self.filtered_indices().len();
        if index >= filtered_len {
            return;
        }

        let previous = self.selected;
        self.selected = index;
        if self.selected != previous {
            self.detail_scroll = 0;
            self.source_context_cache = None;
            self.normalize_open_focus();
        }
    }

    pub(super) fn clamp_selection(&mut self) {
        let previous = self.selected;
        let filtered_len = self.filtered_indices().len();
        if filtered_len == 0 {
            self.selected = 0;
        } else if self.selected >= filtered_len {
            self.selected = filtered_len - 1;
        }

        if self.selected != previous {
            self.detail_scroll = 0;
            self.source_context_cache = None;
            self.normalize_open_focus();
        }
    }

    pub(super) fn cycle_open_focus(&mut self) {
        let Some(finding) = self.selected_finding() else {
            self.open_focus = OpenFocus::Finding;
            return;
        };

        let available = available_open_focuses(finding);
        let index = available
            .iter()
            .position(|focus| *focus == self.open_focus)
            .unwrap_or(0);
        self.open_focus = available[(index + 1) % available.len()];
    }

    pub(super) fn normalize_open_focus(&mut self) {
        let Some(finding) = self.selected_finding() else {
            self.open_focus = OpenFocus::Finding;
            return;
        };

        let available = available_open_focuses(finding);
        if !available.contains(&self.open_focus) {
            self.open_focus = OpenFocus::Finding;
        }
    }

    pub(super) fn advance_spinner(&mut self) {
        self.loading_tick = (self.loading_tick + 1) % LOADING_SHIMMER_CYCLE;
    }

    pub(super) fn filtered_indices(&self) -> Vec<usize> {
        let Some(result) = self.result.as_ref() else {
            return Vec::new();
        };

        let needle = self.search_query.to_ascii_lowercase();
        let mut indices = result
            .findings
            .iter()
            .enumerate()
            .filter(|(_, finding)| self.matches_filters(finding, &needle))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();

        let sort_mode = self.sort_mode;
        indices.sort_by(|left, right| {
            compare_findings_by(&result.findings[*left], &result.findings[*right], sort_mode)
        });

        indices
    }

    /// Count of findings rejected by the session confidence filter alone.
    /// Used in the footer to show "12 of 45" style progress when a filter
    /// is active. Note: search + severity filters also run; this only
    /// tracks the confidence slice so the footer reads naturally.
    pub(super) fn total_after_severity_and_search(&self) -> usize {
        let Some(result) = self.result.as_ref() else {
            return 0;
        };
        let needle = self.search_query.to_ascii_lowercase();
        result
            .findings
            .iter()
            .filter(|finding| self.matches_non_confidence_filters(finding, &needle))
            .count()
    }

    pub(super) fn matches_filters(&self, finding: &Finding, needle: &str) -> bool {
        if !self.matches_non_confidence_filters(finding, needle) {
            return false;
        }
        // Confidence filter is last so it reads naturally as the "final
        // cut" and so the footer counts above (non-confidence filtered)
        // stay independent of the `c` keybind.
        finding.confidence + 1e-6 >= self.session_min_confidence
    }

    pub(super) fn matches_non_confidence_filters(&self, finding: &Finding, needle: &str) -> bool {
        if let Some(min_severity) = self.min_severity {
            if finding.severity < min_severity {
                return false;
            }
        }

        if needle.is_empty() {
            return true;
        }

        [
            finding.rule_id.as_str(),
            finding.description.as_str(),
            finding.file.as_str(),
            finding.snippet.as_str(),
        ]
        .iter()
        .any(|value| value.to_ascii_lowercase().contains(needle))
    }

    pub(super) fn selected_finding(&self) -> Option<&Finding> {
        let result = self.result.as_ref()?;
        let filtered = self.filtered_indices();
        let finding_index = *filtered.get(self.selected)?;
        result.findings.get(finding_index)
    }
}

impl TuiApp {
    pub(super) fn baseline_path_for_actions(&self) -> Result<PathBuf, String> {
        if let Some(path) = self.request.baseline.as_ref() {
            return Ok(PathBuf::from(path));
        }

        if let Some(config) = load_for_scan(
            Path::new(&self.request.path),
            self.request.config.as_deref(),
        )? {
            match self.result.as_ref().map(|result| &result.mode) {
                Some(TuiMode::Scan) => {
                    if let Some(path) = config.scan.baseline.as_ref() {
                        return Ok(PathBuf::from(path));
                    }
                }
                Some(TuiMode::Secrets) => {
                    if let Some(path) = config.secrets.baseline.as_ref() {
                        return Ok(PathBuf::from(path));
                    }
                }
                _ => {}
            }
        }

        Ok(match self.result.as_ref().map(|result| &result.mode) {
            Some(TuiMode::Secrets) => scan_root_path(Path::new(&self.request.path))
                .join(".foxguard/secrets-baseline.json"),
            _ => scan_root_path(Path::new(&self.request.path)).join(".foxguard/baseline.json"),
        })
    }

    pub(super) fn baseline_path_display(&self) -> String {
        self.baseline_path_for_actions()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|error| format!("unavailable ({error})"))
    }

    pub(super) fn config_path_display(&self) -> String {
        crate::config::editable_config_path(
            Path::new(&self.request.path),
            self.request.config.as_deref(),
        )
        .map(|path| path.display().to_string())
        .unwrap_or_else(|error| format!("unavailable ({error})"))
    }

    pub(super) fn review_summary_for_finding(&self, finding: &Finding) -> Option<String> {
        self.review_state_for(finding)
            .map(|state| format!("session {}", state.label()))
    }

    pub(super) fn push_runtime_notice(&mut self, notice: String) {
        self.runtime_notices.push(notice);
    }

    pub(super) fn scroll_detail(&mut self, delta: i32) {
        self.detail_scroll = adjust_scroll(self.detail_scroll, delta);
    }

    pub(super) fn scroll_notices(&mut self, delta: i32) {
        self.notices_scroll = adjust_scroll(self.notices_scroll, delta);
    }

    pub(super) fn notice_count(&self) -> usize {
        self.combined_notices().len()
    }

    pub(super) fn notice_text(&self) -> Text<'static> {
        let notices = self.combined_notices();
        if notices.is_empty() {
            return Text::from("No notices.");
        }

        let lines = notices
            .iter()
            .map(|notice| Line::from(notice.clone()))
            .collect::<Vec<_>>();
        Text::from(lines)
    }

    pub(super) fn combined_notices(&self) -> Vec<String> {
        let mut notices = self
            .result
            .as_ref()
            .map(|result| result.notices.clone())
            .unwrap_or_default();
        notices.extend(self.runtime_notices.iter().cloned());
        notices
    }
}

pub(super) struct SeverityCounts {
    pub(super) critical: usize,
    pub(super) high: usize,
    pub(super) medium: usize,
    pub(super) low: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LaunchMode {
    Scan,
    Diff,
    Secrets,
    Pqc,
}

impl LaunchMode {
    pub(super) fn from_args(args: &TuiArgs) -> Self {
        if args.pq_mode {
            LaunchMode::Pqc
        } else if args.secrets {
            LaunchMode::Secrets
        } else if args.diff.is_some() {
            LaunchMode::Diff
        } else {
            LaunchMode::Scan
        }
    }

    pub(super) fn next(self) -> Self {
        match self {
            LaunchMode::Scan => LaunchMode::Diff,
            LaunchMode::Diff => LaunchMode::Secrets,
            LaunchMode::Secrets => LaunchMode::Pqc,
            LaunchMode::Pqc => LaunchMode::Scan,
        }
    }

    pub(super) fn previous(self) -> Self {
        match self {
            LaunchMode::Scan => LaunchMode::Pqc,
            LaunchMode::Diff => LaunchMode::Scan,
            LaunchMode::Secrets => LaunchMode::Diff,
            LaunchMode::Pqc => LaunchMode::Secrets,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OpenFocus {
    Finding,
    Source,
    Sink,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TriageAction {
    AddToBaseline,
    IgnoreRuleInFile,
    IgnoreSecretRule,
    /// Open the severity picker for the selected finding's rule. The picker
    /// dispatches an `ApplySeverityOverride(_)` once a severity is chosen.
    LowerSeverity,
    /// Emitted by the severity picker — writes `scan.severity_overrides`.
    ApplySeverityOverride(Severity),
    /// Append the rule to `scan.disable_rules` (global denylist).
    DisableRuleGlobally,
    MarkReviewed,
    MarkTodo,
    MarkIgnoreCandidate,
    ClearReviewState,
}

impl TriageAction {
    pub(super) fn label(self) -> String {
        match self {
            TriageAction::AddToBaseline => "Add to baseline".to_string(),
            TriageAction::IgnoreRuleInFile => "Ignore this rule in this file".to_string(),
            TriageAction::IgnoreSecretRule => "Ignore this secret rule".to_string(),
            TriageAction::LowerSeverity => "Lower severity for this rule".to_string(),
            TriageAction::ApplySeverityOverride(severity) => {
                format!("Apply severity override: {}", severity)
            }
            TriageAction::DisableRuleGlobally => "Disable rule globally".to_string(),
            TriageAction::MarkReviewed => "Mark as reviewed".to_string(),
            TriageAction::MarkTodo => "Mark as todo".to_string(),
            TriageAction::MarkIgnoreCandidate => "Mark as ignore candidate".to_string(),
            TriageAction::ClearReviewState => "Clear review state".to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReviewState {
    Reviewed,
    Todo,
    IgnoreCandidate,
}

impl ReviewState {
    pub(super) fn label(self) -> &'static str {
        match self {
            ReviewState::Reviewed => "reviewed",
            ReviewState::Todo => "todo",
            ReviewState::IgnoreCandidate => "ignore-candidate",
        }
    }
}

pub(super) struct ActionMenu {
    pub(super) actions: Vec<TriageAction>,
    pub(super) selected: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExportFormat {
    Cbom,
    Json,
    Sarif,
}

impl ExportFormat {
    pub(super) fn label(self) -> &'static str {
        match self {
            ExportFormat::Cbom => "CBOM (CycloneDX 1.6)",
            ExportFormat::Json => "JSON",
            ExportFormat::Sarif => "SARIF",
        }
    }

    pub(super) fn filename(self) -> &'static str {
        match self {
            ExportFormat::Cbom => "findings.cbom.json",
            ExportFormat::Json => "findings.json",
            ExportFormat::Sarif => "findings.sarif.json",
        }
    }
}

pub(super) struct ExportMenu {
    pub(super) formats: Vec<ExportFormat>,
    pub(super) selected: usize,
}

/// Modal sub-picker shown when the user chooses "Lower severity" from the
/// triage menu. Owns a highlight cursor over `SEVERITY_PICKER_CHOICES` and
/// remembers the rule's current override (if any) so the UI can show it.
pub(super) struct SeverityPicker {
    pub(super) selected: usize,
    pub(super) current: Option<Severity>,
}

/// Severities the "Lower severity" picker offers, ordered low → critical to
/// match how humans tend to think about "dialing down" a noisy rule.
pub(super) const SEVERITY_PICKER_CHOICES: [Severity; 4] = [
    Severity::Low,
    Severity::Medium,
    Severity::High,
    Severity::Critical,
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum SortMode {
    /// Severity desc, then path/line (the pre-existing default behaviour).
    #[default]
    SeverityDesc,
    /// Confidence desc, with severity-desc as a stable tiebreaker.
    ConfidenceDesc,
}

impl SortMode {
    pub(super) fn next(self) -> Self {
        match self {
            SortMode::SeverityDesc => SortMode::ConfidenceDesc,
            SortMode::ConfidenceDesc => SortMode::SeverityDesc,
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            SortMode::SeverityDesc => "severity",
            SortMode::ConfidenceDesc => "confidence",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct SourceContextCacheKey {
    pub(super) path: PathBuf,
    pub(super) line: usize,
    pub(super) end_line: usize,
    pub(super) column: usize,
    pub(super) end_column: usize,
}

impl SourceContextCacheKey {
    pub(super) fn from_finding(scan_path: &str, finding: &Finding) -> Self {
        Self {
            path: resolve_finding_path(scan_path, &finding.file),
            line: finding.line,
            end_line: finding.end_line,
            column: finding.column,
            end_column: finding.end_column,
        }
    }
}

pub(super) enum SourceContextCache {
    Loading {
        key: SourceContextCacheKey,
    },
    Ready {
        key: SourceContextCacheKey,
        lines: Vec<Line<'static>>,
    },
}
