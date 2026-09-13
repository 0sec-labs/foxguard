use super::loading::LOADING_SHIMMER_CYCLE;
use super::persist::{FilterSettings, SessionStore};
use super::resolve_finding_path;
use super::review::{BatchMenu, SavedViewMenu};
use super::widgets::{adjust_scroll, available_open_focuses, compare_findings_by, scan_root_path};
use super::WorkerMessage;
use crate::app::{TuiExecution, TuiMode};
use crate::baseline::fingerprint_finding_at_root;
use crate::cli::TuiArgs;
use crate::config::load_for_scan;
use crate::{Finding, Severity};
use ratatui::layout::Rect;
use ratatui::text::{Line, Text};
use ratatui::widgets::ListState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
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
    pub(super) search_restore_query: String,
    pub(super) search_restore_selection: Option<usize>,
    pub(super) min_severity: Option<Severity>,
    /// View-only lower bound on [`Finding::confidence`], saved with named filters.
    pub(super) session_min_confidence: f32,
    pub(super) sort_mode: SortMode,
    pub(super) selected: usize,
    pub(super) list_state: ListState,
    pub(super) list_area: Rect,
    pub(super) detail_area: Rect,
    pub(super) hover_index: Option<usize>,
    pub(super) show_notices: bool,
    pub(super) show_help: bool,
    pub(super) help_scroll: u16,
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
    pub(super) review_filter: ReviewFilter,
    /// Full-screen detail; otherwise split on wide terminals and list on narrow ones.
    pub(super) show_detail_view: bool,
    /// Derived once when results, filters, sort order, or review marks change.
    cached_filtered: Vec<usize>,
    cached_without_confidence: usize,
    pub(super) reviewed_count: usize,
    pub(super) identity_root: PathBuf,
    pub(super) finding_keys: Vec<String>,
    baseline_kinds: Vec<BaselineFilter>,
    pub(super) baseline_filter: BaselineFilter,
    pub(super) cached_resolved: Vec<usize>,
    pub(super) checked_findings: HashSet<usize>,
    pub(super) batch_menu: Option<BatchMenu>,
    pub(super) saved_view_menu: Option<SavedViewMenu>,
    pub(super) saved_filters: BTreeMap<String, FilterSettings>,
    pub(super) session_root: Option<PathBuf>,
    pub(super) session_store: Option<SessionStore>,
    pub(super) session_error: Option<String>,
    pub(super) session_dirty: bool,
}

impl TuiApp {
    pub(super) fn new(request: TuiArgs) -> Self {
        let mut request = request;
        request.explain = true;
        let identity_root = scan_root_path(Path::new(&request.path));
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
            search_restore_query: String::new(),
            search_restore_selection: None,
            min_severity: None,
            session_min_confidence: 0.0,
            sort_mode: SortMode::default(),
            selected: 0,
            list_state: ListState::default(),
            list_area: Rect::default(),
            detail_area: Rect::default(),
            hover_index: None,
            show_notices: true,
            show_help: false,
            help_scroll: 0,
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
            review_filter: ReviewFilter::All,
            show_detail_view: false,
            cached_filtered: Vec::new(),
            cached_without_confidence: 0,
            reviewed_count: 0,
            identity_root,
            finding_keys: Vec::new(),
            baseline_kinds: Vec::new(),
            baseline_filter: BaselineFilter::All,
            cached_resolved: Vec::new(),
            checked_findings: HashSet::new(),
            batch_menu: None,
            saved_view_menu: None,
            saved_filters: BTreeMap::new(),
            session_root: None,
            session_store: None,
            session_error: None,
            session_dirty: false,
        }
    }

    pub(super) fn begin_scan(&mut self) -> u64 {
        self.apply_launch_selection();
        self.error = None;
        self.result = None;
        self.selected = 0;
        self.list_state = ListState::default();
        self.list_area = Rect::default();
        self.detail_area = Rect::default();
        self.hover_index = None;
        self.scanning = true;
        self.show_launch = false;
        self.show_help = false;
        self.runtime_notices.clear();
        self.activate_review_session();
        self.scan_started_at = Instant::now();
        self.detail_scroll = 0;
        self.notices_scroll = 0;
        self.source_context_cache = None;
        self.open_focus = OpenFocus::Finding;
        self.action_menu = None;
        self.export_menu = None;
        self.severity_picker = None;
        self.checked_findings.clear();
        self.batch_menu = None;
        self.saved_view_menu = None;
        self.finding_keys.clear();
        self.baseline_kinds.clear();
        self.cached_resolved.clear();
        self.show_detail_view = false;
        self.search_mode = false;
        self.search_restore_query.clear();
        self.search_restore_selection = None;
        self.cached_filtered.clear();
        self.cached_without_confidence = 0;
        self.reviewed_count = 0;
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

    pub(super) fn handle_worker_messages(&mut self, rx: &Receiver<WorkerMessage>) -> bool {
        let mut changed = false;
        while let Ok(message) = rx.try_recv() {
            match message {
                WorkerMessage::Scan { request_id, result } => {
                    if request_id != self.active_request_id {
                        continue;
                    }

                    changed = true;
                    self.scanning = false;
                    match result {
                        Ok(result) => {
                            self.error = None;
                            self.install_scan_result(result);
                        }
                        Err(error) => {
                            self.result = None;
                            self.error = Some(error);
                            self.clamp_selection();
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
                        changed = true;
                        self.source_context_cache = Some(SourceContextCache::Ready { key, lines });
                    }
                }
            }
        }
        changed
    }

    pub(super) fn prepare_source_context_load(
        &mut self,
    ) -> Option<(u64, SourceContextCacheKey, Finding)> {
        // Selection changes and rescans invalidate this cache. Loading and ready
        // entries both prevent duplicate requests and idle-frame finding clones.
        if self.request.secrets || self.source_context_cache.is_some() {
            return None;
        }

        let finding = self.selected_finding()?.clone();
        let key = SourceContextCacheKey::from_finding(&self.request.path, &finding);

        self.source_context_cache = Some(SourceContextCache::Loading { key: key.clone() });
        Some((self.active_request_id, key, finding))
    }
}

impl TuiApp {
    pub(super) fn install_scan_result(&mut self, result: TuiExecution) {
        self.finding_keys = result
            .findings
            .iter()
            .map(|finding| fingerprint_finding_at_root(finding, &self.identity_root))
            .collect();
        self.baseline_kinds = vec![BaselineFilter::All; result.findings.len()];
        if let Some(comparison) = &result.baseline_comparison {
            for &index in &comparison.introduced {
                if let Some(kind) = self.baseline_kinds.get_mut(index) {
                    *kind = BaselineFilter::Introduced;
                }
            }
            for &index in &comparison.recurring {
                if let Some(kind) = self.baseline_kinds.get_mut(index) {
                    *kind = BaselineFilter::Recurring;
                }
            }
        }
        self.result = Some(result);
        self.cached_filtered.clear();
        self.cached_resolved.clear();
        self.checked_findings.clear();
        self.source_context_cache = None;
        self.clamp_selection();
    }

    pub(super) fn review_state_at(&self, index: usize) -> Option<ReviewState> {
        self.finding_keys
            .get(index)
            .and_then(|key| self.review_states.get(key))
            .copied()
    }

    pub(super) fn visible_indices(&self) -> &[usize] {
        if self.baseline_filter == BaselineFilter::Resolved {
            &self.cached_resolved
        } else {
            &self.cached_filtered
        }
    }
    pub(super) fn set_baseline_filter(&mut self, filter: BaselineFilter) {
        if self.baseline_filter != filter {
            self.baseline_filter = filter;
            self.selected = 0;
            self.list_state = ListState::default();
            self.cached_filtered.clear();
            self.cached_resolved.clear();
            self.source_context_cache = None;
            self.show_detail_view = false;
            self.detail_scroll = 0;
        }
        self.clamp_selection();
    }

    pub(super) fn toggle_visible_selection(&mut self) {
        if self.baseline_filter == BaselineFilter::Resolved {
            return;
        }
        let all_checked = self
            .cached_filtered
            .iter()
            .all(|index| self.checked_findings.contains(index));
        for &index in &self.cached_filtered {
            if all_checked {
                self.checked_findings.remove(&index);
            } else {
                self.checked_findings.insert(index);
            }
        }
    }

    pub(super) fn review_state_for(&self, finding: &Finding) -> Option<ReviewState> {
        if self.review_states.is_empty() {
            return None;
        }
        self.review_states
            .get(&fingerprint_finding_at_root(finding, &self.identity_root))
            .copied()
    }

    pub(super) fn move_selection(&mut self, delta: isize) {
        let filtered = self.visible_indices();
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
        let filtered_len = self.visible_indices().len();
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
        let previous = self.visible_indices().get(self.selected).copied();
        self.cached_filtered.clear();
        self.cached_resolved.clear();
        self.cached_without_confidence = 0;
        self.reviewed_count = 0;

        if let Some(result) = self.result.as_ref() {
            let needle = self.search_query.to_ascii_lowercase();
            for (index, finding) in result.findings.iter().enumerate() {
                let review = self.review_state_at(index);
                self.reviewed_count += usize::from(review == Some(ReviewState::Reviewed));
                if self.matches_non_confidence_filters(finding, &needle)
                    && self.review_filter.matches(review)
                    && (self.baseline_filter == BaselineFilter::All
                        || self.baseline_kinds.get(index) == Some(&self.baseline_filter))
                {
                    self.cached_without_confidence += 1;
                    if finding.confidence + 1e-6 >= self.session_min_confidence {
                        self.cached_filtered.push(index);
                    }
                }
            }
            let sort_mode = self.sort_mode;
            self.cached_filtered.sort_by(|left, right| {
                compare_findings_by(&result.findings[*left], &result.findings[*right], sort_mode)
            });
            if self.baseline_filter == BaselineFilter::Resolved {
                if let Some(comparison) = &result.baseline_comparison {
                    self.cached_resolved = comparison
                        .resolved
                        .iter()
                        .enumerate()
                        .filter(|(_, entry)| {
                            entry.rule_id.to_ascii_lowercase().contains(&needle)
                                || entry.file.to_ascii_lowercase().contains(&needle)
                        })
                        .map(|(index, _)| index)
                        .collect();
                    self.cached_resolved.sort_by(|left, right| {
                        let left = &comparison.resolved[*left];
                        let right = &comparison.resolved[*right];
                        (&left.file, left.line, &left.rule_id).cmp(&(
                            &right.file,
                            right.line,
                            &right.rule_id,
                        ))
                    });
                }
            }
        }

        self.selected = previous
            .and_then(|index| {
                self.visible_indices()
                    .iter()
                    .position(|item| *item == index)
            })
            .unwrap_or_else(|| {
                self.selected
                    .min(self.visible_indices().len().saturating_sub(1))
            });
        if self.visible_indices().get(self.selected).copied() != previous {
            self.detail_scroll = 0;
            self.source_context_cache = None;
        }
        self.hover_index = None;
        self.normalize_open_focus();
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

    pub(super) fn filtered_indices(&self) -> &[usize] {
        &self.cached_filtered
    }

    /// Findings matching the other active filters, before confidence is applied.
    pub(super) fn total_after_severity_and_search(&self) -> usize {
        self.cached_without_confidence
    }

    /// Whether any non-default filter is active that could be cleared.
    pub(super) fn has_active_filter(&self) -> bool {
        !self.search_query.is_empty()
            || self.min_severity.is_some()
            || self.session_min_confidence > 0.0
            || self.review_filter != ReviewFilter::All
            || self.baseline_filter != BaselineFilter::All
    }

    /// Clear all non-default filters: search query, severity, confidence, review.
    pub(super) fn clear_active_filters(&mut self) {
        self.search_query.clear();
        self.search_mode = false;
        self.min_severity = None;
        self.session_min_confidence = 0.0;
        self.review_filter = ReviewFilter::All;
        self.set_baseline_filter(BaselineFilter::All);
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

    pub(super) fn cycle_review_filter(&mut self) {
        self.review_filter = match self.review_filter {
            ReviewFilter::All => ReviewFilter::Unreviewed,
            ReviewFilter::Unreviewed => ReviewFilter::Todo,
            ReviewFilter::Todo => ReviewFilter::Reviewed,
            ReviewFilter::Reviewed => ReviewFilter::IgnoreCandidate,
            ReviewFilter::IgnoreCandidate => ReviewFilter::All,
        };
        self.clamp_selection();
    }

    pub(super) fn selected_finding(&self) -> Option<&Finding> {
        if self.baseline_filter == BaselineFilter::Resolved {
            return None;
        }
        let result = self.result.as_ref()?;
        let finding_index = *self.cached_filtered.get(self.selected)?;
        result.findings.get(finding_index)
    }

    /// Toggle full-screen detail without changing the selected finding.
    pub(super) fn toggle_detail_view(&mut self) {
        self.show_detail_view = !self.show_detail_view;
    }

    /// Review filter summary string for display.
    pub(super) fn review_filter_label(&self) -> Option<&'static str> {
        match self.review_filter {
            ReviewFilter::All => None,
            _ => Some(self.review_filter.label()),
        }
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
            .map(|state| format!("review {}", state.label()))
    }

    pub(super) fn push_runtime_notice(&mut self, notice: String) {
        self.runtime_notices.push(notice);
        self.notices_scroll = 0;
    }

    pub(super) fn scroll_detail(&mut self, delta: i32) {
        self.detail_scroll = adjust_scroll(self.detail_scroll, delta);
    }

    pub(super) fn scroll_notices(&mut self, delta: i32) {
        self.notices_scroll = adjust_scroll(self.notices_scroll, delta);
    }

    pub(super) fn notice_count(&self) -> usize {
        self.result
            .as_ref()
            .map_or(0, |result| result.notices.len())
            + self.runtime_notices.len()
    }

    pub(super) fn notice_text(&self) -> Text<'static> {
        let notices = self.combined_notices();
        if notices.is_empty() {
            return Text::from("No notices.");
        }

        let lines = notices
            .into_iter()
            .rev()
            .map(Line::from)
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
    LowerSeverity,
    ApplySeverityOverride(Severity),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ReviewFilter {
    #[default]
    All,
    Unreviewed,
    Todo,
    Reviewed,
    IgnoreCandidate,
}

impl ReviewFilter {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Unreviewed => "unreviewed",
            Self::Todo => "todo",
            Self::Reviewed => "reviewed",
            Self::IgnoreCandidate => "ignore",
        }
    }

    fn matches(self, state: Option<ReviewState>) -> bool {
        match self {
            Self::All => true,
            Self::Unreviewed => state.is_none(),
            Self::Todo => state == Some(ReviewState::Todo),
            Self::Reviewed => state == Some(ReviewState::Reviewed),
            Self::IgnoreCandidate => state == Some(ReviewState::IgnoreCandidate),
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
    pub(super) overwrite: Option<PathBuf>,
}

pub(super) struct SeverityPicker {
    pub(super) selected: usize,
    pub(super) current: Option<Severity>,
}

pub(super) const SEVERITY_PICKER_CHOICES: [Severity; 4] = [
    Severity::Low,
    Severity::Medium,
    Severity::High,
    Severity::Critical,
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum SortMode {
    #[default]
    SeverityDesc,
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum BaselineFilter {
    #[default]
    All,
    Introduced,
    Recurring,
    Resolved,
}

impl BaselineFilter {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Introduced => "introduced",
            Self::Recurring => "recurring",
            Self::Resolved => "resolved",
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
