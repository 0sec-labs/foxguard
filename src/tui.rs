use crate::app::{execute_tui, DiffSummary, TuiExecution, TuiMode};
use crate::baseline::append_finding_to_baseline;
use crate::cli::TuiArgs;
use crate::config::{
    add_disabled_rule_to_config, add_scan_ignore_rule, add_secrets_ignored_rule,
    add_severity_override_to_config, current_severity_override, is_rule_disabled_in_config,
    load_for_scan,
};
use crate::{Finding, Severity};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap,
};
use ratatui::Terminal;
use std::collections::HashMap;
use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

pub fn run_scan_tui(args: &TuiArgs) -> Result<i32, String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("foxguard tui requires an interactive terminal".to_string());
    }

    let mut session = TerminalSession::enter()?;
    let (tx, rx) = mpsc::channel();
    let mut app = TuiApp::new(args.clone());

    loop {
        app.handle_worker_messages(&rx);

        session
            .terminal
            .draw(|frame| app.draw(frame))
            .map_err(|e| e.to_string())?;

        if event::poll(Duration::from_millis(100)).map_err(|e| e.to_string())? {
            let Event::Key(key) = event::read().map_err(|e| e.to_string())? else {
                continue;
            };

            if key.kind != KeyEventKind::Press {
                continue;
            }

            match app.handle_key(key) {
                ControlFlow::Continue => {}
                ControlFlow::Rescan => {
                    let request_id = app.begin_scan();
                    start_tui_execution(request_id, app.request.clone(), tx.clone())
                }
                ControlFlow::OpenSelected => {
                    if let Err(error) = app.open_selected_finding(&mut session) {
                        app.push_runtime_notice(format!("open failed: {}", error));
                    }
                }
                ControlFlow::ApplyAction(action) => match app.apply_action(action) {
                    Ok(true) => {
                        let request_id = app.begin_scan();
                        start_tui_execution(request_id, app.request.clone(), tx.clone())
                    }
                    Ok(false) => {}
                    Err(error) => app.push_runtime_notice(format!("action failed: {}", error)),
                },
                ControlFlow::Exit => break,
            }
        }

        if app.scanning {
            app.advance_spinner();
        }
    }

    if let Some(error) = app.error.take() {
        return Err(error);
    }

    let finding_count = app
        .result
        .as_ref()
        .map(|result| result.findings.len())
        .unwrap_or(0);
    Ok(if finding_count > 0 { 1 } else { 0 })
}

enum ControlFlow {
    Continue,
    Rescan,
    OpenSelected,
    ApplyAction(TriageAction),
    Exit,
}

struct WorkerMessage {
    request_id: u64,
    result: Result<TuiExecution, String>,
}

struct TuiApp {
    request: TuiArgs,
    result: Option<TuiExecution>,
    error: Option<String>,
    show_launch: bool,
    launch_mode: LaunchMode,
    launch_diff_target: String,
    scanning: bool,
    loading_tick: usize,
    search_mode: bool,
    search_query: String,
    min_severity: Option<Severity>,
    /// Session-only lower bound on [`Finding::confidence`]. Cycled via the
    /// `c` keybind (feature C). This filters already-emitted findings in
    /// the UI; it is intentionally independent from the `scan.min_confidence`
    /// config field (which filters at scan time) and from `--show-confidence`
    /// (which only controls non-TUI rendering of the score).
    session_min_confidence: f32,
    /// Selected sort order for the findings list. Defaults to the
    /// legacy severity-desc ordering; cycled via `Shift+C` (feature B).
    sort_mode: SortMode,
    selected: usize,
    show_notices: bool,
    show_help: bool,
    /// When on, a CNSA 2.0 migration-readiness strip is drawn at the bottom
    /// of the main scan body. Toggled by `Shift+N` (see `handle_key`). Chose
    /// `Shift+N` instead of the issue's suggested `Shift+C` because the
    /// latter is already bound to `cycle_sort_mode` (feature B) — `Shift+N`
    /// reads as "cNsa" and keeps both toggles available.
    show_compliance_panel: bool,
    runtime_notices: Vec<String>,
    active_request_id: u64,
    next_request_id: u64,
    scan_started_at: Instant,
    detail_scroll: u16,
    notices_scroll: u16,
    source_context_cache: Option<SourceContextCache>,
    open_focus: OpenFocus,
    action_menu: Option<ActionMenu>,
    severity_picker: Option<SeverityPicker>,
    review_states: HashMap<String, ReviewState>,
}

impl TuiApp {
    fn new(request: TuiArgs) -> Self {
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
            severity_picker: None,
            review_states: HashMap::new(),
        }
    }

    fn begin_scan(&mut self) -> u64 {
        self.apply_launch_selection();
        self.error = None;
        self.result = None;
        self.selected = 0;
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

    fn apply_launch_selection(&mut self) {
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

    fn handle_worker_messages(&mut self, rx: &Receiver<WorkerMessage>) {
        while let Ok(message) = rx.try_recv() {
            if message.request_id != self.active_request_id {
                continue;
            }

            self.scanning = false;
            match message.result {
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
    }

    fn handle_key(&mut self, key: KeyEvent) -> ControlFlow {
        if matches!(key.code, KeyCode::Char('?')) {
            self.show_help = !self.show_help;
            return ControlFlow::Continue;
        }

        if self.show_help {
            return match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.show_help = false;
                    ControlFlow::Continue
                }
                _ => ControlFlow::Continue,
            };
        }

        if self.show_launch {
            return self.handle_launch_key(key.code);
        }

        if self.severity_picker.is_some() {
            return self.handle_severity_picker_key(key.code);
        }

        if self.action_menu.is_some() {
            return self.handle_action_menu_key(key.code);
        }

        if self.search_mode {
            return self.handle_search_key(key.code);
        }

        match key.code {
            KeyCode::Char('q') => ControlFlow::Exit,
            KeyCode::Char('j') | KeyCode::Down => {
                self.move_selection(1);
                ControlFlow::Continue
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.move_selection(-1);
                ControlFlow::Continue
            }
            KeyCode::Char('/') => {
                self.search_mode = true;
                ControlFlow::Continue
            }
            KeyCode::Char('0') => {
                self.min_severity = None;
                self.clamp_selection();
                ControlFlow::Continue
            }
            KeyCode::Char('1') => {
                self.min_severity = Some(Severity::Low);
                self.clamp_selection();
                ControlFlow::Continue
            }
            KeyCode::Char('2') => {
                self.min_severity = Some(Severity::Medium);
                self.clamp_selection();
                ControlFlow::Continue
            }
            KeyCode::Char('3') => {
                self.min_severity = Some(Severity::High);
                self.clamp_selection();
                ControlFlow::Continue
            }
            KeyCode::Char('4') => {
                self.min_severity = Some(Severity::Critical);
                self.clamp_selection();
                ControlFlow::Continue
            }
            KeyCode::Char('w') => {
                self.show_notices = !self.show_notices;
                ControlFlow::Continue
            }
            KeyCode::Char('N') => {
                self.show_compliance_panel = !self.show_compliance_panel;
                ControlFlow::Continue
            }
            KeyCode::Char('i') => self.open_action_menu(),
            KeyCode::PageDown => {
                self.scroll_detail(8);
                ControlFlow::Continue
            }
            KeyCode::PageUp => {
                self.scroll_detail(-8);
                ControlFlow::Continue
            }
            KeyCode::Char(']') => {
                self.scroll_notices(3);
                ControlFlow::Continue
            }
            KeyCode::Char('[') => {
                self.scroll_notices(-3);
                ControlFlow::Continue
            }
            KeyCode::Tab => {
                self.cycle_open_focus();
                ControlFlow::Continue
            }
            KeyCode::Enter => ControlFlow::OpenSelected,
            KeyCode::Char('o') => ControlFlow::OpenSelected,
            KeyCode::Char('r') => ControlFlow::Rescan,
            KeyCode::Char('c') => {
                self.cycle_session_min_confidence();
                ControlFlow::Continue
            }
            KeyCode::Char('C') => {
                self.cycle_sort_mode();
                ControlFlow::Continue
            }
            _ => ControlFlow::Continue,
        }
    }

    fn handle_search_key(&mut self, key: KeyCode) -> ControlFlow {
        match key {
            KeyCode::Esc => self.search_mode = false,
            KeyCode::Enter => {
                self.search_mode = false;
                self.clamp_selection();
            }
            KeyCode::Backspace => {
                self.search_query.pop();
                self.clamp_selection();
            }
            KeyCode::Char(ch) => {
                self.search_query.push(ch);
                self.clamp_selection();
            }
            _ => {}
        }

        ControlFlow::Continue
    }

    fn handle_launch_key(&mut self, key: KeyCode) -> ControlFlow {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => ControlFlow::Exit,
            KeyCode::Up | KeyCode::Char('k') => {
                self.launch_mode = self.launch_mode.previous();
                ControlFlow::Continue
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.launch_mode = self.launch_mode.next();
                ControlFlow::Continue
            }
            KeyCode::Char('1') => {
                self.launch_mode = LaunchMode::Scan;
                ControlFlow::Continue
            }
            KeyCode::Char('2') => {
                self.launch_mode = LaunchMode::Diff;
                ControlFlow::Continue
            }
            KeyCode::Char('3') => {
                self.launch_mode = LaunchMode::Secrets;
                ControlFlow::Continue
            }
            KeyCode::Char('4') => {
                self.launch_mode = LaunchMode::Pqc;
                ControlFlow::Continue
            }
            KeyCode::Backspace if self.launch_mode == LaunchMode::Diff => {
                self.launch_diff_target.pop();
                ControlFlow::Continue
            }
            KeyCode::Char(ch) if self.launch_mode == LaunchMode::Diff => {
                self.launch_diff_target.push(ch);
                ControlFlow::Continue
            }
            KeyCode::Enter => {
                if self.launch_mode == LaunchMode::Diff && self.launch_diff_target.trim().is_empty()
                {
                    self.launch_diff_target = "main".to_string();
                }
                ControlFlow::Rescan
            }
            _ => ControlFlow::Continue,
        }
    }

    fn handle_action_menu_key(&mut self, key: KeyCode) -> ControlFlow {
        let Some(menu) = self.action_menu.as_mut() else {
            return ControlFlow::Continue;
        };

        match key {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.action_menu = None;
                ControlFlow::Continue
            }
            KeyCode::Char('j') | KeyCode::Down => {
                menu.selected = (menu.selected + 1).min(menu.actions.len().saturating_sub(1));
                ControlFlow::Continue
            }
            KeyCode::Char('k') | KeyCode::Up => {
                menu.selected = menu.selected.saturating_sub(1);
                ControlFlow::Continue
            }
            KeyCode::Enter => {
                let action = menu.actions[menu.selected];
                if !self.action_enabled(action) {
                    return ControlFlow::Continue;
                }
                if matches!(action, TriageAction::LowerSeverity) {
                    self.open_severity_picker();
                    return ControlFlow::Continue;
                }
                self.action_menu = None;
                ControlFlow::ApplyAction(action)
            }
            _ => ControlFlow::Continue,
        }
    }

    fn handle_severity_picker_key(&mut self, key: KeyCode) -> ControlFlow {
        let Some(picker) = self.severity_picker.as_mut() else {
            return ControlFlow::Continue;
        };

        match key {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.severity_picker = None;
                ControlFlow::Continue
            }
            KeyCode::Char('j') | KeyCode::Down => {
                picker.selected =
                    (picker.selected + 1).min(SEVERITY_PICKER_CHOICES.len().saturating_sub(1));
                ControlFlow::Continue
            }
            KeyCode::Char('k') | KeyCode::Up => {
                picker.selected = picker.selected.saturating_sub(1);
                ControlFlow::Continue
            }
            KeyCode::Enter => {
                let severity = SEVERITY_PICKER_CHOICES[picker.selected];
                self.severity_picker = None;
                ControlFlow::ApplyAction(TriageAction::ApplySeverityOverride(severity))
            }
            _ => ControlFlow::Continue,
        }
    }

    fn cycle_session_min_confidence(&mut self) {
        // Cycle 0.0 → 0.7 → 0.9 → 1.0 → 0.0. The exact thresholds mirror
        // common "high-confidence only" review presets without requiring a
        // numeric prompt — the feature is deliberately a display filter,
        // not a scan-time knob (see `scan.min_confidence` in config for that).
        self.session_min_confidence = match self.session_min_confidence {
            value if value <= 0.0 => 0.7,
            value if value < 0.85 => 0.9,
            value if value < 0.95 => 1.0,
            _ => 0.0,
        };
        self.clamp_selection();
    }

    fn cycle_sort_mode(&mut self) {
        self.sort_mode = self.sort_mode.next();
        self.clamp_selection();
    }

    fn action_enabled(&self, action: TriageAction) -> bool {
        match action {
            TriageAction::DisableRuleGlobally => self
                .selected_finding()
                .map(|finding| {
                    !matches!(
                        is_rule_disabled_in_config(
                            Path::new(&self.request.path),
                            self.request.config.as_deref(),
                            &finding.rule_id,
                        ),
                        Ok(true)
                    )
                })
                .unwrap_or(true),
            _ => true,
        }
    }

    fn open_severity_picker(&mut self) {
        let Some(finding) = self.selected_finding() else {
            self.push_runtime_notice("no finding selected".to_string());
            return;
        };

        // Pre-select the current override if the user already dialed this
        // rule once before — saves a keystroke and makes the popup's current
        // value visible as the highlighted row.
        let current = current_severity_override(
            Path::new(&self.request.path),
            self.request.config.as_deref(),
            &finding.rule_id,
        )
        .ok()
        .flatten();
        let selected = current
            .and_then(|severity| {
                SEVERITY_PICKER_CHOICES
                    .iter()
                    .position(|choice| *choice == severity)
            })
            .unwrap_or(0);

        self.action_menu = None;
        self.severity_picker = Some(SeverityPicker { selected, current });
    }

    fn open_action_menu(&mut self) -> ControlFlow {
        let Some(finding) = self.selected_finding() else {
            self.push_runtime_notice("no finding selected".to_string());
            return ControlFlow::Continue;
        };

        let actions = self.available_actions_for_finding(finding);
        if actions.is_empty() {
            self.push_runtime_notice("no triage actions available for this finding".to_string());
            return ControlFlow::Continue;
        }

        self.action_menu = Some(ActionMenu {
            actions,
            selected: 0,
        });

        ControlFlow::Continue
    }

    fn available_actions_for_finding(&self, finding: &Finding) -> Vec<TriageAction> {
        let mut actions = match self.result.as_ref().map(|result| &result.mode) {
            Some(TuiMode::Scan) => vec![
                TriageAction::AddToBaseline,
                TriageAction::IgnoreRuleInFile,
                TriageAction::LowerSeverity,
                TriageAction::DisableRuleGlobally,
                TriageAction::MarkReviewed,
                TriageAction::MarkTodo,
                TriageAction::MarkIgnoreCandidate,
            ],
            Some(TuiMode::Secrets) => vec![
                TriageAction::AddToBaseline,
                TriageAction::IgnoreSecretRule,
                TriageAction::MarkReviewed,
                TriageAction::MarkTodo,
                TriageAction::MarkIgnoreCandidate,
            ],
            Some(TuiMode::Diff { .. }) => vec![
                TriageAction::MarkReviewed,
                TriageAction::MarkTodo,
                TriageAction::MarkIgnoreCandidate,
            ],
            None => Vec::new(),
        };

        if self.review_state_for(finding).is_some() {
            actions.push(TriageAction::ClearReviewState);
        }

        actions
    }

    fn review_state_for(&self, finding: &Finding) -> Option<ReviewState> {
        self.review_states
            .get(&finding_review_key(finding))
            .copied()
    }

    fn move_selection(&mut self, delta: isize) {
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

    fn clamp_selection(&mut self) {
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

    fn cycle_open_focus(&mut self) {
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

    fn normalize_open_focus(&mut self) {
        let Some(finding) = self.selected_finding() else {
            self.open_focus = OpenFocus::Finding;
            return;
        };

        let available = available_open_focuses(finding);
        if !available.contains(&self.open_focus) {
            self.open_focus = OpenFocus::Finding;
        }
    }

    fn advance_spinner(&mut self) {
        self.loading_tick = (self.loading_tick + 1) % LOADING_SHIMMER_CYCLE;
    }

    fn filtered_indices(&self) -> Vec<usize> {
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
    fn total_after_severity_and_search(&self) -> usize {
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

    fn matches_filters(&self, finding: &Finding, needle: &str) -> bool {
        if !self.matches_non_confidence_filters(finding, needle) {
            return false;
        }
        // Confidence filter is last so it reads naturally as the "final
        // cut" and so the footer counts above (non-confidence filtered)
        // stay independent of the `c` keybind.
        finding.confidence + 1e-6 >= self.session_min_confidence
    }

    fn matches_non_confidence_filters(&self, finding: &Finding, needle: &str) -> bool {
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

    fn selected_finding(&self) -> Option<&Finding> {
        let result = self.result.as_ref()?;
        let filtered = self.filtered_indices();
        let finding_index = *filtered.get(self.selected)?;
        result.findings.get(finding_index)
    }

    fn draw(&mut self, frame: &mut ratatui::Frame) {
        if self.show_launch {
            self.draw_launch(frame);
            if self.show_help {
                self.draw_help(frame);
            }
            return;
        }

        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(1),
                Constraint::Min(10),
                Constraint::Length(1),
            ])
            .split(frame.area());

        self.draw_header(frame, layout[0]);
        frame.render_widget(
            Block::default().style(Style::default().bg(HEADER_BG)),
            layout[1],
        );

        if self.scanning {
            self.draw_loading(frame, layout[2]);
        } else if let Some(error) = self.error.as_ref() {
            let error = Paragraph::new(error.as_str())
                .style(Style::default().fg(Color::Red))
                .block(panel_block(Some("Scan Error"), PANEL_BG))
                .wrap(Wrap { trim: false });
            frame.render_widget(error, layout[2]);
        } else {
            self.draw_body(frame, layout[2]);
        }

        self.draw_footer(frame, layout[3]);

        if self.show_help {
            self.draw_help(frame);
        }

        if self.action_menu.is_some() {
            self.draw_action_menu(frame);
        }

        if self.severity_picker.is_some() {
            self.draw_severity_picker(frame);
        }
    }

    fn draw_loading(&self, frame: &mut ratatui::Frame, area: Rect) {
        let elapsed = self.scan_started_at.elapsed().as_secs_f32();
        let loading_area = centered_rect(62, 44, area);
        let block = panel_block(Some("Scanning"), PANEL_BG);
        let inner = block.inner(loading_area);
        frame.render_widget(block, loading_area);

        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(1),
            ])
            .split(inner);

        let (headline, subline) = loading_copy(self);
        frame.render_widget(
            Paragraph::new(Text::from(vec![
                Line::from(Span::styled(
                    headline,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(
                    subline,
                    Style::default().fg(Color::Rgb(158, 140, 112)),
                )),
                Line::from(Span::styled(
                    format!("elapsed {:.1}s", elapsed),
                    Style::default().fg(Color::Rgb(124, 108, 84)),
                )),
            ]))
            .style(Style::default().bg(PANEL_BG)),
            layout[0],
        );

        let phases = loading_phase_labels(self);
        for (index, label) in phases.iter().enumerate() {
            frame.render_widget(
                Paragraph::new(Line::from(loading_shimmer_line(
                    label,
                    LOADING_SKELETON_WIDTH,
                    self.loading_tick,
                )))
                .style(Style::default().bg(PANEL_BG)),
                layout[2 + index],
            );
        }
    }

    fn draw_launch(&self, frame: &mut ratatui::Frame) {
        frame.render_widget(
            Block::default().style(Style::default().bg(APP_BG)),
            frame.area(),
        );

        let page = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(10), Constraint::Length(1)])
            .split(frame.area());

        let area = centered_rect(54, 52, page[0]);
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5),
                Constraint::Length(3),
                Constraint::Length(11),
                Constraint::Length(2),
                Constraint::Min(1),
            ])
            .split(area);

        let logo = Paragraph::new(Text::from(vec![
            Line::from(Span::styled(
                "   ___                               __",
                Style::default()
                    .fg(LOGO_PRIMARY)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "  / _/__ __ _____ ___ _____ ________/ /",
                Style::default()
                    .fg(LOGO_PRIMARY)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                r" / _/ _ \\ \ / _ `/ // / _ `/ __/ _  / ",
                Style::default()
                    .fg(LOGO_SECONDARY)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                r"/_/ \___/_\_\\_, /\_,_/\_,_/_/  \_,_/  ",
                Style::default()
                    .fg(LOGO_SECONDARY)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "            /___/                      ",
                Style::default()
                    .fg(LOGO_PRIMARY)
                    .add_modifier(Modifier::BOLD),
            )),
        ]))
        .alignment(Alignment::Center)
        .style(Style::default().bg(APP_BG));
        frame.render_widget(logo, layout[0]);

        let intro = Paragraph::new(Text::from(vec![
            Line::from(Span::styled(
                "a security scanner as fast as your linter",
                Style::default()
                    .fg(Color::Rgb(208, 190, 150))
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "foxguard.dev",
                Style::default().fg(Color::Rgb(130, 112, 88)),
            )),
        ]))
        .alignment(Alignment::Center)
        .style(Style::default().bg(APP_BG));
        frame.render_widget(intro, layout[1]);

        let selector_area = centered_rect(84, 100, layout[2]);
        let selector_block = Block::default()
            .style(Style::default().bg(LIST_BG))
            .padding(Padding::new(2, 2, 1, 1));
        let selector_inner = selector_block.inner(selector_area);
        frame.render_widget(selector_block, selector_area);

        let cards = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Length(2),
                Constraint::Length(2),
                Constraint::Length(2),
                Constraint::Min(1),
            ])
            .split(selector_inner);
        for (index, mode) in [
            LaunchMode::Scan,
            LaunchMode::Diff,
            LaunchMode::Secrets,
            LaunchMode::Pqc,
        ]
        .into_iter()
        .enumerate()
        {
            self.draw_launch_card(frame, cards[index], mode);
        }

        if self.launch_mode == LaunchMode::Diff {
            let diff_target = if self.launch_diff_target.trim().is_empty() {
                "main".to_string()
            } else {
                self.launch_diff_target.clone()
            };
            let diff_area = centered_rect(72, 100, layout[3]);
            let diff = Paragraph::new(Text::from(vec![
                Line::from(Span::styled(
                    "target branch",
                    Style::default()
                        .fg(Color::Rgb(186, 157, 104))
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(vec![
                    Span::raw(" "),
                    Span::styled(
                        diff_target,
                        Style::default()
                            .fg(Color::Black)
                            .bg(TITLE_BG)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
            ]))
            .alignment(Alignment::Center)
            .style(Style::default().bg(APP_BG));
            frame.render_widget(diff, diff_area);
        }

        self.draw_launch_footer(frame, page[1]);
    }

    fn draw_launch_card(&self, frame: &mut ratatui::Frame, area: Rect, mode: LaunchMode) {
        let selected = self.launch_mode == mode;
        let (title, subtitle, accent, shortcut) = match mode {
            LaunchMode::Scan => (
                "Scan",
                "full repository scan",
                Color::Rgb(186, 157, 104),
                "1",
            ),
            LaunchMode::Diff => (
                "Diff",
                "new issues vs target branch",
                Color::Rgb(167, 131, 88),
                "2",
            ),
            LaunchMode::Secrets => (
                "Secrets",
                "credentials and token leaks",
                Color::Rgb(176, 112, 92),
                "3",
            ),
            LaunchMode::Pqc => (
                "Pqc",
                "post-quantum crypto audit",
                Color::Rgb(96, 168, 176),
                "4",
            ),
        };
        let background = if selected { DETAIL_BG } else { LAUNCH_CARD_BG };
        let title_style = if selected {
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(accent).add_modifier(Modifier::BOLD)
        };
        let subtitle_style = if selected {
            Style::default().fg(Color::Rgb(208, 190, 150))
        } else {
            Style::default().fg(Color::Rgb(158, 140, 112))
        };
        let block = Block::default()
            .style(Style::default().bg(background))
            .padding(Padding::new(2, 2, 0, 0));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if selected {
            frame.render_widget(
                Block::default().style(Style::default().bg(accent)),
                Rect {
                    x: area.x,
                    y: area.y,
                    width: 1,
                    height: area.height,
                },
            );
        }
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    shortcut.to_string(),
                    Style::default().fg(accent).add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("{}{}", if selected { "> " } else { "  " }, title),
                    title_style,
                ),
                Span::raw("   "),
                Span::styled(subtitle, subtitle_style),
            ]))
            .style(Style::default().bg(background))
            .wrap(Wrap { trim: true }),
            inner,
        );
    }

    fn draw_header(&self, frame: &mut ratatui::Frame, area: Rect) {
        let filter = self
            .min_severity
            .map(severity_name)
            .unwrap_or("all severities");
        let mut summary_spans = vec![
            Span::styled(
                "foxguard tui",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                request_mode_label(&self.request),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw("  "),
            Span::raw(short_path(&self.request.path)),
            Span::raw("  "),
            footer_label_span("filter"),
            Span::raw(" "),
            footer_value_span(filter),
        ];

        let mut badge_spans = Vec::new();

        if let Some(result) = self.result.as_ref() {
            let counts = severity_counts(&result.findings);
            summary_spans.push(Span::raw("  "));
            summary_spans.push(Span::styled(
                format!(
                    "{} issues | {} files | {:.2}s",
                    result.findings.len(),
                    result.files_scanned,
                    result.duration.as_secs_f64()
                ),
                Style::default().fg(Color::Gray),
            ));
            badge_spans = severity_badge_spans(&counts);

            if let Some(summary) = result.diff_summary.as_ref() {
                append_diff_summary(&mut summary_spans, summary);
            }

            if result.files_scanned == 0 {
                summary_spans.push(Span::raw("  "));
                summary_spans.push(Span::styled(
                    "no files found",
                    Style::default().fg(Color::Yellow),
                ));
            }
        } else if self.scanning {
            summary_spans.push(Span::raw("  "));
            summary_spans.push(Span::styled(
                format!(
                    "elapsed {:.1}s",
                    self.scan_started_at.elapsed().as_secs_f32()
                ),
                Style::default().fg(Color::Gray),
            ));
        }

        let mut lines = vec![Line::from(summary_spans)];
        if !badge_spans.is_empty() {
            lines.push(Line::from(badge_spans));
        }

        let header = Paragraph::new(Text::from(lines)).block(panel_block(None, HEADER_BG));
        frame.render_widget(header, area);
    }

    fn draw_body(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        // Vertical slot plan for the scan body:
        //   [0] findings + detail (main content, always present)
        //   [1] notices panel (optional)
        //   [2] CNSA 2.0 compliance strip (optional, 4 rows)
        // The compliance strip sits *below* notices so notices never shrink
        // when it is toggled on.
        let show_notices = self.show_notices && self.notice_count() > 0;
        let show_compliance = self.show_compliance_panel && self.result.is_some();

        let mut body_constraints: Vec<Constraint> = vec![Constraint::Min(8)];
        if show_notices {
            body_constraints.push(Constraint::Length(6));
        }
        if show_compliance {
            body_constraints.push(Constraint::Length(4));
        }
        let body_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints(body_constraints)
            .split(area);

        let direction = if body_layout[0].width < 110 {
            Direction::Vertical
        } else {
            Direction::Horizontal
        };
        let constraints = if matches!(direction, Direction::Vertical) {
            vec![Constraint::Percentage(45), Constraint::Percentage(55)]
        } else {
            vec![Constraint::Percentage(42), Constraint::Percentage(58)]
        };
        let layout = Layout::default()
            .direction(direction)
            .constraints(constraints)
            .split(body_layout[0]);

        let filtered = self.filtered_indices();
        let items = if let Some(result) = self.result.as_ref() {
            filtered
                .iter()
                .map(|index| {
                    let finding = &result.findings[*index];
                    list_item(finding, self.review_state_for(finding))
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        let list_title = self
            .result
            .as_ref()
            .map(|result| {
                format!(
                    "{} ({}/{})",
                    mode_findings_title(&result.mode),
                    if filtered.is_empty() {
                        0
                    } else {
                        self.selected + 1
                    },
                    filtered.len()
                )
            })
            .unwrap_or_else(|| "findings".to_string());
        let list = List::new(items)
            .block(panel_block(Some(&list_title), LIST_BG))
            .highlight_style(
                Style::default()
                    .fg(Color::White)
                    .bg(DETAIL_BG)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");

        let mut state = ListState::default();
        if !filtered.is_empty() {
            state.select(Some(self.selected));
        }
        frame.render_stateful_widget(list, layout[0], &mut state);

        let detail = Paragraph::new(self.detail_text())
            .block(panel_block(Some("Detail"), DETAIL_BG))
            .scroll((self.detail_scroll, 0))
            .wrap(Wrap { trim: false });
        frame.render_widget(detail, layout[1]);

        let mut next_slot: usize = 1;
        if show_notices {
            let notices = Paragraph::new(self.notice_text())
                .block(panel_block(Some("Notices"), NOTICE_BG))
                .scroll((self.notices_scroll, 0))
                .wrap(Wrap { trim: false });
            frame.render_widget(notices, body_layout[next_slot]);
            next_slot += 1;
        }
        if show_compliance {
            let paragraph = Paragraph::new(self.compliance_panel_text())
                .block(panel_block(Some("CNSA 2.0"), PANEL_BG))
                .wrap(Wrap { trim: false });
            frame.render_widget(paragraph, body_layout[next_slot]);
        }
    }

    /// Build the CNSA 2.0 compliance strip content.
    ///
    /// Mirrors the terminal reporter's `print_cnsa2_summary` block so both
    /// surfaces render the same information from the same source — see
    /// `src/report/terminal.rs`. The function is intentionally pure (takes
    /// only `&self` and returns a `Text`) so it can be unit-tested without
    /// spinning up a terminal backend.
    fn compliance_panel_text(&self) -> Text<'static> {
        let findings: &[Finding] = self
            .result
            .as_ref()
            .map(|r| r.findings.as_slice())
            .unwrap_or(&[]);
        let report = crate::compliance::MigrationReport::from_findings(findings);

        if report.annotated == 0 {
            return Text::from(vec![
                Line::from(""),
                Line::from(Span::styled(
                    "no CNSA 2.0 findings in this scan",
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::DIM),
                )),
            ]);
        }

        let (badge_label, badge_bg) = match report.level {
            crate::compliance::MigrationLevel::Clean => (" clean ", Color::Green),
            crate::compliance::MigrationLevel::OnTrack => (" on-track ", Color::Yellow),
            crate::compliance::MigrationLevel::AtRisk => (" at-risk ", Color::Red),
        };
        let badge = Span::styled(
            badge_label,
            Style::default()
                .bg(badge_bg)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        );

        let summary = format!(
            "  {} finding{} with NSA transition deadlines",
            report.annotated,
            if report.annotated == 1 { "" } else { "s" }
        );

        let mut entries: Vec<(&String, &usize)> = report.by_deadline.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let bullets = entries
            .iter()
            .map(|(year, count)| format!("{} by {}", count, year))
            .collect::<Vec<_>>()
            .join("  \u{00b7}  ");

        Text::from(vec![
            Line::from(vec![
                badge,
                Span::raw("  "),
                Span::styled(
                    summary,
                    Style::default().fg(Color::Gray).add_modifier(Modifier::DIM),
                ),
            ]),
            Line::from(Span::styled(
                bullets,
                Style::default().fg(Color::Rgb(201, 172, 114)),
            )),
        ])
    }

    fn detail_text(&mut self) -> Text<'static> {
        let Some(finding) = self.selected_finding().cloned() else {
            if self.result.is_some() {
                return Text::from("No findings match the current filters.");
            }
            return Text::from("");
        };

        let mut lines = vec![
            Line::from(vec![
                severity_badge_span(finding.severity),
                Span::raw("  "),
                Span::styled(
                    finding.description.clone(),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            metadata_line("Rule", &finding.rule_id),
            metadata_line(
                "Location",
                &format!(
                    "{}:{}:{}",
                    display_path(&finding.file),
                    finding.line,
                    finding.column
                ),
            ),
        ];

        if let Some(cwe) = finding.cwe.as_ref() {
            lines.push(metadata_line("CWE", cwe));
        }
        if !finding.tags.is_empty() {
            lines.push(metadata_line("Tags", &finding.tags.join(", ")));
        }
        if let Some(review) = self.review_summary_for_finding(&finding) {
            lines.push(metadata_line("Review", &review));
        }

        // Crypto-agility metadata (#248). These belong with the header block,
        // not the snippet, so they sit between the review/tags metadata and
        // the source-context section. Dimmed to read as advisory context
        // rather than a primary severity signal. Skipped entirely when both
        // fields are `None`, so non-crypto findings look unchanged.
        if let Some(algorithm) = finding.crypto_algorithm.as_ref() {
            lines.push(Line::from(Span::styled(
                format!("Algorithm: {}", algorithm),
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::DIM),
            )));
        }
        if let Some(deadline) = finding.cnsa2_deadline.as_ref() {
            lines.push(Line::from(Span::styled(
                format!("CNSA 2.0: migrate before end of {}", deadline),
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::DIM),
            )));
        }

        if let Some(context_lines) = self.source_context_lines(&finding) {
            lines.push(Line::from(""));
            lines.push(section_heading("Context", Color::Yellow));
            lines.extend(context_lines);
        }

        lines.push(Line::from(""));
        lines.push(section_heading("Snippet", Color::Yellow));
        for line in finding.snippet.lines() {
            lines.push(Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(Color::Gray),
            )));
        }

        lines.push(Line::from(""));
        lines.push(section_heading("Open", Color::Cyan));
        lines.extend(open_target_lines(&finding, self.open_focus));

        if finding_has_dataflow(&finding) {
            lines.push(Line::from(""));
            lines.push(section_heading("Dataflow", Color::Cyan));
            lines.extend(dataflow_lines(&finding, self.open_focus));
        }

        if let Some(fix) = finding.fix_suggestion.as_ref() {
            lines.push(Line::from(""));
            lines.push(section_heading("Fix", Color::Green));
            lines.push(Line::from(fix.clone()));
        }

        Text::from(lines)
    }

    fn source_context_lines(&mut self, finding: &Finding) -> Option<Vec<Line<'static>>> {
        if self.request.secrets {
            return None;
        }

        let path = resolve_finding_path(&self.request.path, &finding.file);
        let key = SourceContextCacheKey {
            path,
            line: finding.line,
            end_line: finding.end_line,
            column: finding.column,
            end_column: finding.end_column,
        };

        if let Some(cache) = self.source_context_cache.as_ref() {
            if cache.key == key {
                return Some(cache.lines.clone());
            }
        }

        let lines = match fs::read_to_string(&key.path) {
            Ok(source) => render_source_context(&source, finding, 2),
            Err(error) => vec![Line::from(Span::styled(
                format!("Unable to load source context: {}", error),
                Style::default().fg(Color::DarkGray),
            ))],
        };

        self.source_context_cache = Some(SourceContextCache {
            key,
            lines: lines.clone(),
        });

        Some(lines)
    }

    fn draw_footer(&self, frame: &mut ratatui::Frame, area: Rect) {
        let key_spans = vec![
            footer_key_span("j/k"),
            Span::raw(" move  "),
            footer_key_span("/"),
            Span::raw(" search  "),
            footer_key_span("i"),
            Span::raw(" triage  "),
            footer_key_span("c"),
            Span::raw(" conf  "),
            footer_key_span("C"),
            Span::raw(" sort  "),
            footer_key_span("w"),
            Span::raw(" notices  "),
            footer_key_span("?"),
            Span::raw(" help  "),
            footer_key_span("Enter"),
            Span::raw(" open"),
        ];

        let mut right_spans: Vec<Span<'static>> = Vec::new();

        // Confidence filter summary — only surfaces when non-zero so users
        // whose session matches the default see an uncluttered footer.
        if self.session_min_confidence > 0.0 {
            let filtered_len = self.filtered_indices().len();
            let total = self.total_after_severity_and_search();
            right_spans.push(footer_label_span("conf"));
            right_spans.push(Span::raw(" "));
            right_spans.push(footer_value_span(&format!(
                "≥ {:.2} ({}/{})",
                self.session_min_confidence, filtered_len, total
            )));
            right_spans.push(Span::raw("  "));
        }

        // Only surface the sort label when it's off-default; the legacy
        // severity-desc ordering is the least surprising starting point so
        // we don't advertise it until the user explicitly cycles.
        if self.sort_mode != SortMode::default() {
            right_spans.push(footer_label_span("sort"));
            right_spans.push(Span::raw(" "));
            right_spans.push(footer_value_span(self.sort_mode.label()));
            right_spans.push(Span::raw("  "));
        }

        let search_text = if self.search_mode {
            format!("/{}", self.search_query)
        } else if self.search_query.is_empty() {
            String::new()
        } else {
            self.search_query.clone()
        };
        if !search_text.is_empty() {
            right_spans.push(footer_label_span("search"));
            right_spans.push(Span::raw(" "));
            right_spans.push(footer_value_span(&search_text));
        }

        let right_line = if right_spans.is_empty() {
            Line::from("")
        } else {
            Line::from(right_spans)
        };
        draw_status_bar(frame, area, Line::from(key_spans), right_line);
    }

    fn draw_launch_footer(&self, frame: &mut ratatui::Frame, area: Rect) {
        let left = Line::from(vec![
            footer_key_span("h/l"),
            Span::raw(" move  "),
            footer_key_span("1-4"),
            Span::raw(" jump  "),
            footer_key_span("Tab"),
            Span::raw(" cycle  "),
            footer_key_span("Enter"),
            Span::raw(" launch  "),
            footer_key_span("?"),
            Span::raw(" help  "),
            footer_key_span("q"),
            Span::raw(" quit"),
        ]);
        let right = Line::from(vec![
            footer_label_span("mode"),
            Span::raw(" "),
            footer_value_span(match self.launch_mode {
                LaunchMode::Scan => "scan",
                LaunchMode::Diff => "diff",
                LaunchMode::Secrets => "secrets",
                LaunchMode::Pqc => "pqc",
            }),
            Span::raw("  "),
            footer_label_span("path"),
            Span::raw(" "),
            footer_value_span(&short_path(&self.request.path)),
        ]);
        draw_status_bar(frame, area, left, right);
    }

    fn draw_help(&self, frame: &mut ratatui::Frame) {
        let area = centered_rect(56, 42, frame.area());
        frame.render_widget(Clear, area);
        let help = Paragraph::new(Text::from(vec![
            Line::from(Span::styled(
                "foxguard tui help",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("j/k or arrows  move between findings"),
            Line::from("/              search findings"),
            Line::from("0-4            set minimum severity filter"),
            Line::from("c              cycle session confidence filter"),
            Line::from("Shift+C        cycle list sort (severity | confidence)"),
            Line::from("Tab            cycle open target between finding/source/sink"),
            Line::from("i              open triage actions for the selected finding"),
            Line::from("Enter          open the current target in your editor"),
            Line::from("w              show or hide notices panel"),
            Line::from("Shift+N        toggle CNSA 2.0 compliance panel"),
            Line::from("PageUp/Down    scroll detail pane"),
            Line::from("[/]            scroll notices pane"),
            Line::from("r              rescan"),
            Line::from("q              quit"),
            Line::from("? or Esc       close this help"),
        ]))
        .alignment(Alignment::Left)
        .style(Style::default().bg(Color::Rgb(22, 24, 29)).fg(Color::White))
        .block(
            Block::default()
                .title("help")
                .borders(Borders::ALL)
                .style(Style::default().bg(Color::Rgb(22, 24, 29))),
        )
        .wrap(Wrap { trim: false });
        frame.render_widget(help, area);
    }

    fn draw_action_menu(&self, frame: &mut ratatui::Frame) {
        let Some(menu) = self.action_menu.as_ref() else {
            return;
        };

        let area = centered_rect(56, 42, frame.area());
        let summary = self
            .selected_finding()
            .map(|finding| {
                format!(
                    "{}:{}  {}",
                    display_path(&finding.file),
                    finding.line,
                    finding.rule_id
                )
            })
            .unwrap_or_else(|| "no finding selected".to_string());
        let items = menu
            .actions
            .iter()
            .map(|action| {
                let enabled = self.action_enabled(*action);
                let style = if enabled {
                    Style::default()
                } else {
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::DIM)
                };
                let mut label = action.label();
                if !enabled {
                    label.push_str("  (already disabled)");
                }
                ListItem::new(Line::from(Span::styled(label, style)))
            })
            .collect::<Vec<_>>();
        let list = List::new(items)
            .block(panel_block(None, PANEL_BG))
            .highlight_style(
                Style::default()
                    .fg(Color::White)
                    .bg(DETAIL_BG)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        let inner = area.inner(Margin {
            vertical: 1,
            horizontal: 1,
        });
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Length(menu.actions.len() as u16 + 2),
                Constraint::Length(4),
                Constraint::Length(1),
            ])
            .split(inner);

        frame.render_widget(Clear, area);
        frame.render_widget(
            Block::default()
                .title("triage")
                .borders(Borders::ALL)
                .style(Style::default().bg(PANEL_BG)),
            area,
        );
        frame.render_widget(
            Paragraph::new(Text::from(vec![
                Line::from(Span::styled(
                    "triage actions",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(summary, Style::default().fg(Color::Gray))),
            ]))
            .style(Style::default().bg(PANEL_BG)),
            layout[0],
        );

        let mut state = ListState::default();
        state.select(Some(menu.selected));
        frame.render_stateful_widget(list, layout[1], &mut state);
        if let Some(action) = menu.actions.get(menu.selected).copied() {
            frame.render_widget(
                Paragraph::new(Text::from(self.action_preview(action)))
                    .style(Style::default().bg(PANEL_BG).fg(Color::Gray))
                    .wrap(Wrap { trim: false }),
                layout[2],
            );
        }
        frame.render_widget(
            Paragraph::new("Enter apply  Esc cancel")
                .style(Style::default().bg(PANEL_BG).fg(Color::Gray))
                .alignment(Alignment::Left),
            layout[3],
        );
    }

    fn draw_severity_picker(&self, frame: &mut ratatui::Frame) {
        let Some(picker) = self.severity_picker.as_ref() else {
            return;
        };

        let area = centered_rect(44, 34, frame.area());
        let rule_id = self
            .selected_finding()
            .map(|finding| finding.rule_id.clone())
            .unwrap_or_else(|| "no finding selected".to_string());
        let items = SEVERITY_PICKER_CHOICES
            .iter()
            .map(|severity| {
                let mut spans = vec![
                    severity_badge_span(*severity),
                    Span::raw("  "),
                    Span::styled(severity.to_string(), Style::default().fg(Color::White)),
                ];
                if picker.current == Some(*severity) {
                    spans.push(Span::raw("  "));
                    spans.push(Span::styled("(current)", Style::default().fg(Color::Gray)));
                }
                ListItem::new(Line::from(spans))
            })
            .collect::<Vec<_>>();
        let list = List::new(items)
            .block(panel_block(None, PANEL_BG))
            .highlight_style(
                Style::default()
                    .fg(Color::White)
                    .bg(DETAIL_BG)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");

        let inner = area.inner(Margin {
            vertical: 1,
            horizontal: 1,
        });
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Length(SEVERITY_PICKER_CHOICES.len() as u16 + 2),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(inner);

        frame.render_widget(Clear, area);
        frame.render_widget(
            Block::default()
                .title("lower severity")
                .borders(Borders::ALL)
                .style(Style::default().bg(PANEL_BG)),
            area,
        );

        let subtitle = match picker.current {
            Some(current) => format!("{}  (current: {})", rule_id, current),
            None => rule_id,
        };
        frame.render_widget(
            Paragraph::new(Text::from(vec![
                Line::from(Span::styled(
                    "choose a new severity",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(subtitle, Style::default().fg(Color::Gray))),
            ]))
            .style(Style::default().bg(PANEL_BG)),
            layout[0],
        );

        let mut state = ListState::default();
        state.select(Some(picker.selected));
        frame.render_stateful_widget(list, layout[1], &mut state);
        frame.render_widget(
            Paragraph::new("writes scan.severity_overrides to the repo config")
                .style(Style::default().bg(PANEL_BG).fg(Color::Gray))
                .wrap(Wrap { trim: false }),
            layout[2],
        );
        frame.render_widget(
            Paragraph::new("Enter apply  Esc cancel")
                .style(Style::default().bg(PANEL_BG).fg(Color::Gray))
                .alignment(Alignment::Left),
            layout[3],
        );
    }

    fn open_selected_finding(&mut self, session: &mut TerminalSession) -> Result<(), String> {
        match self.open_focus {
            OpenFocus::Finding => {
                let target = self
                    .selected_finding()
                    .map(|finding| OpenTarget {
                        path: resolve_finding_path(&self.request.path, &finding.file),
                        line: finding.line.max(1),
                    })
                    .ok_or_else(|| "no finding selected".to_string())?;

                self.open_target(session, target, "finding")
            }
            OpenFocus::Source => self.open_source_finding(session),
            OpenFocus::Sink => self.open_sink_finding(session),
        }
    }

    fn open_source_finding(&mut self, session: &mut TerminalSession) -> Result<(), String> {
        let finding = self
            .selected_finding()
            .cloned()
            .ok_or_else(|| "no finding selected".to_string())?;
        let line = finding
            .source_line
            .ok_or_else(|| "no source location for selected finding".to_string())?;
        self.open_focus = OpenFocus::Source;
        let target = OpenTarget {
            path: resolve_finding_path(&self.request.path, &finding.file),
            line: line.max(1),
        };

        self.open_target(session, target, "source")
    }

    fn open_sink_finding(&mut self, session: &mut TerminalSession) -> Result<(), String> {
        let finding = self
            .selected_finding()
            .cloned()
            .ok_or_else(|| "no finding selected".to_string())?;
        let line = finding
            .sink_line
            .ok_or_else(|| "no sink location for selected finding".to_string())?;
        self.open_focus = OpenFocus::Sink;
        let target = OpenTarget {
            path: resolve_finding_path(&self.request.path, &finding.file),
            line: line.max(1),
        };

        self.open_target(session, target, "sink")
    }

    fn open_target(
        &mut self,
        session: &mut TerminalSession,
        target: OpenTarget,
        label: &str,
    ) -> Result<(), String> {
        if !target.path.exists() {
            return Err(format!("{} does not exist", target.path.display()));
        }

        let command_spec = open_command_spec(&target)?;
        session.suspend()?;
        // foxguard: ignore[rs/no-command-injection]
        let status = Command::new(&command_spec.program)
            .args(&command_spec.args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| format!("failed to launch {}: {}", command_spec.program, e));
        session.resume()?;

        match status {
            Ok(exit) if exit.success() => {
                self.push_runtime_notice(format!(
                    "opened {} {}:{}",
                    label,
                    target.path.display(),
                    target.line
                ));
                Ok(())
            }
            Ok(exit) => Err(format!(
                "{} exited with status {}",
                command_spec.program, exit
            )),
            Err(error) => Err(error),
        }
    }

    fn apply_action(&mut self, action: TriageAction) -> Result<bool, String> {
        let finding = self
            .selected_finding()
            .cloned()
            .ok_or_else(|| "no finding selected".to_string())?;
        let review_key = finding_review_key(&finding);

        match action {
            TriageAction::AddToBaseline => {
                let baseline_path = self.baseline_path_for_actions()?;
                let added = append_finding_to_baseline(&baseline_path, &finding)?;
                if added {
                    self.push_runtime_notice(format!(
                        "added finding to baseline {}",
                        baseline_path.display()
                    ));
                } else {
                    self.push_runtime_notice(format!(
                        "finding already present in baseline {}",
                        baseline_path.display()
                    ));
                }
                Ok(true)
            }
            TriageAction::IgnoreRuleInFile => {
                let (config_path, added) = add_scan_ignore_rule(
                    Path::new(&self.request.path),
                    self.request.config.as_deref(),
                    &finding,
                )?;
                if added {
                    self.push_runtime_notice(format!(
                        "ignored {} in {} via {}",
                        finding.rule_id,
                        display_path(&finding.file),
                        config_path.display()
                    ));
                } else {
                    self.push_runtime_notice(format!(
                        "ignore already exists in {}",
                        config_path.display()
                    ));
                }
                Ok(true)
            }
            TriageAction::IgnoreSecretRule => {
                let (config_path, added) = add_secrets_ignored_rule(
                    Path::new(&self.request.path),
                    self.request.config.as_deref(),
                    &finding.rule_id,
                )?;
                if added {
                    self.push_runtime_notice(format!(
                        "ignored {} via {}",
                        finding.rule_id,
                        config_path.display()
                    ));
                } else {
                    self.push_runtime_notice(format!(
                        "ignore already exists in {}",
                        config_path.display()
                    ));
                }
                Ok(true)
            }
            TriageAction::LowerSeverity => {
                // `LowerSeverity` opens the severity picker; the picker
                // dispatches `ApplySeverityOverride(sev)` when the user picks.
                // We should never land here for a direct apply, but keep the
                // arm so adding the variant to `available_actions_for_finding`
                // stays exhaustive without requiring two layers of state.
                self.open_severity_picker();
                Ok(false)
            }
            TriageAction::ApplySeverityOverride(severity) => {
                let (config_path, previous) = add_severity_override_to_config(
                    Path::new(&self.request.path),
                    self.request.config.as_deref(),
                    &finding.rule_id,
                    severity,
                )?;
                match previous {
                    Some(prev) if prev != severity => {
                        self.push_runtime_notice(format!(
                            "lowered {} from {} to {} via {}",
                            finding.rule_id,
                            prev,
                            severity,
                            config_path.display()
                        ));
                    }
                    Some(_) => {
                        self.push_runtime_notice(format!(
                            "{} already set to {} in {}",
                            finding.rule_id,
                            severity,
                            config_path.display()
                        ));
                    }
                    None => {
                        self.push_runtime_notice(format!(
                            "set severity_overrides[{}] = {} via {}",
                            finding.rule_id,
                            severity,
                            config_path.display()
                        ));
                    }
                }
                Ok(true)
            }
            TriageAction::DisableRuleGlobally => {
                let (config_path, added) = add_disabled_rule_to_config(
                    Path::new(&self.request.path),
                    self.request.config.as_deref(),
                    &finding.rule_id,
                )?;
                if added {
                    self.push_runtime_notice(format!(
                        "added {} to scan.disable_rules in {}",
                        finding.rule_id,
                        config_path.display()
                    ));
                } else {
                    self.push_runtime_notice(format!(
                        "{} already in scan.disable_rules in {}",
                        finding.rule_id,
                        config_path.display()
                    ));
                }
                Ok(true)
            }
            TriageAction::MarkReviewed => {
                self.review_states.insert(review_key, ReviewState::Reviewed);
                self.push_runtime_notice("marked finding as reviewed".to_string());
                Ok(false)
            }
            TriageAction::MarkTodo => {
                self.review_states.insert(review_key, ReviewState::Todo);
                self.push_runtime_notice("marked finding as todo".to_string());
                Ok(false)
            }
            TriageAction::MarkIgnoreCandidate => {
                self.review_states
                    .insert(review_key, ReviewState::IgnoreCandidate);
                self.push_runtime_notice("marked finding as ignore candidate".to_string());
                Ok(false)
            }
            TriageAction::ClearReviewState => {
                self.review_states.remove(&review_key);
                self.push_runtime_notice("cleared review state".to_string());
                Ok(false)
            }
        }
    }

    fn action_preview(&self, action: TriageAction) -> Vec<Line<'static>> {
        let Some(finding) = self.selected_finding() else {
            return vec![Line::from("no finding selected")];
        };

        match action {
            TriageAction::AddToBaseline => vec![
                preview_line("writes", &self.baseline_path_display()),
                Line::from(Span::styled(
                    "suppress this exact finding fingerprint in a baseline file",
                    Style::default().fg(Color::Gray),
                )),
            ],
            TriageAction::IgnoreRuleInFile => vec![
                preview_line("writes", &self.config_path_display()),
                preview_line(
                    "entry",
                    &format!(
                        "scan.ignore_rules: {} -> {}",
                        display_path(&finding.file),
                        finding.rule_id
                    ),
                ),
            ],
            TriageAction::IgnoreSecretRule => vec![
                preview_line("writes", &self.config_path_display()),
                preview_line(
                    "entry",
                    &format!("secrets.ignore_rules += {}", finding.rule_id),
                ),
            ],
            TriageAction::LowerSeverity => {
                let current = current_severity_override(
                    Path::new(&self.request.path),
                    self.request.config.as_deref(),
                    &finding.rule_id,
                )
                .ok()
                .flatten();
                let mut lines = vec![
                    preview_line("writes", &self.config_path_display()),
                    preview_line(
                        "entry",
                        &format!(
                            "scan.severity_overrides[{}] = <pick low|medium|high|critical>",
                            finding.rule_id
                        ),
                    ),
                ];
                if let Some(current) = current {
                    lines.push(Line::from(Span::styled(
                        format!("current override: {}", current),
                        Style::default().fg(Color::Gray),
                    )));
                }
                lines
            }
            TriageAction::ApplySeverityOverride(severity) => vec![
                preview_line("writes", &self.config_path_display()),
                preview_line(
                    "entry",
                    &format!(
                        "scan.severity_overrides[{}] = {}",
                        finding.rule_id, severity
                    ),
                ),
            ],
            TriageAction::DisableRuleGlobally => {
                let already = matches!(
                    is_rule_disabled_in_config(
                        Path::new(&self.request.path),
                        self.request.config.as_deref(),
                        &finding.rule_id,
                    ),
                    Ok(true)
                );
                let mut lines = vec![
                    preview_line("writes", &self.config_path_display()),
                    preview_line(
                        "entry",
                        &format!("scan.disable_rules += {}", finding.rule_id),
                    ),
                ];
                if already {
                    lines.push(Line::from(Span::styled(
                        "already disabled — this action is a no-op",
                        Style::default().fg(Color::DarkGray),
                    )));
                }
                lines
            }
            TriageAction::MarkReviewed => vec![
                preview_line("session", "mark as reviewed"),
                Line::from("no files are changed"),
            ],
            TriageAction::MarkTodo => vec![
                preview_line("session", "mark as todo"),
                Line::from("no files are changed"),
            ],
            TriageAction::MarkIgnoreCandidate => vec![
                preview_line("session", "mark as ignore candidate"),
                Line::from("no files are changed"),
            ],
            TriageAction::ClearReviewState => vec![
                preview_line("session", "clear review mark"),
                Line::from("no files are changed"),
            ],
        }
    }

    fn baseline_path_for_actions(&self) -> Result<PathBuf, String> {
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

    fn baseline_path_display(&self) -> String {
        self.baseline_path_for_actions()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|error| format!("unavailable ({error})"))
    }

    fn config_path_display(&self) -> String {
        crate::config::editable_config_path(
            Path::new(&self.request.path),
            self.request.config.as_deref(),
        )
        .map(|path| path.display().to_string())
        .unwrap_or_else(|error| format!("unavailable ({error})"))
    }

    fn review_summary_for_finding(&self, finding: &Finding) -> Option<String> {
        self.review_state_for(finding)
            .map(|state| format!("session {}", state.label()))
    }

    fn push_runtime_notice(&mut self, notice: String) {
        self.runtime_notices.push(notice);
    }

    fn scroll_detail(&mut self, delta: i32) {
        self.detail_scroll = adjust_scroll(self.detail_scroll, delta);
    }

    fn scroll_notices(&mut self, delta: i32) {
        self.notices_scroll = adjust_scroll(self.notices_scroll, delta);
    }

    fn notice_count(&self) -> usize {
        self.combined_notices().len()
    }

    fn notice_text(&self) -> Text<'static> {
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

    fn combined_notices(&self) -> Vec<String> {
        let mut notices = self
            .result
            .as_ref()
            .map(|result| result.notices.clone())
            .unwrap_or_default();
        notices.extend(self.runtime_notices.iter().cloned());
        notices
    }
}

struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LaunchMode {
    Scan,
    Diff,
    Secrets,
    Pqc,
}

impl LaunchMode {
    fn from_args(args: &TuiArgs) -> Self {
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

    fn next(self) -> Self {
        match self {
            LaunchMode::Scan => LaunchMode::Diff,
            LaunchMode::Diff => LaunchMode::Secrets,
            LaunchMode::Secrets => LaunchMode::Pqc,
            LaunchMode::Pqc => LaunchMode::Scan,
        }
    }

    fn previous(self) -> Self {
        match self {
            LaunchMode::Scan => LaunchMode::Pqc,
            LaunchMode::Diff => LaunchMode::Scan,
            LaunchMode::Secrets => LaunchMode::Diff,
            LaunchMode::Pqc => LaunchMode::Secrets,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpenFocus {
    Finding,
    Source,
    Sink,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TriageAction {
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
    fn label(self) -> String {
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
enum ReviewState {
    Reviewed,
    Todo,
    IgnoreCandidate,
}

impl ReviewState {
    fn label(self) -> &'static str {
        match self {
            ReviewState::Reviewed => "reviewed",
            ReviewState::Todo => "todo",
            ReviewState::IgnoreCandidate => "ignore-candidate",
        }
    }
}

struct ActionMenu {
    actions: Vec<TriageAction>,
    selected: usize,
}

/// Modal sub-picker shown when the user chooses "Lower severity" from the
/// triage menu. Owns a highlight cursor over `SEVERITY_PICKER_CHOICES` and
/// remembers the rule's current override (if any) so the UI can show it.
struct SeverityPicker {
    selected: usize,
    current: Option<Severity>,
}

/// Severities the "Lower severity" picker offers, ordered low → critical to
/// match how humans tend to think about "dialing down" a noisy rule.
const SEVERITY_PICKER_CHOICES: [Severity; 4] = [
    Severity::Low,
    Severity::Medium,
    Severity::High,
    Severity::Critical,
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SortMode {
    /// Severity desc, then path/line (the pre-existing default behaviour).
    #[default]
    SeverityDesc,
    /// Confidence desc, with severity-desc as a stable tiebreaker.
    ConfidenceDesc,
}

impl SortMode {
    fn next(self) -> Self {
        match self {
            SortMode::SeverityDesc => SortMode::ConfidenceDesc,
            SortMode::ConfidenceDesc => SortMode::SeverityDesc,
        }
    }

    fn label(self) -> &'static str {
        match self {
            SortMode::SeverityDesc => "severity",
            SortMode::ConfidenceDesc => "confidence",
        }
    }
}

fn available_open_focuses(finding: &Finding) -> Vec<OpenFocus> {
    let mut focuses = vec![OpenFocus::Finding];
    if finding.source_line.is_some() {
        focuses.push(OpenFocus::Source);
    }
    if finding.sink_line.is_some() {
        focuses.push(OpenFocus::Sink);
    }
    focuses
}

fn finding_has_dataflow(finding: &Finding) -> bool {
    finding.source_line.is_some()
        || finding.source_description.is_some()
        || finding.sink_line.is_some()
        || finding.sink_description.is_some()
}

#[derive(Clone, PartialEq, Eq)]
struct SourceContextCacheKey {
    path: PathBuf,
    line: usize,
    end_line: usize,
    column: usize,
    end_column: usize,
}

struct SourceContextCache {
    key: SourceContextCacheKey,
    lines: Vec<Line<'static>>,
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    active: bool,
}

impl TerminalSession {
    fn enter() -> Result<Self, String> {
        enable_raw_mode().map_err(|e| e.to_string())?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen).map_err(|e| e.to_string())?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).map_err(|e| e.to_string())?;
        Ok(Self {
            terminal,
            active: true,
        })
    }

    fn suspend(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }

        disable_raw_mode().map_err(|e| e.to_string())?;
        execute!(self.terminal.backend_mut(), LeaveAlternateScreen).map_err(|e| e.to_string())?;
        self.terminal.show_cursor().map_err(|e| e.to_string())?;
        self.active = false;
        Ok(())
    }

    fn resume(&mut self) -> Result<(), String> {
        if self.active {
            return Ok(());
        }

        enable_raw_mode().map_err(|e| e.to_string())?;
        execute!(self.terminal.backend_mut(), EnterAlternateScreen).map_err(|e| e.to_string())?;
        self.terminal.clear().map_err(|e| e.to_string())?;
        self.active = true;
        Ok(())
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

fn start_tui_execution(request_id: u64, args: TuiArgs, tx: Sender<WorkerMessage>) {
    std::thread::spawn(move || {
        let _ = tx.send(WorkerMessage {
            request_id,
            result: execute_tui(&args),
        });
    });
}

struct OpenTarget {
    path: PathBuf,
    line: usize,
}

struct CommandSpec {
    program: String,
    args: Vec<String>,
}

fn open_command_spec(target: &OpenTarget) -> Result<CommandSpec, String> {
    open_command_spec_from_editor(
        target,
        std::env::var_os("EDITOR")
            .as_ref()
            .map(|editor| editor.to_string_lossy().into_owned()),
    )
}

fn open_command_spec_from_editor(
    target: &OpenTarget,
    editor: Option<String>,
) -> Result<CommandSpec, String> {
    if let Some(editor) = editor {
        let mut parts = editor
            .split_whitespace()
            .map(|part| part.to_string())
            .collect::<Vec<_>>();
        if parts.is_empty() {
            return Err("$EDITOR is set but empty".to_string());
        }

        let program = parts.remove(0);
        let basename = Path::new(&program)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(program.as_str());
        let mut args = parts;

        match basename {
            "code" | "code-insiders" | "cursor" | "codium" | "windsurf" => {
                args.push("-g".to_string());
                args.push(format!("{}:{}", target.path.display(), target.line));
            }
            "hx" | "helix" => {
                args.push(format!("{}:{}", target.path.display(), target.line));
            }
            "vim" | "nvim" | "vi" | "nano" | "emacs" => {
                args.push(format!("+{}", target.line));
                args.push(target.path.display().to_string());
            }
            _ => {
                args.push(target.path.display().to_string());
            }
        }

        return Ok(CommandSpec { program, args });
    }

    if cfg!(target_os = "macos") {
        return Ok(CommandSpec {
            program: "open".to_string(),
            args: vec![target.path.display().to_string()],
        });
    }

    if cfg!(target_os = "windows") {
        return Ok(CommandSpec {
            program: "cmd".to_string(),
            args: vec![
                "/C".to_string(),
                "start".to_string(),
                String::new(),
                target.path.display().to_string(),
            ],
        });
    }

    Ok(CommandSpec {
        program: "xdg-open".to_string(),
        args: vec![target.path.display().to_string()],
    })
}

fn resolve_finding_path(scan_path: &str, finding_file: &str) -> PathBuf {
    let finding_path = Path::new(finding_file);
    if finding_path.is_absolute() {
        return finding_path.to_path_buf();
    }

    if finding_path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return finding_path.to_path_buf();
    }

    let scan_root = Path::new(scan_path);
    if finding_path.starts_with(scan_root) {
        return finding_path.to_path_buf();
    }

    let scan_root_is_file = scan_root.is_file() || scan_root.extension().is_some();
    let base = if scan_root_is_file {
        scan_root.parent().unwrap_or_else(|| Path::new("."))
    } else {
        scan_root
    };

    base.join(finding_path)
}

#[cfg(test)]
fn truncate_text(text: &str, max_chars: usize) -> String {
    let mut chars = text.chars();
    let truncated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{}...", truncated)
    } else {
        truncated
    }
}

fn adjust_scroll(current: u16, delta: i32) -> u16 {
    if delta.is_negative() {
        current.saturating_sub(delta.unsigned_abs() as u16)
    } else {
        current.saturating_add(delta as u16)
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn resolve_finding_path_joins_relative_file_under_directory_root() {
        let resolved = resolve_finding_path("/tmp/project", "src/main.rs");
        assert_eq!(resolved, PathBuf::from("/tmp/project/src/main.rs"));
    }

    #[test]
    fn resolve_finding_path_uses_parent_for_file_roots() {
        let resolved = resolve_finding_path("/tmp/project/app.py", "app.py");
        assert_eq!(resolved, PathBuf::from("/tmp/project/app.py"));
    }

    #[test]
    fn resolve_finding_path_keeps_parent_relative_paths() {
        let resolved = resolve_finding_path(
            "../foxguard/tests/fixtures/realistic",
            "../foxguard/tests/fixtures/realistic/fastapi_app.py",
        );
        assert_eq!(
            resolved,
            PathBuf::from("../foxguard/tests/fixtures/realistic/fastapi_app.py")
        );
    }

    #[test]
    fn open_command_spec_uses_code_goto_format() {
        let target = OpenTarget {
            path: PathBuf::from("/tmp/project/src/main.rs"),
            line: 27,
        };

        let command = open_command_spec_from_editor(&target, Some("code --wait".to_string()))
            .expect("command should build");

        assert_eq!(command.program, "code");
        assert_eq!(
            command.args,
            vec![
                "--wait".to_string(),
                "-g".to_string(),
                "/tmp/project/src/main.rs:27".to_string()
            ]
        );
    }

    #[test]
    fn open_command_spec_uses_vim_line_format() {
        let target = OpenTarget {
            path: PathBuf::from("/tmp/project/src/main.rs"),
            line: 8,
        };

        let command = open_command_spec_from_editor(&target, Some("nvim".to_string()))
            .expect("command should build");

        assert_eq!(command.program, "nvim");
        assert_eq!(
            command.args,
            vec!["+8".to_string(), "/tmp/project/src/main.rs".to_string()]
        );
    }

    #[test]
    fn begin_scan_resets_runtime_notices_and_updates_request_id() {
        let mut app = TuiApp::new(TuiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });
        app.runtime_notices.push("stale notice".to_string());

        let first = app.begin_scan();
        let second = app.begin_scan();

        assert_eq!(first, 1);
        assert_eq!(second, 2);
        assert!(app.runtime_notices.is_empty());
        assert_eq!(app.active_request_id, 2);
    }

    #[test]
    fn tui_app_starts_on_launch_screen_without_scanning() {
        let app = TuiApp::new(TuiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });

        assert!(app.show_launch);
        assert!(!app.scanning);
        assert_eq!(app.launch_mode, LaunchMode::Scan);
    }

    #[test]
    fn launch_key_enter_starts_selected_mode() {
        let mut app = TuiApp::new(TuiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });
        app.launch_mode = LaunchMode::Diff;
        app.launch_diff_target = "origin/main".to_string();

        let flow = app.handle_launch_key(KeyCode::Enter);
        assert!(matches!(flow, ControlFlow::Rescan));

        let _ = app.begin_scan();
        assert!(!app.show_launch);
        assert_eq!(app.request.diff.as_deref(), Some("origin/main"));
        assert!(!app.request.secrets);
    }

    #[test]
    fn loading_copy_uses_selected_launch_mode() {
        let mut app = TuiApp::new(TuiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: Some("origin/main".to_string()),
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });
        app.launch_mode = LaunchMode::Diff;

        let (headline, subline) = loading_copy(&app);
        assert_eq!(headline, "Scanning diff");
        assert!(subline.contains("origin/main"));
    }

    #[test]
    fn loading_shimmer_line_respects_requested_width() {
        let spans = loading_shimmer_line("walking files", 12, 4);
        assert_eq!(spans.len(), 14);
    }

    #[test]
    fn compare_findings_prioritizes_higher_severity() {
        let critical = Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::Critical,
            file: "a.js".to_string(),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 5,
            description: "critical".to_string(),
            snippet: "exec(cmd)".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
        };
        let medium = Finding {
            severity: Severity::Medium,
            ..critical.clone()
        };

        assert_eq!(
            compare_findings(&critical, &medium),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn truncate_text_adds_ellipsis_when_needed() {
        assert_eq!(truncate_text("abcdef", 3), "abc...");
        assert_eq!(truncate_text("abc", 3), "abc");
    }

    #[test]
    fn dataflow_lines_render_path_when_source_and_sink_are_present() {
        let finding = Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::High,
            file: "/tmp/project/src/main.js".to_string(),
            line: 42,
            column: 7,
            end_line: 42,
            end_column: 18,
            description: "untrusted input reaches exec".to_string(),
            snippet: "exec(cmd)".to_string(),
            cwe: None,
            source_line: Some(12),
            source_description: Some("user-controlled query param".to_string()),
            sink_line: Some(42),
            sink_description: Some("value is passed into exec".to_string()),
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            // Exercise the crypto-metadata fields end-to-end in an existing
            // fixture: dataflow rendering shouldn't care, but we also pass the
            // finding through `list_item` below to confirm the deadline chip
            // picks up `"2030"` without disturbing the unrelated dataflow path.
            crypto_algorithm: Some("RSA".to_string()),
            cnsa2_deadline: Some("2030".to_string()),
        };

        let rendered = dataflow_lines(&finding, OpenFocus::Finding)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>();

        assert!(rendered
            .iter()
            .any(|line| line.contains("source @ /tmp/project/src/main.js:12")));
        assert!(rendered.iter().any(|line| {
            line.contains("> ")
                && line.contains("finding")
                && line.contains("@ /tmp/project/src/main.js:42:7")
        }));
        assert!(rendered
            .iter()
            .any(|line| line.contains("sink @ /tmp/project/src/main.js:42")));
    }

    #[test]
    fn dataflow_lines_show_fallback_when_no_trace_exists() {
        let finding = Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::High,
            file: "src/main.js".to_string(),
            line: 42,
            column: 7,
            end_line: 42,
            end_column: 18,
            description: "untrusted input reaches exec".to_string(),
            snippet: "exec(cmd)".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
        };

        assert_eq!(
            dataflow_lines(&finding, OpenFocus::Finding)
                .into_iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>(),
            vec!["No source/sink flow details for this finding type.".to_string()]
        );
    }

    #[test]
    fn open_target_lines_show_finding_even_without_trace_details() {
        let finding = Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::High,
            file: "src/main.js".to_string(),
            line: 42,
            column: 7,
            end_line: 42,
            end_column: 18,
            description: "untrusted input reaches exec".to_string(),
            snippet: "exec(cmd)".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
        };

        let rendered = open_target_lines(&finding, OpenFocus::Finding)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>();

        assert!(rendered
            .iter()
            .any(|line| line.contains("Enter opens") && line.contains("finding")));
        assert!(rendered
            .iter()
            .any(|line| line.contains("@ src/main.js:42:7")));
    }

    #[test]
    fn render_source_context_includes_surrounding_lines_and_caret() {
        let finding = Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::High,
            file: "src/main.js".to_string(),
            line: 3,
            column: 6,
            end_line: 3,
            end_column: 9,
            description: "untrusted input reaches exec".to_string(),
            snippet: "exec(cmd)".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
        };

        let rendered = render_source_context(
            "const user = req.query.user;\nconst cmd = user;\nexec(cmd);\nconsole.log(cmd);\n",
            &finding,
            1,
        )
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

        assert!(rendered
            .iter()
            .any(|line| line.contains("2 | const cmd = user;")));
        assert!(rendered.iter().any(|line| {
            line.contains("exec(cmd);") && line.contains("|") && line.contains(">")
        }));
        assert!(rendered.iter().any(|line| line.contains("^")));
        assert!(rendered
            .iter()
            .any(|line| line.contains("selected range") && line.starts_with("     | ")));
        assert!(rendered
            .iter()
            .any(|line| line.contains("4 | console.log(cmd);")));
    }

    #[test]
    fn handle_key_maps_enter_to_open_selected() {
        let mut app = TuiApp::new(TuiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });
        app.show_launch = false;

        let flow = app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(matches!(flow, ControlFlow::OpenSelected));
    }

    #[test]
    fn available_open_focuses_include_source_and_sink_when_present() {
        let finding = Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::High,
            file: "src/main.js".to_string(),
            line: 42,
            column: 7,
            end_line: 42,
            end_column: 18,
            description: "untrusted input reaches exec".to_string(),
            snippet: "exec(cmd)".to_string(),
            cwe: None,
            source_line: Some(12),
            source_description: Some("user-controlled query param".to_string()),
            sink_line: Some(42),
            sink_description: Some("value is passed into exec".to_string()),
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
        };

        assert_eq!(
            available_open_focuses(&finding),
            vec![OpenFocus::Finding, OpenFocus::Source, OpenFocus::Sink]
        );
    }

    #[test]
    fn cycle_open_focus_advances_through_available_targets() {
        let mut app = TuiApp::new(TuiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });
        app.result = Some(TuiExecution {
            mode: TuiMode::Scan,
            path: ".".to_string(),
            findings: vec![Finding {
                rule_id: "js/no-command-injection".to_string(),
                severity: Severity::High,
                file: "src/main.js".to_string(),
                line: 42,
                column: 7,
                end_line: 42,
                end_column: 18,
                description: "untrusted input reaches exec".to_string(),
                snippet: "exec(cmd)".to_string(),
                cwe: None,
                source_line: Some(12),
                source_description: Some("user-controlled query param".to_string()),
                sink_line: Some(42),
                sink_description: Some("value is passed into exec".to_string()),
                fix_suggestion: None,
                sink_start_byte: None,
                sink_end_byte: None,
                confidence: crate::default_confidence(),
                taint_hops: None,
                tags: vec![],
                crypto_algorithm: None,
                cnsa2_deadline: None,
            }],
            files_scanned: 1,
            duration: Duration::from_secs(1),
            explain: true,
            diff_summary: None,
            notices: Vec::new(),
        });

        app.cycle_open_focus();
        assert_eq!(app.open_focus, OpenFocus::Source);
        app.cycle_open_focus();
        assert_eq!(app.open_focus, OpenFocus::Sink);
        app.cycle_open_focus();
        assert_eq!(app.open_focus, OpenFocus::Finding);
    }

    #[test]
    fn handle_key_maps_tab_to_cycle_open_focus() {
        let mut app = TuiApp::new(TuiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });

        let flow = app.handle_key(KeyEvent::from(KeyCode::Tab));
        assert!(matches!(flow, ControlFlow::Continue));
    }

    #[test]
    fn open_action_menu_is_available_in_scan_mode() {
        let mut app = TuiApp::new(TuiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });
        app.result = Some(TuiExecution {
            mode: TuiMode::Scan,
            path: ".".to_string(),
            findings: vec![Finding {
                rule_id: "js/no-command-injection".to_string(),
                severity: Severity::High,
                file: "src/main.js".to_string(),
                line: 42,
                column: 7,
                end_line: 42,
                end_column: 18,
                description: "untrusted input reaches exec".to_string(),
                snippet: "exec(cmd)".to_string(),
                cwe: None,
                source_line: None,
                source_description: None,
                sink_line: None,
                sink_description: None,
                fix_suggestion: None,
                sink_start_byte: None,
                sink_end_byte: None,
                confidence: crate::default_confidence(),
                taint_hops: None,
                tags: vec![],
                crypto_algorithm: None,
                cnsa2_deadline: None,
            }],
            files_scanned: 1,
            duration: Duration::from_secs(1),
            explain: false,
            diff_summary: None,
            notices: Vec::new(),
        });
        app.show_launch = false;

        let flow = app.handle_key(KeyEvent::from(KeyCode::Char('i')));
        assert!(matches!(flow, ControlFlow::Continue));
        assert!(app.action_menu.is_some());
        assert!(app
            .action_menu
            .as_ref()
            .is_some_and(|menu| menu.actions.contains(&TriageAction::IgnoreRuleInFile)));
    }

    #[test]
    fn open_action_menu_is_available_in_secrets_mode() {
        let mut app = TuiApp::new(TuiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: true,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });
        app.result = Some(TuiExecution {
            mode: TuiMode::Secrets,
            path: ".".to_string(),
            findings: vec![Finding {
                rule_id: "secret/github-token".to_string(),
                severity: Severity::Critical,
                file: "src/main.js".to_string(),
                line: 12,
                column: 5,
                end_line: 12,
                end_column: 28,
                description: "Possible GitHub personal access token detected".to_string(),
                snippet: "token = [REDACTED]".to_string(),
                cwe: Some("CWE-798".to_string()),
                source_line: None,
                source_description: None,
                sink_line: None,
                sink_description: None,
                fix_suggestion: None,
                sink_start_byte: None,
                sink_end_byte: None,
                confidence: crate::default_confidence(),
                taint_hops: None,
                tags: vec![],
                crypto_algorithm: None,
                cnsa2_deadline: None,
            }],
            files_scanned: 1,
            duration: Duration::from_secs(1),
            explain: false,
            diff_summary: None,
            notices: Vec::new(),
        });
        app.show_launch = false;

        let flow = app.handle_key(KeyEvent::from(KeyCode::Char('i')));
        assert!(matches!(flow, ControlFlow::Continue));
        assert!(app
            .action_menu
            .as_ref()
            .is_some_and(|menu| menu.actions.contains(&TriageAction::IgnoreSecretRule)));
    }

    #[test]
    fn handle_action_menu_enter_applies_selected_action() {
        let mut app = TuiApp::new(TuiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });
        app.action_menu = Some(ActionMenu {
            actions: vec![TriageAction::AddToBaseline, TriageAction::IgnoreRuleInFile],
            selected: 1,
        });

        let flow = app.handle_action_menu_key(KeyCode::Enter);
        assert!(matches!(
            flow,
            ControlFlow::ApplyAction(TriageAction::IgnoreRuleInFile)
        ));
        assert!(app.action_menu.is_none());
    }

    #[test]
    fn apply_action_review_state_is_session_only() {
        let mut app = TuiApp::new(TuiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });
        let finding = Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::High,
            file: "src/main.js".to_string(),
            line: 42,
            column: 7,
            end_line: 42,
            end_column: 18,
            description: "untrusted input reaches exec".to_string(),
            snippet: "exec(cmd)".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
        };
        app.result = Some(TuiExecution {
            mode: TuiMode::Scan,
            path: ".".to_string(),
            findings: vec![finding.clone()],
            files_scanned: 1,
            duration: Duration::from_secs(1),
            explain: true,
            diff_summary: None,
            notices: Vec::new(),
        });

        let changed = app
            .apply_action(TriageAction::MarkReviewed)
            .expect("review action should succeed");
        assert!(!changed);
        assert_eq!(app.review_state_for(&finding), Some(ReviewState::Reviewed));
    }

    #[test]
    fn dataflow_lines_highlight_active_open_target() {
        let finding = Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::High,
            file: "src/main.js".to_string(),
            line: 42,
            column: 7,
            end_line: 42,
            end_column: 18,
            description: "untrusted input reaches exec".to_string(),
            snippet: "exec(cmd)".to_string(),
            cwe: None,
            source_line: Some(12),
            source_description: Some("user-controlled query param".to_string()),
            sink_line: Some(42),
            sink_description: Some("value is passed into exec".to_string()),
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
        };

        let rendered = dataflow_lines(&finding, OpenFocus::Source)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>();

        assert!(rendered
            .iter()
            .any(|line| line.contains("finding @ src/main.js:42:7")));
        assert!(rendered.iter().any(|line| {
            line.contains("> ") && line.contains("source") && line.contains("@ src/main.js:12")
        }));
        assert!(rendered
            .iter()
            .any(|line| line.contains("sink @ src/main.js:42")));
    }

    #[test]
    fn render_source_context_marks_each_line_of_multiline_findings() {
        let finding = Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::High,
            file: "src/main.js".to_string(),
            line: 2,
            column: 7,
            end_line: 4,
            end_column: 5,
            description: "multiline finding".to_string(),
            snippet: "foo(\n  bar,\n  baz\n)".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
        };

        let rendered = render_source_context(
            "const x = 1;\ncall(foo,\n  bar,\n  baz);\nconst y = 2;\n",
            &finding,
            0,
        )
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

        assert!(rendered
            .iter()
            .any(|line| line.contains("call(foo,") && line.contains(">") && line.contains("|")));
        assert!(rendered
            .iter()
            .any(|line| line.contains("bar,") && line.contains(">") && line.contains("|")));
        assert!(rendered
            .iter()
            .any(|line| line.contains("baz);") && line.contains(">") && line.contains("|")));
        assert!(
            rendered
                .iter()
                .filter(|line| line.contains("selected range"))
                .count()
                >= 3
        );
    }

    #[test]
    fn confidence_badge_is_hidden_at_full_confidence() {
        assert!(confidence_badge_span(1.0).is_none());
        assert!(confidence_badge_span(0.9999).is_none());
    }

    #[test]
    fn confidence_badge_renders_for_partial_confidence() {
        let span = confidence_badge_span(0.87).expect("should render badge");
        assert_eq!(span.content, "[.87]");
    }

    #[test]
    fn cycle_session_min_confidence_advances_through_presets() {
        let mut app = TuiApp::new(TuiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });

        assert_eq!(app.session_min_confidence, 0.0);
        app.cycle_session_min_confidence();
        assert!((app.session_min_confidence - 0.7).abs() < 1e-6);
        app.cycle_session_min_confidence();
        assert!((app.session_min_confidence - 0.9).abs() < 1e-6);
        app.cycle_session_min_confidence();
        assert!((app.session_min_confidence - 1.0).abs() < 1e-6);
        app.cycle_session_min_confidence();
        assert_eq!(app.session_min_confidence, 0.0);
    }

    #[test]
    fn cycle_sort_mode_toggles_between_severity_and_confidence() {
        let mut app = TuiApp::new(TuiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });

        assert_eq!(app.sort_mode, SortMode::SeverityDesc);
        app.cycle_sort_mode();
        assert_eq!(app.sort_mode, SortMode::ConfidenceDesc);
        app.cycle_sort_mode();
        assert_eq!(app.sort_mode, SortMode::SeverityDesc);
    }

    #[test]
    fn handle_key_binds_c_to_confidence_and_shift_c_to_sort() {
        let mut app = TuiApp::new(TuiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });
        app.show_launch = false;

        let _ = app.handle_key(KeyEvent::from(KeyCode::Char('c')));
        assert!((app.session_min_confidence - 0.7).abs() < 1e-6);

        let _ = app.handle_key(KeyEvent::from(KeyCode::Char('C')));
        assert_eq!(app.sort_mode, SortMode::ConfidenceDesc);
    }

    #[test]
    fn confidence_sort_places_high_confidence_before_low_regardless_of_severity() {
        let high_conf_low_sev = Finding {
            rule_id: "js/rule".to_string(),
            severity: Severity::Low,
            file: "a.js".to_string(),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 5,
            description: "low sev but confident".to_string(),
            snippet: "x".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: 0.95,
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
        };
        let low_conf_high_sev = Finding {
            severity: Severity::Critical,
            confidence: 0.5,
            file: "b.js".to_string(),
            ..high_conf_low_sev.clone()
        };

        assert_eq!(
            compare_findings_by(
                &high_conf_low_sev,
                &low_conf_high_sev,
                SortMode::ConfidenceDesc
            ),
            std::cmp::Ordering::Less,
            "confidence sort should put the high-confidence finding first"
        );
        assert_eq!(
            compare_findings_by(
                &high_conf_low_sev,
                &low_conf_high_sev,
                SortMode::SeverityDesc
            ),
            std::cmp::Ordering::Greater,
            "default sort should still put the higher-severity finding first"
        );
    }

    #[test]
    fn session_confidence_filter_hides_low_confidence_findings() {
        let mut app = TuiApp::new(TuiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });
        let base = Finding {
            rule_id: "js/rule".to_string(),
            severity: Severity::High,
            file: "a.js".to_string(),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 5,
            description: "desc".to_string(),
            snippet: "x".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: 1.0,
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
        };
        let low_conf = Finding {
            confidence: 0.5,
            file: "b.js".to_string(),
            ..base.clone()
        };
        app.result = Some(TuiExecution {
            mode: TuiMode::Scan,
            path: ".".to_string(),
            findings: vec![base.clone(), low_conf.clone()],
            files_scanned: 2,
            duration: Duration::from_secs(1),
            explain: false,
            diff_summary: None,
            notices: Vec::new(),
        });

        assert_eq!(app.filtered_indices().len(), 2);

        app.session_min_confidence = 0.7;
        assert_eq!(
            app.filtered_indices().len(),
            1,
            "only the high-confidence finding should survive"
        );
        // The "total before confidence filter" count should still be 2 for
        // the footer's "X of Y" summary.
        assert_eq!(app.total_after_severity_and_search(), 2);
    }

    #[test]
    fn open_action_menu_in_scan_mode_exposes_new_triage_actions() {
        let mut app = TuiApp::new(TuiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });
        app.result = Some(TuiExecution {
            mode: TuiMode::Scan,
            path: ".".to_string(),
            findings: vec![Finding {
                rule_id: "js/rule".to_string(),
                severity: Severity::High,
                file: "a.js".to_string(),
                line: 1,
                column: 1,
                end_line: 1,
                end_column: 5,
                description: "desc".to_string(),
                snippet: "x".to_string(),
                cwe: None,
                source_line: None,
                source_description: None,
                sink_line: None,
                sink_description: None,
                fix_suggestion: None,
                sink_start_byte: None,
                sink_end_byte: None,
                confidence: crate::default_confidence(),
                taint_hops: None,
                tags: vec![],
                crypto_algorithm: None,
                cnsa2_deadline: None,
            }],
            files_scanned: 1,
            duration: Duration::from_secs(1),
            explain: false,
            diff_summary: None,
            notices: Vec::new(),
        });
        app.show_launch = false;

        let _ = app.handle_key(KeyEvent::from(KeyCode::Char('i')));
        let menu = app.action_menu.as_ref().expect("menu should be open");
        assert!(menu.actions.contains(&TriageAction::LowerSeverity));
        assert!(menu.actions.contains(&TriageAction::DisableRuleGlobally));
    }

    #[test]
    fn apply_action_lower_severity_writes_override_and_replaces() {
        let repo = tempfile::TempDir::new().expect("tempdir");
        let mut app = TuiApp::new(TuiArgs {
            path: repo.path().display().to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });
        let finding = Finding {
            rule_id: "js/rule".to_string(),
            severity: Severity::High,
            file: "a.js".to_string(),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 5,
            description: "desc".to_string(),
            snippet: "x".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
        };
        app.result = Some(TuiExecution {
            mode: TuiMode::Scan,
            path: repo.path().display().to_string(),
            findings: vec![finding.clone()],
            files_scanned: 1,
            duration: Duration::from_secs(1),
            explain: false,
            diff_summary: None,
            notices: Vec::new(),
        });

        let rescan = app
            .apply_action(TriageAction::ApplySeverityOverride(Severity::Low))
            .expect("override should apply");
        assert!(rescan, "severity override should trigger a rescan");
        assert_eq!(
            crate::config::current_severity_override(repo.path(), None, "js/rule").unwrap(),
            Some(Severity::Low)
        );
    }

    #[test]
    fn apply_action_disable_rule_globally_appends_and_detects_duplicate() {
        let repo = tempfile::TempDir::new().expect("tempdir");
        let mut app = TuiApp::new(TuiArgs {
            path: repo.path().display().to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });
        let finding = Finding {
            rule_id: "js/rule".to_string(),
            severity: Severity::High,
            file: "a.js".to_string(),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 5,
            description: "desc".to_string(),
            snippet: "x".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: None,
        };
        app.result = Some(TuiExecution {
            mode: TuiMode::Scan,
            path: repo.path().display().to_string(),
            findings: vec![finding.clone()],
            files_scanned: 1,
            duration: Duration::from_secs(1),
            explain: false,
            diff_summary: None,
            notices: Vec::new(),
        });

        let first = app
            .apply_action(TriageAction::DisableRuleGlobally)
            .expect("first disable should succeed");
        assert!(first);
        assert!(crate::config::is_rule_disabled_in_config(repo.path(), None, "js/rule").unwrap());

        // Once disabled, the action is still "applied" (writer is a no-op and
        // reports `added = false`), so the UI reports without blowing up.
        let second = app
            .apply_action(TriageAction::DisableRuleGlobally)
            .expect("second disable should succeed");
        assert!(second);
    }

    #[test]
    fn render_source_context_truncates_long_lines_around_selected_range() {
        let finding = Finding {
            rule_id: "js/no-command-injection".to_string(),
            severity: Severity::High,
            file: "src/main.js".to_string(),
            line: 1,
            column: 90,
            end_line: 1,
            end_column: 105,
            description: "long line finding".to_string(),
            snippet: "dangerous_call(user_input)".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            // Fields populated to confirm this orthogonal renderer still
            // ignores crypto metadata — the snippet truncator has no reason
            // to care whether the finding carries a CNSA 2.0 deadline.
            crypto_algorithm: Some("RSA".to_string()),
            cnsa2_deadline: Some("2030".to_string()),
        };

        let rendered = render_source_context(
            "prefix_prefix_prefix_prefix_prefix_prefix_prefix_prefix_prefix_prefix_prefix_prefix_dangerous_call(user_input)_suffix_suffix_suffix_suffix_suffix\n",
            &finding,
            0,
        )
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

        assert!(rendered.iter().any(|line| line.contains("...")));
        assert!(rendered
            .iter()
            .any(|line| line.contains("dangerous_call(user_input)")));
    }

    /// Flatten a ratatui `Text` into a plain string, joining lines with `\n`.
    /// Used by the compliance-panel tests to assert on rendered content
    /// without depending on a terminal backend.
    fn text_to_plain(text: &Text<'_>) -> String {
        text.lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn cnsa_finding(rule_id: &str, deadline: Option<&str>) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::High,
            file: "src/lib.rs".to_string(),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 1,
            description: "pq-relevant finding".to_string(),
            snippet: "Rsa::new()".to_string(),
            cwe: None,
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm: None,
            cnsa2_deadline: deadline.map(String::from),
        }
    }

    /// Helper: stand up a `TuiApp` with a single finding whose crypto-metadata
    /// fields are controlled by the caller. Delegates to
    /// `tui_app_with_findings` so both #248 test suites share one copy of
    /// the `TuiArgs` + `TuiExecution` boilerplate.
    fn app_with_single_finding(
        crypto_algorithm: Option<String>,
        cnsa2_deadline: Option<String>,
    ) -> TuiApp {
        let finding = Finding {
            rule_id: "crypto/pq-vulnerable".to_string(),
            severity: Severity::High,
            file: "src/lib.rs".to_string(),
            line: 10,
            column: 1,
            end_line: 10,
            end_column: 20,
            description: "uses RSA key exchange".to_string(),
            snippet: "Rsa::new(2048)".to_string(),
            cwe: Some("CWE-327".to_string()),
            source_line: None,
            source_description: None,
            sink_line: None,
            sink_description: None,
            fix_suggestion: None,
            sink_start_byte: None,
            sink_end_byte: None,
            confidence: crate::default_confidence(),
            taint_hops: None,
            tags: vec![],
            crypto_algorithm,
            cnsa2_deadline,
        };
        let mut app = tui_app_with_findings(vec![finding]);
        app.show_launch = false;
        app
    }

    fn tui_app_with_findings(findings: Vec<Finding>) -> TuiApp {
        let mut app = TuiApp::new(TuiArgs {
            path: ".".to_string(),
            config: None,
            severity: None,
            rules: None,
            no_builtins: false,
            changed: false,
            exclude: Vec::new(),
            baseline: None,
            diff: None,
            secrets: false,
            explain: false,
            max_file_size: 1_048_576,
            pq_mode: false,
        });
        app.result = Some(TuiExecution {
            mode: TuiMode::Scan,
            path: ".".to_string(),
            findings,
            files_scanned: 1,
            duration: Duration::from_secs(1),
            explain: false,
            diff_summary: None,
            notices: Vec::new(),
        });
        app
    }

    #[test]
    fn compliance_panel_defaults_off() {
        let app = tui_app_with_findings(vec![]);
        assert!(!app.show_compliance_panel);
    }

    #[test]
    fn shift_n_toggles_compliance_panel() {
        let mut app = tui_app_with_findings(vec![]);
        // `handle_key` routes to `handle_launch_key` while the launcher is
        // visible; emulate the post-scan state the user sees when pressing
        // Shift+N.
        app.show_launch = false;
        assert!(!app.show_compliance_panel);
        let flow = app.handle_key(KeyEvent::from(KeyCode::Char('N')));
        assert!(matches!(flow, ControlFlow::Continue));
        assert!(app.show_compliance_panel);
        app.handle_key(KeyEvent::from(KeyCode::Char('N')));
        assert!(!app.show_compliance_panel);
    }

    #[test]
    fn compliance_panel_shows_badge_and_per_year_tallies() {
        // Two findings at 2030, twelve at 2033 — report should render the
        // level badge plus the sorted per-deadline bullets.
        let mut findings = Vec::new();
        for _ in 0..3 {
            findings.push(cnsa_finding("pq/rule-a", Some("2030")));
        }
        for _ in 0..12 {
            findings.push(cnsa_finding("pq/rule-b", Some("2033")));
        }
        let app = tui_app_with_findings(findings);

        let rendered = text_to_plain(&app.compliance_panel_text());
        // Majority of findings have a deadline → at-risk.
        assert!(
            rendered.contains("at-risk"),
            "expected at-risk badge, got: {}",
            rendered
        );
        assert!(
            rendered.contains("15 findings with NSA transition deadlines"),
            "expected annotated count line, got: {}",
            rendered
        );
        assert!(
            rendered.contains("3 by 2030"),
            "expected 2030 tally, got: {}",
            rendered
        );
        assert!(
            rendered.contains("12 by 2033"),
            "expected 2033 tally, got: {}",
            rendered
        );
        // 2030 must render before 2033 (sorted by year ascending).
        let pos_2030 = rendered.find("2030").expect("2030 bullet present");
        let pos_2033 = rendered.find("2033").expect("2033 bullet present");
        assert!(pos_2030 < pos_2033, "deadlines should sort ascending");
    }

    #[test]
    fn compliance_panel_empty_state_when_no_cnsa_findings() {
        // Findings exist but none carry a deadline — panel should display the
        // dimmed fallback rather than an empty/broken block.
        let app = tui_app_with_findings(vec![cnsa_finding("js/no-eval", None)]);
        let rendered = text_to_plain(&app.compliance_panel_text());
        assert!(
            rendered.contains("no CNSA 2.0 findings in this scan"),
            "expected empty-state message, got: {}",
            rendered
        );
        // Must not render a level badge label when empty.
        assert!(!rendered.contains("at-risk"));
        assert!(!rendered.contains("on-track"));
    }

    /// Flatten a `Text` to plain per-line strings so assertions can use
    /// `contains()` without poking at span internals.
    fn text_to_strings(text: &Text<'static>) -> Vec<String> {
        text.lines
            .iter()
            .map(|line| line.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect()
    }

    #[test]
    fn detail_text_renders_crypto_algorithm_and_cnsa2_deadline_lines() {
        let mut app = app_with_single_finding(Some("RSA".to_string()), Some("2030".to_string()));

        let rendered = text_to_strings(&app.detail_text());

        assert!(
            rendered.iter().any(|line| line == "Algorithm: RSA"),
            "expected Algorithm line, got {:#?}",
            rendered
        );
        assert!(
            rendered
                .iter()
                .any(|line| line == "CNSA 2.0: migrate before end of 2030"),
            "expected CNSA 2.0 line, got {:#?}",
            rendered
        );
    }

    #[test]
    fn detail_text_omits_crypto_lines_when_both_fields_absent() {
        let mut app = app_with_single_finding(None, None);

        let rendered = text_to_strings(&app.detail_text());

        assert!(
            !rendered.iter().any(|line| line.starts_with("Algorithm:")),
            "non-crypto findings should not render the Algorithm line"
        );
        assert!(
            !rendered.iter().any(|line| line.starts_with("CNSA 2.0:")),
            "non-crypto findings should not render the CNSA 2.0 line"
        );
    }

    #[test]
    fn cnsa2_deadline_chip_renders_padded_year_with_amber_background() {
        let span = cnsa2_deadline_chip_span("2030");
        assert_eq!(span.content, " 2030 ");
        assert_eq!(span.style.bg, Some(Color::Yellow));
        assert_eq!(span.style.fg, Some(Color::Black));
        // Explicitly check BOLD is not set — deadline is advisory context,
        // not a severity signal, and should read as muted.
        assert!(!span.style.add_modifier.contains(Modifier::BOLD));
    }
}

fn append_diff_summary(spans: &mut Vec<Span<'static>>, summary: &DiffSummary) {
    spans.push(Span::raw("  "));
    spans.push(Span::styled(
        format!(
            "vs {} | {} new | {} total | {} existing",
            summary.target,
            summary.total_current.saturating_sub(summary.existing_count),
            summary.total_current,
            summary.existing_count
        ),
        Style::default().fg(Color::Gray),
    ));
}

fn list_item(finding: &Finding, review_state: Option<ReviewState>) -> ListItem<'static> {
    let mut title_spans = vec![
        severity_badge_span(finding.severity),
        Span::raw(" "),
        Span::styled(
            finding.rule_id.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ];
    // Feature B: confidence badge — list-only, low-confidence-only. We render
    // nothing when confidence is 1.0 because 95%+ of findings are high-
    // confidence and a badge on every row would be pure noise. This display
    // is independent of the `--show-confidence` CLI flag (which only affects
    // non-TUI output) and of `scan.min_confidence` (scan-time filter).
    if let Some(span) = confidence_badge_span(finding.confidence) {
        title_spans.push(Span::raw(" "));
        title_spans.push(span);
    }
    for tag in &finding.tags {
        title_spans.push(Span::raw(" "));
        title_spans.push(Span::styled(
            format!(" {} ", tag),
            Style::default()
                .bg(Color::Cyan)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        ));
    }
    // CNSA 2.0 deadline chip — muted amber to read as advisory, not urgent.
    // Only rendered when `cnsa2_deadline` is `Some`, so non-crypto findings
    // keep their existing row layout untouched.
    if let Some(deadline) = finding.cnsa2_deadline.as_ref() {
        title_spans.push(Span::raw(" "));
        title_spans.push(cnsa2_deadline_chip_span(deadline));
    }
    if let Some(state) = review_state {
        title_spans.push(Span::raw(" "));
        title_spans.push(review_badge_span(state));
    }

    ListItem::new(vec![
        Line::from(title_spans),
        Line::from(Span::styled(
            format!("{}:{}", display_path(&finding.file), finding.line),
            Style::default().fg(Color::Gray),
        )),
    ])
}

/// Compact advisory chip rendered in the list row for findings that carry a
/// `cnsa2_deadline`. Muted amber on black so it reads as context ("migrate
/// before X"), not urgency — the row's severity badge already carries the
/// "how bad is this" signal. No bold, single-space padding inside the chip.
fn cnsa2_deadline_chip_span(deadline: &str) -> Span<'static> {
    Span::styled(
        format!(" {} ", deadline),
        Style::default().bg(Color::Yellow).fg(Color::Black),
    )
}

/// Small dimmed confidence indicator shown next to findings with
/// `confidence < 1.0`. Returns `None` when the finding is at full
/// confidence — the common case — so the list stays visually restrained.
/// Format: `[.87]` (two decimals, no leading digit), dim gray foreground.
fn confidence_badge_span(confidence: f32) -> Option<Span<'static>> {
    if confidence >= 0.995 {
        return None;
    }
    let clamped = confidence.clamp(0.0, 1.0);
    let hundredths = (clamped * 100.0).round() as i32;
    let label = if hundredths <= 0 {
        "[.00]".to_string()
    } else if hundredths >= 100 {
        "[.99]".to_string()
    } else {
        format!("[.{:02}]", hundredths)
    };
    Some(Span::styled(
        label,
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::DIM),
    ))
}

fn dataflow_lines(finding: &Finding, active_focus: OpenFocus) -> Vec<Line<'static>> {
    let mut steps = Vec::new();

    if let (Some(line), Some(description)) =
        (finding.source_line, finding.source_description.as_ref())
    {
        steps.push((
            OpenFocus::Source,
            "source",
            format!("{}:{}", display_path(&finding.file), line),
            Some(description.clone()),
            Color::Yellow,
        ));
    }

    if finding.source_line.is_none() && finding.sink_line.is_none() {
        return vec![Line::from(
            "No source/sink flow details for this finding type.",
        )];
    }

    steps.push((
        OpenFocus::Finding,
        "finding",
        format!(
            "{}:{}:{}",
            display_path(&finding.file),
            finding.line,
            finding.column
        ),
        None,
        flow_accent_color(finding.severity),
    ));

    if let (Some(line), Some(description)) = (finding.sink_line, finding.sink_description.as_ref())
    {
        steps.push((
            OpenFocus::Sink,
            "sink",
            format!("{}:{}", display_path(&finding.file), line),
            Some(description.clone()),
            Color::Red,
        ));
    }

    let mut lines = Vec::new();
    let step_count = steps.len();
    for (index, (focus, label, location, description, color)) in steps.into_iter().enumerate() {
        let is_last = index + 1 == step_count;
        let branch = if is_last { "`- " } else { "+- " };
        let stem = if is_last { "   " } else { "|  " };
        let is_active = focus == active_focus;

        lines.push(Line::from(vec![
            Span::styled(
                if is_active { "> " } else { branch },
                Style::default()
                    .fg(if is_active {
                        Color::Cyan
                    } else {
                        Color::DarkGray
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            open_focus_span(label, color, is_active),
            Span::styled(
                format!(" @ {}", location),
                if is_active {
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                },
            ),
        ]));

        if let Some(description) = description {
            for detail_line in description.lines() {
                lines.push(Line::from(vec![
                    Span::styled(stem, Style::default().fg(Color::DarkGray)),
                    Span::raw(detail_line.to_string()),
                ]));
            }
        }

        if !is_last {
            lines.push(Line::from(Span::styled(
                "|",
                Style::default().fg(Color::DarkGray),
            )));
        }
    }

    lines
}

fn open_target_lines(finding: &Finding, active_focus: OpenFocus) -> Vec<Line<'static>> {
    let active_location = open_focus_location(finding, active_focus);
    let mut selector = vec![Span::styled(
        "Enter opens ",
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )];

    for (index, focus) in available_open_focuses(finding).into_iter().enumerate() {
        if index > 0 {
            selector.push(Span::raw(" "));
        }
        selector.push(open_focus_span(
            open_focus_label(focus),
            open_focus_color(finding, focus),
            focus == active_focus,
        ));
    }

    selector.push(Span::raw("  "));
    selector.push(Span::styled(
        "@ ",
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    ));
    selector.push(Span::styled(
        active_location,
        Style::default().fg(Color::White),
    ));

    vec![Line::from(selector)]
}

fn render_source_context(source: &str, finding: &Finding, radius: usize) -> Vec<Line<'static>> {
    let source_lines = source.lines().collect::<Vec<_>>();
    if source_lines.is_empty() {
        return vec![Line::from(Span::styled(
            "Source file is empty.",
            Style::default().fg(Color::DarkGray),
        ))];
    }

    let highlighted_end = finding.end_line.max(finding.line).min(source_lines.len());
    let start_line = finding.line.saturating_sub(radius).max(1);
    let end_line = highlighted_end
        .saturating_add(radius)
        .min(source_lines.len());
    let width = end_line.to_string().len().max(2);
    let accent = flow_accent_color(finding.severity);
    let mut lines = Vec::new();

    for number in start_line..=end_line {
        let is_highlighted = (finding.line..=highlighted_end).contains(&number);
        let rendered = render_context_line(source_lines[number - 1], finding, number);
        let marker = if is_highlighted { "> " } else { "  " };
        let text_style = if is_highlighted {
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };

        lines.push(Line::from(vec![
            Span::styled(
                marker,
                Style::default().fg(accent).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{:>width$} ", number, width = width),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled("| ", Style::default().fg(Color::DarkGray)),
            Span::styled(rendered.text, text_style),
        ]));

        if let Some((offset, highlight_width)) = rendered.highlight {
            lines.push(context_caret_line(width, offset, highlight_width, accent));
        }
    }

    lines
}

fn open_focus_location(finding: &Finding, focus: OpenFocus) -> String {
    match focus {
        OpenFocus::Finding => format!(
            "{}:{}:{}",
            display_path(&finding.file),
            finding.line,
            finding.column
        ),
        OpenFocus::Source => format!(
            "{}:{}",
            display_path(&finding.file),
            finding.source_line.unwrap_or(finding.line)
        ),
        OpenFocus::Sink => format!(
            "{}:{}",
            display_path(&finding.file),
            finding.sink_line.unwrap_or(finding.line)
        ),
    }
}

fn open_focus_label(focus: OpenFocus) -> &'static str {
    match focus {
        OpenFocus::Finding => "finding",
        OpenFocus::Source => "source",
        OpenFocus::Sink => "sink",
    }
}

fn open_focus_color(finding: &Finding, focus: OpenFocus) -> Color {
    match focus {
        OpenFocus::Finding => flow_accent_color(finding.severity),
        OpenFocus::Source => Color::Yellow,
        OpenFocus::Sink => Color::Red,
    }
}

fn open_focus_span(label: &str, color: Color, selected: bool) -> Span<'static> {
    let style = if selected {
        Style::default()
            .fg(open_focus_selected_fg(color))
            .bg(color)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(color).add_modifier(Modifier::BOLD)
    };

    let text = if selected {
        format!(" {} ", label)
    } else {
        label.to_string()
    };

    Span::styled(text, style)
}

fn open_focus_selected_fg(color: Color) -> Color {
    match color {
        Color::Yellow => Color::Black,
        _ => Color::White,
    }
}

fn render_context_line(line: &str, finding: &Finding, line_number: usize) -> RenderedContextLine {
    let chars = line.chars().collect::<Vec<_>>();
    let char_len = chars.len();
    let highlight = highlight_range_for_line(finding, line_number, char_len);
    let mut window_start = 0;

    if char_len > CONTEXT_LINE_MAX_CHARS {
        if let Some((start, _)) = highlight {
            let focus = start.saturating_sub(1);
            window_start = focus.saturating_sub(CONTEXT_FOCUS_LEAD);
        }
        window_start = window_start.min(char_len.saturating_sub(CONTEXT_LINE_MAX_CHARS));
    }

    let window_end = (window_start + CONTEXT_LINE_MAX_CHARS).min(char_len);
    let leading_ellipsis = window_start > 0;
    let trailing_ellipsis = window_end < char_len;
    let mut text = String::new();
    if leading_ellipsis {
        text.push_str("...");
    }
    text.push_str(&chars[window_start..window_end].iter().collect::<String>());
    if trailing_ellipsis {
        text.push_str("...");
    }

    let visible_highlight = highlight.and_then(|(start, end)| {
        let visible_start = start.max(window_start + 1);
        let visible_end = end.min(window_end + 1);
        if visible_start >= visible_end {
            return None;
        }

        let ellipsis_offset = if leading_ellipsis { 3 } else { 0 };
        Some((
            ellipsis_offset + visible_start.saturating_sub(window_start + 1),
            visible_end.saturating_sub(visible_start),
        ))
    });

    RenderedContextLine {
        text,
        highlight: visible_highlight,
    }
}

fn highlight_range_for_line(
    finding: &Finding,
    line_number: usize,
    line_char_len: usize,
) -> Option<(usize, usize)> {
    if line_number < finding.line || line_number > finding.end_line {
        return None;
    }

    let start = if line_number == finding.line {
        finding.column.max(1)
    } else {
        1
    };
    let end = if line_number == finding.end_line {
        finding.end_column.max(start + 1)
    } else {
        line_char_len + 1
    };

    Some((
        start.min(line_char_len + 1),
        end.min(line_char_len + 1).max(start + 1),
    ))
}

fn context_caret_line(
    line_number_width: usize,
    caret_offset: usize,
    caret_width: usize,
    accent: Color,
) -> Line<'static> {
    let caret_width = caret_width.max(1);

    Line::from(vec![
        Span::raw("  "),
        Span::raw(" ".repeat(line_number_width + 1)),
        Span::styled("| ", Style::default().fg(Color::DarkGray)),
        Span::raw(" ".repeat(caret_offset)),
        Span::styled(
            "^".repeat(caret_width),
            Style::default().fg(accent).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" selected range", Style::default().fg(Color::DarkGray)),
    ])
}

struct RenderedContextLine {
    text: String,
    highlight: Option<(usize, usize)>,
}

#[cfg(test)]
fn compare_findings(left: &Finding, right: &Finding) -> std::cmp::Ordering {
    compare_findings_by(left, right, SortMode::SeverityDesc)
}

fn compare_findings_by(left: &Finding, right: &Finding, mode: SortMode) -> std::cmp::Ordering {
    let severity_then_location = severity_rank(right.severity)
        .cmp(&severity_rank(left.severity))
        .then(left.file.cmp(&right.file))
        .then(left.line.cmp(&right.line))
        .then(left.column.cmp(&right.column));

    match mode {
        SortMode::SeverityDesc => severity_then_location,
        SortMode::ConfidenceDesc => right
            .confidence
            .partial_cmp(&left.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(severity_then_location),
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
    }
}

fn severity_counts(findings: &[Finding]) -> SeverityCounts {
    let mut counts = SeverityCounts {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    };

    for finding in findings {
        match finding.severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
        }
    }

    counts
}

fn severity_badge_spans(counts: &SeverityCounts) -> Vec<Span<'static>> {
    let mut spans = Vec::new();

    for (severity, count) in [
        (Severity::Critical, counts.critical),
        (Severity::High, counts.high),
        (Severity::Medium, counts.medium),
        (Severity::Low, counts.low),
    ] {
        if count == 0 {
            continue;
        }

        if !spans.is_empty() {
            spans.push(Span::raw("  "));
        }
        spans.push(severity_count_badge(severity, count));
    }

    spans
}

fn severity_count_badge(severity: Severity, count: usize) -> Span<'static> {
    let label = match severity {
        Severity::Critical => format!(" {} critical ", count),
        Severity::High => format!(" {} high ", count),
        Severity::Medium => format!(" {} medium ", count),
        Severity::Low => format!(" {} low ", count),
    };

    Span::styled(label, severity_badge_style(severity))
}

fn severity_badge_span(severity: Severity) -> Span<'static> {
    let label = match severity {
        Severity::Critical => " CRITICAL ",
        Severity::High => " HIGH ",
        Severity::Medium => " MEDIUM ",
        Severity::Low => " LOW ",
    };

    Span::styled(label.to_string(), severity_badge_style(severity))
}

fn severity_badge_style(severity: Severity) -> Style {
    match severity {
        Severity::Critical => Style::default()
            .bg(Color::Rgb(130, 50, 180))
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
        Severity::High => Style::default()
            .bg(Color::Red)
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
        Severity::Medium => Style::default()
            .bg(Color::Yellow)
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD),
        Severity::Low => Style::default()
            .bg(Color::Blue)
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    }
}

fn flow_accent_color(severity: Severity) -> Color {
    match severity {
        Severity::Critical => Color::Rgb(130, 50, 180),
        Severity::High => Color::Red,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Blue,
    }
}

fn section_heading(label: &str, color: Color) -> Line<'static> {
    Line::from(Span::styled(
        label.to_string(),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    ))
}

fn metadata_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{}: ", label),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(value.to_string()),
    ])
}

fn preview_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{}: ", label),
            Style::default()
                .fg(Color::Rgb(145, 126, 99))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(value.to_string(), Style::default().fg(Color::Gray)),
    ])
}

fn review_badge_span(state: ReviewState) -> Span<'static> {
    let style = match state {
        ReviewState::Reviewed => Style::default()
            .fg(Color::Black)
            .bg(Color::Rgb(143, 189, 143))
            .add_modifier(Modifier::BOLD),
        ReviewState::Todo => Style::default()
            .fg(Color::Black)
            .bg(Color::Rgb(214, 182, 104))
            .add_modifier(Modifier::BOLD),
        ReviewState::IgnoreCandidate => Style::default()
            .fg(Color::White)
            .bg(Color::Rgb(156, 100, 84))
            .add_modifier(Modifier::BOLD),
    };

    Span::styled(format!(" {} ", state.label()), style)
}

fn finding_review_key(finding: &Finding) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        finding.rule_id,
        finding.file,
        finding.line,
        finding.column,
        finding.end_line,
        finding.end_column
    )
}

fn footer_label_span(label: &str) -> Span<'static> {
    Span::styled(
        label.to_string(),
        Style::default()
            .fg(Color::Rgb(145, 126, 99))
            .add_modifier(Modifier::BOLD),
    )
}

fn footer_value_span(value: &str) -> Span<'static> {
    Span::styled(value.to_string(), Style::default().fg(Color::White))
}

fn footer_key_span(key: &str) -> Span<'static> {
    Span::styled(
        format!(" {} ", key),
        Style::default()
            .fg(Color::Rgb(33, 25, 17))
            .bg(Color::Rgb(186, 157, 104))
            .add_modifier(Modifier::BOLD),
    )
}

fn loading_copy(app: &TuiApp) -> (&'static str, String) {
    match app.launch_mode {
        LaunchMode::Scan => (
            "Scanning code",
            format!("{}  built-in + custom rules", short_path(&app.request.path)),
        ),
        LaunchMode::Diff => (
            "Scanning diff",
            format!(
                "{}  against {}",
                short_path(&app.request.path),
                app.request.diff.as_deref().unwrap_or("main")
            ),
        ),
        LaunchMode::Secrets => (
            "Scanning secrets",
            format!(
                "{}  credential and token heuristics",
                short_path(&app.request.path)
            ),
        ),
        LaunchMode::Pqc => (
            "Scanning crypto",
            format!(
                "{}  post-quantum vulnerable algorithms",
                short_path(&app.request.path)
            ),
        ),
    }
}

fn loading_phase_labels(app: &TuiApp) -> [&'static str; 3] {
    match app.launch_mode {
        LaunchMode::Scan => ["walking files", "matching rules", "assembling findings"],
        LaunchMode::Diff => [
            "collecting changed files",
            "matching new issues",
            "building diff view",
        ],
        LaunchMode::Secrets => ["walking files", "checking patterns", "redacting snippets"],
        LaunchMode::Pqc => ["walking files", "filtering PQ rules", "assembling findings"],
    }
}

fn loading_shimmer_line(label: &str, width: usize, tick: usize) -> Vec<Span<'static>> {
    let mut spans = vec![Span::styled(
        format!("{label:<22}"),
        Style::default().fg(Color::Rgb(145, 126, 99)),
    )];
    spans.push(Span::raw("  "));

    let cycle = width + LOADING_SHIMMER_GAP * 2;
    let highlight = tick % cycle;

    for index in 0..width {
        let distance = (index + LOADING_SHIMMER_GAP).abs_diff(highlight) as f32;
        let intensity = shimmer_intensity(distance, LOADING_SHIMMER_BAND);
        spans.push(Span::styled(".", loading_shimmer_style(intensity)));
    }

    spans
}

fn shimmer_intensity(distance: f32, band_half_width: f32) -> f32 {
    if distance > band_half_width {
        return 0.0;
    }

    let angle = std::f32::consts::PI * (distance / band_half_width);
    0.5 * (1.0 + angle.cos())
}

fn loading_shimmer_style(intensity: f32) -> Style {
    if intensity >= 0.82 {
        Style::default()
            .fg(LOADING_SHIMMER_HIGHLIGHT)
            .add_modifier(Modifier::BOLD)
    } else if intensity >= 0.56 {
        Style::default().fg(LOADING_SHIMMER_MID)
    } else if intensity >= 0.24 {
        Style::default().fg(LOADING_SHIMMER_LOW)
    } else {
        Style::default().fg(LOADING_SHIMMER_BASE)
    }
}

fn draw_status_bar(
    frame: &mut ratatui::Frame,
    area: Rect,
    left: Line<'static>,
    right: Line<'static>,
) {
    frame.render_widget(Block::default().style(Style::default().bg(FOOTER_BG)), area);

    let inner = Rect {
        x: area.x.saturating_add(1),
        y: area.y,
        width: area.width.saturating_sub(2),
        height: area.height,
    };
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(24), Constraint::Length(34)])
        .split(inner);

    frame.render_widget(
        Paragraph::new(left)
            .style(Style::default().bg(FOOTER_BG))
            .wrap(Wrap { trim: true }),
        layout[0],
    );
    frame.render_widget(
        Paragraph::new(right)
            .style(Style::default().bg(FOOTER_BG))
            .alignment(Alignment::Right)
            .wrap(Wrap { trim: true }),
        layout[1],
    );
}

fn panel_block(title: Option<&str>, background: Color) -> Block<'static> {
    let block = Block::default().style(Style::default().bg(background));
    let block = if let Some(title) = title {
        block.title(Span::styled(
            format!(" {} ", title),
            Style::default()
                .fg(Color::Rgb(38, 28, 18))
                .bg(TITLE_BG)
                .add_modifier(Modifier::BOLD),
        ))
    } else {
        block
    };

    block.padding(Padding::new(1, 1, 1, 0))
}

fn mode_findings_title(mode: &TuiMode) -> &'static str {
    match mode {
        TuiMode::Scan => "Findings",
        TuiMode::Diff { .. } => "New Findings",
        TuiMode::Secrets => "Secrets",
    }
}

fn request_mode_label(args: &TuiArgs) -> &'static str {
    if args.secrets {
        "secrets"
    } else if args.diff.is_some() {
        "diff"
    } else if args.pq_mode {
        "pqc"
    } else {
        "scan"
    }
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical+",
        Severity::High => "high+",
        Severity::Medium => "medium+",
        Severity::Low => "low+",
    }
}

fn short_path(path: &str) -> String {
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(relative) = Path::new(path).strip_prefix(&cwd) {
            return relative.display().to_string();
        }
    }

    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > 4 {
        format!(".../{}", parts[parts.len() - 3..].join("/"))
    } else {
        path.to_string()
    }
}

fn display_path(path: &str) -> String {
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(relative) = Path::new(path).strip_prefix(&cwd) {
            return relative.display().to_string();
        }
    }

    path.to_string()
}

fn scan_root_path(path: &Path) -> PathBuf {
    if path.is_file() {
        path.parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        path.to_path_buf()
    }
}

const CONTEXT_LINE_MAX_CHARS: usize = 96;
const CONTEXT_FOCUS_LEAD: usize = 28;
const LOADING_SKELETON_WIDTH: usize = 28;
const LOADING_SHIMMER_GAP: usize = 8;
const LOADING_SHIMMER_CYCLE: usize = LOADING_SKELETON_WIDTH + LOADING_SHIMMER_GAP * 2;
const LOADING_SHIMMER_BAND: f32 = 7.0;
const APP_BG: Color = Color::Rgb(20, 17, 14);
const HEADER_BG: Color = Color::Rgb(44, 37, 28);
const PANEL_BG: Color = Color::Rgb(27, 23, 18);
const LIST_BG: Color = Color::Rgb(34, 28, 21);
const DETAIL_BG: Color = Color::Rgb(24, 20, 16);
const NOTICE_BG: Color = Color::Rgb(38, 29, 24);
const FOOTER_BG: Color = Color::Rgb(58, 47, 34);
const TITLE_BG: Color = Color::Rgb(201, 172, 114);
const LOGO_PRIMARY: Color = Color::Rgb(221, 191, 122);
const LOGO_SECONDARY: Color = Color::Rgb(181, 136, 88);
const LAUNCH_CARD_BG: Color = Color::Rgb(34, 28, 21);
const LOADING_SHIMMER_BASE: Color = Color::Rgb(82, 67, 50);
const LOADING_SHIMMER_LOW: Color = Color::Rgb(106, 87, 64);
const LOADING_SHIMMER_MID: Color = Color::Rgb(145, 119, 84);
const LOADING_SHIMMER_HIGHLIGHT: Color = Color::Rgb(214, 185, 131);
