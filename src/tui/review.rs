use super::input::ControlFlow;
use super::persist::{FilterSettings, SessionStore};
use super::state::{BaselineFilter, ReviewState, TriageAction, TuiApp};
use super::widgets::{panel_block, LOGO_PRIMARY, PANEL_BG, TEXT_MUTED, TEXT_PRIMARY};
use crate::app::TuiMode;
use crate::baseline::append_findings_to_baseline_at_root;
use crate::config::load_for_scan;
use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Clear, List, ListItem, ListState, Paragraph, Wrap};
use std::collections::BTreeMap;
use std::path::Path;

pub(super) struct BatchMenu {
    request_id: u64,
    targets: Vec<(usize, String)>,
    actions: Vec<TriageAction>,
    selected: usize,
    confirming: bool,
    scroll: u16,
    list_state: ListState,
}

pub(super) struct SavedViewMenu {
    selected: usize,
    mode: SavedViewMode,
    list_state: ListState,
    error: Option<String>,
}

enum SavedViewMode {
    Browse,
    Name(String),
    ConfirmSave(String),
    ConfirmDelete(String),
    ConfirmReload,
    ConfirmRecover,
}

impl TriageAction {
    pub(super) fn review_mark(self) -> Option<Option<ReviewState>> {
        match self {
            Self::MarkReviewed => Some(Some(ReviewState::Reviewed)),
            Self::MarkTodo => Some(Some(ReviewState::Todo)),
            Self::MarkIgnoreCandidate => Some(Some(ReviewState::IgnoreCandidate)),
            Self::ClearReviewState => Some(None),
            _ => None,
        }
    }
}

impl TuiApp {
    pub(super) fn activate_review_session(&mut self) {
        let config = match load_for_scan(
            Path::new(&self.request.path),
            self.request.config.as_deref(),
        ) {
            Ok(config) => config,
            Err(error) => {
                self.session_error = Some(error.clone());
                self.push_runtime_notice(format!("review state unavailable: {error}"));
                return;
            }
        };
        self.identity_root = crate::path_identity::project_root(
            Path::new(&self.request.path),
            config.as_ref().map(|config| config.project_root.as_path()),
        );
        let Some(root) = &self.session_root else {
            if let Some(error) = &self.session_error {
                self.push_runtime_notice(format!(
                    "review state unavailable: {error}; marks are not saved"
                ));
            }
            return;
        };
        let mode = if self.request.secrets {
            "secrets".to_string()
        } else if let Some(target) = &self.request.diff {
            format!("diff:{target}")
        } else if self.request.pq_mode {
            "pqc".to_string()
        } else {
            "scan".to_string()
        };
        let store = SessionStore::new(root, &self.identity_root, &mode);
        if self
            .session_store
            .as_ref()
            .is_some_and(|current| current.path() == store.path())
        {
            if !self.session_dirty {
                if let Err(error) = self.reload_review_session() {
                    self.push_runtime_notice(format!(
                        "review state unavailable: {error}; F opens recovery controls"
                    ));
                }
            }
            return;
        }
        self.session_store = Some(store);
        self.review_states.clear();
        self.saved_filters.clear();
        self.session_dirty = false;
        if let Err(error) = self.reload_review_session() {
            self.push_runtime_notice(format!(
                "review state unavailable: {error}; F opens recovery controls"
            ));
        }
    }

    fn reload_review_session(&mut self) -> Result<(), String> {
        let result = self
            .session_store
            .as_mut()
            .ok_or_else(|| {
                self.session_error
                    .clone()
                    .unwrap_or_else(|| "review storage is unavailable".into())
            })?
            .load();
        match result {
            Ok(data) => {
                self.review_states = data.review_states;
                self.saved_filters = data.filters;
                self.session_error = None;
                self.session_dirty = false;
                self.clamp_selection();
                Ok(())
            }
            Err(error) => {
                self.session_error = Some(error.clone());
                Err(error)
            }
        }
    }

    pub(super) fn flush_review_session(&mut self) -> Result<(), String> {
        let result = if let Some(store) = &mut self.session_store {
            store.save(&self.review_states, &self.saved_filters)
        } else if let Some(error) = &self.session_error {
            Err(error.clone())
        } else {
            // Detached state is used by callers that have not enabled persistence.
            Ok(())
        };
        match result {
            Ok(()) => {
                self.session_dirty = false;
                self.session_error = None;
                Ok(())
            }
            Err(error) => {
                self.session_dirty = true;
                self.session_error = Some(error.clone());
                Err(format!(
                    "could not confirm a durable save; changes remain in this session: {error}"
                ))
            }
        }
    }

    pub(super) fn update_review_mark(&mut self, key: &str, mark: Option<ReviewState>) {
        if let Some(mark) = mark {
            self.review_states.insert(key.to_owned(), mark);
        } else {
            self.review_states.remove(key);
        }
        self.session_dirty = true;
    }

    fn current_filter_settings(&self) -> FilterSettings {
        FilterSettings {
            search_query: self.search_query.clone(),
            min_severity: self.min_severity,
            min_confidence: self.session_min_confidence,
            review_filter: self.review_filter,
            sort_mode: self.sort_mode,
            baseline_filter: self.baseline_filter,
        }
    }

    fn save_named_filter(&mut self, name: String) -> Result<(), String> {
        self.saved_filters
            .insert(name.clone(), self.current_filter_settings());
        self.session_dirty = true;
        self.flush_review_session()?;
        self.push_runtime_notice(format!("saved filter {name:?}"));
        Ok(())
    }

    fn load_named_filter(&mut self, name: &str) -> Result<(), String> {
        let settings = self
            .saved_filters
            .get(name)
            .ok_or_else(|| "filter no longer exists".to_string())?;
        if settings.baseline_filter != BaselineFilter::All
            && self
                .result
                .as_ref()
                .and_then(|result| result.baseline_comparison.as_ref())
                .is_none()
        {
            return Err("this filter needs a baseline comparison; use --baseline <file> or configure a baseline".into());
        }
        self.search_query.clone_from(&settings.search_query);
        self.min_severity = settings.min_severity;
        self.session_min_confidence = settings.min_confidence;
        self.review_filter = settings.review_filter;
        self.sort_mode = settings.sort_mode;
        let baseline_filter = settings.baseline_filter;
        self.set_baseline_filter(baseline_filter);
        self.push_runtime_notice(format!("loaded filter {name:?}"));
        Ok(())
    }

    pub(super) fn open_saved_views(&mut self) {
        self.saved_view_menu = Some(SavedViewMenu {
            selected: 0,
            mode: SavedViewMode::Browse,
            list_state: ListState::default(),
            error: self.session_error.clone(),
        });
    }

    pub(super) fn handle_saved_view_key(&mut self, key: KeyCode) -> ControlFlow {
        let Some(mut menu) = self.saved_view_menu.take() else {
            return ControlFlow::Continue;
        };
        menu.error = None;
        let mut close = false;
        let mut outcome: Result<(), String> = Ok(());
        match &mut menu.mode {
            SavedViewMode::Browse => match key {
                KeyCode::Esc | KeyCode::Char('q') => close = true,
                KeyCode::Down | KeyCode::Char('j') => {
                    menu.selected =
                        (menu.selected + 1).min(self.saved_filters.len().saturating_sub(1))
                }
                KeyCode::Up | KeyCode::Char('k') => menu.selected = menu.selected.saturating_sub(1),
                KeyCode::Char('s') => menu.mode = SavedViewMode::Name(String::new()),
                KeyCode::Char('r') => menu.mode = SavedViewMode::ConfirmReload,
                KeyCode::Char('R') => menu.mode = SavedViewMode::ConfirmRecover,
                KeyCode::Char('w') => outcome = self.flush_review_session(),
                KeyCode::Enter | KeyCode::Char('d') => {
                    if let Some(name) = self.saved_filters.keys().nth(menu.selected).cloned() {
                        if key == KeyCode::Enter {
                            outcome = self.load_named_filter(&name);
                            close = outcome.is_ok();
                        } else {
                            menu.mode = SavedViewMode::ConfirmDelete(name);
                        }
                    }
                }
                _ => {}
            },
            SavedViewMode::Name(draft) => match key {
                KeyCode::Esc => menu.mode = SavedViewMode::Browse,
                KeyCode::Backspace => {
                    draft.pop();
                }
                KeyCode::Char(ch) if !ch.is_control() && draft.chars().count() < 64 => {
                    draft.push(ch)
                }
                KeyCode::Enter => {
                    let name = draft.trim().to_owned();
                    if name.is_empty() {
                        outcome = Err("a filter name cannot be empty".into());
                    } else if self.saved_filters.contains_key(&name) {
                        menu.mode = SavedViewMode::ConfirmSave(name);
                    } else {
                        outcome = self.save_named_filter(name);
                        menu.mode = SavedViewMode::Browse;
                    }
                }
                _ => {}
            },
            confirmation => match key {
                KeyCode::Esc | KeyCode::Char('n') => menu.mode = SavedViewMode::Browse,
                KeyCode::Char('y') => {
                    outcome = match confirmation {
                        SavedViewMode::ConfirmSave(name) => self.save_named_filter(name.clone()),
                        SavedViewMode::ConfirmDelete(name) => {
                            self.saved_filters.remove(name);
                            self.session_dirty = true;
                            self.flush_review_session()
                        }
                        SavedViewMode::ConfirmReload => self.reload_review_session(),
                        SavedViewMode::ConfirmRecover => {
                            match self
                                .session_store
                                .as_mut()
                                .ok_or_else(|| "review storage is unavailable".to_string())
                                .and_then(SessionStore::recover)
                            {
                                Ok(backup) => {
                                    if let Some(path) = backup {
                                        self.push_runtime_notice(format!(
                                            "previous review state preserved at {}",
                                            path.display()
                                        ));
                                    }
                                    self.reload_review_session()
                                }
                                Err(error) => Err(error),
                            }
                        }
                        _ => unreachable!("only confirmation modes reach this branch"),
                    };
                    menu.mode = SavedViewMode::Browse;
                }
                _ => {}
            },
        }
        if let Err(error) = outcome {
            self.push_runtime_notice(format!("saved filters: {error}"));
            menu.error = Some(error);
        }
        menu.selected = menu
            .selected
            .min(self.saved_filters.len().saturating_sub(1));
        if !close {
            self.saved_view_menu = Some(menu);
        }
        ControlFlow::Continue
    }

    pub(super) fn cycle_baseline_filter(&mut self) {
        if self
            .result
            .as_ref()
            .and_then(|result| result.baseline_comparison.as_ref())
            .is_none()
        {
            self.push_runtime_notice(
                "baseline categories require --baseline <file> or a configured baseline".into(),
            );
            return;
        }
        let next = match self.baseline_filter {
            BaselineFilter::All => BaselineFilter::Introduced,
            BaselineFilter::Introduced => BaselineFilter::Recurring,
            BaselineFilter::Recurring => BaselineFilter::Resolved,
            BaselineFilter::Resolved => BaselineFilter::All,
        };
        self.set_baseline_filter(next);
    }

    pub(super) fn toggle_checked_finding(&mut self) {
        if self.baseline_filter == BaselineFilter::Resolved {
            return;
        }
        if let Some(&index) = self.filtered_indices().get(self.selected) {
            if !self.checked_findings.remove(&index) {
                self.checked_findings.insert(index);
            }
        }
    }

    pub(super) fn open_batch_menu(&mut self) {
        if self.baseline_filter == BaselineFilter::Resolved {
            return;
        }
        let Some(result) = &self.result else {
            return;
        };
        let targets: Vec<_> = self
            .finding_keys
            .iter()
            .enumerate()
            .filter(|(index, _)| self.checked_findings.contains(index))
            .map(|(index, key)| (index, key.clone()))
            .collect();
        if targets.is_empty() {
            self.push_runtime_notice(
                "select findings with Space or a before opening batch actions".into(),
            );
            return;
        }
        let mut actions = vec![
            TriageAction::MarkReviewed,
            TriageAction::MarkTodo,
            TriageAction::MarkIgnoreCandidate,
            TriageAction::ClearReviewState,
        ];
        match result.mode {
            TuiMode::Scan => {
                actions.extend([
                    TriageAction::AddToBaseline,
                    TriageAction::IgnoreRuleInFile,
                    TriageAction::DisableRuleGlobally,
                ]);
                actions.extend(
                    super::state::SEVERITY_PICKER_CHOICES
                        .into_iter()
                        .map(TriageAction::ApplySeverityOverride),
                );
            }
            TuiMode::Secrets => {
                actions.extend([TriageAction::AddToBaseline, TriageAction::IgnoreSecretRule])
            }
            TuiMode::Diff { .. } => {}
        }
        self.batch_menu = Some(BatchMenu {
            request_id: self.active_request_id,
            targets,
            actions,
            selected: 0,
            confirming: false,
            scroll: 0,
            list_state: ListState::default(),
        });
    }

    pub(super) fn handle_batch_key(&mut self, key: KeyCode) -> ControlFlow {
        let Some(menu) = &mut self.batch_menu else {
            return ControlFlow::Continue;
        };
        if key == KeyCode::Esc {
            self.batch_menu = None;
            return ControlFlow::Continue;
        }
        if menu.confirming {
            match key {
                KeyCode::Char('y') => return ControlFlow::ApplyBatch,
                KeyCode::Char('n') => {
                    menu.confirming = false;
                    menu.scroll = 0;
                }
                KeyCode::Down | KeyCode::Char('j') => menu.scroll = menu.scroll.saturating_add(1),
                KeyCode::Up | KeyCode::Char('k') => menu.scroll = menu.scroll.saturating_sub(1),
                KeyCode::PageDown => menu.scroll = menu.scroll.saturating_add(8),
                KeyCode::PageUp => menu.scroll = menu.scroll.saturating_sub(8),
                KeyCode::Home => menu.scroll = 0,
                KeyCode::End => menu.scroll = u16::MAX,
                _ => {}
            }
        } else {
            match key {
                KeyCode::Down | KeyCode::Char('j') => {
                    menu.selected = (menu.selected + 1).min(menu.actions.len() - 1)
                }
                KeyCode::Up | KeyCode::Char('k') => menu.selected = menu.selected.saturating_sub(1),
                KeyCode::Enter => {
                    menu.confirming = true;
                    menu.scroll = 0;
                }
                _ => {}
            }
        }
        ControlFlow::Continue
    }

    pub(super) fn apply_batch(&mut self) -> Result<bool, String> {
        let menu = self
            .batch_menu
            .take()
            .ok_or_else(|| "no batch preview is open".to_string())?;
        if !menu.confirming {
            return Err("preview the batch before confirming it".into());
        }
        if self.scanning
            || menu.request_id != self.active_request_id
            || self.result.is_none()
            || menu
                .targets
                .iter()
                .any(|(index, key)| self.finding_keys.get(*index) != Some(key))
        {
            return Err(
                "scan changed since this batch was selected; select and preview again".into(),
            );
        }
        let action = menu.actions[menu.selected];
        let count = menu.targets.len();
        if let Some(mark) = action.review_mark() {
            for (_, key) in &menu.targets {
                self.update_review_mark(key, mark);
            }
            self.clamp_selection();
            self.flush_review_session()?;
            for (index, _) in &menu.targets {
                self.checked_findings.remove(index);
            }
            self.push_runtime_notice(format!(
                "batch: {} applied to {count} selected findings",
                action.label()
            ));
            return Ok(false);
        }
        if action == TriageAction::AddToBaseline {
            let path = self.baseline_path_for_actions()?;
            let result = self.result.as_ref().expect("checked above");
            let added = append_findings_to_baseline_at_root(
                &path,
                menu.targets
                    .iter()
                    .map(|(index, _)| &result.findings[*index]),
                &self.identity_root,
            )?;
            self.request.baseline = Some(path.to_string_lossy().into_owned());
            for (index, _) in &menu.targets {
                self.checked_findings.remove(index);
            }
            self.push_runtime_notice(format!(
                "batch: {count} selected findings processed; {added} new baseline entries in {}",
                path.display()
            ));
            return Ok(true);
        }
        // Repository-wide actions share effects across findings. Write each rule
        // (or rule/file pair) once, retaining each target for accurate outcomes.
        let groups: Vec<Vec<usize>> = {
            let result = self.result.as_ref().expect("checked above");
            let mut groups: BTreeMap<(&str, &str), Vec<usize>> = BTreeMap::new();
            for (index, _) in &menu.targets {
                let finding = &result.findings[*index];
                let file = if action == TriageAction::IgnoreRuleInFile {
                    finding.file.as_str()
                } else {
                    ""
                };
                groups
                    .entry((&finding.rule_id, file))
                    .or_default()
                    .push(*index);
            }
            groups.into_values().collect()
        };
        let mut completed = 0;
        let mut failed = 0;
        let mut rescan = false;
        for group in groups {
            let finding = self.result.as_ref().expect("checked above").findings[group[0]].clone();
            match self.apply_action_to_finding(action, &finding) {
                Ok(changed) => {
                    completed += group.len();
                    rescan |= changed;
                    for index in group {
                        self.checked_findings.remove(&index);
                    }
                }
                Err(error) => {
                    failed += group.len();
                    self.push_runtime_notice(format!(
                        "batch failed for {} in {} ({} selected): {error}",
                        finding.rule_id,
                        finding.file,
                        group.len()
                    ));
                }
            }
        }
        self.push_runtime_notice(format!("batch: {completed}/{count} selected findings processed; {failed} failed. Successful writes were not rolled back."));
        Ok(rescan)
    }

    pub(super) fn draw_review_modals(&mut self, frame: &mut ratatui::Frame) {
        let area = review_modal_area(frame.area());
        if self.saved_view_menu.is_some() {
            self.draw_saved_views(frame, area);
        }
        if self.batch_menu.is_some() {
            self.draw_batch_menu(frame, area);
        }
    }

    fn draw_saved_views(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        let menu = self.saved_view_menu.as_ref().expect("modal is open");
        let message = match &menu.mode {
            SavedViewMode::Browse => None,
            SavedViewMode::Name(draft) => Some((
                vec![
                    Line::from("Name the current filter settings:"),
                    Line::from(format!("{draft}_")),
                ],
                "Enter save  Esc back",
            )),
            SavedViewMode::ConfirmSave(name) => Some((
                vec![
                    Line::from(format!("Replace saved filter {name:?}?")),
                    Line::from("The current filters will replace its settings."),
                ],
                "y replace  Esc cancel",
            )),
            SavedViewMode::ConfirmDelete(name) => Some((
                vec![
                    Line::from(format!("Delete saved filter {name:?}?")),
                    Line::from("Review marks are not deleted."),
                ],
                "y delete  Esc cancel",
            )),
            SavedViewMode::ConfirmReload => Some((
                vec![
                    Line::from("Reload saved marks and filters?"),
                    Line::from("Discard unsaved changes in this session."),
                ],
                "y reload  Esc cancel",
            )),
            SavedViewMode::ConfirmRecover => Some((
                vec![
                    Line::from("Back up this review file and reset?"),
                    Line::from("Clears all marks and saved filters."),
                    Line::from("For the current project and mode."),
                    Line::from("Unsaved changes are NOT backed up."),
                ],
                "y back up + reset  Esc cancel",
            )),
        };
        if let Some((mut lines, footer)) = message {
            if let Some(error) = &menu.error {
                lines.push(Line::from(error.clone()));
            }
            draw_review_text(frame, area, "Saved filters", lines, &mut 0, footer);
            return;
        }
        frame.render_widget(Clear, area);
        let title = if self.session_dirty {
            "Saved filters - UNSAVED changes"
        } else if self.session_error.is_some() {
            "Saved filters - storage error"
        } else {
            "Saved filters"
        };
        let block = panel_block(Some(title), PANEL_BG);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let parts = Layout::vertical([
            Constraint::Min(1),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(inner);
        let items: Vec<_> = self
            .saved_filters
            .keys()
            .map(|name| ListItem::new(name.as_str()))
            .collect();
        let selected = menu.selected;
        let details = menu.error.clone().unwrap_or_else(|| self.saved_filters.values().nth(selected).map(|settings| format!(
            "{} | {} | confidence >= {:.0}%\n{} | severity {}\nSearch: {}",
            settings.review_filter.label(), settings.sort_mode.label(), settings.min_confidence * 100.0,
            settings.baseline_filter.label(), settings.min_severity.map_or_else(|| "all".into(), |severity| severity.to_string()),
            if settings.search_query.is_empty() { "(none)" } else { &settings.search_query }
        )).unwrap_or_else(|| "No saved filters. Press s to name the current search, severity, confidence, review and baseline filters.".into()));
        if items.is_empty() {
            frame.render_widget(
                Paragraph::new("No saved filters").style(Style::default().fg(TEXT_MUTED)),
                parts[0],
            );
        } else {
            let menu = self.saved_view_menu.as_mut().expect("modal is open");
            menu.list_state.select(Some(selected));
            frame.render_stateful_widget(
                List::new(items)
                    .style(Style::default().fg(TEXT_PRIMARY))
                    .highlight_style(
                        Style::default()
                            .fg(LOGO_PRIMARY)
                            .add_modifier(Modifier::BOLD),
                    )
                    .highlight_symbol("> "),
                parts[0],
                &mut menu.list_state,
            );
        }
        frame.render_widget(
            Paragraph::new(details)
                .wrap(Wrap { trim: false })
                .style(Style::default().fg(TEXT_MUTED)),
            parts[1],
        );
        frame.render_widget(
            Paragraph::new("Enter load s save d delete\nr reload R reset w retry Esc close")
                .style(Style::default().fg(TEXT_PRIMARY)),
            parts[2],
        );
    }

    fn draw_batch_menu(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        let menu = self.batch_menu.as_ref().expect("modal is open");
        let count = menu.targets.len();
        if !menu.confirming {
            frame.render_widget(Clear, area);
            let title = format!("Batch actions - {count} selected");
            let block = panel_block(Some(&title), PANEL_BG);
            let inner = block.inner(area);
            frame.render_widget(block, area);
            let parts = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(inner);
            let items: Vec<_> = menu
                .actions
                .iter()
                .map(|action| ListItem::new(action.label()))
                .collect();
            let menu = self.batch_menu.as_mut().expect("modal is open");
            menu.list_state.select(Some(menu.selected));
            frame.render_stateful_widget(
                List::new(items)
                    .style(Style::default().fg(TEXT_PRIMARY))
                    .highlight_style(
                        Style::default()
                            .fg(LOGO_PRIMARY)
                            .add_modifier(Modifier::BOLD),
                    )
                    .highlight_symbol("> "),
                parts[0],
                &mut menu.list_state,
            );
            frame.render_widget(
                Paragraph::new("Enter preview  Esc cancel").style(Style::default().fg(TEXT_MUTED)),
                parts[1],
            );
            return;
        }
        let action = menu.actions[menu.selected];
        let visible = self
            .filtered_indices()
            .iter()
            .filter(|index| self.checked_findings.contains(index))
            .count();
        let mut lines = vec![
            Line::from(action.label()),
            Line::from(format!(
                "{count} selected: {visible} visible, {} hidden by filters",
                count - visible
            )),
        ];
        if action.review_mark().is_some() {
            lines.push(Line::from(
                "Changes local review marks; repository files are untouched.",
            ));
            if let Some(store) = &self.session_store {
                lines.push(Line::from(format!("Writes {}", store.path().display())));
            }
        } else if action == TriageAction::AddToBaseline {
            lines.push(Line::from(format!(
                "Writes baseline {}",
                self.baseline_path_display()
            )));
            lines.push(Line::from("Adds only these exact finding fingerprints."));
        } else {
            lines.push(Line::from(format!(
                "Writes configuration {}",
                self.config_path_display()
            )));
            lines.push(Line::from(if action == TriageAction::IgnoreRuleInFile {
                "Scope: each selected rule/file pair, including UNSELECTED findings of that rule in that file."
            } else {
                "Scope: selected RULES across the entire configured project, including UNSELECTED findings."
            }));
            lines.push(Line::from(
                "Not a transaction: successful writes remain if another target fails.",
            ));
        }
        lines.push(Line::from(""));
        lines.push(Line::from("Exact selected findings:"));
        if let Some(result) = &self.result {
            for (index, _) in &menu.targets {
                if let Some(finding) = result.findings.get(*index) {
                    lines.push(Line::from(format!(
                        "{}  {}:{}",
                        finding.rule_id, finding.file, finding.line
                    )));
                }
            }
        }
        let menu = self.batch_menu.as_mut().expect("modal is open");
        draw_review_text(
            frame,
            area,
            "Confirm batch - no writes yet",
            lines,
            &mut menu.scroll,
            "y apply  n back  Esc cancel  PgDn scroll",
        );
    }
}

fn review_modal_area(area: Rect) -> Rect {
    let width = area.width.saturating_sub(2).min(96);
    let height = area.height.saturating_sub(2).min(26);
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    )
}

fn draw_review_text(
    frame: &mut ratatui::Frame,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    scroll: &mut u16,
    footer: &str,
) {
    frame.render_widget(Clear, area);
    let block = panel_block(Some(title), PANEL_BG);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let parts = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(inner);
    let paragraph = Paragraph::new(Text::from(lines))
        .wrap(Wrap { trim: false })
        .style(Style::default().fg(TEXT_PRIMARY));
    let maximum = paragraph
        .line_count(parts[0].width)
        .saturating_sub(parts[0].height as usize)
        .min(u16::MAX as usize) as u16;
    *scroll = (*scroll).min(maximum);
    frame.render_widget(paragraph.scroll((*scroll, 0)), parts[0]);
    frame.render_widget(
        Paragraph::new(footer).style(Style::default().fg(TEXT_MUTED)),
        parts[1],
    );
}
