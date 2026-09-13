use super::state::{
    ActionMenu, BaselineFilter, ExportFormat, ExportMenu, LaunchMode, OpenFocus, ReviewState,
    SeverityPicker, TriageAction, TuiApp, SEVERITY_PICKER_CHOICES,
};
use super::widgets::{
    display_path, drain_queued_scroll_events, finding_list_index_at_position, preview_line,
};
use super::{open_command_spec, resolve_finding_path, OpenTarget, TerminalSession};
use crate::app::TuiMode;
use crate::baseline::{append_finding_to_baseline_at_root, fingerprint_finding_at_root};
use crate::config::{
    add_disabled_rule_to_config, add_scan_ignore_rule, add_secrets_ignored_rule,
    add_severity_override_to_config, current_severity_override, is_rule_disabled_in_config,
    load_for_scan,
};
use crate::{Finding, Severity};
use crossterm::event::{self, KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use std::path::Path;
use std::process::{Command, Stdio};

pub(super) enum ControlFlow {
    Continue,
    Rescan,
    OpenSelected,
    ApplyAction(TriageAction),
    ApplyBatch,
    Exit,
}

impl TuiApp {
    pub(super) fn handle_key(&mut self, key: KeyEvent) -> ControlFlow {
        if key.kind == event::KeyEventKind::Release
            || (key.kind == event::KeyEventKind::Repeat && key.code == KeyCode::Enter)
        {
            return ControlFlow::Continue;
        }
        // Ctrl+C / Ctrl+Shift+C always exits.
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
        {
            return ControlFlow::Exit;
        }
        // Modified shortcuts must not consume ordinary text typed into search.
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && key.code == KeyCode::Char('u')
            && self.search_mode
        {
            self.search_query.clear();
            self.clamp_selection();
            return ControlFlow::Continue;
        }
        // Catch-all: any other Ctrl/Alt combination is ignored (not re-mapped).
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return ControlFlow::Continue;
        }

        if self.show_help {
            return match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => {
                    self.show_help = false;
                    self.help_scroll = 0;
                    ControlFlow::Continue
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.help_scroll = self.help_scroll.saturating_sub(1);
                    ControlFlow::Continue
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.help_scroll = self.help_scroll.saturating_add(1);
                    ControlFlow::Continue
                }
                KeyCode::PageUp => {
                    self.help_scroll = self.help_scroll.saturating_sub(8);
                    ControlFlow::Continue
                }
                KeyCode::PageDown => {
                    self.help_scroll = self.help_scroll.saturating_add(8);
                    ControlFlow::Continue
                }
                KeyCode::Home => {
                    self.help_scroll = 0;
                    ControlFlow::Continue
                }
                KeyCode::End => {
                    self.help_scroll = u16::MAX;
                    ControlFlow::Continue
                }
                _ => ControlFlow::Continue,
            };
        }
        if self.saved_view_menu.is_some() {
            return self.handle_saved_view_key(key.code);
        }
        if self.batch_menu.is_some() {
            return self.handle_batch_key(key.code);
        }

        if key.code == KeyCode::Char('?')
            && !self.search_mode
            && self.severity_picker.is_none()
            && self.action_menu.is_none()
            && self.export_menu.is_none()
        {
            self.show_help = true;
            self.help_scroll = 0;
            return ControlFlow::Continue;
        }

        if self.show_launch {
            return self.handle_launch_key(key.code);
        }
        if self.scanning {
            return if key.code == KeyCode::Char('q') {
                ControlFlow::Exit
            } else {
                ControlFlow::Continue
            };
        }

        if self.severity_picker.is_some() {
            return self.handle_severity_picker_key(key.code);
        }

        if self.action_menu.is_some() {
            return self.handle_action_menu_key(key.code);
        }

        if self.export_menu.is_some() {
            return self.handle_export_menu_key(key.code);
        }

        if self.search_mode {
            return self.handle_search_key(key.code);
        }
        if self.error.is_some() {
            match key.code {
                KeyCode::Home => {
                    self.detail_scroll = 0;
                    return ControlFlow::Continue;
                }
                KeyCode::End => {
                    self.detail_scroll = u16::MAX;
                    return ControlFlow::Continue;
                }
                KeyCode::Char('q' | 'r' | 'w' | 'F' | '[' | ']')
                | KeyCode::PageUp
                | KeyCode::PageDown => {}
                _ => return ControlFlow::Continue,
            }
        }

        match key.code {
            KeyCode::Char('q') => ControlFlow::Exit,
            KeyCode::Char(' ') => {
                self.toggle_checked_finding();
                ControlFlow::Continue
            }
            KeyCode::Char('a') => {
                self.toggle_visible_selection();
                ControlFlow::Continue
            }
            KeyCode::Char('x') => {
                self.open_batch_menu();
                ControlFlow::Continue
            }
            KeyCode::Char('F') => {
                self.open_saved_views();
                ControlFlow::Continue
            }
            KeyCode::Char('b') => {
                self.cycle_baseline_filter();
                ControlFlow::Continue
            }
            KeyCode::Home => {
                self.select_filtered_index(0);
                ControlFlow::Continue
            }
            KeyCode::End => {
                let len = self.visible_indices().len();
                if len > 0 {
                    self.select_filtered_index(len - 1);
                }
                ControlFlow::Continue
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.move_selection(1);
                ControlFlow::Continue
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.move_selection(-1);
                ControlFlow::Continue
            }
            KeyCode::Char('/') => {
                self.search_restore_query.clone_from(&self.search_query);
                self.search_restore_selection = self.visible_indices().get(self.selected).copied();
                self.search_mode = true;
                ControlFlow::Continue
            }
            KeyCode::Esc => {
                if self.show_detail_view {
                    self.show_detail_view = false;
                } else if self.has_active_filter() {
                    self.clear_active_filters();
                    self.push_runtime_notice(
                        "all filters cleared (search, severity, confidence, review, baseline)"
                            .to_string(),
                    );
                }
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
            KeyCode::Char('e') if self.baseline_filter == BaselineFilter::Resolved => {
                self.push_runtime_notice("historical rows are metadata only; switch baseline category to export current findings".into());
                ControlFlow::Continue
            }
            KeyCode::Char('e') => self.open_export_menu(),
            KeyCode::Char('i') => self.open_action_menu(),
            KeyCode::PageDown => {
                if self.detail_area.height > 0 {
                    self.scroll_detail(self.detail_area.height.saturating_sub(2).max(1) as i32);
                } else {
                    self.move_selection(self.list_area.height.saturating_sub(2).max(1) as isize);
                }
                ControlFlow::Continue
            }
            KeyCode::PageUp => {
                if self.detail_area.height > 0 {
                    self.scroll_detail(-(self.detail_area.height.saturating_sub(2).max(1) as i32));
                } else {
                    self.move_selection(-(self.list_area.height.saturating_sub(2).max(1) as isize));
                }
                ControlFlow::Continue
            }
            KeyCode::Char(']') => {
                self.scroll_notices(1);
                ControlFlow::Continue
            }
            KeyCode::Char('[') => {
                self.scroll_notices(-1);
                ControlFlow::Continue
            }
            KeyCode::Tab => {
                self.cycle_open_focus();
                ControlFlow::Continue
            }
            KeyCode::Enter => ControlFlow::OpenSelected,
            KeyCode::Char('o') => ControlFlow::OpenSelected,
            KeyCode::Char('r') if !self.scanning => ControlFlow::Rescan,
            KeyCode::Char('r') => ControlFlow::Continue,
            KeyCode::Char('c') => {
                self.cycle_session_min_confidence();
                ControlFlow::Continue
            }
            KeyCode::Char('C') => {
                self.cycle_sort_mode();
                ControlFlow::Continue
            }
            // v: toggle between list+detail split and full-list view
            KeyCode::Char('v') => {
                self.toggle_detail_view();
                ControlFlow::Continue
            }
            // f: cycle review-status filter
            KeyCode::Char('f') => {
                self.cycle_review_filter();
                ControlFlow::Continue
            }
            _ => ControlFlow::Continue,
        }
    }

    pub(super) fn can_handle_finding_mouse(&self) -> bool {
        !self.show_launch
            && !self.show_help
            && self.severity_picker.is_none()
            && self.action_menu.is_none()
            && self.export_menu.is_none()
            && self.batch_menu.is_none()
            && self.saved_view_menu.is_none()
            && !self.scanning
            && !self.search_mode
    }

    pub(super) fn handle_mouse(&mut self, mouse: MouseEvent) {
        match mouse.kind {
            kind @ (MouseEventKind::ScrollUp | MouseEventKind::ScrollDown) => {
                let last_kind = drain_queued_scroll_events(kind);
                match last_kind {
                    MouseEventKind::ScrollUp if self.show_detail_view || self.error.is_some() => {
                        self.scroll_detail(-1)
                    }
                    MouseEventKind::ScrollDown if self.show_detail_view || self.error.is_some() => {
                        self.scroll_detail(1)
                    }
                    MouseEventKind::ScrollUp => self.move_selection(-1),
                    MouseEventKind::ScrollDown => self.move_selection(1),
                    _ => {}
                }
            }
            MouseEventKind::Down(event::MouseButton::Left) => {
                if let Some(index) = finding_list_index_at_position(
                    self.list_area,
                    self.list_state.offset(),
                    self.visible_indices().len(),
                    mouse.column,
                    mouse.row,
                ) {
                    self.select_filtered_index(index);
                }
            }
            MouseEventKind::Moved => {
                self.hover_index = finding_list_index_at_position(
                    self.list_area,
                    self.list_state.offset(),
                    self.visible_indices().len(),
                    mouse.column,
                    mouse.row,
                );
            }
            _ => {}
        }
    }

    pub(super) fn handle_search_key(&mut self, key: KeyCode) -> ControlFlow {
        match key {
            KeyCode::Esc => {
                self.search_query = std::mem::take(&mut self.search_restore_query);
                self.search_mode = false;
                self.clamp_selection();
                if let Some(index) = self.search_restore_selection.take().and_then(|original| {
                    self.visible_indices()
                        .iter()
                        .position(|index| *index == original)
                }) {
                    self.select_filtered_index(index);
                }
            }
            KeyCode::Enter => {
                self.search_mode = false;
                self.search_restore_query.clear();
                self.search_restore_selection = None;
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

    pub(super) fn handle_launch_key(&mut self, key: KeyCode) -> ControlFlow {
        match key {
            KeyCode::Char(ch) if self.launch_mode == LaunchMode::Diff => {
                self.launch_diff_target.push(ch);
                ControlFlow::Continue
            }
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

    pub(super) fn handle_action_menu_key(&mut self, key: KeyCode) -> ControlFlow {
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

    pub(super) fn open_export_menu(&mut self) -> ControlFlow {
        if self.result.is_none() {
            self.push_runtime_notice("no results to export".to_string());
            return ControlFlow::Continue;
        }
        self.export_menu = Some(ExportMenu {
            formats: vec![ExportFormat::Cbom, ExportFormat::Json, ExportFormat::Sarif],
            selected: 0,
            overwrite: None,
        });
        ControlFlow::Continue
    }

    pub(super) fn handle_export_menu_key(&mut self, key: KeyCode) -> ControlFlow {
        let Some(menu) = self.export_menu.as_mut() else {
            return ControlFlow::Continue;
        };
        if let Some(path) = menu.overwrite.as_ref() {
            match key {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    let path = path.clone();
                    let format = menu.formats[menu.selected];
                    self.export_menu = None;
                    self.export_findings_to_with_atomic_write(format, &path, true);
                }
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Char('q') => {
                    self.export_menu = None;
                }
                _ => {}
            }
            return ControlFlow::Continue;
        }
        match key {
            KeyCode::Esc | KeyCode::Char('q') => self.export_menu = None,
            KeyCode::Char('j') | KeyCode::Down => {
                menu.selected = (menu.selected + 1).min(menu.formats.len().saturating_sub(1));
            }
            KeyCode::Char('k') | KeyCode::Up => menu.selected = menu.selected.saturating_sub(1),
            KeyCode::Enter => {
                let format = menu.formats[menu.selected];
                self.export_with_overwrite_check(format, format.filename().into());
            }
            _ => {}
        }
        ControlFlow::Continue
    }

    pub(super) fn export_with_overwrite_check(
        &mut self,
        format: ExportFormat,
        path: std::path::PathBuf,
    ) {
        self.export_menu = None;
        match path.symlink_metadata() {
            Ok(metadata) if metadata.is_file() => {
                self.export_menu = Some(ExportMenu {
                    formats: vec![format],
                    selected: 0,
                    overwrite: Some(path),
                });
            }
            Ok(_) => {
                self.show_notices = true;
                self.push_runtime_notice(format!(
                    "export refused: {} is not a regular file (symlinks are not followed)",
                    path.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.export_findings_to_with_atomic_write(format, &path, false);
            }
            Err(error) => {
                self.show_notices = true;
                self.push_runtime_notice(format!("export failed: {}: {error}", path.display()));
            }
        }
    }

    /// Write beside the destination, then atomically publish; never follow a
    /// destination symlink or replace an existing file without confirmation.
    pub(super) fn export_findings_to_with_atomic_write(
        &mut self,
        format: ExportFormat,
        path: &std::path::Path,
        overwrite: bool,
    ) {
        let findings = match self.result.as_ref() {
            Some(r) => &r.findings,
            None => return,
        };

        let finding_count = findings.len();
        let mut empty_cbom = false;
        let content = match format {
            ExportFormat::Cbom => {
                let (cbom, empty_but_findings_present) = crate::report::cbom::build_cbom(findings);
                empty_cbom = empty_but_findings_present;
                serde_json::to_string_pretty(&cbom).expect("Failed to serialize CBOM")
            }
            ExportFormat::Json => {
                serde_json::to_string_pretty(findings).expect("Failed to serialize findings")
            }
            ExportFormat::Sarif => {
                let sarif = crate::report::sarif::build_sarif(findings);
                serde_json::to_string_pretty(&sarif).expect("Failed to serialize SARIF")
            }
        };

        if empty_cbom {
            self.push_runtime_notice(
                "CBOM export is empty: no cryptographic findings detected".to_string(),
            );
        }

        let write_result = (|| -> Result<(), String> {
            match path.symlink_metadata() {
                Ok(metadata) if !metadata.is_file() => {
                    return Err(format!("{} is not a regular file", path.display()));
                }
                Ok(_) if !overwrite => {
                    return Err(format!(
                        "{} already exists; export again to confirm replacement",
                        path.display()
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
            let dir = path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let mut tmp = tempfile::NamedTempFile::new_in(dir)
                .map_err(|e| format!("cannot create temp file: {e}"))?;
            std::io::Write::write_all(&mut tmp, content.as_bytes())
                .map_err(|e| format!("write failed: {e}"))?;
            if overwrite {
                tmp.persist(path)
            } else {
                tmp.persist_noclobber(path)
            }
            .map_err(|e| format!("cannot publish {}: {e}", path.display()))?;
            Ok(())
        })();

        match write_result {
            Ok(()) => {
                self.push_runtime_notice(format!(
                    "exported {} findings to {}",
                    finding_count,
                    path.display()
                ));
            }
            Err(err) => {
                self.show_notices = true;
                self.push_runtime_notice(format!("export failed: {}", err));
            }
        }
    }

    pub(super) fn handle_severity_picker_key(&mut self, key: KeyCode) -> ControlFlow {
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

    pub(super) fn cycle_session_min_confidence(&mut self) {
        self.session_min_confidence = match self.session_min_confidence {
            value if value <= 0.0 => 0.7,
            value if value < 0.85 => 0.9,
            value if value < 0.95 => 1.0,
            _ => 0.0,
        };
        self.clamp_selection();
    }

    pub(super) fn cycle_sort_mode(&mut self) {
        self.sort_mode = self.sort_mode.next();
        self.clamp_selection();
    }

    pub(super) fn action_enabled(&self, action: TriageAction) -> bool {
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

    pub(super) fn open_severity_picker(&mut self) {
        let Some(finding) = self.selected_finding() else {
            self.push_runtime_notice("no finding selected".to_string());
            return;
        };

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

    pub(super) fn open_action_menu(&mut self) -> ControlFlow {
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

    pub(super) fn available_actions_for_finding(&self, finding: &Finding) -> Vec<TriageAction> {
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
}

impl TuiApp {
    pub(super) fn open_selected_finding(
        &mut self,
        session: &mut TerminalSession,
    ) -> Result<(), String> {
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

    pub(super) fn open_source_finding(
        &mut self,
        session: &mut TerminalSession,
    ) -> Result<(), String> {
        let finding = self
            .selected_finding()
            .cloned()
            .ok_or_else(|| "no finding selected".to_string())?;
        let line = finding.source_line.unwrap_or(finding.line);
        self.open_focus = OpenFocus::Source;
        let target = OpenTarget {
            path: resolve_finding_path(&self.request.path, &finding.file),
            line: line.max(1),
        };

        self.open_target(session, target, "source")
    }

    pub(super) fn open_sink_finding(
        &mut self,
        session: &mut TerminalSession,
    ) -> Result<(), String> {
        let finding = self
            .selected_finding()
            .cloned()
            .ok_or_else(|| "no finding selected".to_string())?;
        let line = finding.sink_line.unwrap_or(finding.line);
        self.open_focus = OpenFocus::Sink;
        let target = OpenTarget {
            path: resolve_finding_path(&self.request.path, &finding.file),
            line: line.max(1),
        };

        self.open_target(session, target, "sink")
    }

    pub(super) fn open_target(
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

    pub(super) fn apply_action(&mut self, action: TriageAction) -> Result<bool, String> {
        let finding = self
            .selected_finding()
            .cloned()
            .ok_or_else(|| "no finding selected".to_string())?;
        let result = self.apply_action_to_finding(action, &finding)?;
        self.clamp_selection();
        if action.review_mark().is_some() {
            self.flush_review_session()?;
        }
        Ok(result)
    }

    pub(super) fn apply_action_to_finding(
        &mut self,
        action: TriageAction,
        finding: &Finding,
    ) -> Result<bool, String> {
        match action {
            TriageAction::AddToBaseline => {
                let baseline_path = self.baseline_path_for_actions()?;
                let config = load_for_scan(
                    Path::new(&self.request.path),
                    self.request.config.as_deref(),
                )?;
                let identity_root = crate::path_identity::project_root(
                    Path::new(&self.request.path),
                    config.as_ref().map(|config| config.project_root.as_path()),
                );
                let added =
                    append_finding_to_baseline_at_root(&baseline_path, finding, &identity_root)?;
                self.request.baseline = Some(baseline_path.to_string_lossy().into_owned());
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
                    finding,
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
                let key = fingerprint_finding_at_root(finding, &self.identity_root);
                self.update_review_mark(&key, Some(ReviewState::Reviewed));
                self.push_runtime_notice("marked finding as reviewed".to_string());
                Ok(false)
            }
            TriageAction::MarkTodo => {
                let key = fingerprint_finding_at_root(finding, &self.identity_root);
                self.update_review_mark(&key, Some(ReviewState::Todo));
                self.push_runtime_notice("marked finding as todo".to_string());
                Ok(false)
            }
            TriageAction::MarkIgnoreCandidate => {
                let key = fingerprint_finding_at_root(finding, &self.identity_root);
                self.update_review_mark(&key, Some(ReviewState::IgnoreCandidate));
                self.push_runtime_notice("marked finding as ignore candidate".to_string());
                Ok(false)
            }
            TriageAction::ClearReviewState => {
                let key = fingerprint_finding_at_root(finding, &self.identity_root);
                self.update_review_mark(&key, None);
                self.push_runtime_notice("cleared review state".to_string());
                Ok(false)
            }
        }
    }

    pub(super) fn action_preview(&self, action: TriageAction) -> Vec<Line<'static>> {
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
                preview_line("review state", "mark as reviewed"),
                Line::from("saved per project and scan mode; repository unchanged"),
            ],
            TriageAction::MarkTodo => vec![
                preview_line("review state", "mark as todo"),
                Line::from("saved per project and scan mode; repository unchanged"),
            ],
            TriageAction::MarkIgnoreCandidate => vec![
                preview_line("review state", "mark as ignore candidate"),
                Line::from("saved per project and scan mode; repository unchanged"),
            ],
            TriageAction::ClearReviewState => vec![
                preview_line("review state", "clear review mark"),
                Line::from("saved per project and scan mode; repository unchanged"),
            ],
        }
    }
}
