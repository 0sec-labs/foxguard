use super::state::{
    ActionMenu, ExportFormat, ExportMenu, LaunchMode, OpenFocus, ReviewState, SeverityPicker,
    TriageAction, TuiApp, SEVERITY_PICKER_CHOICES,
};
use super::widgets::{
    display_path, drain_queued_scroll_events, finding_list_index_at_position, finding_review_key,
    preview_line,
};
use super::{open_command_spec, resolve_finding_path, OpenTarget, TerminalSession};
use crate::app::TuiMode;
use crate::baseline::append_finding_to_baseline;
use crate::config::{
    add_disabled_rule_to_config, add_scan_ignore_rule, add_secrets_ignored_rule,
    add_severity_override_to_config, current_severity_override, is_rule_disabled_in_config,
};
use crate::{Finding, Severity};
use crossterm::event::{self, KeyCode, KeyEvent, MouseEvent, MouseEventKind};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use std::path::Path;
use std::process::{Command, Stdio};

pub(super) enum ControlFlow {
    Continue,
    Rescan,
    OpenSelected,
    ApplyAction(TriageAction),
    Exit,
}

impl TuiApp {
    pub(super) fn handle_key(&mut self, key: KeyEvent) -> ControlFlow {
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

        if self.export_menu.is_some() {
            return self.handle_export_menu_key(key.code);
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
            KeyCode::Char('e') => self.open_export_menu(),
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
            _ => ControlFlow::Continue,
        }
    }

    pub(super) fn can_handle_finding_mouse(&self) -> bool {
        !self.show_launch
            && !self.show_help
            && self.severity_picker.is_none()
            && self.action_menu.is_none()
            && self.export_menu.is_none()
            && !self.search_mode
    }

    pub(super) fn handle_mouse(&mut self, mouse: MouseEvent) {
        match mouse.kind {
            kind @ (MouseEventKind::ScrollUp | MouseEventKind::ScrollDown) => {
                let last_kind = drain_queued_scroll_events(kind);
                match last_kind {
                    MouseEventKind::ScrollUp => self.move_selection(-1),
                    MouseEventKind::ScrollDown => self.move_selection(1),
                    _ => {}
                }
            }
            MouseEventKind::Down(event::MouseButton::Left) => {
                if let Some(index) = finding_list_index_at_position(
                    self.list_area,
                    self.list_state.offset(),
                    self.filtered_indices().len(),
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
                    self.filtered_indices().len(),
                    mouse.column,
                    mouse.row,
                );
            }
            _ => {}
        }
    }

    pub(super) fn handle_search_key(&mut self, key: KeyCode) -> ControlFlow {
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

    pub(super) fn handle_launch_key(&mut self, key: KeyCode) -> ControlFlow {
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
        });
        ControlFlow::Continue
    }

    pub(super) fn handle_export_menu_key(&mut self, key: KeyCode) -> ControlFlow {
        let Some(menu) = self.export_menu.as_mut() else {
            return ControlFlow::Continue;
        };

        match key {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.export_menu = None;
                ControlFlow::Continue
            }
            KeyCode::Char('j') | KeyCode::Down => {
                menu.selected = (menu.selected + 1).min(menu.formats.len().saturating_sub(1));
                ControlFlow::Continue
            }
            KeyCode::Char('k') | KeyCode::Up => {
                menu.selected = menu.selected.saturating_sub(1);
                ControlFlow::Continue
            }
            KeyCode::Enter => {
                let format = menu.formats[menu.selected];
                self.export_menu = None;
                self.export_findings(format);
                ControlFlow::Continue
            }
            _ => ControlFlow::Continue,
        }
    }

    pub(super) fn export_findings(&mut self, format: ExportFormat) {
        self.export_findings_to(format, format.filename().as_ref());
    }

    pub(super) fn export_findings_to(&mut self, format: ExportFormat, path: &std::path::Path) {
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

        match std::fs::write(path, &content) {
            Ok(()) => {
                self.push_runtime_notice(format!(
                    "exported {} findings to {}",
                    finding_count,
                    path.display()
                ));
            }
            Err(err) => {
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
}
