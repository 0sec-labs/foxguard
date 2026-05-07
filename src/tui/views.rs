use super::state::{
    LaunchMode, SortMode, SourceContextCache, SourceContextCacheKey, TuiApp,
    SEVERITY_PICKER_CHOICES,
};
use super::widgets::*;
use crate::Finding;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap,
};

impl TuiApp {
    pub(super) fn draw(&mut self, frame: &mut ratatui::Frame) {
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

        if self.export_menu.is_some() {
            self.draw_export_menu(frame);
        }

        if self.severity_picker.is_some() {
            self.draw_severity_picker(frame);
        }
    }

    pub(super) fn draw_loading(&self, frame: &mut ratatui::Frame, area: Rect) {
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

    pub(super) fn draw_launch(&self, frame: &mut ratatui::Frame) {
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

    pub(super) fn draw_launch_card(
        &self,
        frame: &mut ratatui::Frame,
        area: Rect,
        mode: LaunchMode,
    ) {
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

    pub(super) fn draw_header(&self, frame: &mut ratatui::Frame, area: Rect) {
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

    pub(super) fn draw_body(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        // Vertical slot plan for the scan body:
        //   [0] findings + detail (main content, always present)
        //   [1] notices panel (optional)
        //   [2] CNSA 2.0 compliance strip (optional, 4 rows)
        // The compliance strip sits *below* notices so notices never shrink
        // when it is toggled on.
        let show_notices = self.show_notices && self.notice_count() > 0;
        let show_compliance =
            self.show_compliance_panel && self.result.is_some() && self.request.pq_mode;

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
        let hover = self.hover_index;
        let items = if let Some(result) = self.result.as_ref() {
            filtered
                .iter()
                .enumerate()
                .map(|(display_index, index)| {
                    let finding = &result.findings[*index];
                    let mut item = list_item(finding, self.review_state_for(finding));
                    if hover == Some(display_index) && self.selected != display_index {
                        item = item.style(Style::default().bg(Color::Rgb(40, 40, 50)));
                    }
                    item
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
            .highlight_symbol(">> ")
            .scroll_padding(0);

        if !filtered.is_empty() {
            self.list_state.select(Some(self.selected));
        } else {
            self.list_state.select(None);
        }
        self.list_area = layout[0];
        frame.render_stateful_widget(list, layout[0], &mut self.list_state);

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
    pub(super) fn compliance_panel_text(&self) -> Text<'static> {
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

    pub(super) fn detail_text(&mut self) -> Text<'static> {
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

    pub(super) fn source_context_lines(&self, finding: &Finding) -> Option<Vec<Line<'static>>> {
        if self.request.secrets {
            return None;
        }

        let key = SourceContextCacheKey::from_finding(&self.request.path, finding);

        match self.source_context_cache.as_ref() {
            Some(SourceContextCache::Ready {
                key: cached_key,
                lines,
            }) if *cached_key == key => Some(lines.clone()),
            Some(SourceContextCache::Loading { key: cached_key }) if *cached_key == key => None,
            _ => None,
        }
    }

    pub(super) fn draw_footer(&self, frame: &mut ratatui::Frame, area: Rect) {
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

    pub(super) fn draw_launch_footer(&self, frame: &mut ratatui::Frame, area: Rect) {
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

    pub(super) fn draw_help(&self, frame: &mut ratatui::Frame) {
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
            Line::from("e              export findings (CBOM / JSON / SARIF)"),
            Line::from("PageUp/Down    scroll detail pane"),
            Line::from("[/]            scroll notices pane"),
            Line::from("mouse wheel    move between findings"),
            Line::from("mouse click    select a finding"),
            Line::from("Shift-drag     terminal-native text selection"),
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

    pub(super) fn draw_action_menu(&self, frame: &mut ratatui::Frame) {
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

    pub(super) fn draw_export_menu(&self, frame: &mut ratatui::Frame) {
        let Some(menu) = self.export_menu.as_ref() else {
            return;
        };

        let area = centered_rect(40, 40, frame.area());
        let items = menu
            .formats
            .iter()
            .map(|fmt| ListItem::new(Line::from(Span::styled(fmt.label(), Style::default()))))
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
                Constraint::Length(1),
                Constraint::Length(menu.formats.len() as u16 + 2),
                Constraint::Length(1),
            ])
            .split(inner);

        frame.render_widget(Clear, area);
        frame.render_widget(
            Block::default()
                .title("export")
                .borders(Borders::ALL)
                .style(Style::default().bg(PANEL_BG)),
            area,
        );
        frame.render_widget(
            Paragraph::new(Span::styled(
                "export findings as",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(PANEL_BG)),
            layout[0],
        );

        let mut state = ListState::default();
        state.select(Some(menu.selected));
        frame.render_stateful_widget(list, layout[1], &mut state);
        frame.render_widget(
            Paragraph::new("Enter export  Esc cancel")
                .style(Style::default().bg(PANEL_BG).fg(Color::Gray))
                .alignment(Alignment::Left),
            layout[2],
        );
    }

    pub(super) fn draw_severity_picker(&self, frame: &mut ratatui::Frame) {
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
}
