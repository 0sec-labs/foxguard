use super::state::{
    BaselineFilter, LaunchMode, SortMode, SourceContextCache, SourceContextCacheKey, TuiApp,
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
        frame.render_widget(
            Block::default().style(Style::default().bg(APP_BG).fg(TEXT_PRIMARY)),
            frame.area(),
        );
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
                Constraint::Length(
                    if frame.area().height >= 16
                        && self
                            .result
                            .as_ref()
                            .and_then(|result| result.baseline_comparison.as_ref())
                            .is_some()
                    {
                        4
                    } else {
                        3
                    },
                ),
                Constraint::Length(if frame.area().height >= 20 { 1 } else { 0 }),
                Constraint::Min(1),
                Constraint::Length(if self.search_mode { 2 } else { 1 }),
            ])
            .split(frame.area());

        self.draw_header(frame, layout[0]);
        frame.render_widget(
            Block::default().style(Style::default().bg(HEADER_BG)),
            layout[1],
        );

        if self.scanning {
            super::loading::draw_loading(self, frame, layout[2]);
        } else if let Some(error) = self.error.as_ref() {
            let notice_height =
                if self.show_notices && self.notice_count() > 0 && layout[2].height >= 7 {
                    layout[2].height.saturating_sub(4).min(5)
                } else {
                    0
                };
            let parts = Layout::vertical([Constraint::Min(1), Constraint::Length(notice_height)])
                .split(layout[2]);
            self.list_area = Rect::default();
            self.detail_area = parts[0];
            render_scrollable_panel(
                frame,
                parts[0],
                Paragraph::new(error.as_str()).style(Style::default().fg(ERROR_TEXT)),
                panel_block(Some("Scan Error - PgUp/Dn scroll"), PANEL_BG),
                &mut self.detail_scroll,
            );
            if notice_height > 0 {
                render_scrollable_panel(
                    frame,
                    parts[1],
                    Paragraph::new(self.notice_text()),
                    panel_block(Some("Notices - [/] scroll"), NOTICE_BG),
                    &mut self.notices_scroll,
                );
            }
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
        self.draw_review_modals(frame);
    }

    pub(super) fn draw_launch(&self, frame: &mut ratatui::Frame) {
        frame.render_widget(
            Block::default().style(Style::default().bg(APP_BG)),
            frame.area(),
        );
        let page = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(1)])
            .split(frame.area());
        let width = page[0].width.saturating_sub(4).min(88);
        let compact = page[0].height < 18;
        let logo_height = if page[0].height >= 26 && width >= 44 {
            5
        } else {
            0
        };
        let heading_height = if logo_height > 0 { 1 } else { 2 };
        let path_height = if compact { 1 } else { 2 };
        let card_height = if compact { 1 } else { 2 };
        let target_height = if compact { 1 } else { 2 };
        let height = (logo_height + heading_height + path_height + card_height * 4 + target_height)
            .min(page[0].height);
        let area = Rect::new(
            page[0].x + (page[0].width - width) / 2,
            page[0].y + (page[0].height - height) / 2,
            width,
            height,
        );
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(logo_height),
                Constraint::Length(heading_height),
                Constraint::Length(path_height),
                Constraint::Length(card_height * 4),
                Constraint::Length(target_height),
            ])
            .split(area);
        if logo_height > 0 {
            let logo = [
                "   ___                               __",
                "  / _/__ __ _____ ___ _____ ________/ /",
                r" / _/ _ \\ \ / _ `/ // / _ `/ __/ _  / ",
                r"/_/ \___/_\_\\_, /\_,_/\_,_/_/  \_,_/  ",
                "            /___/                      ",
            ];
            frame.render_widget(
                Paragraph::new(Text::from(
                    logo.into_iter().map(Line::from).collect::<Vec<_>>(),
                ))
                .alignment(Alignment::Center)
                .style(Style::default().fg(LOGO_PRIMARY)),
                layout[0],
            );
        }
        frame.render_widget(
            Paragraph::new(if logo_height > 0 {
                "Choose a scan mode"
            } else {
                "foxguard\nChoose a scan mode"
            })
            .alignment(Alignment::Center)
            .style(
                Style::default()
                    .fg(LOGO_PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
            layout[1],
        );
        let path = short_path(&self.request.path);
        let available = width.saturating_sub(6) as usize;
        let path = if unicode_width::UnicodeWidthStr::width(path.as_str()) > available {
            let mut remaining = available.saturating_sub(1);
            let mut start = path.len();
            for (offset, grapheme) in
                unicode_segmentation::UnicodeSegmentation::grapheme_indices(path.as_str(), true)
                    .rev()
            {
                let cells = unicode_width::UnicodeWidthStr::width(grapheme);
                if cells > remaining {
                    break;
                }
                remaining -= cells;
                start = offset;
            }
            format!("…{}", &path[start..])
        } else {
            path
        };
        frame.render_widget(
            Paragraph::new(format!("Path: {path}")).style(Style::default().fg(TEXT_MUTED)),
            layout[2],
        );
        let cards = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(card_height); 4])
            .split(layout[3]);
        for (index, mode) in [
            LaunchMode::Scan,
            LaunchMode::Diff,
            LaunchMode::Secrets,
            LaunchMode::Pqc,
        ]
        .into_iter()
        .enumerate()
        {
            self.draw_launch_card(frame, cards[index], mode, width < 50);
        }
        let target = if self.launch_mode == LaunchMode::Diff {
            format!("Target: {}_", self.launch_diff_target)
        } else {
            "1–4 select a mode · Enter starts".to_string()
        };
        frame.render_widget(
            Paragraph::new(target)
                .style(Style::default().fg(LOGO_PRIMARY))
                .wrap(Wrap { trim: false }),
            layout[4],
        );
        self.draw_launch_footer(frame, page[1]);
    }

    pub(super) fn draw_launch_card(
        &self,
        frame: &mut ratatui::Frame,
        area: Rect,
        mode: LaunchMode,
        compact: bool,
    ) {
        let selected = self.launch_mode == mode;
        let (title, subtitle, shortcut) = match mode {
            LaunchMode::Scan => ("Scan", "full repository scan", "1"),
            LaunchMode::Diff => ("Diff", "new issues vs target branch", "2"),
            LaunchMode::Secrets => ("Secrets", "credentials and token leaks", "3"),
            LaunchMode::Pqc => ("PQC", "post-quantum crypto audit", "4"),
        };
        let background = if selected { DETAIL_BG } else { LAUNCH_CARD_BG };
        let title_style = Style::default()
            .fg(if selected { LOGO_PRIMARY } else { TEXT_PRIMARY })
            .add_modifier(Modifier::BOLD);
        let subtitle_style = Style::default().fg(TEXT_MUTED);
        let block = Block::default()
            .style(Style::default().bg(background))
            .padding(Padding::new(2, 2, 0, 0));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if selected {
            frame.render_widget(
                Block::default().style(Style::default().bg(LOGO_PRIMARY)),
                Rect {
                    x: area.x,
                    y: area.y,
                    width: 1,
                    height: area.height,
                },
            );
        }
        let subtitle_text = if compact { "" } else { subtitle };
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    shortcut.to_string(),
                    Style::default()
                        .fg(if selected { LOGO_PRIMARY } else { TEXT_MUTED })
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("{}{}", if selected { "> " } else { "  " }, title),
                    title_style,
                ),
                if !compact {
                    Span::raw("   ")
                } else {
                    Span::raw("")
                },
                Span::styled(subtitle_text, subtitle_style),
            ]))
            .style(Style::default().bg(background))
            .wrap(Wrap { trim: true }),
            inner,
        );
    }

    pub(super) fn draw_header(&self, frame: &mut ratatui::Frame, area: Rect) {
        let mut filters = Vec::new();
        if !self.search_query.is_empty() {
            filters.push(format!("/{}", self.search_query));
        }
        if self.baseline_filter != BaselineFilter::Resolved {
            if let Some(severity) = self.min_severity {
                filters.push(format!(">= {}", severity_name(severity)));
            }
            if self.session_min_confidence > 0.0 {
                filters.push(format!(
                    "confidence >= {:.0}%",
                    self.session_min_confidence * 100.0
                ));
            }
            if let Some(review) = self.review_filter_label() {
                filters.push(review.to_string());
            }
            if self.sort_mode != SortMode::default() {
                filters.push(format!("sort {}", self.sort_mode.label()));
            }
        }
        let comparison = self
            .result
            .as_ref()
            .and_then(|result| result.baseline_comparison.as_ref());
        let mut summary = vec![Span::styled(
            "foxguard",
            Style::default()
                .fg(LOGO_PRIMARY)
                .add_modifier(Modifier::BOLD),
        )];
        if self.session_dirty {
            summary.push(Span::styled(
                " UNSAVED",
                Style::default()
                    .fg(LOGO_PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ));
        } else if self.session_error.is_some() {
            summary.push(Span::styled(
                " state error",
                Style::default().fg(ERROR_TEXT),
            ));
        }
        summary.push(Span::raw(format!(
            " {} ",
            request_mode_label(&self.request)
        )));
        if comparison.is_some() && area.height < 4 && !filters.is_empty() {
            summary.push(Span::raw(filters.join(" | ")));
        } else {
            summary.push(Span::raw(short_path(&self.request.path)));
            if let Some(result) = &self.result {
                summary.push(Span::styled(
                    format!(
                        "  {} findings  {} files  {:.2}s",
                        result.findings.len(),
                        result.files_scanned,
                        result.duration.as_secs_f64()
                    ),
                    Style::default().fg(TEXT_MUTED),
                ));
                if let Some(diff) = &result.diff_summary {
                    append_diff_summary(&mut summary, diff);
                }
            }
        }
        let mut lines = vec![Line::from(summary)];
        if let Some(comparison) = comparison {
            let counts = if area.width < 76 {
                format!(
                    "b {} | +{} ={} -{}",
                    self.baseline_filter.label(),
                    comparison.introduced.len(),
                    comparison.recurring.len(),
                    comparison.resolved.len()
                )
            } else {
                format!(
                    "b {} | introduced {} | recurring {} | resolved {}",
                    self.baseline_filter.label(),
                    comparison.introduced.len(),
                    comparison.recurring.len(),
                    comparison.resolved.len()
                )
            };
            lines.push(Line::from(Span::styled(
                counts,
                Style::default().fg(LOGO_PRIMARY),
            )));
        }
        if comparison.is_none() || area.height >= 4 {
            if !filters.is_empty() {
                lines.push(Line::from(filters.join(" | ")));
            } else if self.baseline_filter == BaselineFilter::Resolved {
                lines.push(Line::from("Historical metadata; only search applies"));
            } else if let Some(result) = &self.result {
                let mut badges = severity_badge_spans(&severity_counts(&result.findings));
                if self.baseline_filter != BaselineFilter::All {
                    badges.insert(0, Span::raw("Current scan: "));
                }
                lines.push(Line::from(badges));
            }
        }
        frame.render_widget(
            Paragraph::new(Text::from(lines))
                .block(panel_block(None, HEADER_BG))
                .style(Style::default().fg(TEXT_PRIMARY)),
            area,
        );
    }

    pub(super) fn draw_body(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        let show_notices = self.show_notices && self.notice_count() > 0 && area.height >= 6;
        let show_compliance =
            self.show_compliance_panel && self.result.is_some() && self.request.pq_mode;

        let mut body_constraints: Vec<Constraint> = vec![Constraint::Min(1)];
        if show_notices {
            body_constraints.push(Constraint::Length(
                (self.notice_count().saturating_add(2).min(5) as u16)
                    .min(area.height / 3)
                    .max(3),
            ));
        }
        if show_compliance {
            body_constraints.push(Constraint::Length(4));
        }
        let body_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints(body_constraints)
            .split(area);

        if self.baseline_filter == BaselineFilter::Resolved {
            self.draw_resolved(frame, body_layout[0]);
        } else {
            let (findings_area, detail_area) = if self.show_detail_view {
                (None, Some(body_layout[0]))
            } else if body_layout[0].width >= 100 {
                let constraints = [Constraint::Percentage(42), Constraint::Percentage(58)];
                let layout = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints(constraints)
                    .split(body_layout[0]);
                (Some(layout[0]), Some(layout[1]))
            } else {
                (Some(body_layout[0]), None)
            };

            self.list_area = Rect::default();
            self.detail_area = detail_area.unwrap_or_default();
            if let Some(findings_area) = findings_area {
                let filtered = self.filtered_indices();
                let hover = self.hover_index;
                let items = if let Some(result) = self.result.as_ref() {
                    filtered
                        .iter()
                        .enumerate()
                        .map(|(display_index, index)| {
                            let finding = &result.findings[*index];
                            let mut item = list_item(
                                finding,
                                self.review_state_at(*index),
                                self.checked_findings.contains(index),
                            );
                            if hover == Some(display_index) && self.selected != display_index {
                                item = item.style(Style::default().bg(PANEL_BG));
                            }
                            item
                        })
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };

                let filtered_len = filtered.len();
                let list_title = self
                    .result
                    .as_ref()
                    .map(|result| {
                        let review = self.review_filter_label().unwrap_or("all");
                        if !self.checked_findings.is_empty() {
                            format!(
                                "{} {filtered_len}/{} | {} selected",
                                self.baseline_filter.label(),
                                result.findings.len(),
                                self.checked_findings.len()
                            )
                        } else if result.baseline_comparison.is_some() {
                            format!(
                                "{} {filtered_len}/{} | {review} | {} reviewed",
                                self.baseline_filter.label(),
                                result.findings.len(),
                                self.reviewed_count
                            )
                        } else if findings_area.width < 64 {
                            format!(
                                "{filtered_len}/{} {review} · {} reviewed",
                                result.findings.len(),
                                self.reviewed_count
                            )
                        } else {
                            format!(
                                "{} {filtered_len}/{} · {review} · {} reviewed",
                                mode_findings_title(&result.mode),
                                result.findings.len(),
                                self.reviewed_count
                            )
                        }
                    })
                    .unwrap_or_else(|| "findings".to_string());

                if items.is_empty() && self.result.is_some() {
                    // Empty state with recovery hints
                    let empty_text = if self.has_active_filter() {
                        Text::from(vec![
                            Line::from(Span::styled(
                                "No findings match the current filters.",
                                Style::default().fg(Color::Gray),
                            )),
                            Line::from(""),
                            Line::from(Span::styled(
                                "Esc  clear all filters",
                                Style::default().fg(LOGO_PRIMARY),
                            )),
                            Line::from(Span::styled(
                                "/    adjust search",
                                Style::default().fg(LOGO_PRIMARY),
                            )),
                            Line::from(Span::styled(
                                "0-4  adjust severity",
                                Style::default().fg(LOGO_PRIMARY),
                            )),
                        ])
                    } else {
                        Text::from(vec![
                            Line::from(Span::styled(
                                "No findings were detected.",
                                Style::default().fg(Color::Gray),
                            )),
                            Line::from(""),
                            Line::from(Span::styled(
                                "r  rescan",
                                Style::default().fg(LOGO_PRIMARY),
                            )),
                            Line::from(Span::styled("q  quit", Style::default().fg(LOGO_PRIMARY))),
                        ])
                    };

                    let empty_block = panel_block(Some(&list_title), LIST_BG);
                    frame.render_widget(
                        Paragraph::new(empty_text)
                            .block(empty_block)
                            .wrap(Wrap { trim: false }),
                        findings_area,
                    );
                } else {
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

                    if filtered_len > 0 {
                        self.list_state.select(Some(self.selected));
                    } else {
                        self.list_state.select(None);
                    }
                    self.list_area = findings_area;
                    frame.render_stateful_widget(list, findings_area, &mut self.list_state);
                }
            }

            if let Some(detail_area) = detail_area {
                let title = if self.show_detail_view {
                    "Detail · PgUp/PgDn scroll · Esc back"
                } else {
                    "Detail · v expand · PgUp/PgDn scroll"
                };
                render_scrollable_panel(
                    frame,
                    detail_area,
                    Paragraph::new(self.detail_text()),
                    panel_block(Some(title), DETAIL_BG),
                    &mut self.detail_scroll,
                );
            }
        }

        let mut next_slot: usize = 1;
        if show_notices {
            render_scrollable_panel(
                frame,
                body_layout[next_slot],
                Paragraph::new(self.notice_text()),
                panel_block(Some("Notices - [/] scroll"), NOTICE_BG),
                &mut self.notices_scroll,
            );
            next_slot += 1;
        }
        if show_compliance {
            let paragraph = Paragraph::new(self.compliance_panel_text())
                .block(panel_block(Some("CNSA 2.0"), PANEL_BG))
                .wrap(Wrap { trim: false });
            frame.render_widget(paragraph, body_layout[next_slot]);
        }
    }

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

    /// Keep every actionable section available through scrolling at every size.
    pub(super) fn detail_text(&self) -> Text<'static> {
        let Some(finding) = self.selected_finding() else {
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
        if let Some(review) = self.review_summary_for_finding(finding) {
            lines.push(metadata_line("Review", &review));
        }

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

        if let Some(context_lines) = self.source_context_lines(finding) {
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
        lines.extend(open_target_lines(finding, self.open_focus));

        if finding_has_dataflow(finding) {
            lines.push(Line::from(""));
            lines.push(section_heading("Dataflow", Color::Cyan));
            lines.extend(dataflow_lines(finding, self.open_focus));
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

    pub(super) fn draw_footer(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        if self.scanning {
            frame.render_widget(
                Paragraph::new("Ctrl+C quit  ? help")
                    .style(Style::default().bg(FOOTER_BG).fg(TEXT_MUTED)),
                area,
            );
            return;
        }
        if self.error.is_some() {
            frame.render_widget(
                Paragraph::new("PgUp/Dn error  [/] notices  r retry  q")
                    .style(Style::default().bg(FOOTER_BG).fg(TEXT_PRIMARY)),
                area,
            );
            return;
        }
        if self.search_mode {
            let query = Line::from(format!("/{}", self.search_query));
            let width = query.width();
            let scroll = width.saturating_sub(area.width.saturating_sub(1) as usize);
            frame.render_widget(
                Paragraph::new(query)
                    .scroll((0, scroll.min(u16::MAX as usize) as u16))
                    .style(Style::default().bg(FOOTER_BG).fg(Color::Cyan)),
                Rect::new(area.x, area.y, area.width, 1),
            );
            frame.set_cursor_position((
                area.x + width.min(area.width.saturating_sub(1) as usize) as u16,
                area.y,
            ));
            frame.render_widget(
                Paragraph::new("Enter apply  Esc cancel  Ctrl+U clear")
                    .style(Style::default().bg(FOOTER_BG).fg(Color::Gray)),
                Rect::new(
                    area.x,
                    area.y.saturating_add(1),
                    area.width,
                    area.height.saturating_sub(1),
                ),
            );
            return;
        }
        if self.baseline_filter == BaselineFilter::Resolved {
            frame.render_widget(
                Paragraph::new("b category  / find  v detail  ? help  q")
                    .style(Style::default().bg(FOOTER_BG).fg(TEXT_PRIMARY)),
                area,
            );
            return;
        }
        let is_narrow = area.width < 80;

        let mut shortcuts = vec![
            ("/", "find"),
            ("Space", "select"),
            ("x", "batch"),
            ("F", "views"),
        ];
        if area.width >= 64 {
            shortcuts.extend([("v", "detail"), ("a", "all")]);
            if self
                .result
                .as_ref()
                .and_then(|result| result.baseline_comparison.as_ref())
                .is_some()
            {
                shortcuts.push(("b", "base"));
            }
        }
        if area.width >= 104 {
            shortcuts.extend([("i", "triage"), ("f", "review"), ("e", "export")]);
        }
        if area.width >= 150 {
            shortcuts.extend([("c", "confidence"), ("C", "sort"), ("w", "notices")]);
        }
        shortcuts.extend([("?", ""), ("q", "")]);
        let mut key_spans = Vec::new();
        for (index, (key, description)) in shortcuts.into_iter().enumerate() {
            if index > 0 {
                key_spans.push(Span::raw(" "));
            }
            key_spans.push(footer_key_span(key));
            if !description.is_empty() {
                key_spans.push(Span::raw(format!(" {description}")));
            }
        }

        let mut right_spans: Vec<Span<'static>> = Vec::new();

        // Right-side status indicators — compress on narrow
        if self.session_min_confidence > 0.0 {
            let filtered_len = self.filtered_indices().len();
            let total = self.total_after_severity_and_search();
            if is_narrow {
                right_spans.push(footer_value_span(&format!(
                    "c{:.0} {}/{}",
                    self.session_min_confidence * 100.0,
                    filtered_len,
                    total
                )));
            } else {
                right_spans.push(footer_label_span("conf"));
                right_spans.push(Span::raw(" "));
                right_spans.push(footer_value_span(&format!(
                    "≥ {:.2} ({}/{})",
                    self.session_min_confidence, filtered_len, total
                )));
            }
            right_spans.push(Span::raw("  "));
        }

        if self.sort_mode != SortMode::default() {
            if is_narrow {
                right_spans.push(footer_value_span(self.sort_mode.label()));
            } else {
                right_spans.push(footer_label_span("sort"));
                right_spans.push(Span::raw(" "));
                right_spans.push(footer_value_span(self.sort_mode.label()));
            }
            right_spans.push(Span::raw("  "));
        }

        // Review filter status
        if let Some(rf) = self.review_filter_label() {
            if is_narrow {
                right_spans.push(footer_value_span(rf));
            } else {
                right_spans.push(footer_label_span("review"));
                right_spans.push(Span::raw(" "));
                right_spans.push(footer_value_span(rf));
            }
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
            if is_narrow {
                right_spans.push(footer_value_span(&search_text));
            } else {
                right_spans.push(footer_label_span("search"));
                right_spans.push(Span::raw(" "));
                right_spans.push(footer_value_span(&search_text));
            }
        }

        let right_line = if right_spans.is_empty() {
            Line::from("")
        } else {
            Line::from(right_spans)
        };
        draw_status_bar(frame, area, Line::from(key_spans), right_line);
    }

    pub(super) fn draw_launch_footer(&self, frame: &mut ratatui::Frame, area: Rect) {
        let navigation = if self.launch_mode == LaunchMode::Diff {
            "↑↓"
        } else {
            "j/k"
        };
        let mut hints = Vec::new();
        if area.width >= 50 {
            hints.extend([
                footer_key_span(navigation),
                Span::raw(" "),
                footer_key_span("Tab"),
                Span::raw("  "),
            ]);
        }
        hints.extend([
            footer_key_span("Enter"),
            Span::raw(" start  "),
            footer_key_span("?"),
            Span::raw(" help  "),
            footer_key_span("Esc"),
            Span::raw(" quit"),
        ]);
        let left = Line::from(hints);
        draw_status_bar(frame, area, left, Line::from(""));
    }

    pub(super) fn draw_help(&mut self, frame: &mut ratatui::Frame) {
        let bounds = frame.area();
        let width = bounds.width.saturating_sub(2).min(88);
        let height = bounds.height.saturating_sub(2).min(36);
        let area = Rect::new(
            bounds.x + (bounds.width - width) / 2,
            bounds.y + (bounds.height - height) / 2,
            width,
            height,
        );
        frame.render_widget(Clear, area);
        let inner_width = width.saturating_sub(2).max(1) as usize;
        let visible_rows = height.saturating_sub(2) as usize;

        let shortcuts: &[&str] = if self.show_launch && self.launch_mode == LaunchMode::Diff {
            &[
                "Arrows/Tab     Select scan mode",
                "Type           Edit target branch",
                "Backspace      Delete target character",
                "Enter          Launch diff scan",
                "Esc or Ctrl+C  Quit",
            ]
        } else if self.show_launch {
            &[
                "j/k or arrows  Select scan mode",
                "Tab            Cycle scan mode",
                "1-4            Jump to a mode",
                "Enter          Launch scan",
                "Diff mode: type the target branch",
                "Backspace      Edit diff target",
                "q or Esc       Quit",
                "Ctrl+C         Quit from any view",
            ]
        } else {
            &[
                "j/k or arrows  Move between findings",
                "Home/End       First/last finding",
                "/              Search findings",
                "Esc            Cancel search / back / clear filters",
                "Enter          Confirm search filter",
                "Ctrl+U         Clear search text",
                "0-4            Minimum severity",
                "c              Confidence filter",
                "Shift+C        Cycle sort order",
                "Tab            Finding/source/sink",
                "Space          Toggle finding selection",
                "a              Select / clear visible findings",
                "x              Batch actions for ALL selections",
                "Enter previews; y confirms; Esc cancels without writes.",
                "Hidden selections are included and counted in previews.",
                "Rule-wide changes can affect unselected findings.",
                "Successful batch writes are not rolled back on failure.",
                "Shift+F        Saved filters and review-state controls",
                "In saved filters: s save, Enter load, d delete, w retry",
                "r reload discards unsaved changes; R backs up and resets.",
                "b              All > Introduced > Recurring > Resolved",
                "Baseline counts: + introduced, = recurring, - resolved.",
                "Resolved means absent from this scan, not verified fixed.",
                "Historical rows are read-only; only search applies.",
                "v expands historical metadata; PgUp/Down scrolls it.",
                "i              Triage selected finding",
                "v              Toggle detail/list view",
                "Enter or o     Open in your editor",
                "Editor choice  VISUAL, EDITOR, then nvim/vim/nano/vi",
                "w              Toggle notices",
                "Shift+N        CNSA 2.0 panel",
                "e              Export CBOM/JSON/SARIF",
                "f              All > Unreviewed > Todo > Reviewed > Ignore",
                "Review marks persist per project and mode; reviewed is done.",
                "Existing exports require y to replace; Esc cancels.",
                "PageUp/Down    Page list / scroll visible detail",
                "[/]            Scroll notices",
                "Mouse wheel    Move findings / scroll expanded detail",
                "Mouse click    Select a finding",
                "Shift-drag     Select terminal text",
                "r              Rescan",
                "q              Quit",
                "Ctrl+C         Quit from any view",
            ]
        };

        let lines: Vec<Line<'_>> = shortcuts
            .iter()
            .flat_map(|text| {
                text.as_bytes().chunks(inner_width).map(|chunk| {
                    Line::from(std::str::from_utf8(chunk).expect("help shortcuts are ASCII"))
                })
            })
            .collect();
        let max_scroll = lines
            .len()
            .saturating_sub(visible_rows)
            .min(u16::MAX as usize) as u16;
        self.help_scroll = self.help_scroll.min(max_scroll);
        let title = format!("Help {}/{}", usize::from(self.help_scroll) + 1, lines.len());
        let block = Block::default()
            .title(title)
            .title_bottom("Esc/? close | j/k PgUp/Dn scroll")
            .borders(Borders::ALL)
            .style(Style::default().bg(PANEL_BG).fg(TEXT_PRIMARY));
        frame.render_widget(
            Paragraph::new(lines)
                .block(block)
                .scroll((self.help_scroll, 0)),
            area,
        );
    }

    pub(super) fn draw_action_menu(&self, frame: &mut ratatui::Frame) {
        let Some(menu) = self.action_menu.as_ref() else {
            return;
        };

        let bounds = frame.area();
        let width = bounds.width.saturating_sub(2).min(88);
        let height = bounds.height.saturating_sub(2).min(26);
        let area = Rect::new(
            bounds.x + (bounds.width - width) / 2,
            bounds.y + (bounds.height - height) / 2,
            width,
            height,
        );
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
                Constraint::Length(if height >= 14 { 2 } else { 1 }),
                Constraint::Min(2),
                Constraint::Length(if height >= 18 { 4 } else { 2 }),
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

        let size = frame.area();
        let width = size.width.saturating_sub(2).min(58);
        let height = size.height.saturating_sub(2).min(10);
        let area = Rect::new(
            size.x + (size.width - width) / 2,
            size.y + (size.height - height) / 2,
            width,
            height,
        );
        if let Some(path) = menu.overwrite.as_ref() {
            frame.render_widget(Clear, area);
            frame.render_widget(
                Paragraph::new(Text::from(vec![
                    Line::from("Replace the existing report?"),
                    Line::from(path.display().to_string()),
                    Line::from(""),
                    Line::from("y replace   n / Esc cancel"),
                ]))
                .block(
                    Block::default()
                        .title("Confirm overwrite")
                        .borders(Borders::ALL),
                )
                .style(Style::default().bg(PANEL_BG).fg(Color::Yellow))
                .wrap(Wrap { trim: false }),
                area,
            );
            return;
        }
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
                format!(
                    "Export all {} findings",
                    self.result
                        .as_ref()
                        .map_or(0, |result| result.findings.len())
                ),
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
