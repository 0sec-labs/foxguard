use super::state::TuiApp;
use super::widgets::{panel_block, DETAIL_BG, LIST_BG, LOGO_PRIMARY, TEXT_MUTED, TEXT_PRIMARY};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Text};
use ratatui::widgets::{List, ListItem, Paragraph, Wrap};

impl TuiApp {
    pub(super) fn draw_resolved(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        self.list_area = Rect::default();
        self.detail_area = Rect::default();
        let Some(comparison) = self
            .result
            .as_ref()
            .and_then(|result| result.baseline_comparison.as_ref())
        else {
            frame.render_widget(Paragraph::new("No baseline comparison is available. Use --baseline <file> or configure a baseline.").wrap(Wrap { trim: false }), area);
            return;
        };
        let vertical = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).split(area);
        frame.render_widget(
            Paragraph::new("Absent now; not verified fixed")
                .style(Style::default().fg(LOGO_PRIMARY)),
            vertical[0],
        );
        let content = vertical[1];
        let (list_area, detail_area) = if self.show_detail_view {
            (None, Some(content))
        } else if content.width >= 100 {
            let split =
                Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)])
                    .split(content);
            (Some(split[0]), Some(split[1]))
        } else {
            (Some(content), None)
        };
        if let Some(list_area) = list_area {
            self.list_area = list_area;
            self.list_state
                .select((!self.cached_resolved.is_empty()).then_some(self.selected));
            let title = format!(
                "Resolved {}/{} - read only",
                self.cached_resolved.len(),
                comparison.resolved.len()
            );
            let block = panel_block(Some(&title), LIST_BG);
            if self.cached_resolved.is_empty() {
                let message = if comparison.resolved.is_empty() {
                    "No baseline entries are absent from this scan."
                } else {
                    "No historical entries match the search. / edits search; Esc clears filters."
                };
                frame.render_widget(
                    Paragraph::new(message)
                        .block(block)
                        .wrap(Wrap { trim: false })
                        .style(Style::default().fg(TEXT_MUTED)),
                    list_area,
                );
            } else {
                let items: Vec<_> = self
                    .cached_resolved
                    .iter()
                    .map(|&index| {
                        let entry = &comparison.resolved[index];
                        ListItem::new(vec![
                            Line::from(entry.rule_id.as_str()),
                            Line::from(format!("{}:{}", entry.file, entry.line)),
                        ])
                    })
                    .collect();
                frame.render_stateful_widget(
                    List::new(items)
                        .block(block)
                        .style(Style::default().fg(TEXT_PRIMARY))
                        .highlight_style(
                            Style::default()
                                .fg(LOGO_PRIMARY)
                                .bg(DETAIL_BG)
                                .add_modifier(Modifier::BOLD),
                        )
                        .highlight_symbol(">> ")
                        .scroll_padding(0),
                    list_area,
                    &mut self.list_state,
                );
            }
        }
        if let Some(detail_area) = detail_area {
            self.detail_area = detail_area;
            let entry = self
                .cached_resolved
                .get(self.selected)
                .and_then(|&index| comparison.resolved.get(index));
            let text = if let Some(entry) = entry {
                Text::from(vec![
                    Line::from(entry.rule_id.as_str()),
                    Line::from(format!("File: {}", entry.file)),
                    Line::from(format!("Line: {}", entry.line)),
                    Line::from(format!("Fingerprint: {}", entry.fingerprint)),
                    Line::from(""),
                    Line::from("Not reported in the current scan. Changed scope, rules or thresholds can produce this absence; it does not verify remediation."),
                    Line::from(""),
                    Line::from("Historical metadata only: there is no saved severity, confidence, source code or dataflow. Only search applies to this category."),
                ])
            } else {
                Text::from("Select a historical entry.")
            };
            super::widgets::render_scrollable_panel(
                frame,
                detail_area,
                Paragraph::new(text).style(Style::default().fg(TEXT_PRIMARY)),
                panel_block(Some("Historical detail - v / PgUp/Dn"), DETAIL_BG),
                &mut self.detail_scroll,
            );
        }
    }
}
