use super::state::{LaunchMode, OpenFocus, ReviewState, SeverityCounts, SortMode, TuiApp};
use crate::app::{DiffSummary, TuiMode};
use crate::cli::TuiArgs;
use crate::{Finding, Severity};
use crossterm::event::{self, Event, MouseEvent, MouseEventKind};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, ListItem, Padding, Paragraph, Wrap};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

pub(super) fn available_open_focuses(finding: &Finding) -> Vec<OpenFocus> {
    let mut focuses = vec![OpenFocus::Finding];
    if finding.source_line.is_some() || finding.source_description.is_some() {
        focuses.push(OpenFocus::Source);
    }
    if finding.sink_line.is_some() || finding.sink_description.is_some() {
        focuses.push(OpenFocus::Sink);
    }
    focuses
}

pub(super) fn finding_has_dataflow(finding: &Finding) -> bool {
    finding.source_line.is_some()
        || finding.source_description.is_some()
        || finding.sink_line.is_some()
        || finding.sink_description.is_some()
}

#[cfg(test)]
pub(super) fn truncate_text(text: &str, max_chars: usize) -> String {
    let mut chars = text.chars();
    let truncated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{}...", truncated)
    } else {
        truncated
    }
}

pub(super) fn adjust_scroll(current: u16, delta: i32) -> u16 {
    if delta.is_negative() {
        current.saturating_sub(delta.unsigned_abs() as u16)
    } else {
        current.saturating_add(delta as u16)
    }
}

pub(super) fn drain_queued_scroll_events(first_kind: MouseEventKind) -> MouseEventKind {
    let mut last_kind = first_kind;
    while event::poll(Duration::ZERO).unwrap_or(false) {
        match event::read() {
            Ok(Event::Mouse(MouseEvent {
                kind: kind @ (MouseEventKind::ScrollUp | MouseEventKind::ScrollDown),
                ..
            })) => last_kind = kind,
            Ok(event) => {
                stash_event(event);
                break;
            }
            _ => break,
        }
    }
    last_kind
}

static STASHED_EVENT: OnceLock<Mutex<Option<Event>>> = OnceLock::new();

fn stashed_event() -> &'static Mutex<Option<Event>> {
    STASHED_EVENT.get_or_init(|| Mutex::new(None))
}

pub(super) fn stash_event(event: Event) {
    let Ok(mut stashed) = stashed_event().lock() else {
        return;
    };
    if stashed.is_none() {
        *stashed = Some(event);
    }
}

pub(super) fn pop_stashed_event() -> Option<Event> {
    stashed_event().lock().ok()?.take()
}

pub(super) fn has_stashed_event() -> bool {
    stashed_event()
        .lock()
        .map(|stashed| stashed.is_some())
        .unwrap_or(false)
}

pub(super) fn pop_stashed_event_or_read() -> std::io::Result<Event> {
    if let Some(event) = pop_stashed_event() {
        return Ok(event);
    }

    event::read()
}

pub(super) fn finding_list_index_at_position(
    list_area: Rect,
    list_offset: usize,
    item_count: usize,
    column: u16,
    row: u16,
) -> Option<usize> {
    let content = finding_list_content_area(list_area);
    if column < content.x
        || column >= content.x.saturating_add(content.width)
        || row < content.y
        || row >= content.y.saturating_add(content.height)
    {
        return None;
    }

    let row_in_content = row.saturating_sub(content.y);
    let index = list_offset + usize::from(row_in_content / FINDING_LIST_ITEM_HEIGHT);
    (index < item_count).then_some(index)
}

pub(super) fn finding_list_content_area(area: Rect) -> Rect {
    Rect {
        x: area.x.saturating_add(1),
        y: area.y.saturating_add(2),
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(2),
    }
}

pub(super) fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
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

pub(super) fn append_diff_summary(spans: &mut Vec<Span<'static>>, summary: &DiffSummary) {
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

pub(super) fn list_item(finding: &Finding, review_state: Option<ReviewState>) -> ListItem<'static> {
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
    // Crypto algorithm chip — magenta, sits between tags and deadline.
    // Only PQ findings carry this field; non-crypto rows are untouched.
    if let Some(algo) = finding.crypto_algorithm.as_ref() {
        title_spans.push(Span::raw(" "));
        title_spans.push(crypto_algorithm_chip_span(algo));
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
pub(super) fn cnsa2_deadline_chip_span(deadline: &str) -> Span<'static> {
    Span::styled(
        format!(" {} ", deadline),
        Style::default().bg(Color::Yellow).fg(Color::Black),
    )
}

/// Compact algorithm chip for findings that carry `crypto_algorithm`.
/// Magenta on white, no bold — metadata context, same reasoning as the
/// deadline chip.
pub(super) fn crypto_algorithm_chip_span(algo: &str) -> Span<'static> {
    Span::styled(
        format!(" {} ", algo),
        Style::default().bg(Color::Magenta).fg(Color::White),
    )
}

/// Small dimmed confidence indicator shown next to findings with
/// `confidence < 1.0`. Returns `None` when the finding is at full
/// confidence — the common case — so the list stays visually restrained.
/// Format: `[.87]` (two decimals, no leading digit), dim gray foreground.
pub(super) fn confidence_badge_span(confidence: f32) -> Option<Span<'static>> {
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

pub(super) fn dataflow_lines(finding: &Finding, active_focus: OpenFocus) -> Vec<Line<'static>> {
    let mut steps = Vec::new();

    if finding.source_line.is_some() || finding.source_description.is_some() {
        let location = finding
            .source_line
            .map(|line| format!("{}:{}", display_path(&finding.file), line))
            .unwrap_or_else(|| display_path(&finding.file));
        steps.push((
            OpenFocus::Source,
            "source",
            location,
            finding.source_description.clone(),
            Color::Yellow,
        ));
    }

    if finding.source_line.is_none()
        && finding.source_description.is_none()
        && finding.sink_line.is_none()
        && finding.sink_description.is_none()
    {
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

    if finding.sink_line.is_some() || finding.sink_description.is_some() {
        let location = finding
            .sink_line
            .map(|line| format!("{}:{}", display_path(&finding.file), line))
            .unwrap_or_else(|| display_path(&finding.file));
        steps.push((
            OpenFocus::Sink,
            "sink",
            location,
            finding.sink_description.clone(),
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

pub(super) fn open_target_lines(finding: &Finding, active_focus: OpenFocus) -> Vec<Line<'static>> {
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

pub(super) fn render_source_context(
    source: &str,
    finding: &Finding,
    radius: usize,
) -> Vec<Line<'static>> {
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
    let clusters = display_clusters(line);
    let char_len = clusters.last().map(|cluster| cluster.end_char).unwrap_or(0);
    let cell_len = clusters.last().map(|cluster| cluster.end_cell).unwrap_or(0);
    let highlight = highlight_range_for_line(finding, line_number, char_len);
    let highlight_cells = highlight.map(|(start, end)| {
        (
            cell_offset_for_char_boundary(&clusters, start.saturating_sub(1), BoundarySide::Start),
            cell_offset_for_char_boundary(&clusters, end.saturating_sub(1), BoundarySide::End),
        )
    });
    let mut window_start_cell = 0;

    if cell_len > CONTEXT_LINE_MAX_CHARS {
        if let Some((start, _)) = highlight_cells {
            window_start_cell = start.saturating_sub(CONTEXT_FOCUS_LEAD);
        }
        window_start_cell = window_start_cell.min(cell_len.saturating_sub(CONTEXT_LINE_MAX_CHARS));
    }

    let window_end_cell = (window_start_cell + CONTEXT_LINE_MAX_CHARS).min(cell_len);
    let leading_ellipsis = window_start_cell > 0;
    let trailing_ellipsis = window_end_cell < cell_len;
    let visible_clusters = clusters
        .iter()
        .filter(|cluster| {
            cluster.end_cell > window_start_cell && cluster.start_cell < window_end_cell
        })
        .collect::<Vec<_>>();
    let visible_origin_cell = visible_clusters
        .first()
        .map(|cluster| cluster.start_cell)
        .unwrap_or(window_start_cell);
    let visible_end_cell = visible_clusters
        .last()
        .map(|cluster| cluster.end_cell)
        .unwrap_or(window_end_cell);

    let mut text = String::new();
    if leading_ellipsis {
        text.push_str("...");
    }
    for cluster in &visible_clusters {
        text.push_str(&cluster.rendered);
    }
    if trailing_ellipsis {
        text.push_str("...");
    }

    let visible_highlight = highlight_cells.and_then(|(start, end)| {
        let visible_start = start.max(visible_origin_cell);
        let visible_end = end.min(visible_end_cell);
        if visible_start >= visible_end {
            return None;
        }

        let ellipsis_offset = if leading_ellipsis { 3 } else { 0 };
        Some((
            ellipsis_offset + visible_start.saturating_sub(visible_origin_cell),
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

struct DisplayCluster {
    rendered: String,
    start_char: usize,
    end_char: usize,
    start_cell: usize,
    end_cell: usize,
}

fn display_clusters(line: &str) -> Vec<DisplayCluster> {
    let mut clusters = Vec::new();
    let mut char_index = 0;
    let mut cell_index = 0;

    for grapheme in line.graphemes(true) {
        let char_count = grapheme.chars().count();
        let width = grapheme_display_width(grapheme);
        let rendered = render_grapheme(grapheme);
        clusters.push(DisplayCluster {
            rendered,
            start_char: char_index,
            end_char: char_index + char_count,
            start_cell: cell_index,
            end_cell: cell_index + width,
        });
        char_index += char_count;
        cell_index += width;
    }

    clusters
}

fn render_grapheme(grapheme: &str) -> String {
    if grapheme == "\t" {
        " ".repeat(CONTEXT_TAB_WIDTH)
    } else {
        grapheme.to_string()
    }
}

fn grapheme_display_width(grapheme: &str) -> usize {
    if grapheme == "\t" {
        CONTEXT_TAB_WIDTH
    } else {
        grapheme.width()
    }
}

#[derive(Clone, Copy)]
enum BoundarySide {
    Start,
    End,
}

fn cell_offset_for_char_boundary(
    clusters: &[DisplayCluster],
    char_boundary: usize,
    side: BoundarySide,
) -> usize {
    for cluster in clusters {
        if char_boundary <= cluster.start_char {
            return cluster.start_cell;
        }
        if char_boundary < cluster.end_char {
            return match side {
                BoundarySide::Start => cluster.start_cell,
                BoundarySide::End => cluster.end_cell,
            };
        }
        if char_boundary == cluster.end_char {
            return cluster.end_cell;
        }
    }

    clusters.last().map(|cluster| cluster.end_cell).unwrap_or(0)
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
pub(super) fn compare_findings(left: &Finding, right: &Finding) -> std::cmp::Ordering {
    compare_findings_by(left, right, SortMode::SeverityDesc)
}

pub(super) fn compare_findings_by(
    left: &Finding,
    right: &Finding,
    mode: SortMode,
) -> std::cmp::Ordering {
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

pub(super) fn severity_counts(findings: &[Finding]) -> SeverityCounts {
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

pub(super) fn severity_badge_spans(counts: &SeverityCounts) -> Vec<Span<'static>> {
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

pub(super) fn severity_badge_span(severity: Severity) -> Span<'static> {
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

pub(super) fn section_heading(label: &str, color: Color) -> Line<'static> {
    Line::from(Span::styled(
        label.to_string(),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    ))
}

pub(super) fn metadata_line(label: &str, value: &str) -> Line<'static> {
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

pub(super) fn preview_line(label: &str, value: &str) -> Line<'static> {
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

pub(super) fn finding_review_key(finding: &Finding) -> String {
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

pub(super) fn footer_label_span(label: &str) -> Span<'static> {
    Span::styled(
        label.to_string(),
        Style::default()
            .fg(Color::Rgb(145, 126, 99))
            .add_modifier(Modifier::BOLD),
    )
}

pub(super) fn footer_value_span(value: &str) -> Span<'static> {
    Span::styled(value.to_string(), Style::default().fg(Color::White))
}

pub(super) fn footer_key_span(key: &str) -> Span<'static> {
    Span::styled(
        format!(" {} ", key),
        Style::default()
            .fg(Color::Rgb(33, 25, 17))
            .bg(Color::Rgb(186, 157, 104))
            .add_modifier(Modifier::BOLD),
    )
}

pub(super) fn loading_copy(app: &TuiApp) -> (&'static str, String) {
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

pub(super) fn loading_phase_labels(app: &TuiApp) -> [&'static str; 3] {
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

pub(super) fn loading_shimmer_line(label: &str, width: usize, tick: usize) -> Vec<Span<'static>> {
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

pub(super) fn draw_status_bar(
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

pub(super) fn panel_block(title: Option<&str>, background: Color) -> Block<'static> {
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

pub(super) fn mode_findings_title(mode: &TuiMode) -> &'static str {
    match mode {
        TuiMode::Scan => "Findings",
        TuiMode::Diff { .. } => "New Findings",
        TuiMode::Secrets => "Secrets",
    }
}

pub(super) fn request_mode_label(args: &TuiArgs) -> &'static str {
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

pub(super) fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical+",
        Severity::High => "high+",
        Severity::Medium => "medium+",
        Severity::Low => "low+",
    }
}

pub(super) fn short_path(path: &str) -> String {
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

pub(super) fn display_path(path: &str) -> String {
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(relative) = Path::new(path).strip_prefix(&cwd) {
            return relative.display().to_string();
        }
    }

    path.to_string()
}

pub(super) fn scan_root_path(path: &Path) -> PathBuf {
    if path.is_file() {
        path.parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        path.to_path_buf()
    }
}

pub(super) const CONTEXT_LINE_MAX_CHARS: usize = 96;
pub(super) const CONTEXT_FOCUS_LEAD: usize = 28;
const CONTEXT_TAB_WIDTH: usize = 4;
pub(super) const LOADING_SKELETON_WIDTH: usize = 28;
pub(super) const LOADING_SHIMMER_GAP: usize = 8;
pub(super) const LOADING_SHIMMER_CYCLE: usize = LOADING_SKELETON_WIDTH + LOADING_SHIMMER_GAP * 2;
pub(super) const LOADING_SHIMMER_BAND: f32 = 7.0;
// `list_item` renders exactly two lines: title/metadata and file:line.
pub(super) const FINDING_LIST_ITEM_HEIGHT: u16 = 2;
pub(super) const APP_BG: Color = Color::Rgb(20, 17, 14);
pub(super) const HEADER_BG: Color = Color::Rgb(44, 37, 28);
pub(super) const PANEL_BG: Color = Color::Rgb(27, 23, 18);
pub(super) const LIST_BG: Color = Color::Rgb(34, 28, 21);
pub(super) const DETAIL_BG: Color = Color::Rgb(24, 20, 16);
pub(super) const NOTICE_BG: Color = Color::Rgb(38, 29, 24);
pub(super) const FOOTER_BG: Color = Color::Rgb(58, 47, 34);
pub(super) const TITLE_BG: Color = Color::Rgb(201, 172, 114);
pub(super) const LOGO_PRIMARY: Color = Color::Rgb(221, 191, 122);
pub(super) const LOGO_SECONDARY: Color = Color::Rgb(181, 136, 88);
pub(super) const LAUNCH_CARD_BG: Color = Color::Rgb(34, 28, 21);
pub(super) const LOADING_SHIMMER_BASE: Color = Color::Rgb(82, 67, 50);
pub(super) const LOADING_SHIMMER_LOW: Color = Color::Rgb(106, 87, 64);
pub(super) const LOADING_SHIMMER_MID: Color = Color::Rgb(145, 119, 84);
pub(super) const LOADING_SHIMMER_HIGHLIGHT: Color = Color::Rgb(214, 185, 131);
