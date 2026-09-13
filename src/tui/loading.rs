//! Indeterminate scan activity; no simulated phases or completion percentage.

use std::borrow::Cow;

use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Paragraph},
    Frame,
};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

use super::state::{LaunchMode, TuiApp};
use super::widgets::{short_path, APP_BG, LOGO_PRIMARY, PANEL_BG, TEXT_MUTED, TEXT_PRIMARY};

/// Four seconds at the scan-only 100 ms redraw cadence.
pub(super) const LOADING_SHIMMER_CYCLE: usize = 40;
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub(super) fn draw_loading(app: &TuiApp, frame: &mut Frame, area: Rect) {
    frame.render_widget(Block::default().style(Style::default().bg(APP_BG)), area);
    let title = match app.launch_mode {
        LaunchMode::Scan => "Scanning code",
        LaunchMode::Diff => "Scanning Git diff",
        LaunchMode::Secrets => "Scanning secrets",
        LaunchMode::Pqc => "Scanning cryptography",
    };
    if area.width < 4 || area.height < 3 {
        frame.render_widget(
            Paragraph::new(title).style(Style::default().fg(TEXT_PRIMARY)),
            area,
        );
        return;
    }
    let width = area.width.saturating_sub(4).clamp(4, 76);
    let height = area.height.min(5);
    let card = Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    );
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(TEXT_MUTED))
        .style(Style::default().bg(PANEL_BG).fg(TEXT_PRIMARY))
        .title(Line::from(vec![
            Span::raw(" "),
            Span::styled(
                SPINNER[app.loading_tick % SPINNER.len()],
                Style::default().fg(LOGO_PRIMARY),
            ),
            Span::styled(
                format!(" {title} "),
                Style::default()
                    .fg(LOGO_PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
    let inner = block.inner(card);
    frame.render_widget(block, card);
    if inner.height >= 2 {
        let path = short_path(&app.request.path);
        let target = match (app.launch_mode, app.request.diff.as_deref()) {
            (LaunchMode::Diff, Some(target)) => format!("{path} · {target}"),
            _ => path,
        };
        frame.render_widget(
            Paragraph::new(fit_path(&target, inner.width as usize))
                .style(Style::default().fg(TEXT_PRIMARY)),
            Rect::new(inner.x, inner.y, inner.width, 1),
        );
    }
    if inner.height >= 3 {
        let tick = app.loading_tick % LOADING_SHIMMER_CYCLE;
        let half = LOADING_SHIMMER_CYCLE / 2;
        let step = if tick < half {
            tick
        } else {
            LOADING_SHIMMER_CYCLE - 1 - tick
        };
        let center = step * inner.width.saturating_sub(1) as usize / (half - 1);
        let spans = (0..inner.width as usize)
            .map(|column| {
                let distance = column.abs_diff(center);
                let (glyph, color) = if distance <= 2 {
                    ("━", LOGO_PRIMARY)
                } else if distance <= 4 {
                    ("━", TEXT_PRIMARY)
                } else {
                    ("─", TEXT_MUTED)
                };
                Span::styled(glyph, Style::default().fg(color))
            })
            .collect::<Vec<_>>();
        frame.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect::new(inner.x, inner.y + 1, inner.width, 1),
        );
    }
    let elapsed = app.scan_started_at.elapsed();
    let elapsed = if elapsed.as_secs() < 60 {
        format!("{:.1}s", elapsed.as_secs_f32())
    } else {
        format!("{}m {:02}s", elapsed.as_secs() / 60, elapsed.as_secs() % 60)
    };
    let hint = "Ctrl+C quit";
    let footer = if inner.width as usize >= elapsed.len() + hint.len() + 2 {
        let gap = inner.width as usize - elapsed.len() - hint.len();
        Line::from(vec![
            Span::styled(elapsed, Style::default().fg(TEXT_MUTED)),
            Span::raw(" ".repeat(gap)),
            Span::styled(hint, Style::default().fg(TEXT_PRIMARY)),
        ])
    } else {
        Line::styled(hint, Style::default().fg(TEXT_PRIMARY))
    };
    frame.render_widget(
        Paragraph::new(footer),
        Rect::new(inner.x, inner.bottom() - 1, inner.width, 1),
    );
}

fn fit_path(text: &str, columns: usize) -> Cow<'_, str> {
    if text.width() <= columns {
        return Cow::Borrowed(text);
    }
    if columns == 0 {
        return Cow::Borrowed("");
    }
    let head_budget = (columns - 1) / 2;
    let tail_budget = columns - 1 - head_budget;
    let (mut head, mut used) = (0, 0);
    for (offset, grapheme) in text.grapheme_indices(true) {
        if used + grapheme.width() > head_budget {
            break;
        }
        used += grapheme.width();
        head = offset + grapheme.len();
    }
    let (mut tail, mut used) = (text.len(), 0);
    for (offset, grapheme) in text.grapheme_indices(true).rev() {
        if offset < head || used + grapheme.width() > tail_budget {
            break;
        }
        used += grapheme.width();
        tail = offset;
    }
    Cow::Owned(format!("{}…{}", &text[..head], &text[tail..]))
}
