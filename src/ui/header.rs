// ui/header.rs — Branded badge | Tab pills | Live UTC clock & engine status
use crate::app::{AppState, Tab, WorkerState};
use crate::ui::theme;
use chrono::Utc;
use ratatui::{
    layout::{Alignment, Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};

pub fn render_header(frame: &mut Frame, area: ratatui::layout::Rect, app: &AppState) {
    // Outer block gives the header its rounded border frame
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::style_border());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Split inner row into: [brand badge] [tab pills] [status + clock]
    let cols = Layout::horizontal([
        Constraint::Length(20),   // brand badge
        Constraint::Min(0),       // tab pills (center)
        Constraint::Length(30),   // clock + status
    ])
    .split(inner);

    // ── Left: Brand Badge ─────────────────────────────────────────────────────
    let badge = Paragraph::new(Line::from(vec![
        Span::styled(" 🔐 ", Style::default()),
        Span::styled("TORCRYPT", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" v0.1.0", Style::default().fg(Color::DarkGray)),
    ]))
    .alignment(Alignment::Left);
    frame.render_widget(badge, cols[0]);

    // ── Center: Tab Pills ─────────────────────────────────────────────────────
    fn tab_span(label: &str, tab: Tab, current: Tab) -> Span<'static> {
        let text = format!(" {label} ");
        let label_owned = text.clone();
        if tab == current {
            Span::styled(
                label_owned,
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(
                label_owned,
                Style::default()
                    .fg(Color::DarkGray)
                    .bg(Color::Indexed(237)),
            )
        }
    }

    let tab_line = Line::from(vec![
        Span::raw(" "),
        tab_span("[1] Dashboard", Tab::Dashboard, app.current_tab),
        Span::raw(" "),
        tab_span("[2] Benchmark", Tab::Benchmark, app.current_tab),
        Span::raw(" "),
        tab_span("[3] Sessions",  Tab::Sessions,  app.current_tab),
        Span::raw(" "),
        tab_span("[4] System",    Tab::System,    app.current_tab),
    ]);

    let tabs = Paragraph::new(tab_line).alignment(Alignment::Center);
    frame.render_widget(tabs, cols[1]);

    // ── Right: Status + UTC Clock ─────────────────────────────────────────────
    let (status_icon, status_style) = match app.worker_state {
        WorkerState::Running   => ("● READY",   theme::style_neon()),
        WorkerState::Paused    => ("⏸ PAUSED",  theme::style_amber()),
        WorkerState::Stopped   => ("■ STOPPED", theme::style_red()),
        WorkerState::Completed => ("✔ DONE",    theme::style_neon()),
    };

    let now = Utc::now().format("%H:%M:%S UTC").to_string();

    let right_line = Line::from(vec![
        Span::styled(status_icon, status_style.add_modifier(Modifier::BOLD)),
        Span::styled("  │  ", Style::default().fg(Color::DarkGray)),
        Span::styled(now, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
    ]);

    let right = Paragraph::new(right_line).alignment(Alignment::Right);
    frame.render_widget(right, cols[2]);
}
