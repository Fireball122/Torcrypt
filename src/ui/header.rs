// ui/header.rs — Cyberpunk top navigation bar with UTC clock and dirty-state tab indicators
use crate::app::{AppState, Tab, WorkerState};
use crate::ui::theme;
use chrono::Utc;
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

pub fn render_header(frame: &mut Frame, area: Rect, app: &AppState) {
    let cols = Layout::horizontal([
        Constraint::Length(28), // Left: Cyberpunk Banner Title
        Constraint::Min(0),     // Center: Tab Badges
        Constraint::Length(24), // Right: Engine Status + Live UTC Clock
    ])
    .split(area);

    // ── Left: App Title Badge ──────────────────────────────────────────────────
    let title_line = Line::from(vec![
        Span::styled(" ◈ TORCRYPT ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" v0.1.20 ", Style::default().fg(Color::Cyan).add_modifier(Modifier::DIM)),
    ]);
    let title = Paragraph::new(title_line).alignment(Alignment::Left);
    frame.render_widget(title, cols[0]);

    // ── Center: Tab Navigation Badges ──────────────────────────────────────────
    fn tab_span<'a>(label: &'a str, tab: Tab, current: Tab) -> Span<'a> {
        if tab == current {
            Span::styled(
                format!("  {}  ", label),
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(
                format!("  {}  ", label),
                Style::default()
                    .fg(Color::DarkGray)
                    .bg(Color::Indexed(237)),
            )
        }
    }

    let tab_line = Line::from(vec![
        tab_span("[1] Analyze",   Tab::Analyze,   app.current_tab),
        Span::raw(" "),
        tab_span("[2] Dashboard", Tab::Dashboard, app.current_tab),
        Span::raw(" "),
        tab_span("[3] Benchmark", Tab::Benchmark, app.current_tab),
        Span::raw(" "),
        tab_span("[4] Sessions",  Tab::Sessions,  app.current_tab),
        Span::raw(" "),
        tab_span("[5] System",    Tab::System,    app.current_tab),
    ]);

    let tabs = Paragraph::new(tab_line).alignment(Alignment::Center);
    frame.render_widget(tabs, cols[1]);

    // ── Right: Status + UTC Clock ─────────────────────────────────────────────
    let (status_icon, status_style) = match app.worker_state {
        WorkerState::Idle      => ("● STANDBY",   theme::style_neon()),
        WorkerState::Running   => ("● RUNNING",   theme::style_neon()),
        WorkerState::Paused    => ("⏸ PAUSED",    theme::style_amber()),
        WorkerState::Stopped   => ("■ STOPPED",   theme::style_red()),
        WorkerState::Completed => ("✨ FOUND",     theme::style_neon()),
        WorkerState::Exhausted => ("❌ EXHAUSTED", theme::style_amber()),
    };

    let now = Utc::now().format("%H:%M:%S UTC").to_string();

    let right_line = Line::from(vec![
        Span::styled(status_icon, status_style.add_modifier(Modifier::BOLD)),
        Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
        Span::styled(now, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
    ]);

    let right = Paragraph::new(right_line).alignment(Alignment::Right);
    frame.render_widget(right, cols[2]);
}
