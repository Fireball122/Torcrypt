// ui/header.rs — Cyberpunk top navigation bar with UTC clock and dirty-state tab indicators
use crate::app::{AppState, ClickAction, Tab, WorkerState};
use crate::ui::theme;
use chrono::Utc;
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

pub fn render_header(frame: &mut Frame, area: Rect, app: &mut AppState) {
    let cols = Layout::horizontal([
        Constraint::Length(28), // Left: Cyberpunk Banner Title
        Constraint::Min(0),     // Center: Tab Badges
        Constraint::Length(40), // Right: Engine Status + Active Backend + Live UTC Clock
    ])
    .split(area);

    // ── Left: App Title Badge ──────────────────────────────────────────────────
    let title_line = Line::from(vec![
        Span::styled(" ◈ TORCRYPT ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" v0.1.25 ", Style::default().fg(Color::Cyan).add_modifier(Modifier::DIM)),
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

    // Register tab click regions — each tab label is "  [N] Name  " = fixed widths
    // Widths: Analyze=13, Dashboard=14, Benchmark=14, Sessions=13, System=11 (plus 1 space gap)
    let tab_defs: &[(&str, Tab, u16)] = &[
        ("  [1] Analyze  ",   Tab::Analyze,   15),
        ("  [2] Dashboard  ", Tab::Dashboard,  16),
        ("  [3] Benchmark  ", Tab::Benchmark,  16),
        ("  [4] Sessions  ",  Tab::Sessions,   15),
        ("  [5] System  ",    Tab::System,     13),
    ];
    // Total tab bar content width
    let total_tab_w: u16 = tab_defs.iter().map(|(_, _, w)| w + 1).sum::<u16>().saturating_sub(1);
    let tab_bar_left = cols[1].x + cols[1].width.saturating_sub(total_tab_w) / 2;
    let mut cur_x = tab_bar_left;
    for (_, tab, w) in tab_defs {
        app.click_regions.push((
            ratatui::layout::Rect::new(cur_x, cols[1].y, *w, cols[1].height),
            ClickAction::SwitchTab(*tab),
        ));
        cur_x += w + 1; // +1 for the space separator
    }

    // ── Right: Status + UTC Clock ─────────────────────────────────────────────
    let (status_icon, status_style) = match app.worker_state {
        WorkerState::Idle      => ("● STANDBY",   theme::style_neon()),
        WorkerState::Running   => ("● RUNNING",   theme::style_neon()),
        WorkerState::Paused    => ("⏸ PAUSED",    theme::style_amber()),
        WorkerState::Stopped   => ("■ STOPPED",   theme::style_red()),
        WorkerState::Completed => ("● FOUND",     theme::style_neon()),
        WorkerState::Exhausted => ("● EXHAUSTED", theme::style_amber()),
    };

    let now = Utc::now().format("%H:%M:%S UTC").to_string();

    let backend_span = match app.active_backend {
        crate::engine::backends::BackendType::Hashcat   => Span::styled(" [HASHCAT] ", Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)),
        crate::engine::backends::BackendType::John      => Span::styled(" [JOHN] ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        crate::engine::backends::BackendType::Fcrackzip => Span::styled(" [FCRACKZIP] ", Style::default().fg(Color::Black).bg(Color::LightMagenta).add_modifier(Modifier::BOLD)),
        crate::engine::backends::BackendType::Native    => Span::styled(" [NATIVE] ", Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)),
        crate::engine::backends::BackendType::None      => Span::raw(""),
    };

    let right_line = Line::from(vec![
        Span::styled(status_icon, status_style.add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        backend_span,
        Span::styled("│ ", Style::default().fg(Color::DarkGray)),
        Span::styled(now, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
    ]);
    let right = Paragraph::new(right_line).alignment(Alignment::Right);
    frame.render_widget(right, cols[2]);
}
