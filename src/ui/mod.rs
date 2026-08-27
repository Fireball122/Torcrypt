// ui/mod.rs — Master render dispatcher: fills the entire terminal with zero dead space
pub mod analyze;
pub mod benchmark;
pub mod dashboard;
pub mod footer;
pub mod header;
pub mod help;
pub mod sessions;
pub mod splash;
pub mod system;

use crate::app::{AppState, Tab};
use ratatui::{
    layout::{Constraint, Layout},
    Frame,
};

// ─── Theme: shared palette constants ─────────────────────────────────────────
pub mod theme {
    use ratatui::style::{Color, Modifier, Style};

    // Palette
    pub const CYAN:     Color = Color::Cyan;
    pub const GREEN:    Color = Color::Green;
    pub const AMBER:    Color = Color::Yellow;
    pub const MAGENTA:  Color = Color::Magenta;
    pub const WHITE:    Color = Color::White;
    pub const GRAY:     Color = Color::DarkGray;
    pub const RED:      Color = Color::Red;

    // Background surface tones (256-colour indexed)
    pub const BG_BASE:    Color = Color::Indexed(235); // #262626
    pub const BG_SURFACE: Color = Color::Indexed(237); // #3a3a3a
    pub const BG_RAISED:  Color = Color::Indexed(239); // #4e4e4e

    pub const TEXT_DIM: Color = Color::Indexed(245);   // muted label text

    // Semantic styles
    pub fn style_base()    -> Style { Style::default().bg(BG_BASE) }
    pub fn style_header()  -> Style { Style::default().fg(CYAN).add_modifier(Modifier::BOLD) }
    pub fn style_border()  -> Style { Style::default().fg(CYAN) }
    pub fn style_title()   -> Style { Style::default().fg(CYAN).add_modifier(Modifier::BOLD) }
    pub fn style_subtext() -> Style { Style::default().fg(TEXT_DIM) }
    pub fn style_neon()    -> Style { Style::default().fg(GREEN).add_modifier(Modifier::BOLD) }
    pub fn style_amber()   -> Style { Style::default().fg(AMBER).add_modifier(Modifier::BOLD) }
    pub fn style_red()     -> Style { Style::default().fg(RED).add_modifier(Modifier::BOLD) }
    pub fn style_dim()     -> Style { Style::default().fg(GRAY) }

    pub fn status_style(status: &str) -> Style {
        match status {
            s if s.contains("ACTIVE") | s.contains("ENABLED") | s.contains("READY")
                => style_neon(),
            s if s.contains("PAUSED") | s.contains("WARN")
                => style_amber(),
            s if s.contains("FAIL") | s.contains("ERR") | s.contains("DISABLED")
                => style_red(),
            s if s.contains("COMPLETED") | s.contains("DONE")
                => Style::default().fg(GREEN),
            _  => Style::default().fg(WHITE),
        }
    }
}

/// Top-level render: splash screen or header + content + footer. Zero dead space.
pub fn render(frame: &mut Frame, app: &mut AppState) {
    let area = frame.area();

    // 1. If in startup splash mode, render splash animation across full screen
    if app.in_splash {
        splash::render_splash(frame, area, app);
        return;
    }

    // 2. Main 3-Zone View
    let rows = Layout::vertical([
        Constraint::Length(3),          // header
        Constraint::Min(0),             // content (fills everything)
        Constraint::Length(1),          // footer
    ])
    .split(area);

    header::render_header(frame, rows[0], app);

    match app.current_tab {
        Tab::Analyze   => analyze::render_analyze(frame, rows[1], app),
        Tab::Dashboard => dashboard::render_dashboard(frame, rows[1], app),
        Tab::Benchmark => benchmark::render_benchmark(frame, rows[1], app),
        Tab::Sessions  => sessions::render_sessions(frame, rows[1], app),
        Tab::System    => system::render_system(frame, rows[1], app),
    }

    footer::render_footer(frame, rows[2], app);

    // Help modal rendered last (floats over everything)
    if app.show_help {
        help::render_help_modal(frame, area, app);
    }
}
