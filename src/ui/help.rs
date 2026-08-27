// ui/help.rs — Centered floating overlay: keybinding reference in 4 groups
use crate::app::AppState;
use crate::ui::theme;
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table},
    Frame,
};

pub fn render_help_modal(frame: &mut Frame, area: Rect, _app: &AppState) {
    // Centre the modal: 70% wide, 80% tall, clamped to reasonable dimensions
    let modal_w = (area.width as f32 * 0.70).round() as u16;
    let modal_h = (area.height as f32 * 0.80).round() as u16;
    let x       = area.x + (area.width.saturating_sub(modal_w)) / 2;
    let y       = area.y + (area.height.saturating_sub(modal_h)) / 2;

    let modal_rect = Rect::new(x, y, modal_w, modal_h);

    // Clear the background beneath the modal to prevent see-through artefacts
    frame.render_widget(Clear, modal_rect);

    let block = Block::default()
        .title(Line::from(vec![
            Span::raw(" ─ ◈ "),
            Span::styled("TORCRYPT SHORTCUT REFERENCE", theme::style_title()),
            Span::styled("  [? / Esc] dismiss ", theme::style_dim()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(theme::style_border());
    let inner = block.inner(modal_rect);
    frame.render_widget(block, modal_rect);

    // Stack: 4 group tables separated by small gaps
    let sections = Layout::vertical([
        Constraint::Length(1),    // gap
        Constraint::Length(7),    // Navigation
        Constraint::Length(1),    // divider
        Constraint::Length(6),    // Execution
        Constraint::Length(1),    // divider
        Constraint::Length(5),    // Session Controls
        Constraint::Length(1),    // divider
        Constraint::Length(5),    // Global
        Constraint::Min(0),       // footer note
    ])
    .split(inner);

    render_group(
        frame, sections[1], "⬡  NAVIGATION",
        &[
            ("[1]",     "Switch to Dashboard tab"),
            ("[2]",     "Switch to Benchmark tab"),
            ("[3]",     "Switch to Sessions tab"),
            ("[4]",     "Switch to System tab"),
            ("[J / K] or [↑ / ↓]", "Move selection up / down"),
        ],
    );

    render_divider(frame, sections[2]);

    render_group(
        frame, sections[3], "⬡  EXECUTION",
        &[
            ("[Space]",  "Pause / Resume active cipher worker pipeline"),
            ("[C]",      "Cancel active session — abort all worker threads"),
            ("[B]",      "Run multi-threaded cryptographic benchmark suite"),
        ],
    );

    render_divider(frame, sections[4]);

    render_group(
        frame, sections[5], "⬡  SESSION CONTROLS",
        &[
            ("[/]",      "Activate search filter bar in Sessions view"),
            ("[Enter]",  "Confirm search filter and close search bar"),
            ("[Esc]",    "Dismiss search / close this help overlay"),
        ],
    );

    render_divider(frame, sections[6]);

    render_group(
        frame, sections[7], "⬡  GLOBAL",
        &[
            ("[?]",         "Toggle this keyboard reference overlay"),
            ("[Q / Ctrl+C]","Safely wipe key memory buffers and exit Torcrypt"),
        ],
    );

    // Footer tip
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "  Tip: All key memory is securely zeroed on exit via mlock + explicit_bzero.",
                theme::style_dim(),
            ),
        ]))
        .alignment(Alignment::Left),
        sections[8],
    );
}

fn render_group(frame: &mut Frame, area: Rect, title: &str, bindings: &[(&str, &str)]) {
    let rows = Layout::vertical([
        Constraint::Length(1),    // group title
        Constraint::Min(0),       // table
    ])
    .split(area);

    // Group title line
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("  {title}"),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
        ])),
        rows[0],
    );

    let table_rows: Vec<Row> = bindings
        .iter()
        .map(|(k, action)| {
            Row::new(vec![
                Cell::from(*k).style(
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(*action).style(Style::default().fg(Color::White)),
            ])
        })
        .collect();

    let widths = [Constraint::Length(24), Constraint::Min(0)];
    let table  = Table::new(table_rows, widths)
        .column_spacing(2);

    frame.render_widget(table, rows[1]);
}

fn render_divider(frame: &mut Frame, area: Rect) {
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "  ─────────────────────────────────────────────────────",
                theme::style_dim(),
            ),
        ])),
        area,
    );
}
