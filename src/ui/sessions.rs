// ui/sessions.rs — Interactive TableState registry with metadata sidebar and
//                  bottom search filter bar (/ to activate, Esc to dismiss)
use crate::app::{AppState, Session};
use crate::ui::theme;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Cell, Paragraph, Row, Table, TableState,
        Wrap,
    },
    Frame,
};

pub fn render_sessions(frame: &mut Frame, area: Rect, app: &mut AppState) {
    let rows = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(3),   // search bar
    ])
    .split(area);

    let split = Layout::horizontal([
        Constraint::Percentage(65),
        Constraint::Percentage(35),
    ])
    .split(rows[0]);

    if app.potfile_view {
        render_potfile_table(frame, split[0], app);
        render_potfile_inspector(frame, split[1], app);
    } else {
        render_sessions_table(frame, split[0], app);
        render_inspector(frame, split[1], app);
    }
    render_search_bar(frame, rows[1], app);
}

// ─── Main Session Table ───────────────────────────────────────────────────────

fn render_sessions_table(frame: &mut Frame, area: Rect, app: &mut AppState) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("SESSION REGISTRY", theme::style_title()),
            Span::styled(
                format!("  {} sessions", app.sessions.len()),
                theme::style_subtext(),
            ),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::style_border());

    let filtered = app.filtered_sessions();
    let sel = app.sessions_selected.min(filtered.len().saturating_sub(1));

    let header = Row::new(vec![
        Cell::from("  ID").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("Target Path").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("Cipher").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("KDF").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("Status").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("Created At").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
    ]);

    let rows: Vec<Row> = filtered
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let is_sel = i == sel;
            let prefix  = if is_sel { "▶ " } else { "  " };

            let id_cell = Cell::from(format!("{}{}", prefix, s.id)).style(if is_sel {
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            });

            let target_str = truncate(&s.target, 28);

            Row::new(vec![
                id_cell,
                Cell::from(target_str).style(theme::style_subtext()),
                Cell::from(s.cipher.as_str()).style(Style::default().fg(Color::Magenta)),
                Cell::from(s.kdf.as_str()).style(theme::style_dim()),
                Cell::from(s.status.as_str()).style(theme::status_style(&s.status)),
                Cell::from(s.created_at.as_str()).style(theme::style_dim()),
            ])
            .style(if is_sel {
                Style::default().bg(Color::Indexed(237)).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            })
        })
        .collect();

    let widths = [
        Constraint::Length(12),  // ID
        Constraint::Min(20),     // Target (flex)
        Constraint::Length(18),  // Cipher
        Constraint::Length(14),  // KDF
        Constraint::Length(11),  // Status
        Constraint::Length(16),  // Created At
    ];

    let mut ts = TableState::default().with_selected(Some(sel));
    let table = Table::new(rows, widths)
        .block(block)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(Style::default().bg(Color::Indexed(237)));

    frame.render_stateful_widget(table, area, &mut ts);
}

// ─── Right Sidebar Inspector ─────────────────────────────────────────────────

fn render_inspector(frame: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("SESSION INSPECTOR", theme::style_title()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Magenta));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let filtered = app.filtered_sessions();
    let sel = app.sessions_selected.min(filtered.len().saturating_sub(1));

    if filtered.is_empty() {
        let p = Paragraph::new(Line::from(vec![
            Span::styled("  No sessions match your search.", theme::style_dim()),
        ]))
        .wrap(Wrap { trim: false });
        frame.render_widget(p, inner);
        return;
    }

    let s: &Session = filtered[sel];
    let max_w = inner.width.saturating_sub(18) as usize;

    let lines = vec![
        Line::from(vec![
            Span::styled("  Session ID   : ", theme::style_subtext()),
            Span::styled(s.id.clone(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Created At   : ", theme::style_subtext()),
            Span::styled(s.created_at.clone(), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![Span::raw("")]),
        Line::from(vec![
            Span::styled("  Target Vault : ", theme::style_subtext()),
        ]),
        Line::from(vec![
            Span::styled(
                format!("    {}", truncate(&s.target, max_w + 4)),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![Span::raw("")]),
        Line::from(vec![
            Span::styled("  Cipher Suite : ", theme::style_subtext()),
            Span::styled(s.cipher.clone(), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Key Derivat. : ", theme::style_subtext()),
            Span::styled(s.kdf.clone(), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Status       : ", theme::style_subtext()),
            Span::styled(s.status.clone(), theme::status_style(&s.status).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![Span::raw("")]),
        Line::from(vec![
            Span::styled("  Keys Checked : ", theme::style_subtext()),
            Span::styled(fmt_num(s.keys_checked), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Throughput   : ", theme::style_subtext()),
            Span::styled(
                if s.speed_mbps > 0.0 { format!("{:.0} c/s", s.speed_mbps) } else { "—".into() },
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  RAM Alloc    : ", theme::style_subtext()),
            Span::styled(format!("{} MB dedicated", s.memory_mb), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled("  Worker Cores : ", theme::style_subtext()),
            Span::styled(format!("{} threads", s.threads), Style::default().fg(Color::Green)),
        ]),
    ];

    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        inner,
    );
}

// ─── Search Bar ──────────────────────────────────────────────────────────────

fn render_search_bar(frame: &mut Frame, area: Rect, app: &AppState) {
    let (title, border_style, content) = if app.search_mode {
        (
            Line::from(vec![
                Span::styled(" 🔍 SEARCH FILTER ACTIVE — [Enter] confirm  [Esc] cancel ", theme::style_amber()),
            ]),
            theme::style_amber(),
            Line::from(vec![
                Span::styled("  Search: ", theme::style_subtext()),
                Span::styled(app.search_query.clone(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                Span::styled("█", Style::default().fg(Color::Cyan).add_modifier(Modifier::RAPID_BLINK)),
            ]),
        )
    } else {
        (
            Line::from(vec![
                Span::styled("─ ◈ SEARCH SESSIONS ", theme::style_dim()),
            ]),
            theme::style_dim(),
            Line::from(vec![
                Span::styled(
                    "  Press  ",
                    theme::style_subtext(),
                ),
                Span::styled(" / ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled(
                    "  to filter sessions or potfile records...",
                    theme::style_subtext(),
                ),
            ]),
        )
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border_style);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(content), inner);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> String {
    crate::ui::truncate(s, max)
}

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { out.push(','); }
        out.push(c);
    }
    out.chars().rev().collect()
}

fn render_potfile_table(frame: &mut Frame, area: Rect, app: &mut AppState) {
    let filtered = app.filtered_potfile();
    let sel = app.potfile_selected.min(filtered.len().saturating_sub(1));

    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("GLOBAL PERSISTENT POTFILE", theme::style_title()),
            Span::styled(format!("  {} cached passwords  ", filtered.len()), theme::style_subtext()),
            Span::styled("[P: Switch to Sessions]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Green));

    let header = Row::new(vec![
        Cell::from("  Target / Signature").style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("Plaintext Password").style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("Algorithm").style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("Cracked Timestamp").style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
    ]);

    let rows: Vec<Row> = filtered
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let is_sel = i == sel;
            let prefix = if is_sel { "▶ " } else { "  " };

            let target_str = truncate(&r.hash_or_sig, 30);

            Row::new(vec![
                Cell::from(format!("{}{}", prefix, target_str)).style(if is_sel {
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                } else {
                    theme::style_subtext()
                }),
                Cell::from(r.plaintext.as_str()).style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Cell::from(r.algo.as_str()).style(Style::default().fg(Color::Magenta)),
                Cell::from(r.cracked_at.as_str()).style(theme::style_dim()),
            ])
            .style(if is_sel {
                Style::default().bg(Color::Indexed(237)).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            })
        })
        .collect();

    let widths = [
        Constraint::Percentage(40),
        Constraint::Percentage(25),
        Constraint::Percentage(18),
        Constraint::Percentage(17),
    ];

    let mut ts = TableState::default().with_selected(Some(sel));
    let table = Table::new(rows, widths)
        .block(block)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(Style::default().bg(Color::Indexed(237)));

    frame.render_stateful_widget(table, area, &mut ts);
}

fn render_potfile_inspector(frame: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("POTFILE ENTRY DETAILS", theme::style_title()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Green));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let filtered = app.filtered_potfile();
    let sel = app.potfile_selected.min(filtered.len().saturating_sub(1));

    if filtered.is_empty() {
        let p = Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![Span::styled("  No potfile records cached yet.", theme::style_subtext())]),
            Line::from(""),
            Line::from(vec![Span::styled("  Cracked hashes and containers are", theme::style_dim())]),
            Line::from(vec![Span::styled("  automatically saved here for instant", theme::style_dim())]),
            Line::from(vec![Span::styled("  lookup on future recovery runs.", theme::style_dim())]),
        ]);
        frame.render_widget(p, inner);
        return;
    }

    let r = filtered[sel];

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Target / Sig  : ", theme::style_subtext()),
            Span::styled(truncate(&r.hash_or_sig, inner.width.saturating_sub(18) as usize), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Plaintext Pass: ", theme::style_subtext()),
            Span::styled(&r.plaintext, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Password Len  : ", theme::style_subtext()),
            Span::styled(format!("{} characters", r.plaintext.len()), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Algorithm     : ", theme::style_subtext()),
            Span::styled(&r.algo, Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Cracked Date  : ", theme::style_subtext()),
            Span::styled(&r.cracked_at, theme::style_dim()),
        ]),
        Line::from(vec![
            Span::styled("  Cache Status  : ", theme::style_subtext()),
            Span::styled("✨ PERSISTED IN POTFILE (0.001 ms)", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        ]),
    ];

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}
