// ui/dashboard.rs — 40/60 Responsive 2-Column Grid: Worker Card + Progress |
//                   Sparkline Throughput + Auto-Scrolling Activity Stream
use crate::app::{AppState, LogLevel, WorkerState};
use crate::ui::theme;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Gauge, Paragraph, Row, Sparkline, Table, Cell,
        Wrap,
    },
    Frame,
};

pub fn render_dashboard(frame: &mut Frame, area: Rect, app: &AppState) {
    let cols = Layout::horizontal([
        Constraint::Percentage(40),
        Constraint::Percentage(60),
    ])
    .split(area);

    render_left(frame, cols[0], app);
    render_right(frame, cols[1], app);
}

// ─── LEFT COLUMN ─────────────────────────────────────────────────────────────

fn render_left(frame: &mut Frame, area: Rect, app: &AppState) {
    let rows = Layout::vertical([
        Constraint::Length(10),   // Live Worker Card
        Constraint::Length(5),    // Progress Gauge
        Constraint::Length(5),    // Thread Pool Saturation
        Constraint::Min(0),       // Cipher Info / extra
    ])
    .split(area);

    render_worker_card(frame, rows[0], app);
    render_progress_gauge(frame, rows[1], app);
    render_thread_gauge(frame, rows[2], app);
    render_cipher_info(frame, rows[3], app);
}

fn render_worker_card(frame: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("LIVE CIPHER WORKER", theme::style_title()),
            Span::raw(" "),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::style_border());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let speed = app.speed_mbps;

    let items_label = if app.items_total > 0 {
        format!("{} / {} files", fmt_num(app.items_done), fmt_num(app.items_total))
    } else {
        "—".into()
    };

    let elapsed_label = if app.worker_state == WorkerState::Running || app.worker_state == WorkerState::Paused {
        Line::from(vec![
            Span::styled("  Elapsed / ETA : ", theme::style_subtext()),
            Span::styled(fmt_duration(app.elapsed_secs), Style::default().fg(Color::White)),
            Span::styled(" elapsed │ ETA ", theme::style_subtext()),
            Span::styled(fmt_duration(app.eta_secs), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ])
    } else {
        Line::from(vec![
            Span::styled("  Elapsed / ETA : ", theme::style_subtext()),
            Span::styled("—", theme::style_dim()),
        ])
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("  Cipher Suite  : ", theme::style_subtext()),
            Span::styled(app.cipher_suite.clone(),
                Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Target Vault  : ", theme::style_subtext()),
            Span::styled(truncate(&app.target_path, inner.width.saturating_sub(18) as usize),
                Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("  Items Done    : ", theme::style_subtext()),
            Span::styled(items_label, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Throughput    : ", theme::style_subtext()),
            Span::styled(
                format!("{:.1} MB/s", speed),
                if speed > 0.0 { Style::default().fg(Color::Green).add_modifier(Modifier::BOLD) } else { theme::style_dim() },
            ),
        ]),
        elapsed_label,
        Line::from(vec![
            Span::styled("  Engine Status : ", theme::style_subtext()),
            Span::styled(
                match app.worker_state {
                    WorkerState::Idle      => "● STANDBY (Awaiting Job)",
                    WorkerState::Running   => "▶ RUNNING",
                    WorkerState::Paused    => "⏸ PAUSED",
                    WorkerState::Stopped   => "■ STOPPED",
                    WorkerState::Completed => "✔ COMPLETED",
                },
                theme::status_style(match app.worker_state {
                    WorkerState::Idle      => "READY",
                    WorkerState::Running   => "ACTIVE",
                    WorkerState::Paused    => "PAUSED",
                    WorkerState::Stopped   => "FAIL",
                    WorkerState::Completed => "DONE",
                }),
            ),
        ]),
    ];

    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        inner,
    );
}

fn render_progress_gauge(frame: &mut Frame, area: Rect, app: &AppState) {
    let pct = app.progress_pct();

    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("ENCRYPTION PIPELINE", theme::style_title()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::style_border());

    let label_str = if app.items_total > 0 {
        format!("{:.1}%  ─  {} / {} files", pct, fmt_num(app.items_done), fmt_num(app.items_total))
    } else {
        "0.0%  ─  STANDBY".into()
    };

    let gauge = Gauge::default()
        .block(block)
        .gauge_style(
            Style::default()
                .fg(Color::Cyan)
                .bg(Color::Indexed(237))
                .add_modifier(Modifier::BOLD),
        )
        .percent(pct as u16)
        .label(label_str);

    frame.render_widget(gauge, area);
}

fn render_thread_gauge(frame: &mut Frame, area: Rect, app: &AppState) {
    let sat = app.thread_saturation_pct();

    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("THREAD POOL SATURATION", theme::style_title()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Magenta));

    let label_str = if app.thread_active > 0 {
        format!("{}/{} Cores Active  ({sat}% Saturation)", app.thread_active, app.thread_count)
    } else {
        format!("0/{} Cores Active (IDLE)", app.thread_count)
    };

    let gauge = Gauge::default()
        .block(block)
        .gauge_style(
            Style::default()
                .fg(Color::Green)
                .bg(Color::Indexed(237))
                .add_modifier(Modifier::BOLD),
        )
        .percent(sat as u16)
        .label(label_str);

    frame.render_widget(gauge, area);
}

fn render_cipher_info(frame: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("CRYPTOGRAPHIC PIPELINE", theme::style_title()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows_data = [
        ("Algorithm",  app.cipher_suite.as_str(), Color::Magenta),
        ("Key Length",  "256-bit AES-GCM",        Color::Cyan),
        ("IV / Nonce",  "96-bit (GCM Standard)",  Color::White),
        ("Auth Tag",    "128-bit GHASH",           Color::Green),
        ("KDF",         "Argon2id (64 MB Cost)",   Color::Yellow),
        ("AES-NI",      "ENABLED ✔",               Color::Green),
    ];

    let rows: Vec<Row> = rows_data
        .iter()
        .map(|(k, v, c)| {
            Row::new(vec![
                Cell::from(*k).style(theme::style_subtext()),
                Cell::from(*v).style(Style::default().fg(*c).add_modifier(Modifier::BOLD)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(14),
        Constraint::Min(0),
    ];

    let table = Table::new(rows, widths)
        .column_spacing(2);

    frame.render_widget(table, inner);
}

// ─── RIGHT COLUMN ─────────────────────────────────────────────────────────────

fn render_right(frame: &mut Frame, area: Rect, app: &AppState) {
    let rows = Layout::vertical([
        Constraint::Length(8),   // Sparkline chart
        Constraint::Min(0),      // Activity stream (fills rest)
    ])
    .split(area);

    render_sparkline(frame, rows[0], app);
    render_activity_stream(frame, rows[1], app);
}

fn render_sparkline(frame: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("REAL-TIME THROUGHPUT", theme::style_title()),
            Span::styled("  (MB/s — 60s window)", theme::style_subtext()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::style_border());

    let data: Vec<u64> = app.throughput_history.iter().copied().collect();

    let spark = Sparkline::default()
        .block(block)
        .data(&data)
        .max(600)
        .direction(ratatui::widgets::RenderDirection::LeftToRight)
        .style(Style::default().fg(Color::Cyan))
        .bar_set(symbols::bar::NINE_LEVELS);

    frame.render_widget(spark, area);
}

fn render_activity_stream(frame: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("ENGINE ACTIVITY STREAM", theme::style_title()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::style_border());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let max_rows = inner.height as usize;
    let logs: Vec<_> = app
        .log_ring
        .iter()
        .rev()
        .take(max_rows)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    let col_w = inner.width.saturating_sub(12) as usize;

    let rows: Vec<Row> = logs
        .iter()
        .map(|entry| {
            let (badge, badge_style) = match entry.level {
                LogLevel::Info => ("[INFO]", Style::default().fg(Color::Cyan)),
                LogLevel::Lock => ("[LOCK]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                LogLevel::Warn => ("[WARN]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                LogLevel::Err  => ("[ERR ]", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            };

            let payload = if entry.path.is_empty() {
                entry.message.clone()
            } else {
                format!("{}  {}", entry.path, entry.message)
            };

            Row::new(vec![
                Cell::from(entry.timestamp.as_str()).style(theme::style_dim()),
                Cell::from(badge).style(badge_style),
                Cell::from(truncate(&payload, col_w)).style(Style::default().fg(Color::White)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(9),   // timestamp
        Constraint::Length(7),   // badge
        Constraint::Min(0),      // payload
    ];

    let table = Table::new(rows, widths)
        .column_spacing(1)
        .header(
            Row::new(vec!["Time", "Level", "Path / Event Payload"])
                .style(Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        );

    frame.render_widget(table, inner);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { out.push(','); }
        out.push(c);
    }
    out.chars().rev().collect()
}

fn fmt_duration(secs: f64) -> String {
    let s = secs as u64;
    if s >= 3600 {
        format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
    } else {
        format!("{:02}:{:02}", s / 60, s % 60)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { return s.to_string(); }
    format!("{}…", &s[..max.saturating_sub(1)])
}
