// ui/benchmark.rs — Multi-algorithm throughput bar chart, latency matrix,
//                   and live progress gauge during execution runs
use crate::app::AppState;
use crate::ui::theme;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Bar, BarChart, BarGroup, Block, BorderType, Borders, Cell, Gauge, Paragraph,
        Row, Table, Wrap,
    },
    Frame,
};

pub fn render_benchmark(frame: &mut Frame, area: Rect, app: &AppState) {
    let rows = Layout::vertical([
        Constraint::Length(3),   // Run-progress bar (shown during benchmark, else description)
        Constraint::Min(0),      // Main split
    ])
    .split(area);

    render_progress_bar(frame, rows[0], app);

    let main = Layout::horizontal([
        Constraint::Percentage(55),   // Bar chart
        Constraint::Percentage(45),   // Latency matrix + detail
    ])
    .split(rows[1]);

    render_bar_chart(frame, main[0], app);
    render_matrix(frame, main[1], app);
}

// ─── Progress / Hint Bar ─────────────────────────────────────────────────────

fn render_progress_bar(frame: &mut Frame, area: Rect, app: &AppState) {
    if app.bench_running {
        let gauge = Gauge::default()
            .block(
                Block::default()
                    .title(Line::from(vec![
                        Span::styled(" ⚙ BENCHMARK RUNNING — press [B] to stop ", theme::style_amber()),
                    ]))
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(theme::style_amber()),
            )
            .gauge_style(Style::default().fg(Color::Yellow).bg(Color::Indexed(237)))
            .percent(app.bench_progress as u16)
            .label(format!("{}% complete", app.bench_progress));
        frame.render_widget(gauge, area);
    } else {
        let hint = Paragraph::new(Line::from(vec![
            Span::styled(" ◈ ", theme::style_dim()),
            Span::styled("Multi-Core Cryptographic Benchmark Suite  ", theme::style_subtext()),
            Span::styled(" [B] ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(" Run benchmark  ", theme::style_subtext()),
            Span::styled(" [J/K] ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(" Select algorithm", theme::style_subtext()),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(theme::style_dim()),
        );
        frame.render_widget(hint, area);
    }
}

// ─── Multi-Core Throughput Comparison Bar Chart ───────────────────────────────

fn render_bar_chart(frame: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("MULTI-CORE THROUGHPUT COMPARISON", theme::style_title()),
            Span::styled("  (MB/s)", theme::style_subtext()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::style_border());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let bar_width = (inner.width.saturating_sub(2) / app.bench_results.len() as u16)
        .max(3)
        .min(18);

    let bars: Vec<Bar> = app
        .bench_results
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let color = if i == app.bench_selected {
                Color::Cyan
            } else if r.hw_accel {
                Color::Green
            } else {
                Color::Yellow
            };

            // Shorten name to fit bar_width
            let label = shorten_algo(&r.name, bar_width as usize);

            Bar::default()
                .value(r.multi_mb)
                .label(Line::from(label))
                .style(Style::default().fg(color))
                .value_style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
        })
        .collect();

    let group = BarGroup::default().bars(&bars);

    let max_val = app
        .bench_results
        .iter()
        .map(|r| r.multi_mb)
        .max()
        .unwrap_or(2000)
        .max(100);

    let chart = BarChart::default()
        .data(group)
        .bar_width(bar_width)
        .bar_gap(1)
        .max(max_val)
        .direction(ratatui::layout::Direction::Vertical);
    frame.render_widget(chart, inner);
}

fn shorten_algo(name: &str, max: usize) -> String {
    let s = name
        .replace("(AVX2)", "")
        .replace("(16MB Cost)", "")
        .replace("Poly1305", "Pl1305")
        .replace("ChaCha20", "CCA20")
        .replace("XChaCha20", "XCCA20")
        .trim()
        .to_string();
    if s.len() <= max {
        s
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

// ─── Latency / Throughput Matrix + Detail Panel ──────────────────────────────

fn render_matrix(frame: &mut Frame, area: Rect, app: &AppState) {
    let rows = Layout::vertical([
        Constraint::Min(0),      // Matrix table
        Constraint::Length(12),  // Selected algorithm detail card
    ])
    .split(area);

    render_matrix_table(frame, rows[0], app);
    render_detail_card(frame, rows[1], app);
}

fn render_matrix_table(frame: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("CIPHER LATENCY & INTEGRITY MATRIX", theme::style_title()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::style_border());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let header = Row::new(vec![
        Cell::from("Algorithm").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("1-Core").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("16-Core").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("Latency").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("HWACCEL").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
    ]);

    let rows: Vec<Row> = app
        .bench_results
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let row_style = if i == app.bench_selected {
                Style::default().bg(Color::Indexed(237)).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let hw = if r.hw_accel {
                Cell::from("✔ YES").style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
            } else {
                Cell::from("✖ NO").style(Style::default().fg(Color::Red))
            };

            let prefix = if i == app.bench_selected { "▶ " } else { "  " };
            let name_short = format!("{}{}", prefix, shorten_algo(&r.name, 18));

            Row::new(vec![
                Cell::from(name_short).style(if i == app.bench_selected {
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                }),
                Cell::from(format!("{} MB/s", r.single_mb)).style(Style::default().fg(Color::DarkGray)),
                Cell::from(format!("{} MB/s", r.multi_mb)).style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Cell::from(format!("{:.2}µs", r.latency_us)).style(Style::default().fg(Color::Yellow)),
                hw,
            ])
            .style(row_style)
        })
        .collect();

    let widths = [
        Constraint::Min(16),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(9),
        Constraint::Length(8),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(Style::default().bg(Color::Indexed(237)));

    frame.render_widget(table, inner);
}

fn render_detail_card(frame: &mut Frame, area: Rect, app: &AppState) {
    let sel = &app.bench_results[app.bench_selected];

    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("SELECTED ALGORITHM DETAIL", theme::style_title()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Magenta));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let hw_str = if sel.hw_accel { "AES-NI + AVX2 vectorised lanes" } else { "Software fallback (no SIMD)" };
    let nist_std = match sel.name.as_str() {
        n if n.contains("AES-256-GCM")   => "NIST SP800-38D (256-bit AEAD)",
        n if n.contains("ChaCha20")       => "RFC 8439 (256-bit stream cipher)",
        n if n.contains("XChaCha20")      => "192-bit extended nonce variant",
        n if n.contains("AES-256-CTR")    => "NIST SP800-38A high-throughput",
        n if n.contains("Argon2id")       => "RFC 9106 memory-hard KDF",
        _                                 => "N/A",
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("  Algorithm    : ", theme::style_subtext()),
            Span::styled(sel.name.clone(), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  NIST Standard: ", theme::style_subtext()),
            Span::styled(nist_std, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  1-Core  MB/s : ", theme::style_subtext()),
            Span::styled(format!("{} MB/s", sel.single_mb), Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled("  16-Core MB/s : ", theme::style_subtext()),
            Span::styled(
                format!("{} MB/s", sel.multi_mb),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Latency (µs) : ", theme::style_subtext()),
            Span::styled(format!("{:.2} µs", sel.latency_us), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled("  HW Accel     : ", theme::style_subtext()),
            Span::styled(hw_str, if sel.hw_accel { theme::style_neon() } else { theme::style_dim() }),
        ]),
    ];

    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        inner,
    );
}
