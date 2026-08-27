// ui/system.rs — 3-Card System Diagnostics: Host & Runtime | Hardware Monitors |
//               Cryptographic Engine Capability Flags
use crate::app::AppState;
use crate::ui::theme;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Gauge, Paragraph, Row, Table},
    Frame,
};

pub fn render_system(frame: &mut Frame, area: Rect, app: &AppState) {
    // Top row: two cards side by side; bottom row: one full-width crypto card
    let rows = Layout::vertical([
        Constraint::Percentage(50),
        Constraint::Percentage(50),
    ])
    .split(area);

    let top_cols = Layout::horizontal([
        Constraint::Percentage(50),
        Constraint::Percentage(50),
    ])
    .split(rows[0]);

    render_host_card(frame, top_cols[0], app);
    render_hardware_monitors(frame, top_cols[1], app);
    render_crypto_flags(frame, rows[1], app);
}

// ─── Card 1: Host & Environment ──────────────────────────────────────────────

fn render_host_card(frame: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("HOST ENVIRONMENT & RUNTIME", theme::style_title()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::style_border());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows_data: &[(&str, &str, Color)] = &[
        ("Operating System", &app.sys_os,     Color::White),
        ("Architecture",     &app.sys_arch,   Color::Cyan),
        ("Kernel Version",   &app.sys_kernel, Color::White),
        ("CPU",              &app.sys_cpu,    Color::Yellow),
        ("Compiler",         "GCC 14 / Clang 19 (C++20)", Color::Green),
        ("Rustc",            &app.sys_rustc,  Color::Indexed(214)),
        ("Crypto Engine",    "OpenSSL 3.0 Native EVP", Color::Magenta),
        ("Binary Install",   "/usr/local/bin/torcrypt", Color::Cyan),
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

    let widths = [Constraint::Length(18), Constraint::Min(0)];
    let table = Table::new(rows, widths).column_spacing(2);
    frame.render_widget(table, inner);
}

// ─── Card 2: Hardware Resource Monitors ──────────────────────────────────────

fn render_hardware_monitors(frame: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("HARDWARE LOAD MONITOR", theme::style_title()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::style_border());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let ram_pct = ((app.ram_used_gb / app.ram_total_gb) * 100.0) as u16;

    let sub_rows = Layout::vertical([
        Constraint::Length(1),   // CPU label
        Constraint::Length(1),   // CPU bar
        Constraint::Length(1),   // gap
        Constraint::Length(1),   // RAM label
        Constraint::Length(1),   // RAM bar
        Constraint::Length(1),   // gap
        Constraint::Min(0),      // per-core mini bars
    ])
    .split(inner);

    // CPU label
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("CPU Utilization: ", theme::style_subtext()),
            Span::styled(
                format!("{}% across {} cores", app.cpu_usage_pct, app.thread_count),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
        ])),
        sub_rows[0],
    );

    // CPU Gauge
    let cpu_gauge = Gauge::default()
        .gauge_style(Style::default().fg(Color::Cyan).bg(Color::Indexed(237)))
        .percent(app.cpu_usage_pct as u16)
        .label(format!("{}%", app.cpu_usage_pct));
    frame.render_widget(cpu_gauge, sub_rows[1]);

    // RAM label
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("RAM Allocated:   ", theme::style_subtext()),
            Span::styled(
                format!("{:.1} GB / {:.0} GB  ({ram_pct}%)", app.ram_used_gb, app.ram_total_gb),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
        ])),
        sub_rows[3],
    );

    // RAM Gauge
    let ram_gauge = Gauge::default()
        .gauge_style(Style::default().fg(Color::Green).bg(Color::Indexed(237)))
        .percent(ram_pct)
        .label(format!("{ram_pct}%"));
    frame.render_widget(ram_gauge, sub_rows[4]);

    // Per-core utilisation mini bars
    let core_area = sub_rows[6];
    let core_count = app.thread_count as usize;
    if core_area.height > 0 && core_count > 0 {
        let per_core_rows: Vec<Constraint> = (0..core_count.min(core_area.height as usize))
            .map(|_| Constraint::Length(1))
            .collect();

        let core_rects = Layout::vertical(per_core_rows).split(core_area);

        // Simulate per-core loads with deterministic variation
        let base = app.cpu_usage_pct as u64;
        for (i, &core_rect) in core_rects.iter().enumerate() {
            let load = ((base + (i as u64 * 7) % 40) % 100) as usize;
            let color = if load > 80 { Color::Red }
                else if load > 60  { Color::Yellow }
                else               { Color::Green };

            let total_bar_w = (core_rect.width as usize).saturating_sub(18).max(4);
            let filled_w = (load * total_bar_w) / 100;
            let empty_w = total_bar_w.saturating_sub(filled_w);

            let gauge = Paragraph::new(Line::from(vec![
                Span::styled(
                    format!(" Core {:>2}: {:>3}%  ", i, load),
                    theme::style_subtext(),
                ),
                Span::styled("█".repeat(filled_w), Style::default().fg(color)),
                Span::styled("░".repeat(empty_w), theme::style_dim()),
            ]));
            frame.render_widget(gauge, core_rect);
        }
    }
}

// ─── Card 3: Cryptographic Engine Capabilities (Full-Width) ──────────────────

fn render_crypto_flags(frame: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("HARDWARE CRYPTOGRAPHIC CAPABILITIES", theme::style_title()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::style_border());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let cols = Layout::horizontal([
        Constraint::Percentage(50),
        Constraint::Percentage(50),
    ])
    .split(inner);

    let flags_left: &[(&str, bool, &str)] = &[
        ("AES-NI Acceleration",    app.aes_ni,  "Native hardware AES-GCM encryption & key schedule"),
        ("AVX2 Vectorization",     app.avx2,    "256-bit SIMD lane dispatch for ChaCha20 / Poly1305"),
        ("RDRAND Hardware Entropy", app.rdrand, "On-die DRNG — cryptographically secure random numbers"),
        ("VAES-512 Pipeline",      app.vaes512, "CPU Architecture fallback: 256-bit AES-NI active"),
    ];

    let flags_right: &[(&str, &str, Color)] = &[
        ("Cipher Backend",     "OpenSSL 3.0 EVP (native)",         Color::Magenta),
        ("KDF Algorithms",     "Argon2id · PBKDF2 · BLAKE3",       Color::White),
        ("Key Storage",        "Locked mmap (mlock/mprotect)",      Color::Cyan),
        ("Side-Channel Guard", "Constant-time comparisons (CT)",    Color::Green),
        ("HMAC Integrity",     "SHA-512 / BLAKE2b per chunk",       Color::White),
        ("Session Storage",    "SQLite3 (WAL mode, 64-page cache)",   Color::Yellow),
    ];

    let left_rows: Vec<Row> = flags_left
        .iter()
        .map(|(name, enabled, desc)| {
            let (badge, style) = if *enabled {
                ("ENABLED ✔", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
            } else {
                ("DISABLED ✖", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
            };
            Row::new(vec![
                Cell::from(*name).style(theme::style_subtext()),
                Cell::from(badge).style(style),
                Cell::from(*desc).style(theme::style_dim()),
            ])
        })
        .collect();

    let left_widths = [
        Constraint::Length(24),
        Constraint::Length(12),
        Constraint::Min(0),
    ];
    let left_table = Table::new(left_rows, left_widths)
        .column_spacing(1)
        .header(
            Row::new(vec![
                Cell::from("Feature").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
                Cell::from("Status").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
                Cell::from("Notes").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
            ])
        );
    frame.render_widget(left_table, cols[0]);

    let right_rows: Vec<Row> = flags_right
        .iter()
        .map(|(k, v, c)| {
            Row::new(vec![
                Cell::from(*k).style(theme::style_subtext()),
                Cell::from(*v).style(Style::default().fg(*c).add_modifier(Modifier::BOLD)),
            ])
        })
        .collect();

    let right_widths = [Constraint::Length(22), Constraint::Min(0)];
    let right_table = Table::new(right_rows, right_widths)
        .column_spacing(2)
        .header(
            Row::new(vec![
                Cell::from("Component").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
                Cell::from("Implementation").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
            ])
        );
    frame.render_widget(right_table, cols[1]);
}
