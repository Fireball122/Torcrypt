// ui/analyze.rs — [Tab 1] Interactive File Selector & Smart Decryption Analyzer with Leveled Wordlist Attack Profiles
use crate::app::{AppState, ComputeEngine};
use crate::ui::theme;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Cell, Gauge, Paragraph, Row, Table, TableState,
        Wrap,
    },
    Frame,
};

pub fn render_analyze(frame: &mut Frame, area: Rect, app: &mut AppState) {
    let cols = Layout::horizontal([
        Constraint::Percentage(45), // Left: File System Explorer
        Constraint::Percentage(55), // Right: Smart Analysis & Attack Launcher
    ])
    .split(area);

    render_file_explorer(frame, cols[0], app);
    render_smart_inspector(frame, cols[1], app);
}

// ─── LEFT COLUMN: File Explorer Table ─────────────────────────────────────────

fn render_file_explorer(frame: &mut Frame, area: Rect, app: &mut AppState) {
    let rows = Layout::vertical([
        Constraint::Length(3), // Current Directory Banner
        Constraint::Min(0),    // File / Directory List Table
    ])
    .split(area);

    let cur_path_str = app.current_dir.to_string_lossy();
    let path_block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("EXPLORER", theme::style_title()),
            Span::styled("  [← / Bksp: Back] ", theme::style_dim()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::style_border());

    let path_p = Paragraph::new(Line::from(vec![
        Span::styled(" 📁 ", Style::default()),
        Span::styled(truncate(&cur_path_str, area.width.saturating_sub(10) as usize),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    ]))
    .block(path_block);

    frame.render_widget(path_p, rows[0]);

    let table_block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("FILE SELECTOR", theme::style_title()),
            Span::styled(format!("  ({} items) ", app.dir_entries.len()), theme::style_subtext()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::style_border());

    let header = Row::new(vec![
        Cell::from("  Type").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("Name").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        Cell::from("Size").style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
    ]);

    let sel = app.file_selected_idx;
    let table_rows: Vec<Row> = app
        .dir_entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let is_sel = i == sel;
            let prefix = if is_sel { "▶ " } else { "  " };

            let type_style = if entry.is_parent {
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
            } else if entry.is_dir {
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else if entry.is_encrypted {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                theme::style_subtext()
            };

            let name_style = if is_sel {
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
            } else if entry.is_parent {
                Style::default().fg(Color::Green)
            } else if entry.is_dir {
                Style::default().fg(Color::Cyan)
            } else if entry.is_encrypted {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            let size_str = if entry.is_dir {
                "—".into()
            } else {
                fmt_file_size(entry.size_bytes)
            };

            Row::new(vec![
                Cell::from(format!("{}{}", prefix, entry.badge)).style(type_style),
                Cell::from(truncate(&entry.name, 32)).style(name_style),
                Cell::from(size_str).style(theme::style_dim()),
            ])
            .style(if is_sel {
                Style::default().bg(Color::Indexed(237)).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            })
        })
        .collect();

    let widths = [
        Constraint::Length(12),
        Constraint::Min(20),
        Constraint::Length(10),
    ];

    let mut ts = TableState::default().with_selected(Some(sel));
    let table = Table::new(table_rows, widths)
        .block(table_block)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(Style::default().bg(Color::Indexed(237)));

    frame.render_stateful_widget(table, rows[1], &mut ts);
}

// ─── RIGHT COLUMN: Smart Decryption Analysis & Launcher Card ──────────────────

fn render_smart_inspector(frame: &mut Frame, area: Rect, app: &AppState) {
    let rows = Layout::vertical([
        Constraint::Length(14), // Container Inspection Report
        Constraint::Min(0),     // Attack Recommender & Execution Launcher
    ])
    .split(area);

    render_inspection_report(frame, rows[0], app);
    render_attack_launcher(frame, rows[1], app);
}

fn render_inspection_report(frame: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("CONTAINER INSPECTION REPORT", theme::style_title()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme::style_border());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let a = &app.analysis;

    let (lock_badge, lock_style) = if a.is_encrypted {
        ("🔒 LOCKED CONTAINER / CAPTURE", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
    } else if a.mime_type.contains("Directory") {
        ("📁 DIRECTORY / FOLDER", Style::default().fg(Color::Cyan))
    } else {
        ("🔓 UNENCRYPTED / PLAINTEXT", Style::default().fg(Color::DarkGray))
    };

    let entropy_pct = ((a.entropy / 8.0) * 100.0).clamp(0.0, 100.0) as u16;

    let engine_badge = match a.recommended_engine {
        ComputeEngine::GpuPrimary  => (format!("🚀 {}", app.sys_gpu_name), Color::Green),
        ComputeEngine::Hybrid      => (format!("⚡ HYBRID ({} + {})", app.sys_cpu, app.sys_gpu_name), Color::Cyan),
        ComputeEngine::CpuSimd     => (format!("⚙ {}", app.sys_cpu), Color::Yellow),
        ComputeEngine::TlsKeylog   => ("🔑 TLS 1.3 KEYLOG STREAM DECRYPTOR".into(), Color::Green),
        ComputeEngine::PcapInspect => ("📡 PCAP PROTOCOL CREDENTIAL EXTRACTOR".into(), Color::Cyan),
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("  Target Path   : ", theme::style_subtext()),
            Span::styled(truncate(&a.file_path, inner.width.saturating_sub(18) as usize),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Container Type: ", theme::style_subtext()),
            Span::styled(a.mime_type.clone(), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  File Size     : ", theme::style_subtext()),
            Span::styled(fmt_file_size(a.file_size), Style::default().fg(Color::White)),
            Span::styled("  │ Magic Header: ", theme::style_subtext()),
            Span::styled(a.magic_header.clone(), Style::default().fg(Color::Magenta)),
        ]),
        Line::from(vec![
            Span::styled("  Lock Status   : ", theme::style_subtext()),
            Span::styled(lock_badge, lock_style),
        ]),
        Line::from(vec![
            Span::styled("  Detected Crypt: ", theme::style_subtext()),
            Span::styled(a.lock_type.clone(),
                if a.is_encrypted { Style::default().fg(Color::Green).add_modifier(Modifier::BOLD) } else { theme::style_dim() }),
        ]),
        Line::from(vec![
            Span::styled("  Auto-Router   : ", theme::style_subtext()),
            Span::styled(engine_badge.0, Style::default().fg(engine_badge.1).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled(format!("  Entropy: {:.2} / 8.00 bits ({}% Randomness) ", a.entropy, entropy_pct), theme::style_subtext()),
        ]),
    ];

    let content_layout = Layout::vertical([
        Constraint::Length(7), // Metadata lines
        Constraint::Length(1), // Entropy Gauge Bar
        Constraint::Min(0),
    ])
    .split(inner);

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), content_layout[0]);

    let entropy_gauge = Gauge::default()
        .gauge_style(
            Style::default()
                .fg(if a.entropy > 7.5 { Color::Green } else if a.entropy > 5.0 { Color::Yellow } else { Color::Cyan })
                .bg(Color::Indexed(237)),
        )
        .percent(entropy_pct)
        .label(format!("{:.2} bits/byte entropy", a.entropy));

    frame.render_widget(entropy_gauge, content_layout[1]);
}

fn render_attack_launcher(frame: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("PASSWORD LIST TIERS & DECRYPTION LAUNCHER", theme::style_title()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(if app.analysis.ready_to_crack {
            Style::default().fg(Color::Green)
        } else {
            theme::style_border()
        });
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let a = &app.analysis;

    if !a.ready_to_crack {
        let p = Paragraph::new(vec![
            Line::from(vec![Span::raw("")]),
            Line::from(vec![
                Span::styled("  ◈ Navigation & Instructions:", theme::style_subtext()),
            ]),
            Line::from(vec![
                Span::styled("    • Navigate with ", theme::style_subtext()),
                Span::styled("[J / K] or [↑ / ↓]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled(" to browse items in explorer.", theme::style_subtext()),
            ]),
            Line::from(vec![
                Span::styled("    • Press ", theme::style_subtext()),
                Span::styled("[Enter]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled(" on a directory or ", theme::style_subtext()),
                Span::styled("[← / Backspace / H]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled(" to go back.", theme::style_subtext()),
            ]),
            Line::from(vec![
                Span::styled("    • Select an encrypted file (ZIP, PCAP, PDF, RAR, AES vault) to analyze.", theme::style_subtext()),
            ]),
            Line::from(vec![
                Span::styled("    • Detected acceleration hardware: ", theme::style_subtext()),
                Span::styled(format!("{} + {}", app.sys_cpu, app.sys_gpu_name), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            ]),
        ]);
        frame.render_widget(p, inner);
        return;
    }

    // Leveled attack tiers: Level 1 (10k), Level 2 (14.34M RockYou), Level 3 (100M+ Advanced Rules/Masks)
    let tiers = [
        (
            "Level 1: High-Frequency Common (10,000 Passwords)",
            "Top 10,000 Passwords + Common Wi-Fi defaults + 4-digit PINs (Instant check)  (~0.1s - 1s)",
        ),
        (
            "Level 2: Standard Production Corpus (14,344,392 Candidates)",
            "RockYou full corpus + Best64 permutation mutation rules (General real-world use)  (~5-15s)",
        ),
        (
            "Level 3: Advanced Hardened Multi-Corpus (100,000,000+ Keyspace)",
            "Multi-corpus + Markov n-grams + Hybrid rule mutations + Custom masks + KPA  (~30-60s)",
        ),
    ];

    let mut strat_lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("  Select Password List Profile  ", theme::style_subtext()),
            Span::styled("[Tab]", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(" to cycle  │  ", theme::style_subtext()),
            Span::styled("[1-3]", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(" direct jump:", theme::style_subtext()),
        ]),
        Line::from(vec![Span::raw("")]),
    ];

    for (i, (title, desc)) in tiers.iter().enumerate() {
        let is_active = i == app.attack_selected;
        let pill = if is_active {
            Span::styled(format!(" ▶ [{}] ", title), Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(format!("   [{}] ", title), Style::default().fg(Color::DarkGray).bg(Color::Indexed(237)))
        };

        strat_lines.push(Line::from(vec![
            pill,
            Span::styled(format!("  {}", desc), if is_active { Style::default().fg(Color::White) } else { theme::style_dim() }),
        ]));
        strat_lines.push(Line::from(vec![Span::raw("")]));
    }

    let sub_sections = Layout::vertical([
        Constraint::Min(0),     // Strategies
        Constraint::Length(3),  // Big Launch Button
    ])
    .split(inner);

    frame.render_widget(Paragraph::new(strat_lines).wrap(Wrap { trim: false }), sub_sections[0]);

    let launch_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD));

    let tier_label = match app.attack_selected {
        0 => "LEVEL 1 (10K COMMON)",
        1 => "LEVEL 2 (14.3M STANDARD)",
        2 => "LEVEL 3 (100M+ ADVANCED)",
        _ => "LEVEL 2",
    };

    let launch_p = Paragraph::new(Line::from(vec![
        Span::styled(" 🚀 PRESS ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled(" [A] ", Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(" OR ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled(" [SPACE] ", Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" TO LAUNCH {} DECRYPTION PIPELINE ", tier_label), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
    ]))
    .alignment(ratatui::layout::Alignment::Center)
    .block(launch_block);

    frame.render_widget(launch_p, sub_sections[1]);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { return s.to_string(); }
    format!("{}…", &s[..max.saturating_sub(1)])
}

fn fmt_file_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}
