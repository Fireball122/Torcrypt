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

    if app.mask_modal_open {
        render_mask_modal(frame, area, app);
    }
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

    let mut title_spans = vec![
        Span::raw("─ ◈ "),
        Span::styled("FILE SELECTOR", theme::style_title()),
        Span::styled(format!("  ({} items) ", app.dir_entries.len()), theme::style_subtext()),
    ];
    if let Some(wl) = &app.custom_wordlist {
        let wl_name = wl.file_name().unwrap_or_default().to_string_lossy();
        title_spans.push(Span::styled(
            format!(" [WL: {}] ", wl_name),
            Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD),
        ));
    }
    let table_block = Block::default()
        .title(Line::from(title_spans))
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
            Span::styled("  Execution Route: ", theme::style_subtext()),
            Span::styled(
                if !a.is_encrypted {
                    "INSPECTION ONLY (No password required)"
                } else if a.ready_to_crack {
                    if a.lock_type.contains("ZipCrypto")
                        || a.lock_type.contains("WinZip")
                        || a.lock_type.contains("PDF")
                        || a.lock_type.contains("RAR5")
                        || a.lock_type.contains("7-Zip")
                        || a.lock_type.contains("KeePass")
                        || a.lock_type.contains("MD5")
                        || a.lock_type.contains("SHA-1")
                        || a.lock_type.contains("SHA-256")
                        || a.lock_type.contains("NTLM")
                    {
                        "✔ NATIVE VERIFIED (In-process cryptographic engine)"
                    } else {
                        "⚙ EXTERNAL DELEGATION (Hashcat / John the Ripper)"
                    }
                } else {
                    "✖ NOT CRACKABLE IN-PROCESS (Requires external extractor tool)"
                },
                if !a.is_encrypted {
                    Style::default().fg(Color::DarkGray)
                } else if a.ready_to_crack {
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                },
            ),
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
        Constraint::Length(8), // Metadata lines (8 rows)
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

    let mut strat_lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("  Select Attack Strategy / Tool Profile  ", theme::style_subtext()),
            Span::styled("[Tab]", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(" to cycle  │  ", theme::style_subtext()),
            Span::styled("[1-6]", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(" direct jump:", theme::style_subtext()),
        ]),
        Line::from(vec![Span::raw("")]),
    ];

    for (i, opt) in app.attack_options.iter().enumerate() {
        let is_active = i == app.attack_selected;
        let pill = if is_active {
            Span::styled(format!(" ▶ [{}] ", i + 1), Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(format!("   [{}] ", i + 1), Style::default().fg(Color::DarkGray).bg(Color::Indexed(237)))
        };
        let rec_badge = if opt.is_auto_recommended {
            Span::styled(" ⚡(AUTO-RECOMMENDED)", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
        } else {
            Span::raw("")
        };
        let title_style = if is_active {
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        let desc_style = if is_active {
            Style::default().fg(Color::Cyan)
        } else {
            theme::style_dim()
        };

        strat_lines.push(Line::from(vec![
            pill,
            Span::styled(format!(" {}", opt.title), title_style),
            rec_badge,
        ]));
        strat_lines.push(Line::from(vec![
            Span::styled(format!("      ↳ Feasibility: {} │ Keyspace: {} │ {}", opt.feasibility, opt.keyspace_name, opt.desc), desc_style),
        ]));
        strat_lines.push(Line::from(vec![Span::raw("")]));
    }

    // Wordlist status notice — warn honestly when only the embedded 600-entry list is available.
    use crate::engine::crackers::generator::CandidateIterator;
    let wl_line = if app.custom_wordlist.is_some() {
        let wl_name = app.custom_wordlist.as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        Line::from(vec![
            Span::styled("  ◈ Wordlist: ", theme::style_subtext()),
            Span::styled(format!("Custom → {}", wl_name), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        ])
    } else if let Some(path) = CandidateIterator::system_wordlist_path() {
        Line::from(vec![
            Span::styled("  ◈ Wordlist: ", theme::style_subtext()),
            Span::styled(format!("System → {}", path), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ])
    } else {
        Line::from(vec![
            Span::styled("  ⚠ Wordlist: ", Style::default().fg(Color::Yellow)),
            Span::styled("Embedded 600-entry list only — install rockyou.txt or press [W] to load a custom wordlist for real-world coverage.", Style::default().fg(Color::Yellow)),
        ])
    };
    strat_lines.push(wl_line);

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

    let active_label = if !app.attack_options.is_empty() && app.attack_selected < app.attack_options.len() {
        app.attack_options[app.attack_selected].title.clone()
    } else {
        "SELECTED STRATEGY".into()
    };

    let checkpoint = app.session_db.as_ref().and_then(|db| db.get_latest_checkpoint(&app.analysis.file_path));
    let mut spans = vec![
        Span::styled(" [A / Space] ", Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" Launch {} ", active_label), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
    ];
    if let Some((ses_id, offset)) = checkpoint {
        spans.push(Span::styled(" │ ", theme::style_dim()));
        spans.push(Span::styled(" [R] ", Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)));
        spans.push(Span::styled(format!(" Resume {} @ #{} ", ses_id, fmt_number(offset)), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    }
    spans.push(Span::styled(" │ ", theme::style_dim()));
    spans.push(Span::styled(" [M] ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)));
    spans.push(Span::styled(" Custom Mask ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));

    let launch_p = Paragraph::new(Line::from(spans))
        .alignment(ratatui::layout::Alignment::Center)
        .block(launch_block);

    frame.render_widget(launch_p, sub_sections[1]);
}
// ─── Helpers ─────────────────────────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> String {
    crate::ui::truncate(s, max)
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

fn render_mask_modal(frame: &mut Frame, area: Rect, app: &AppState) {
    let popup_area = centered_rect(65, 45, area);
    frame.render_widget(ratatui::widgets::Clear, popup_area);

    let mask = crate::engine::crackers::generator::CompiledMask::parse(&app.mask_input);
    let keyspace_str = fmt_number(mask.total);

    let est_time_secs = (mask.total as f64) / (if app.sys_gpu_available { 40_000.0 } else { 4_000.0 });
    let est_time_str = if est_time_secs < 1.0 {
        "< 1 second".to_string()
    } else if est_time_secs < 60.0 {
        format!("{:.1} seconds", est_time_secs)
    } else if est_time_secs < 3600.0 {
        format!("{:.1} minutes", est_time_secs / 60.0)
    } else {
        format!("{:.1} hours", est_time_secs / 3600.0)
    };

    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("─ ◈ "),
            Span::styled("CUSTOM RECOVERY MASK COMPILER", theme::style_title()),
            Span::raw(" "),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let rows = Layout::vertical([
        Constraint::Length(3), // Input box
        Constraint::Length(2), // Keyspace & time stats
        Constraint::Length(4), // Token legend
        Constraint::Min(0),    // Action hints
    ])
    .split(inner);

    let input_p = Paragraph::new(Line::from(vec![
        Span::styled(" Template: ", theme::style_subtext()),
        Span::styled(&app.mask_input, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled("█", Style::default().fg(Color::Cyan)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(input_p, rows[0]);

    let stats_p = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(" Keyspace: ", theme::style_subtext()),
            Span::styled(format!("{} candidates", keyspace_str), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled("  │ Est. Time: ", theme::style_subtext()),
            Span::styled(est_time_str, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]),
    ]);
    frame.render_widget(stats_p, rows[1]);

    let legend_p = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(" ?d: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled("0-9 (10)  ", theme::style_subtext()),
            Span::styled("?l: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled("a-z (26)  ", theme::style_subtext()),
            Span::styled("?u: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled("A-Z (26)  ", theme::style_subtext()),
        ]),
        Line::from(vec![
            Span::styled(" ?s: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled("Symbols (33)  ", theme::style_subtext()),
            Span::styled("?a: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled("All ASCII (95)  ", theme::style_subtext()),
            Span::styled("Literal: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled("e.g. Pass?d?d!", theme::style_subtext()),
        ]),
    ]);
    frame.render_widget(legend_p, rows[2]);

    let actions = Paragraph::new(Line::from(vec![
        Span::styled(" [Enter] ", Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(" Launch Mask Attack    ", theme::style_title()),
        Span::styled(" [Esc] ", Style::default().fg(Color::Black).bg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::styled(" Cancel", theme::style_subtext()),
    ]));
    frame.render_widget(actions, rows[3]);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(r);

    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(popup_layout[1])[1]
}

fn fmt_number(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { out.push(','); }
        out.push(c);
    }
    out.chars().rev().collect()
}
