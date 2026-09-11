// ui/analyze.rs — [Tab 1] Interactive File Selector & Smart Decryption Analyzer with Leveled Wordlist Attack Profiles
use crate::app::{AppState, ComputeEngine};
use crate::ui::theme;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Cell, Gauge, Paragraph, Row, Table,
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
        Span::styled(" [PATH] ", theme::style_subtext()),
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
    let name_max_len = rows[1].width.saturating_sub(26).max(20) as usize;

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
                Cell::from(truncate(&entry.name, name_max_len)).style(name_style),
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

    app.file_table_state.select(Some(sel));
    let table = Table::new(table_rows, widths)
        .block(table_block)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(Style::default().bg(Color::Indexed(237)));

    frame.render_stateful_widget(table, rows[1], &mut app.file_table_state);

    // Register clickable file rows synchronized with table scroll offset
    let offset = app.file_table_state.offset();
    let visible_rows = rows[1].height.saturating_sub(2) as usize; // border + header
    let data_start_y = rows[1].y + 2;
    for i in 0..visible_rows {
        let file_idx = offset + i;
        if file_idx >= app.dir_entries.len() { break; }
        let row_y = data_start_y + i as u16;
        if row_y >= rows[1].y + rows[1].height.saturating_sub(1) { break; }
        app.click_regions.push((
            ratatui::layout::Rect::new(rows[1].x + 1, row_y, rows[1].width.saturating_sub(2), 1),
            crate::app::ClickAction::SelectFile(file_idx),
        ));
    }
}

// ─── RIGHT COLUMN: Smart Decryption Analysis & Launcher Card ──────────────────

fn render_smart_inspector(frame: &mut Frame, area: Rect, app: &mut AppState) {
    let rows = Layout::vertical([
        Constraint::Length(10), // Container & Engine Inspection Deck
        Constraint::Min(0),     // Attack Strategy Recommender & Execution Launcher
    ])
    .split(area);

    render_inspection_report(frame, rows[0], app);
    render_attack_launcher(frame, rows[1], app);
}

fn render_inspection_report(frame: &mut Frame, area: Rect, app: &mut AppState) {
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
        ("LOCKED CONTAINER / CAPTURE", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
    } else if a.mime_type.contains("Directory") {
        ("DIRECTORY / FOLDER", Style::default().fg(Color::Cyan))
    } else {
        ("UNENCRYPTED / PLAINTEXT", Style::default().fg(Color::DarkGray))
    };

    let entropy_pct = ((a.entropy / 8.0) * 100.0).clamp(0.0, 100.0) as u16;

    let engine_badge = match a.recommended_engine {
        ComputeEngine::GpuPrimary  => (format!("GPU ({})", app.sys_gpu_name), Color::Green),
        ComputeEngine::Hybrid      => (format!("HYBRID ({} + {})", app.sys_cpu, app.sys_gpu_name), Color::Cyan),
        ComputeEngine::CpuSimd     => (format!("CPU ({})", app.sys_cpu), Color::Yellow),
        ComputeEngine::TlsKeylog   => ("TLS 1.3 KEYLOG STREAM DECRYPTOR".into(), Color::Green),
        ComputeEngine::PcapInspect => ("PCAP PROTOCOL CREDENTIAL EXTRACTOR".into(), Color::Cyan),
    };

    let resolved = if a.ready_to_crack {
        app.backend_catalog.resolve_backend(
            app.backend_selection,
            std::path::Path::new(&a.file_path),
            &a.lock_type,
            a.ready_to_crack,
        )
    } else {
        crate::engine::backends::BackendType::None
    };

    use crate::engine::backends::BackendSelection;
    let mut engine_spans = vec![Span::styled("  Engine: ", theme::style_subtext())];

    let pill_defs: [(BackendSelection, &str); 5] = [
        (BackendSelection::Auto, "[Auto]"),
        (BackendSelection::Hashcat, "[Hashcat]"),
        (BackendSelection::John, "[John]"),
        (BackendSelection::Fcrackzip, "[fcrackzip]"),
        (BackendSelection::Native, "[Native]"),
    ];

    let engine_row_y = inner.y + 4; // 5th row inside inner block
    let mut cur_pill_x = inner.x + 10;

    for (sel, label) in pill_defs {
        let is_sel = app.backend_selection == sel;
        let style = if is_sel {
            Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Cyan).bg(Color::Indexed(237))
        };
        engine_spans.push(Span::styled(format!(" {} ", label), style));
        engine_spans.push(Span::raw(" "));

        let pill_w = (label.len() + 2) as u16;
        app.click_regions.push((
            ratatui::layout::Rect::new(cur_pill_x, engine_row_y, pill_w, 1),
            crate::app::ClickAction::SelectEnginePill(sel),
        ));
        cur_pill_x += pill_w + 1;
    }

    engine_spans.push(Span::styled("[E: Modal]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    app.click_regions.push((
        ratatui::layout::Rect::new(cur_pill_x, engine_row_y, 10, 1),
        crate::app::ClickAction::OpenEngineModal,
    ));

    let lines = vec![
        Line::from(vec![
            Span::styled("  Target Path   : ", theme::style_subtext()),
            Span::styled(truncate(&a.file_path, inner.width.saturating_sub(18) as usize),
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Container Type: ", theme::style_subtext()),
            Span::styled(a.mime_type.clone(), Style::default().fg(Color::White)),
            Span::styled("  │ Size: ", theme::style_subtext()),
            Span::styled(fmt_file_size(a.file_size), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Magic Header  : ", theme::style_subtext()),
            Span::styled(a.magic_header.clone(), Style::default().fg(Color::Magenta)),
            Span::styled("  │ Status: ", theme::style_subtext()),
            Span::styled(lock_badge, lock_style),
        ]),
        Line::from(vec![
            Span::styled("  Detected Crypt: ", theme::style_subtext()),
            Span::styled(a.lock_type.clone(),
                if a.is_encrypted { Style::default().fg(Color::Green).add_modifier(Modifier::BOLD) } else { theme::style_dim() }),
            Span::styled(format!("  (Entropy: {:.2}/8.00 bits) ", a.entropy), theme::style_subtext()),
        ]),
        Line::from(engine_spans),
    ];

    let content_layout = Layout::vertical([
        Constraint::Length(5), // Metadata lines (5 rows)
        Constraint::Min(0),    // Entropy gauge
    ])
    .split(inner);

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), content_layout[0]);

    let entropy_gauge = Gauge::default()
        .gauge_style(
            Style::default()
                .fg(if a.entropy > 7.5 { Color::Green } else if a.entropy > 5.0 { Color::Yellow } else { Color::Cyan })
                .bg(Color::Indexed(237)),
        )
        .percent(entropy_pct.min(100))
        .label(format!("{:.2} bits/byte entropy", a.entropy));

    frame.render_widget(entropy_gauge, content_layout[1]);
}

fn render_engine_selector_card(frame: &mut Frame, area: Rect, app: &mut AppState) {
    let a = &app.analysis;
    let rec = app.backend_catalog.suggest_backend(
        std::path::Path::new(&a.file_path),
        &a.lock_type,
        a.ready_to_crack,
    );
    let resolved = if a.ready_to_crack {
        app.backend_catalog.resolve_backend(
            app.backend_selection,
            std::path::Path::new(&a.file_path),
            &a.lock_type,
            a.ready_to_crack,
        )
    } else {
        crate::engine::backends::BackendType::None
    };

    let title_line = Line::from(vec![
        Span::raw("─ ◈ "),
        Span::styled("DECRYPTION ENGINE AUTO-RECOMMENDER & SELECTOR", theme::style_title()),
        Span::styled("  [Press ", theme::style_subtext()),
        Span::styled("E", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled(" to choose] ", theme::style_subtext()),
        Span::styled(format!("(Active: {}) ", resolved.short_name()), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
    ]);

    let block = Block::default()
        .title(title_line)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(if a.ready_to_crack { Style::default().fg(Color::Cyan) } else { theme::style_border() });
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if !a.ready_to_crack {
        let p = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("  Select an encrypted file on the left to see compatible decryption engines and recommendations.", theme::style_subtext()),
            ]),
        ]);
        frame.render_widget(p, inner);
        return;
    }

    let cat = &app.backend_catalog;
    let mut engines = vec![
        (crate::engine::backends::BackendType::Hashcat, cat.has_hashcat()),
        (crate::engine::backends::BackendType::John, cat.has_john()),
    ];
    if cat.has_fcrackzip() && (a.file_path.ends_with(".zip") || a.lock_type.to_lowercase().contains("zip")) {
        engines.push((crate::engine::backends::BackendType::Fcrackzip, true));
    }
    engines.push((crate::engine::backends::BackendType::Native, a.ready_to_crack));

    let rows: Vec<Row> = engines
        .into_iter()
        .map(|(btype, installed)| {
            let is_active = resolved == btype;
            let is_rec = rec.suggested == btype;

            let cursor = if is_active {
                Cell::from(" ▶ ACTIVE ").style(Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD))
            } else {
                Cell::from("   ────── ").style(theme::style_dim())
            };

            let name_cell = Cell::from(btype.display_name()).style(
                if is_active {
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                }
            );

            let status_cell = if installed {
                Cell::from("INSTALLED").style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
            } else {
                Cell::from("NOT DETECTED").style(Style::default().fg(Color::DarkGray))
            };

            let rec_cell = if is_rec {
                Cell::from(format!("[RECOMMENDED] {}", rec.reason))
                    .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            } else {
                Cell::from("").style(theme::style_dim())
            };

            Row::new(vec![cursor, name_cell, status_cell, rec_cell])
        })
        .collect();

    // ── 4-pill engine selector bar ──────────────────────────────────────────────
    use crate::engine::backends::BackendSelection;
    let layout = Layout::vertical([
        Constraint::Length(1), // pill bar
        Constraint::Min(0),    // detail table
    ])
    .split(inner);

    let pill_options: [(BackendSelection, &str, bool); 4] = [
        (BackendSelection::Auto,    " [1] Auto    ", true),
        (BackendSelection::Hashcat, " [2] Hashcat ", cat.has_hashcat()),
        (BackendSelection::John,    " [3] John    ", cat.has_john()),
        (BackendSelection::Native,  " [4] Native  ", true),
    ];
    let pills: Vec<Span> = pill_options.iter().map(|(sel, label, avail)| {
        let active = app.backend_selection == *sel;
        if active {
            Span::styled(*label, Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD))
        } else if *avail {
            Span::styled(*label, Style::default().fg(Color::Cyan))
        } else {
            Span::styled(*label, theme::style_dim())
        }
    }).collect();
    let mut pill_spans = vec![Span::styled("  ENGINE: ", theme::style_subtext())];
    pill_spans.extend(pills);
    pill_spans.push(Span::styled("  [E] Open picker", theme::style_subtext()));
    frame.render_widget(Paragraph::new(Line::from(pill_spans)), layout[0]);
    // Register pill click regions — "  ENGINE: " is 10 chars, each pill label is fixed width
    let pill_label_widths: [(BackendSelection, u16); 4] = [
        (BackendSelection::Auto,    13), // " [1] Auto    "
        (BackendSelection::Hashcat, 13), // " [2] Hashcat "
        (BackendSelection::John,    13), // " [3] John    "
        (BackendSelection::Native,  13), // " [4] Native  "
    ];
    let mut pill_x = layout[0].x + 10; // skip "  ENGINE: "
    for (sel, w) in &pill_label_widths {
        app.click_regions.push((
            ratatui::layout::Rect::new(pill_x, layout[0].y, *w, 1),
            crate::app::ClickAction::SelectEnginePill(*sel),
        ));
        pill_x += w;
    }
    // The "[E] Open picker" text registers the whole remaining area as modal opener
    app.click_regions.push((
        ratatui::layout::Rect::new(pill_x, layout[0].y, layout[0].width.saturating_sub(pill_x - layout[0].x), 1),
        crate::app::ClickAction::OpenEngineModal,
    ));

    let widths = [
        Constraint::Length(11),
        Constraint::Length(34),
        Constraint::Length(15),
        Constraint::Min(0),
    ];
    let table = Table::new(rows, widths).column_spacing(1);
    frame.render_widget(table, layout[1]);

}

fn render_attack_launcher(frame: &mut Frame, area: Rect, app: &mut AppState) {
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
            Line::from(vec![
                Span::styled("    • Decryption GUI Backend (Press ", theme::style_subtext()),
                Span::styled("[E]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(" to choose engine — ", theme::style_subtext()),
                Span::styled(app.backend_selection.display_name(), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(format!(" │ Detected: {}", app.backend_catalog.summary()), theme::style_subtext()),
            ]),
        ]);
        frame.render_widget(p, inner);
        return;
    }

    let sub_sections = Layout::vertical([
        Constraint::Min(0),     // Strategies
        Constraint::Length(3),  // Big Launch Button
    ])
    .split(inner);

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
            Span::styled(format!(" ▶ Tier {} ", i + 1), Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(format!("   Tier {} ", i + 1), Style::default().fg(Color::DarkGray).bg(Color::Indexed(237)))
        };
        let rec_badge = if opt.is_auto_recommended {
            Span::styled(" [AUTO-RECOMMENDED]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
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

        let title_max = sub_sections[0].width.saturating_sub(24).max(15) as usize;
        strat_lines.push(Line::from(vec![
            pill,
            Span::styled(format!(" {}", truncate(&opt.title, title_max)), title_style),
            rec_badge,
        ]));

        let desc_text = format!("      ↳ Feasibility: {} │ Keyspace: {} │ {}", opt.feasibility, opt.keyspace_name, opt.desc);
        let desc_max = sub_sections[0].width.saturating_sub(4).max(20) as usize;
        strat_lines.push(Line::from(vec![
            Span::styled(truncate(&desc_text, desc_max), desc_style),
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
    let resolved = app.backend_catalog.resolve_backend(
        app.backend_selection,
        std::path::Path::new(&app.analysis.file_path),
        &app.analysis.lock_type,
        app.analysis.ready_to_crack,
    );
    let rec = app.backend_catalog.suggest_backend(
        std::path::Path::new(&app.analysis.file_path),
        &app.analysis.lock_type,
        app.analysis.ready_to_crack,
    );
    let is_rec = resolved == rec.suggested;

    let mut spans = vec![
        Span::styled(" [A / Space] ", Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" Launch via {} ", resolved.short_name()), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
    ];
    if is_rec {
        spans.push(Span::styled(" [RECOMMENDED] ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    }
    spans.push(Span::styled(format!("({}) ", active_label), Style::default().fg(Color::White)));
    spans.push(Span::styled(" │ [E] Engine: ", theme::style_subtext()));
    spans.push(Span::styled(format!("{} ", app.backend_selection.short_name()), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    spans.push(Span::styled(" │ [T] Cascade: ", theme::style_subtext()));
    spans.push(if app.auto_cascade {
        Span::styled("ON", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("OFF", theme::style_dim())
    });
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
    // Register attack option click regions (each option = 3 lines: title, desc, blank)
    // strat_lines[0] = header text, strat_lines[1] = blank → data starts at line 2
    if app.analysis.ready_to_crack {
        let data_y = sub_sections[0].y + 2; // 2 header lines
        for i in 0..app.attack_options.len() {
            let row_y = data_y + (i as u16) * 3;
            if row_y >= sub_sections[0].y + sub_sections[0].height { break; }
            app.click_regions.push((
                ratatui::layout::Rect::new(sub_sections[0].x, row_y, sub_sections[0].width, 2),
                crate::app::ClickAction::SelectAttack(i),
            ));
        }
        // Launch button is the whole sub_sections[1] block
        app.click_regions.push((sub_sections[1], crate::app::ClickAction::LaunchAttack));
    }
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

    let feas = crate::engine::feasibility::estimate_feasibility(mask.total, &app.analysis.lock_type, app.sys_gpu_available);
    let est_time_str = feas.human_duration;

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
