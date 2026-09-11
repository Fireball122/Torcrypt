// src/ui/engine_modal.rs — Decryption Engine Picker Modal (Auto, Hashcat, John, Native)
use crate::app::AppState;
use crate::engine::backends::BackendSelection;
use crate::ui::theme;
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table},
    Frame,
};

pub fn render_engine_modal(frame: &mut Frame, area: Rect, app: &mut AppState) {
    let modal_w = (area.width as f32 * 0.78).round().clamp(50.0, 92.0) as u16;
    let modal_h = 16u16.min(area.height.saturating_sub(2));
    let x       = area.x + (area.width.saturating_sub(modal_w)) / 2;
    let y       = area.y + (area.height.saturating_sub(modal_h)) / 2;

    let modal_rect = Rect::new(x, y, modal_w, modal_h);
    frame.render_widget(Clear, modal_rect);

    let block = Block::default()
        .title(Line::from(vec![
            Span::raw(" ─ ◈ "),
            Span::styled("CHOOSE DECRYPTION ENGINE", theme::style_title()),
            Span::styled("  [Press 1-5 or Enter] ", theme::style_dim()),
        ]))
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(modal_rect);
    frame.render_widget(block, modal_rect);

    let cat = &app.backend_catalog;
    let rec = cat.suggest_backend(
        std::path::Path::new(&app.analysis.file_path),
        &app.analysis.lock_type,
        app.analysis.ready_to_crack,
    );

    let options = [
        (
            1,
            BackendSelection::Auto,
            "Auto-detect best engine based on file format",
            format!("Resolves to: {}", rec.suggested.short_name()),
            true,
        ),
        (
            2,
            BackendSelection::Hashcat,
            "GPU / OpenCL / CUDA accelerator (fastest candidate throughput)",
            if cat.has_hashcat() { "INSTALLED" } else { "NOT DETECTED" }.into(),
            cat.has_hashcat(),
        ),
        (
            3,
            BackendSelection::John,
            "John the Ripper Multi-Core SIMD & Jumbo container formats",
            if cat.has_john() { "INSTALLED" } else { "NOT DETECTED" }.into(),
            cat.has_john(),
        ),
        (
            4,
            BackendSelection::Fcrackzip,
            "fcrackzip dedicated optimized ZIP cracking utility",
            if cat.has_fcrackzip() { "INSTALLED" } else { "NOT DETECTED" }.into(),
            cat.has_fcrackzip(),
        ),
        (
            5,
            BackendSelection::Native,
            "Built-in pure-Rust AVX2 in-process verification engine",
            "AVAILABLE".into(),
            true,
        ),
    ];

    let rows: Vec<Row> = options
        .iter()
        .enumerate()
        .map(|(i, (num, sel, desc, status, avail))| {
            let is_selected = app.backend_selection == *sel;
            let is_cursor = app.engine_modal_selected == i;

            let radio = if is_selected {
                Span::styled("(•)", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
            } else {
                Span::styled("( )", theme::style_dim())
            };

            let key_badge = Span::styled(
                format!(" [{}] ", num),
                if is_cursor {
                    Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                },
            );

            let name_str = sel.short_name();
            let name_span = Span::styled(
                format!("{:<9}", name_str),
                if is_selected {
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                },
            );

            let desc_span = Span::styled(desc.to_string(), theme::style_subtext());

            let status_span = Span::styled(
                format!("[{}]", status),
                if *avail {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::DarkGray)
                },
            );

            let rec_span = if *sel == BackendSelection::Auto || rec.suggested.short_name() == name_str {
                Span::styled(" [RECOMMENDED]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            } else {
                Span::raw("")
            };

            let line1 = Line::from(vec![
                Span::raw("  "),
                radio,
                Span::raw(" "),
                key_badge,
                Span::raw(" "),
                name_span,
                Span::raw(" "),
                status_span,
                rec_span,
            ]);
            let line2 = Line::from(vec![
                Span::raw("        ↳ "),
                desc_span,
            ]);

            let row_style = if is_cursor {
                Style::default().bg(Color::Indexed(237))
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(vec![line1, line2]),
            ])
            .style(row_style)
            .height(2)
        })
        .collect();

    let layout = Layout::vertical([
        Constraint::Length(1), // top gap
        Constraint::Length(10), // options table
        Constraint::Length(1), // instructions
    ])
    .split(inner);

    let table = Table::new(rows, [Constraint::Percentage(100)]);
    frame.render_widget(table, layout[1]);
    // Close on click anywhere in modal border (lowest priority — row regions override it)
    app.click_regions.push((modal_rect, crate::app::ClickAction::CloseModal));
    // Register clickable modal rows — each row is 2 lines tall, starting at layout[1].y
    for i in 0usize..5 {
        let row_y = layout[1].y + (i as u16) * 2;
        if row_y + 1 >= layout[1].y + layout[1].height { break; }
        app.click_regions.push((
            ratatui::layout::Rect::new(layout[1].x, row_y, layout[1].width, 2),
            crate::app::ClickAction::EngineModalRow(i),
        ));
    }

    let help_line = Line::from(vec![
        Span::styled("  Press ", theme::style_subtext()),
        Span::styled("[1-4]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" or ", theme::style_subtext()),
        Span::styled("[↑/↓] + [Enter]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" to choose │ ", theme::style_subtext()),
        Span::styled("[Esc / E]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled(" to dismiss", theme::style_subtext()),
    ]);
    let help_p = Paragraph::new(help_line).alignment(Alignment::Center);
    frame.render_widget(help_p, layout[2]);
}
