#![allow(dead_code, unused_variables)]
// main.rs — TORCRYPT TUI Entry Point: Crossterm raw mode + 30 FPS event loop with Interactive Log Scrolling
mod app;
pub mod engine;
mod ui;

use std::io;
use std::time::{Duration, Instant};

use app::{AppState, Tab};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers, MouseEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

fn main() -> io::Result<()> {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        original_hook(panic_info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend  = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;
    term.hide_cursor()?;

    // Drain residual startup keystrokes
    while event::poll(Duration::from_millis(50))? {
        let _ = event::read()?;
    }

    let result = run(&mut term);

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    term.show_cursor()?;
    result
}

fn run(term: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    let mut app       = AppState::default();
    let tick_rate     = Duration::from_millis(33); // 30 FPS
    let mut last_tick = Instant::now();

    loop {
        // Drain all pending telemetry events from the background decryption worker
        while let Ok(event) = app.engine.try_recv() {
            app.handle_telemetry(event);
        }

        term.draw(|frame| ui::render(frame, &mut app))?;
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }

                    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                        return Ok(());
                    }

                    if app.in_splash {
                        if key.code == KeyCode::Char('q') || key.code == KeyCode::Char('Q') {
                            return Ok(());
                        }
                        app.in_splash = false;
                        continue;
                    }

                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q')
                            if !app.search_mode && !app.show_help && !app.engine_modal_open && !app.mask_modal_open =>
                        {
                            return Ok(());
                        }
                        KeyCode::Esc => {
                            if app.engine_modal_open { app.engine_modal_open = false; }
                            else if app.mask_modal_open { app.mask_modal_open = false; }
                            else { app.show_help = false; app.search_mode = false; }
                        }
                        KeyCode::PageUp => {
                            if app.current_tab == Tab::Dashboard {
                                let max_scroll = app.log_ring.len().saturating_sub(5);
                                app.log_scroll_offset = (app.log_scroll_offset + 8).min(max_scroll);
                            }
                        }
                        KeyCode::PageDown => {
                            if app.current_tab == Tab::Dashboard {
                                app.log_scroll_offset = app.log_scroll_offset.saturating_sub(8);
                            }
                        }
                        KeyCode::Home => {
                            if app.current_tab == Tab::Dashboard {
                                let max_scroll = app.log_ring.len().saturating_sub(5);
                                app.log_scroll_offset = max_scroll;
                            }
                        }
                        KeyCode::End => {
                            if app.current_tab == Tab::Dashboard {
                                app.log_scroll_offset = 0; // Snap to bottom live stream
                            }
                        }
                        KeyCode::Enter if app.engine_modal_open => {
                            let sel = match app.engine_modal_selected {
                                0 => crate::engine::backends::BackendSelection::Auto,
                                1 => crate::engine::backends::BackendSelection::Hashcat,
                                2 => crate::engine::backends::BackendSelection::John,
                                3 => crate::engine::backends::BackendSelection::Fcrackzip,
                                _ => crate::engine::backends::BackendSelection::Native,
                            };
                            app.apply_engine_selection(sel);
                            app.engine_modal_open = false;
                        }
                        KeyCode::Enter if app.search_mode => {
                            app.search_mode = false;
                        }
                        KeyCode::Enter if app.current_tab == Tab::Analyze => {
                            if !app.dir_entries.is_empty() && app.file_selected_idx < app.dir_entries.len() {
                                let entry = app.dir_entries[app.file_selected_idx].clone();
                                if entry.is_dir {
                                    app.current_dir = entry.path;
                                    app.refresh_directory();
                                } else if app.analysis.ready_to_crack {
                                    app.launch_attack_from_analysis();
                                }
                            }
                        }
                        KeyCode::Backspace if app.search_mode => {
                            app.search_query.pop();
                        }
                        KeyCode::Backspace | KeyCode::Left if app.current_tab == Tab::Analyze => {
                            app.navigate_up_directory();
                        }
                        KeyCode::Tab if app.current_tab == Tab::Analyze => {
                            let opt_count = app.attack_options.len().max(1);
                            app.attack_selected = (app.attack_selected + 1) % opt_count;
                        }
                        KeyCode::Up => {
                            if app.engine_modal_open {
                                app.engine_modal_selected = app.engine_modal_selected.saturating_sub(1);
                            } else {
                                if app.current_tab == Tab::Analyze && app.file_selected_idx > 0 {
                                    app.file_selected_idx -= 1;
                                    app.analyze_selected_file();
                                }
                                if app.current_tab == Tab::Dashboard {
                                    let max_scroll = app.log_ring.len().saturating_sub(5);
                                    app.log_scroll_offset = (app.log_scroll_offset + 1).min(max_scroll);
                                }
                                if app.current_tab == Tab::Sessions && app.sessions_selected > 0 {
                                    app.sessions_selected -= 1;
                                }
                                if app.current_tab == Tab::Benchmark && app.bench_selected > 0 {
                                    app.bench_selected -= 1;
                                }
                            }
                        }
                        KeyCode::Down => {
                            if app.engine_modal_open {
                                app.engine_modal_selected = (app.engine_modal_selected + 1).min(4);
                            } else {
                                if app.current_tab == Tab::Analyze && !app.dir_entries.is_empty() {
                                    app.file_selected_idx = (app.file_selected_idx + 1).min(app.dir_entries.len().saturating_sub(1));
                                    app.analyze_selected_file();
                                }
                                if app.current_tab == Tab::Dashboard {
                                    app.log_scroll_offset = app.log_scroll_offset.saturating_sub(1);
                                }
                                if app.current_tab == Tab::Sessions {
                                    app.sessions_selected = (app.sessions_selected + 1)
                                        .min(app.sessions.len().saturating_sub(1));
                                }
                                if app.current_tab == Tab::Benchmark {
                                    app.bench_selected = (app.bench_selected + 1)
                                        .min(app.bench_results.len().saturating_sub(1));
                                }
                            }
                        }
                        KeyCode::Char(c) => app.on_key_char(c),
                        _ => {}
                    }
                }
                Event::Resize(_, _) => { /* ratatui automatically reflows layout */ }
                Event::Mouse(mouse) => {
                    match mouse.kind {
                        MouseEventKind::Down(_) => {
                            app.handle_click(mouse.column, mouse.row);
                        }
                        MouseEventKind::ScrollUp => {
                            app.scroll_up();
                        }
                        MouseEventKind::ScrollDown => {
                            app.scroll_down();
                        }
                        _ => {}
                    }
                }
                _ => {} // FocusGained, FocusLost, Paste — not used
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.on_tick();
            last_tick = Instant::now();
        }
    }
}
