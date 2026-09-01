#![allow(dead_code, unused_variables)]
// main.rs — TORCRYPT TUI Entry Point: Crossterm raw mode + 30 FPS event loop with Interactive Log Scrolling
mod app;
mod ui;

use std::io;
use std::time::{Duration, Instant};

use app::{AppState, Tab};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

fn main() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend  = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;
    term.hide_cursor()?;

    // Drain residual startup keystrokes
    while event::poll(Duration::from_millis(50))? {
        let _ = event::read()?;
    }

    let result = run(&mut term);

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    result
}

fn run(term: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    let mut app       = AppState::default();
    let tick_rate     = Duration::from_millis(33); // 30 FPS
    let mut last_tick = Instant::now();

    loop {
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
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Char('Q') => return Ok(()),
                            KeyCode::Esc | KeyCode::Enter | KeyCode::Char(' ') => {
                                if app.splash_start_time.elapsed().as_millis() >= 1000 {
                                    app.in_splash = false;
                                }
                            }
                            _ => {}
                        }
                        continue;
                    }

                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q')
                            if !app.search_mode && !app.show_help =>
                        {
                            return Ok(());
                        }
                        KeyCode::Esc => {
                            app.show_help   = false;
                            app.search_mode = false;
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
                        KeyCode::Down => {
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
                        KeyCode::Char(c) => app.on_key_char(c),
                        _ => {}
                    }
                }
                Event::Resize(_, _) => { /* ratatui automatically reflows layout */ }
                _ => {}
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.on_tick();
            last_tick = Instant::now();
        }
    }
}
