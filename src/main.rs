#![allow(dead_code, unused_variables)]
// main.rs — TORCRYPT TUI Entry Point: Crossterm raw mode + 30 FPS event loop
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
    // ── Setup terminal ────────────────────────────────────────────────────────
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend  = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;
    term.hide_cursor()?;

    let result = run(&mut term);

    // ── Teardown terminal ─────────────────────────────────────────────────────
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
        // ── Draw frame ────────────────────────────────────────────────────────
        term.draw(|frame| ui::render(frame, &mut app))?;

        // ── Non-blocking input poll (remainder of 33ms frame budget) ─────────
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => {
                    // 1. MUST ignore Release and Repeat events on Windows (prevents initial launch keystroke release from canceling splash)
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }

                    // 2. Escape / Interrupt sequences
                    if key.modifiers.contains(KeyModifiers::CONTROL) {
                        match key.code {
                            KeyCode::Char('c') => return Ok(()),
                            _ => {}
                        }
                    }

                    // 3. If in splash animation, only intentional skip keys dismiss after a 250ms startup grace period
                    if app.in_splash {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Char('Q') => return Ok(()),
                            KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Esc => {
                                if app.splash_start_time.elapsed().as_millis() > 250 {
                                    app.in_splash = false;
                                }
                            }
                            _ => {}
                        }
                        continue;
                    }

                    // 4. Main keyboard handling
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
                            app.attack_selected = (app.attack_selected + 1) % 3;
                        }
                        KeyCode::Up => {
                            if app.current_tab == Tab::Analyze && app.file_selected_idx > 0 {
                                app.file_selected_idx -= 1;
                                app.analyze_selected_file();
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
                Event::Resize(_, _) => { /* ratatui handles reflow automatically */ }
                _ => {}
            }
        }

        // ── Tick at 30 FPS ────────────────────────────────────────────────────
        if last_tick.elapsed() >= tick_rate {
            app.on_tick();
            last_tick = Instant::now();
        }
    }
}
