#![allow(dead_code, unused_variables)]
// main.rs — TORCRYPT TUI Entry Point: Crossterm raw mode + 30 FPS event loop
mod app;
mod ui;

use std::io;
use std::time::{Duration, Instant};

use app::AppState;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
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
    let mut app     = AppState::default();
    let tick_rate   = Duration::from_millis(33); // 30 FPS
    let mut last_tick = Instant::now();

    loop {
        // ── Draw frame ────────────────────────────────────────────────────────
        term.draw(|frame| ui::render(frame, &mut app))?;

        // ── Non-blocking input poll (remainder of 33ms frame budget) ─────────
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => {
                    // Escape sequences first
                    if key.modifiers.contains(KeyModifiers::CONTROL) {
                        match key.code {
                            KeyCode::Char('c') => return Ok(()),
                            _ => {}
                        }
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
                        KeyCode::Enter if app.search_mode => {
                            app.search_mode = false;
                        }
                        KeyCode::Backspace if app.search_mode => {
                            app.search_query.pop();
                        }
                        KeyCode::Up => {
                            if app.current_tab == app::Tab::Sessions
                                && app.sessions_selected > 0
                            {
                                app.sessions_selected -= 1;
                            }
                            if app.current_tab == app::Tab::Benchmark
                                && app.bench_selected > 0
                            {
                                app.bench_selected -= 1;
                            }
                        }
                        KeyCode::Down => {
                            if app.current_tab == app::Tab::Sessions {
                                app.sessions_selected = (app.sessions_selected + 1)
                                    .min(app.sessions.len().saturating_sub(1));
                            }
                            if app.current_tab == app::Tab::Benchmark {
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
