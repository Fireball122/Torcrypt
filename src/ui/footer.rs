// ui/footer.rs — Context-aware unified hotkey bar (1 line, zero dead space)
use crate::app::{AppState, Tab, WorkerState};
use ratatui::{
    layout::Alignment,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

pub fn render_footer(frame: &mut Frame, area: ratatui::layout::Rect, app: &AppState) {
    fn key(k: &'static str) -> Span<'static> {
        Span::styled(
            format!(" {k} "),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    }
    fn label(t: &'static str) -> Span<'static> {
        Span::styled(
            format!(" {t}  "),
            Style::default().fg(Color::DarkGray),
        )
    }

    let mut spans: Vec<Span> = vec![
        key("1-5"), label("Tabs"),
    ];

    match app.current_tab {
        Tab::Analyze => {
            spans.push(key("J/K"));
            spans.push(label("Navigate"));
            spans.push(key("Enter"));
            spans.push(label("Open"));
            spans.push(key("← / Bksp"));
            spans.push(label("Back"));
            spans.push(key("Tab"));
            spans.push(label("Tier"));
            spans.push(key("W"));
            spans.push(label("Wordlist"));
            spans.push(key("E"));
            spans.push(label("Backend"));
            spans.push(key("X"));
            spans.push(label("Export Audit"));
            if app.analysis.ready_to_crack {
                spans.push(key("M"));
                spans.push(label("Mask"));
                spans.push(key("R"));
                spans.push(label("Resume"));
                spans.push(key("A / Space"));
                spans.push(label("Launch"));
            }
        }
        Tab::Dashboard => {
            let pause_label: &'static str = if app.worker_state == WorkerState::Paused {
                "Resume"
            } else {
                "Pause"
            };
            spans.push(key("Space"));
            spans.push(label(pause_label));
            spans.push(key("C"));
            spans.push(label("Cancel"));
            spans.push(key("PgUp/Dn or J/K"));
            spans.push(label("Scroll Log"));
            if app.log_scroll_offset > 0 {
                spans.push(key("G / End"));
                spans.push(label("Live Tail"));
            }
        }
        Tab::Benchmark => {
            spans.push(key("B"));
            spans.push(label("Run Benchmark"));
            spans.push(key("J/K"));
            spans.push(label("Select"));
        }
        Tab::Sessions => {
            spans.push(key("P"));
            spans.push(label("Potfile / Sessions"));
            spans.push(key("/"));
            spans.push(label("Search"));
            spans.push(key("J/K"));
            spans.push(label("Navigate"));
            spans.push(key("E"));
            spans.push(label("Export Audit"));
        }
        Tab::System => {}
    }

    spans.push(key("?"));
    spans.push(label("Help"));
    spans.push(key("Q"));
    spans.push(label("Quit"));

    let bar = Paragraph::new(Line::from(spans)).alignment(Alignment::Left);
    frame.render_widget(bar, area);
}
