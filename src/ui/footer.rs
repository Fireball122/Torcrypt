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
            spans.push(key("Tab"));
            spans.push(label("Strategy"));
            if app.analysis.ready_to_crack {
                spans.push(key("A / Space"));
                spans.push(label("Launch Recovery"));
            }
            spans.push(key("H"));
            spans.push(label("Parent Dir"));
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
        }
        Tab::Benchmark => {
            spans.push(key("B"));
            spans.push(label("Run Benchmark"));
            spans.push(key("J/K"));
            spans.push(label("Select"));
        }
        Tab::Sessions => {
            spans.push(key("/"));
            spans.push(label("Search"));
            spans.push(key("J/K"));
            spans.push(label("Navigate"));
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
