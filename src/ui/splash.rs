// ui/splash.rs — 13-Frame Padlock Unlock Animation & TORCRYPT ASCII Banner
use crate::app::AppState;
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

pub fn render_splash(frame: &mut Frame, area: Rect, app: &AppState) {
    static BANNER: [&str; 6] = [
        " _____   ___   ____      ______   _____   __   __  ____    _____ ",
        "|_   _| / _ \\  |  _ \\   / _____| |  __ \\  \\ \\ / / /  __ \\ |_____|",
        "  | |  | | | | | |_) |  | |      | |__) |  \\ V /  | |__) |  | |  ",
        "  | |  | | | | |  _ <   | |      |  _  /    > <   |  ___/   | |  ",
        "  | |  | |_| | | | \\ \\  | \\____  | | \\ \\   / /    | |       | | ",
        "  |_|   \\___/  |_|  \\_\\  \\_____| |_|  \\_\\ /_/     |_|       |_|",
    ];

    static FRAMES: [&str; 13] = [
        "     .--------.\n    / .------. \\\n   / /        \\ \\\n   | |        | |\n  _| |________| |_\n.' |_|        |_| '.\n'._____ ____ _____.'\n|     .'____'.     |\n'.__.'.'    '.'.__.'\n'.__  |      |  __.'\n|   '.'.____.'.'   |\n'.____'.____.'____.'\n'.________________.'",
        "     .--------.\n    / .------. \\\n   / /        \\ \\\n   | |        | |\n   | |        | |\n  _| |________| |_\n.' |_|        |_| '.\n'._____ ____ _____.'\n|     .'____'.     |\n'.__.'.'    '.'.__.'\n'.__  |      |  __.'\n|   '.'.____.'.'   |\n'.____'.____.'____.'\n'.________________.'",
        "     .--------.\n    / .------. \\\n   / /        \\ \\\n   | |        | |\n   | |        | |\n   | |        | |\n  _|_|________| |_\n.' ( )        |_| '.\n'._____ ____ _____.'\n|     .'____'.     |\n'.__.'.'    '.'.__.'\n'.__  |      |  __.'\n|   '.'.____.'.'   |\n'.____'.____.'____.'\n'.________________.'",
        "     .--------.\n    / .------. \\\n   / /        \\ \\\n   | |        | |\n   | |        | |\n   | |        | |\n   |_|        | |\n  ____________| |_\n.' ( )        |_| '.\n'._____ ____ _____.'\n|     .'____'.     |\n'.__.'.'    '.'.__.'\n'.__  |      |  __.'\n|   '.'.____.'.'   |\n'.____'.____.'____.'\n'.________________.'",
        "       .------.\n      / .----. \\\n     / /      \\ \\\n     | |      | |\n     | |      | |\n     | |      | |\n     |_|      | |\n  ____________| |_\n.' ( )        |_| '.\n'._____ ____ _____.'\n|     .'____'.     |\n'.__.'.'    '.'.__.'\n'.__  |      |  __.'\n|   '.'.____.'.'   |\n'.____'.____.'____.'\n'.________________.'",
        "         .----.\n        / .--. \\\n       / /    \\ \\\n       | |    | |\n       | |    | |\n       | |    | |\n       |_|    | |\n  ____________| |_\n.' ( )        |_| '.\n'._____ ____ _____.'\n|     .'____'.     |\n'.__.'.'    '.'.__.'\n'.__  |      |  __.'\n|   '.'.____.'.'   |\n'.____'.____.'____.'\n'.________________.'",
        "           .--.\n          / .-. \\\n         / /   \\ \\\n         | |   | |\n         | |   | |\n         | |   | |\n         |_|   | |\n  ____________| |_\n.' ( )        |_| '.\n'._____ ____ _____.'\n|     .'____'.     |\n'.__.'.'    '.'.__.'\n'.__  |      |  __.'\n|   '.'.____.'.'   |\n'.____'.____.'____.'\n'.________________.'",
        "             ..\n            /  \\\n           / /\\ \\\n           |||| |\n           |||| |\n           |||| |\n           |_|| |\n  ____________| |_\n.' ( )        |_| '.\n'._____ ____ _____.'\n|     .'____'.     |\n'.__.'.'    '.'.__.'\n'.__  |      |  __.'\n|   '.'.____.'.'   |\n'.____'.____.'____.'\n'.________________.'",
        "              ..\n              ||\n             /  \\\n             |  |\n             |  |\n             |  |\n             |  |\n  ____________| |_\n.' ( )        |_| '.\n'._____ ____ _____.'\n|     .'____'.     |\n'.__.'.'    '.'.__.'\n'.__  |      |  __.'\n|   '.'.____.'.'   |\n'.____'.____.'____.'\n'.________________.'",
        "                .--.\n               / .. \\\n              / /  \\ \\\n              | |  | |\n              | |  | |\n              | |  | |\n              | |  |_|\n  ____________| |_\n.' ( )        |_| '.\n'._____ ____ _____.'\n|     .'____'.     |\n'.__.'.'    '.'.__.'\n'.__  |      |  __.'\n|   '.'.____.'.'   |\n'.____'.____.'____.'\n'.________________.'",
        "               .------.\n              / .----. \\\n             / /      \\ \\\n             | |      | |\n             | |      | |\n             | |      | |\n             | |      |_|\n  ____________| |_\n.' ( )        |_| '.\n'._____ ____ _____.'\n|     .'____'.     |\n'.__.'.'    '.'.__.'\n'.__  |      |  __.'\n|   '.'.____.'.'   |\n'.____'.____.'____.'\n'.________________.'",
        "                .------.\n               / .----. \\\n              / /      \\ \\\n              | |      | |\n              | |      | |\n              | |      | |\n              | |      |_|\n  ____________| |_\n.' ( )        |_| '.\n'._____ ____ _____.'\n|     .'____'.     |\n'.__.'.'    '.'.__.'\n'.__  |      |  __.'\n|   '.'.____.'.'   |\n'.____'.____.'____.'\n'.________________.'",
        "                .--------.\n               / .------. \\\n              / /        \\ \\\n              | |        | |\n              | |        | |\n              | |        | |\n              | |        |_|\n  ____________| |_\n.' ( )        |_| '.\n'._____ ____ _____.'\n|     .'____'.     |\n'.__.'.'    '.'.__.'\n'.__  |      |  __.'\n|   '.'.____.'.'   |\n'.____'.____.'____.'\n'.________________.'",
    ];

    let frame_idx = app.splash_frame.min(12);
    let is_unlocked = frame_idx == 12;

    let color = if is_unlocked {
        Color::Green
    } else {
        Color::Yellow
    };

    let style = Style::default().fg(color).add_modifier(Modifier::BOLD);

    let status_text = if is_unlocked {
        "[ DECRYPTED ]".to_string()
    } else {
        let dots = (frame_idx % 3) + 1;
        format!("[ DECRYPTING{} ]", ".".repeat(dots))
    };

    let lock_art = FRAMES[frame_idx];
    let lock_lines: Vec<&str> = lock_art.lines().collect();

    // Total content height: 6 (banner) + 1 (gap) + 14 (lock) + 1 (gap) + 1 (status) + 1 (tip) = ~24
    let content_height = 6 + 1 + lock_lines.len() as u16 + 2 + 1;
    let top_pad = (area.height.saturating_sub(content_height)) / 2;

    let rows = Layout::vertical([
        Constraint::Length(top_pad),
        Constraint::Length(6),                     // Banner
        Constraint::Length(1),                     // Gap
        Constraint::Length(lock_lines.len() as u16), // Padlock Art
        Constraint::Length(1),                     // Gap
        Constraint::Length(1),                     // Status text
        Constraint::Length(1),                     // Skip tip
        Constraint::Min(0),
    ])
    .split(area);

    // 1. Banner
    let banner_lines: Vec<Line> = BANNER
        .iter()
        .map(|&line| Line::from(Span::styled(line, style)))
        .collect();
    frame.render_widget(
        Paragraph::new(banner_lines).alignment(Alignment::Center),
        rows[1],
    );

    // 2. Padlock Art
    let art_lines: Vec<Line> = lock_lines
        .iter()
        .map(|&line| Line::from(Span::styled(line, style)))
        .collect();
    frame.render_widget(
        Paragraph::new(art_lines).alignment(Alignment::Center),
        rows[3],
    );

    // 3. Status Text
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(status_text, style),
        ]))
        .alignment(Alignment::Center),
        rows[5],
    );

    // 4. Skip Tip
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Press [Space / Enter] to skip", Style::default().fg(Color::DarkGray)),
        ]))
        .alignment(Alignment::Center),
        rows[6],
    );
}
