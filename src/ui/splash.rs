// ui/splash.rs — 1:1 Direct Port of TORCRYPT C++ 13-Frame Padlock Animation
use crate::app::AppState;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

static BANNER: [&str; 6] = [
    r#" _____   ___   ____      ______   _____   __   __  ____    _____ "#,
    r#"|_   _| / _ \  |  _ \   / _____| |  __ \  \ \ / / /  __ \ |_____|"#,
    r#"  | |  | | | | | |_) |  | |      | |__) |  \ V /  | |__) |  | |  "#,
    r#"  | |  | | | | |  _ <   | |      |  _  /    > <   |  ___/   | |  "#,
    r#"  | |  | |_| | | | \ \  | \____  | | \ \   / /    | |       | | "#,
    r#"  |_|   \___/  |_|  \_\  \_____| |_|  \_\ /_/     |_|       |_|"#,
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

pub fn render_splash(frame: &mut Frame, area: Rect, app: &AppState) {
    let width  = area.width as usize;
    let height = area.height as usize;

    let f = app.splash_frame.min(12);

    // Split frame into lines
    let raw_frame = FRAMES[f];
    let mut art_lines: Vec<&str> = raw_frame.lines().collect();

    // Pad art lines at the top to 16 lines (keeps lock body pinned to the baseline)
    while art_lines.len() < 16 {
        art_lines.insert(0, "");
    }

    let color = if f == 12 {
        Color::Green
    } else {
        Color::Yellow
    };
    let style = Style::default().fg(color).add_modifier(Modifier::BOLD);

    let status = if f == 12 {
        "[ DECRYPTED ]".to_string()
    } else {
        let dots = (f % 3) + 1;
        format!("[ DECRYPTING{} ]", ".".repeat(dots))
    };

    let k_banner_width = 65usize;
    let k_banner_height = 6usize;
    let k_lock_body_width = 20usize;

    let content_h = k_banner_height + 1 + art_lines.len() + 2;
    let top_pad   = height.saturating_sub(content_h) / 2;

    let banner_left_pad = width.saturating_sub(k_banner_width) / 2;
    let lock_left_pad   = width.saturating_sub(k_lock_body_width) / 2;
    let status_off      = width.saturating_sub(status.len()) / 2;

    let banner_pad = " ".repeat(banner_left_pad);
    let lock_pad   = " ".repeat(lock_left_pad);
    let status_pad = " ".repeat(status_off);

    let mut lines: Vec<Line> = Vec::with_capacity(height);

    for _ in 0..top_pad {
        lines.push(Line::from(""));
    }

    for &b in BANNER.iter() {
        lines.push(Line::from(Span::styled(format!("{}{}", banner_pad, b), style)));
    }

    lines.push(Line::from(""));

    for &l in art_lines.iter() {
        lines.push(Line::from(Span::styled(format!("{}{}", lock_pad, l), style)));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(format!("{}{}", status_pad, status), style)));

    let p = Paragraph::new(lines);
    frame.render_widget(p, area);
}
