use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

use crate::app::{AppState, SignForm};

pub fn draw_frame(f: &mut Frame, app_state: &AppState) {
    match app_state {
        AppState::Unconnected => {
            draw_centered_message(f, "Connect Device", "Searching for USB device...")
        }
        AppState::EmptyWallet => draw_menu(
            f,
            "Wallet Empty",
            vec![
                "Press 'i' to Initialize new wallet",
                "Press 'r' to Restore from mnemonic",
                "Press 'q' to Quit",
            ],
        ),
        AppState::MnemonicConfirm => draw_centered_message(
            f,
            "Confirm Mnemonic",
            "Please match the mnemonic on your device.",
        ),
        AppState::MnemonicInput { mnemonic } => draw_mnemonic_input(f, mnemonic),
        AppState::PinInput { pin, is_set_pin } => draw_pin_input(f, pin, *is_set_pin),
        AppState::Unlocked => draw_menu(
            f,
            "Wallet Unlocked",
            vec![
                "Press 's' to Sign Transaction",
                "Press 'r' to Receive Address",
                "Press 'w' to Wipe Wallet",
                "Press 'q' to Quit",
            ],
        ),
        AppState::Sign { form } => draw_sign_form(f, form),
        AppState::TxConfirm => draw_centered_message(
            f,
            "Confirm Transaction",
            "Please review and confirm on your device.",
        ),
        AppState::Display { content } => draw_content_display(f, "Result", content),
        AppState::Wipe => draw_confirmation(
            f,
            "Wipe Wallet",
            "Are you sure? This action is irreversible.",
        ),
        AppState::Error(err, prev_state) => {
            // Recursive call: Draw the background state first
            draw_frame(f, prev_state);
            // Then draw the error popup on top
            draw_error_popup(f, err);
        }
        AppState::Exit => {} // Frame will close
    }
}

/// Helper to draw a simple centered message
fn draw_centered_message(f: &mut Frame, title: &str, msg: &str) {
    let area = centered_rect(f.area(), 50, 20);
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let text = Paragraph::new(msg)
        .block(block)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });

    f.render_widget(text, area);
}

/// Helper to draw a menu list
fn draw_menu(f: &mut Frame, title: &str, items: Vec<&str>) {
    let area = centered_rect(f.area(), 50, 40);
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    // Join items with double newlines for spacing
    let text_content = items.join("\n\n");
    let paragraph = Paragraph::new(text_content)
        .block(block)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

/// Draw the mnemonic input screen
fn draw_mnemonic_input(f: &mut Frame, mnemonic: &[String]) {
    let area = centered_rect(f.area(), 60, 50);
    let block = Block::default()
        .title("Restore Wallet")
        .borders(Borders::ALL);

    // Layout: Instructions at top, Words in middle
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)].as_ref())
        .margin(1)
        .split(area);

    f.render_widget(block, area);

    let instructions =
        Paragraph::new("Type words. Press ENTER to next word. Press ENTER twice to finish.")
            .style(Style::default().fg(Color::Gray));
    f.render_widget(instructions, chunks[0]);

    // Format the words typed so far
    let mut spans = Vec::new();
    for (i, word) in mnemonic.iter().enumerate() {
        let is_last = i == mnemonic.len() - 1;
        let prefix = format!("{}. ", i + 1);

        let style = if is_last {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };

        spans.push(Span::styled(prefix, Style::default().fg(Color::Gray)));
        spans.push(Span::styled(format!("{} ", word), style));
    }

    let input_area = Paragraph::new(Line::from(spans)).wrap(Wrap { trim: true });

    f.render_widget(input_area, chunks[1]);
}

/// Draw PIN input (masked)
fn draw_pin_input(f: &mut Frame, pin: &[u8], is_set_pin: bool) {
    let title = if is_set_pin {
        "Set New PIN"
    } else {
        "Unlock Wallet"
    };
    let area = centered_rect(f.area(), 40, 20);

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    // Mask the pin with asterisks
    let masked_pin = "*".repeat(pin.len());
    let text = Paragraph::new(masked_pin)
        .block(block)
        .alignment(Alignment::Center);

    f.render_widget(text, area);
}

/// Draw the transaction signing form with focus highlighting
fn draw_sign_form(f: &mut Frame, form: &SignForm) {
    let area = centered_rect(f.area(), 70, 80);
    let block = Block::default()
        .title("Sign Transaction")
        .borders(Borders::ALL);
    f.render_widget(block, area);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints(
            [
                Constraint::Length(3), // Nonce
                Constraint::Length(3), // To
                Constraint::Length(3), // Value
                Constraint::Length(3), // Data
                Constraint::Length(3), // Gas Limit
                Constraint::Length(3), // Max Fee
                Constraint::Length(3), // Priority Fee
                Constraint::Min(1),    // Help text
            ]
            .as_ref(),
        )
        .split(area);

    let fields = [
        ("Nonce", &form.nonce),
        ("To", &form.to),
        ("Value (Wei)", &form.value),
        ("Data", &form.data),
        ("Gas Limit", &form.gas_limit),
        ("Max Fee", &form.max_fee),
        ("Priority Fee", &form.priority_fee),
    ];

    for (i, (label, value)) in fields.iter().enumerate() {
        let is_focused = i == form.focus_index;

        let border_style = if is_focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let input_block = Block::default()
            .title(*label)
            .borders(Borders::ALL)
            .border_style(border_style);

        let input_text = Paragraph::new(value.as_str()).block(input_block);
        f.render_widget(input_text, layout[i]);
    }

    let help_text = Paragraph::new("TAB to switch fields | ENTER to Sign | ESC to Cancel")
        .style(Style::default().fg(Color::Gray))
        .alignment(Alignment::Center);
    f.render_widget(help_text, layout[7]);
}

/// Draw generic content display
fn draw_content_display(f: &mut Frame, title: &str, content: &str) {
    let area = centered_rect(f.area(), 80, 60);
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    let text = Paragraph::new(content)
        .block(block)
        .wrap(Wrap { trim: true })
        .alignment(Alignment::Center);

    f.render_widget(text, area);
}

/// Draw confirmation dialog
fn draw_confirmation(f: &mut Frame, title: &str, msg: &str) {
    let area = centered_rect(f.area(), 50, 20);
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));

    let content = format!("{}\n\n[Enter] Confirm  [Esc] Cancel", msg);
    let text = Paragraph::new(content)
        .block(block)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });

    f.render_widget(text, area);
}

/// Draw error popup on top of existing state
fn draw_error_popup(f: &mut Frame, err_msg: &str) {
    let area = centered_rect(f.area(), 60, 20);

    // Clear the area first so the background doesn't bleed through
    f.render_widget(Clear, area);

    let block = Block::default()
        .title("Error")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));

    let text = Paragraph::new(format!("{}\n\nPress [Enter] to dismiss", err_msg))
        .block(block)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });

    f.render_widget(text, area);
}

/// Helper function to center a rect within another rect
fn centered_rect(r: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}
