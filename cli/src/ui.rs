use common::PIN_LEN;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

use crate::app::{AppState, SignForm};

// --- Constants for "Geeky" Styling ---
const COLOR_PRIMARY: Color = Color::Cyan;
const COLOR_SECONDARY: Color = Color::LightGreen;
const COLOR_ALERT: Color = Color::Red;
const COLOR_INACTIVE: Color = Color::DarkGray;
const COLOR_TEXT: Color = Color::White;

pub fn draw_frame(f: &mut Frame, app_state: &AppState) {
    match app_state {
        AppState::Unconnected => draw_centered_message(
            f,
            "SYSTEM DISCONNECTED",
            "Searching for USB wallet device...",
        ),
        AppState::EmptyWallet => draw_menu(
            f,
            "WALLET NOT FOUND",
            vec![
                "[i] Initialize New Wallet",
                "[r] Restore from Mnemonic",
                "[q] Quit System",
            ],
            COLOR_PRIMARY,
        ),
        AppState::MnemonicConfirm => draw_centered_message(
            f,
            "CONFIRMATION REQUIRED",
            "Please confirm the mnemonic on your wallet device.",
        ),
        AppState::MnemonicInput { mnemonic } => draw_mnemonic_input(f, mnemonic),
        AppState::PinInput { pin, is_set_pin } => draw_pin_input(f, pin, *is_set_pin),
        AppState::Unlocked => draw_menu(
            f,
            "ACCESS GRANTED",
            vec![
                "[s] Sign Transaction",
                "[r] Receive Address",
                "[w] Wipe Wallet",
                "[q] Quit System",
            ],
            COLOR_SECONDARY,
        ),
        AppState::Sign { form } => draw_sign_form(f, form),
        AppState::TxConfirm => draw_centered_message(
            f,
            "AWAITING SIGNATURE",
            "Please review and confirm details on your wallet device.",
        ),
        AppState::Display { content } => draw_content_display(f, " ADDRESS ", content),
        AppState::Wipe => draw_confirmation(
            f,
            "SYSTEM WIPE",
            "CRITICAL WARNING: This action is irreversible.",
        ),
        AppState::Error(err, prev_state) => {
            draw_frame(f, prev_state);
            draw_error_popup(f, err);
        }
        AppState::Exit => {}
    }
}

/// Helper to draw a simple centered message
fn draw_centered_message(f: &mut Frame, title: &str, msg: &str) {
    let area = centered_rect(f.area(), 50, 20);
    let block = Block::default()
        .title(Span::styled(
            format!(" {} ", title),
            Style::default()
                .fg(COLOR_PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(COLOR_PRIMARY));

    let inner_area = block.inner(area);
    f.render_widget(block, area);

    let available_width = inner_area.width.max(1) as usize;
    let required_height = msg
        .lines()
        .map(|line| {
            // Ceiling division: (len + width - 1) / width
            (line.len() + available_width - 1) / available_width
        })
        .sum::<usize>()
        .max(1) as u16; // Ensure at least height 1

    let vertical_center = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Min(0),                  // Top Spacer
                Constraint::Length(required_height), // Dedicated Text Area in the middle
                Constraint::Min(0),                  // Bottom Spacer
            ]
            .as_ref(),
        )
        .split(inner_area);

    let text = Paragraph::new(msg)
        .style(Style::default().fg(COLOR_TEXT))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });

    f.render_widget(text, vertical_center[1]);
}

/// Helper to draw a menu list
fn draw_menu(f: &mut Frame, title: &str, items: Vec<&str>, border_color: Color) {
    let area = centered_rect(f.area(), 40, 40);
    let block = Block::default()
        .title(Span::styled(
            format!(" {} ", title),
            Style::default()
                .fg(border_color)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let inner_area = block.inner(area);
    f.render_widget(block, area);

    let content_height = (items.len() * 2).saturating_sub(1) as u16;

    let vertical_center = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Min(0),                 // Top Spacer (expands)
                Constraint::Length(content_height), // Exact Text Height
                Constraint::Min(0),                 // Bottom Spacer (expands)
            ]
            .as_ref(),
        )
        .split(inner_area);

    let text_content = items.join("\n\n");
    let paragraph = Paragraph::new(text_content)
        .style(Style::default().fg(COLOR_TEXT))
        .alignment(Alignment::Center) // Horizontal Center
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, vertical_center[1]);
}

/// Draw the mnemonic input screen with a 6x4 Grid
fn draw_mnemonic_input(f: &mut Frame, mnemonic: &[String]) {
    // 1. Setup Main Area
    let area = centered_rect(f.area(), 80, 70);
    let block = Block::default()
        .title(Span::styled(
            " RESTORE SEQUENCE ",
            Style::default()
                .fg(COLOR_SECONDARY)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(COLOR_SECONDARY));

    // Split: Instructions (Top), Grid (Bottom)
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(1)].as_ref())
        .margin(2)
        .split(area);

    f.render_widget(block, area);

    // 2. Instructions
    let instructions = Paragraph::new(
        "Enter 24-word mnemonic phrase.\nPress SPACE/ENTER to advance. Double ENTER to finish.",
    )
    .style(Style::default().fg(COLOR_SECONDARY))
    .alignment(Alignment::Center);
    f.render_widget(instructions, main_layout[0]);

    // 3. The 6x4 Grid Layout for 24 words
    // Split vertical space into 6 rows
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Ratio(1, 6),
                Constraint::Ratio(1, 6),
                Constraint::Ratio(1, 6),
                Constraint::Ratio(1, 6),
                Constraint::Ratio(1, 6),
                Constraint::Ratio(1, 6),
            ]
            .as_ref(),
        )
        .split(main_layout[1]);

    // Iterate through slots 0 to 23
    for i in 0..24 {
        let row_idx = i / 4;
        let col_idx = i % 4;

        // Split the current row into 4 columns to get the cell
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(
                [
                    Constraint::Ratio(1, 4),
                    Constraint::Ratio(1, 4),
                    Constraint::Ratio(1, 4),
                    Constraint::Ratio(1, 4),
                ]
                .as_ref(),
            )
            .split(rows[row_idx]);

        let cell_area = cols[col_idx];

        // Determine content and style for this cell
        let (num_style, content, text_style) = if i < mnemonic.len() {
            // Word entered
            let (word_style, line_style) = if i == mnemonic.len() - 1 {
                // Last entered word (active-like)
                (
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                    Style::default().fg(COLOR_SECONDARY),
                )
            } else {
                (
                    Style::default().fg(COLOR_TEXT),
                    Style::default().fg(COLOR_INACTIVE),
                )
            };
            (line_style, mnemonic[i].clone(), word_style)
        } else {
            // Future slot
            (
                Style::default().fg(COLOR_INACTIVE),
                String::new(),
                Style::default(),
            )
        };

        // Draw the underline block
        let block = Block::default()
            .borders(Borders::BOTTOM)
            .border_style(num_style); // Color the line based on state

        // Render the number prefix and the word
        // We pad the area slightly so text doesn't touch the borders
        let inner_area = block.inner(cell_area);
        f.render_widget(block, cell_area);

        // Draw "1. " prefix
        let prefix = format!("{}.", i + 1);
        let content_line = Line::from(vec![
            Span::styled(prefix, Style::default().fg(COLOR_INACTIVE)),
            Span::raw(" "),
            Span::styled(content, text_style),
        ]);

        let p = Paragraph::new(content_line).alignment(Alignment::Left);

        // Render text inside the underlined box
        f.render_widget(p, inner_area);
    }
}

/// Draw PIN input with individual slots
fn draw_pin_input(f: &mut Frame, pin: &[u8], is_set_pin: bool) {
    let title = if is_set_pin {
        " SET SECURITY PIN "
    } else {
        " AUTHENTICATE "
    };

    let area = centered_rect(f.area(), 60, 20);

    let block = Block::default()
        .title(Span::styled(
            title,
            Style::default()
                .fg(COLOR_PRIMARY)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(COLOR_PRIMARY));

    f.render_widget(block, area);

    // Create a horizontal layout area in the middle of the box
    let vertical_center = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage(40), // Top spacing
                Constraint::Length(3),      // The slots row
                Constraint::Percentage(40), // Bottom spacing
            ]
            .as_ref(),
        )
        .split(area);

    // Create the slots
    let mut constraints = Vec::new();
    // Add spacer at start
    constraints.push(Constraint::Min(1));
    for _ in 0..PIN_LEN {
        constraints.push(Constraint::Length(4)); // Width of slot
        constraints.push(Constraint::Length(2)); // Spacer
    }
    // Add spacer at end
    constraints.push(Constraint::Min(1));

    let slot_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints)
        .split(vertical_center[1]);

    // Draw slots
    for i in 0..PIN_LEN {
        // Map logical index i to layout index.
        // Layout index 0 is spacer. Slot 0 is at index 1. Spacer at 2. Slot 1 at 3...
        // Formula: layout_idx = 1 + (i * 2)
        let layout_idx = 1 + (i * 2);

        let slot_area = slot_layout[layout_idx];

        // Determine style: Active/Filled vs Empty
        let border_color = if i < pin.len() {
            COLOR_SECONDARY // Green if filled
        } else if i == pin.len() {
            COLOR_PRIMARY // Cyan if current cursor
        } else {
            COLOR_INACTIVE // Gray if empty
        };

        // Draw Underline (using Bottom border)
        let slot_block = Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(border_color));

        f.render_widget(slot_block, slot_area);

        // Draw Content
        if i < pin.len() {
            // Draw huge asterisk
            let asterisk = Paragraph::new("*")
                .alignment(Alignment::Center)
                .style(Style::default().fg(COLOR_TEXT).add_modifier(Modifier::BOLD));
            f.render_widget(asterisk, slot_area);
        }
    }
}

/// Draw the transaction signing form with focus highlighting
fn draw_sign_form(f: &mut Frame, form: &SignForm) {
    let area = centered_rect(f.area(), 70, 80);
    let block = Block::default()
        .title(" SIGN TRANSACTION ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(COLOR_SECONDARY));
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

        let (border_color, text_style) = if is_focused {
            (
                Color::Yellow,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            (COLOR_INACTIVE, Style::default().fg(COLOR_TEXT))
        };

        let input_block = Block::default()
            .title(Span::styled(*label, Style::default().fg(border_color)))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color));

        let input_text = Paragraph::new(value.as_str())
            .block(input_block)
            .style(text_style);
        f.render_widget(input_text, layout[i]);
    }

    let help_text = Paragraph::new("TAB: Switch | ENTER: Sign | ESC: Cancel")
        .style(Style::default().fg(COLOR_INACTIVE))
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
        .style(Style::default().fg(COLOR_TEXT))
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
        .border_style(Style::default().fg(COLOR_ALERT));

    let content = format!("{}\n\n[Enter] Confirm  [Esc] Cancel", msg);
    let text = Paragraph::new(content)
        .block(block)
        .style(Style::default().fg(COLOR_ALERT))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });

    f.render_widget(text, area);
}

/// Draw error popup on top of existing state
fn draw_error_popup(f: &mut Frame, err_msg: &str) {
    let area = centered_rect(f.area(), 60, 20);

    f.render_widget(Clear, area);

    let block = Block::default()
        .title(" SYSTEM ERROR ")
        .borders(Borders::ALL)
        .border_style(
            Style::default()
                .fg(COLOR_ALERT)
                .add_modifier(Modifier::BOLD),
        );

    let text = Paragraph::new(format!("{}\n\nPress [Enter] to dismiss", err_msg))
        .block(block)
        .style(Style::default().fg(COLOR_TEXT))
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
