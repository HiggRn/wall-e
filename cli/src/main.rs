use std::{sync::mpsc::channel, time::Duration};

use common::Transport;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{Terminal, prelude::CrosstermBackend};

use crate::{
    app::App,
    io::{IoAction, IoEvent},
    transport::SerialTransport,
};

mod app;
mod io;
mod transport;
mod ui;

fn main() -> anyhow::Result<()> {
    // TUI opening boilerplate
    terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // set up transport thread
    let (tx_ui, rx_ui) = channel::<IoEvent>(); // IO -> UI
    let (tx_io, rx_io) = channel::<IoAction>(); // UI -> IO
    std::thread::spawn(move || {
        let mut transport: Option<SerialTransport> = None;

        loop {
            // 1. Check for incoming commands from UI (Non-blocking)
            if let Ok(action) = rx_io.try_recv() {
                match action {
                    IoAction::Connect => {
                        if let (Some(t), app_state) = crate::io::try_connect() {
                            transport = Some(t);
                            tx_ui.send(IoEvent::Connected(app_state)).unwrap()
                        }
                    }
                    IoAction::Send(cmd) => {
                        if let Some(t) = &mut transport {
                            if let Err(e) = t.send(cmd) {
                                tx_ui.send(IoEvent::Error(e.to_string())).unwrap();
                            }
                        }
                    }
                }
            }

            // 2. Poll the device (Non-blocking)
            if let Some(t) = &mut transport {
                match t.poll() {
                    Ok(Some(resp)) => {
                        tx_ui.send(IoEvent::ResponseReceived(resp)).unwrap();
                    }
                    Err(e) => {
                        // TODO:Handle disconnection or errors
                    }
                    _ => {}
                }
            }

            // Sleep briefly to prevent 100% CPU usage on the IO thread
            std::thread::sleep(Duration::from_millis(10));
        }
    });

    // run app
    let mut app = App::new(tx_io, rx_ui);
    app.run(&mut terminal)?;

    // TUI closing boilerplate
    execute!(std::io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    terminal::disable_raw_mode()?;

    Ok(())
}
