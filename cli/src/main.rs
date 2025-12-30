use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{Terminal, prelude::CrosstermBackend};

use crate::app::App;

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
    let (tx, rx) = crate::io::spawn_background_thread();

    // run app
    let mut app = App::new(tx, rx);
    app.run(&mut terminal)?;

    // TUI closing boilerplate
    execute!(std::io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    terminal::disable_raw_mode()?;

    Ok(())
}
