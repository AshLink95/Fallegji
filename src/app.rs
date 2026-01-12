//TODO: allow customization of border styles, max height, and colors using a toml-style dotfile. Parameters will be set in constants decided by the dotfile.
use std::io::{self, Write};
use anyhow::Result;
use regex::Regex;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    cursor::SetCursorStyle,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Alignment},
    style::Style,
    widgets::{Block, Borders, Paragraph},
    text::Line,
    Terminal,
};

use crate::vim::{Vim, input_handling};
use crate::ui_screens::Screen;
use crate::{onboarding, initServer, initClient, chat};
use crate::config::Config;

// Seqeuence parsing regex
lazy_static::lazy_static! { static ref RE_NUM: Regex = Regex::new(r"\d+").unwrap(); }
lazy_static::lazy_static! {
    static ref RE_CHR: Regex = Regex::new(r"[a-zA-Z]+").unwrap();
}

pub fn app() -> Result<()> {
    // Config file (TODO: make mut after messaging & change to `~/.fallgejirc` in prod)
    let config = Config::load("fallegji.toml", Some("test"))?;

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut vim_mode = Vim::Normal;
    let mut seq = String::new();
    let mut input = String::new();
    let mut cursor_pos: usize = 0; // cursor position
    let mut persis_y: usize = 0;   // peristant y position

    let curr_screen = Screen::Chat; //dbg: should be mut and init to Onboarding

    #[allow(unused)] //macros are weird
    loop {
        if curr_screen == Screen::Onboarding {
            onboarding!(terminal, vim_mode, input, cursor_pos, persis_y, curr_screen, config);
        } else if curr_screen == Screen::InitServer {
            initServer!(terminal, vim_mode, input, cursor_pos, persis_y, curr_screen, config);
        } else if curr_screen == Screen::InitClient {
            initClient!(terminal, vim_mode, input, cursor_pos, persis_y, curr_screen, config);
        } else if curr_screen == Screen::Chat {
            chat!(terminal, vim_mode, seq, input, cursor_pos, persis_y, curr_screen, config);
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
