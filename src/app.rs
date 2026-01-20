//TODO: allow customization of border styles, max height, and colors using a toml-style dotfile. Parameters will be set in constants decided by the dotfile.
use std::{io::{self, Write}, net::SocketAddr, sync::{Arc, Mutex}};
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
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
    text::{Line, Span},
    Terminal,
};

use crate::{config::ChatChoice, vim::{Vim, input_handling}};
use crate::ui_screens::Screen;
use crate::{home, initServer, initClient, chat};
use crate::config::Config;

use x25519_dalek::{PublicKey, StaticSecret};
use chacha20poly1305::aead::OsRng; //dbg

// Seqeuence parsing regex
lazy_static::lazy_static! { static ref RE_NUM: Regex = Regex::new(r"\d+").unwrap(); }
lazy_static::lazy_static! {
    static ref RE_CHR: Regex = Regex::new(r"[a-zA-Z]+").unwrap();
}
pub fn app() -> Result<()> {
    // Config file (TODO: change to `~/.fallgejirc` in prod)
    static CONFIG: &str = "fallegji.toml";
    let mut chats = ChatChoice::load(CONFIG)?;
    let mut config = Config::load(CONFIG, None)?;
    let mut choice = String::from("");

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // home state
    let mut home_active_section = 0; // 0 = hop into, 1 = create chat
    let mut home_active_field = 0; // For create chat: 0 = chat name, 1 = user name, 2 = rendezvous
    let mut chat_name_input = String::new();
    let mut user_name_input = String::new();
    let mut rendezvous_input = String::new();

    // Admin rendezvous state
    let mut admin_active_section = 2;
    let mut admin_active_row = false; // notify/kick & accept/delete
    let mut admin_active_col = 0;
    let requests = Arc::new(Mutex::new(Vec::<(SocketAddr, String)>::new()));
    // let requests = Arc::new(Mutex::new(vec![ //dbg
    //     (SocketAddr::from(([127, 0, 0, 1], 8080)), "initial1".to_string()),
    //     (SocketAddr::from(([127, 0, 0, 1], 8081)), "initial2".to_string()),
    //     (SocketAddr::from(([127, 0, 0, 1], 8082)), "initial3".to_string()),
    // ]));

    // regular input box state
    let mut vim_mode = Vim::Normal;
    let mut seq = String::new();
    let mut input = String::new();
    let mut cursor_pos: usize = 0; // cursor position
    let mut persis_y: usize = 0;   // peristant y position

    let mut curr_screen = Screen::Home;

    #[allow(unused)] //macros are weird
    loop {
        if curr_screen == Screen::Home {
            home!(terminal, curr_screen, config, choice, chats, home_active_section, home_active_field, chat_name_input, user_name_input, rendezvous_input);
        } else if curr_screen == Screen::InitServer {
            initServer!(terminal, curr_screen, config, choice, chats, admin_active_section, admin_active_row, admin_active_col, requests, input);
        } else if curr_screen == Screen::InitClient {
            initClient!(terminal, curr_screen, config);
        } else if curr_screen == Screen::Chat {
            chat!(terminal, curr_screen, config, choice, chats, vim_mode, seq, input, cursor_pos, persis_y);
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
