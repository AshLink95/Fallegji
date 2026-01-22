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

use crate::{config::ChatChoice, connection::{Connection, get_free_port}, messaging::Chat, auth::Role, vim::{Vim, input_handling}};
use crate::ui_screens::Screen;
use crate::{home, initServer, initClient, chat};
use crate::config::Config;

use x25519_dalek::{PublicKey, StaticSecret};
// use tokio_util::sync::CancellationToken;

// initiation functions
async fn startstuffnew(choice: &str, user_name: &str, rendezvous: &str, ran: &mut bool) -> Result<(Connection, Chat, StaticSecret, PublicKey, u64, i32)> {
    if !*ran {
        return Err(anyhow::anyhow!("startstuffnew already ran"));
    }
    let (addr, listener) = get_free_port().await?;
    let (chat, prvkey, pubkey, user_id, peer_id, peermap) = Chat::new(choice, user_name, addr.port()).await?;
    let conn = Connection::new(prvkey.clone(), rendezvous.parse::<SocketAddr>()?, (addr, listener), peermap).await;
    *ran = false;
    Ok((conn, chat, prvkey, pubkey, user_id, peer_id))
}
async fn startstuffold(choice: &str, config: &Config, ran: &mut bool) -> Result<(Connection, Chat)> {
    if !*ran {
        return Err(anyhow::anyhow!("startstuffold already ran"));
    }
    let socket = get_free_port().await?;
    let prvkey = config.prvkey.as_ref().unwrap().clone();
    let (chat, peermap) = Chat::old(choice, config.user_name.as_ref().unwrap(), prvkey.clone()).await?;
    let conn = Connection::new(prvkey, config.rendezvous.unwrap(), socket, peermap).await;
    *ran = false;
    Ok((conn, chat))
}

// Seqeuence parsing regex
lazy_static::lazy_static! { static ref RE_NUM: Regex = Regex::new(r"\d+").unwrap(); }
lazy_static::lazy_static! {
    static ref RE_CHR: Regex = Regex::new(r"[a-zA-Z]+").unwrap();
}
pub async fn app() -> Result<()> {
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

    // App meat: Connection and Chat
    let mut conn: Connection;
    let mut chat: Chat;
    let mut run_once_dum = true;
    (_, chat, _, _, _, _) = startstuffnew("test", "user", "1.1.1.1:1", &mut run_once_dum).await?; //dbg
    let mut run_once;

    // Admin rendezvous state (TODO: add admin check from chat struct instance)
    let mut admin_active_section = 2;
    let mut admin_active_row = false; // notify/kick & accept/delete
    let mut admin_active_col = 0;
    // let token = CancellationToken::new();
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
            home!(terminal, curr_screen, config, choice, chats, conn, chat, home_active_section, home_active_field, chat_name_input, user_name_input, rendezvous_input, run_once);
        } else if curr_screen == Screen::InitServer {
            initServer!(terminal, curr_screen, config, choice, chats, admin_active_section, admin_active_row, admin_active_col, requests, input);
        } else if curr_screen == Screen::InitClient {
            initClient!(terminal, curr_screen, config);
        } else if curr_screen == Screen::Chat {
            chat!(terminal, curr_screen, config, choice, chats, conn, chat, vim_mode, seq, input, cursor_pos, persis_y);
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
