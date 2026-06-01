use std::{io, net::SocketAddr, sync::{Arc, Mutex}};
use anyhow::Result;
use regex::Regex;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers, KeyboardEnhancementFlags, PushKeyboardEnhancementFlags},
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

use crate::{config::ChatChoice, connection::{Connection, get_free_port}, messaging::{Message, Chat}, auth::Role, vim::{Vim, input_handling}};
use crate::ui_screens::Screen;
use crate::{home, initServer, initClient, chat};
use crate::config::Config;

use x25519_dalek::{PublicKey, StaticSecret};
// use tokio_util::sync::CancellationToken;

// admin initialization functions
async fn startstuffnew(choice: &str, user_name: &str, rendezvous: &str, ran: &mut bool) -> Result<(Connection, Chat, StaticSecret, PublicKey, u64, i32)> {
    if !*ran {
        return Err(anyhow::anyhow!("startstuffnew already ran"));
    }
    let (addr, listener) = get_free_port().await?;
    let (chat, prvkey, pubkey, user_id, peer_id, peermap) = Chat::new(choice, user_name, addr.port()).await?;
    let conn = Connection::new(prvkey.clone(), rendezvous.parse::<SocketAddr>()?, (addr, listener), peermap).await;
    //TODO: start listening for requests

    *ran = false;
    Ok((conn, chat, prvkey, pubkey, user_id, peer_id))
}
async fn startstuffold(choice: &str, config: &Config, ran: &mut bool) -> Result<(Connection, Chat)> {
    if !*ran {
        return Err(anyhow::anyhow!("startstuffold already ran"));
    }
    //TODO: generate user from key and uid then check with ver_id
    let socket = get_free_port().await?;
    let prvkey = config.prvkey.as_ref().unwrap().clone();
    let (chat, peermap) = Chat::old(choice, config.user_name.as_ref().unwrap(), prvkey.clone()).await?;
    let conn = Connection::new(prvkey, config.rendezvous.unwrap(), socket, peermap).await;
    chat.send_join(&conn).await?;
    //TODO: start listening for requests

    *ran = false;
    Ok((conn, chat))
}

//TODO: startstuff new and old for noon-admin members (same user in a new chat gets auto accepted)

// Seqeuence parsing regex
lazy_static::lazy_static! { static ref RE_NUM: Regex = Regex::new(r"\d+").unwrap(); }
lazy_static::lazy_static! {
    static ref RE_CHR: Regex = Regex::new(r"[a-zA-Z]+").unwrap();
}
pub async fn app() -> Result<()> {
    // Config file (TODO: change to `~/.fallgejirc` for linux in prod)
    // share dir (TODO: change to `~/.local/share/fallgeji` for linux in prod)
    static CONFIG: &str = "fallegji.toml";
    static SHARE: &str = ".";
    let mut chats = ChatChoice::load(CONFIG)?;
    let mut config = Config::load(CONFIG, None)?;
    let mut choice = String::from("");

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let _ = execute!(
        stdout,
        PushKeyboardEnhancementFlags(
            KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
        )
    );
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // home state
    let mut home_active_section = 0; // 0 = hop into, 1 = create chat
    let mut home_active_field = 0; // For create chat: 0 = chat name, 1 = user name, 2 = rendezvous
    let mut chat_name_input = String::new();
    let mut user_name_input = String::new();
    let mut rendezvous_input = String::new();
    let mut chat_2_delete: Option<usize> = None;

    // App meat: Connection and Chat
    let mut conn: Option<Connection> = None;
    let mut chat: Option<Chat> = None;
    let mut run_once: bool = true;

    // Admin rendezvous state
    let mut admin_active_section = 2;
    let mut admin_active_row = false; // notify/kick & accept/delete
    let mut admin_active_col = 0;
    // let token = CancellationToken::new();
    let requests = Arc::new(Mutex::new(Vec::<(SocketAddr, String, PublicKey)>::new()));

    // regular input box state
    let mut vim_mode = Vim::Normal;
    let mut seq = String::new();
    let mut input = String::new();
    let mut cursor_pos: usize = 0; // cursor position
    let mut persis_y: usize = 0;   // peristant y position
    let mut anim_tick: usize = 0; // client animation tick

    let mut curr_screen = Screen::Home;

    #[allow(unused)] //macros are weird
    #[allow(clippy::collapsible_match)] //TODO: refactor to match
    loop {
        if curr_screen == Screen::Home {
            home!(terminal, curr_screen, config, choice, chats, conn, chat, home_active_section, home_active_field, chat_name_input, user_name_input, rendezvous_input, chat_2_delete, anim_tick, run_once);
        } else if curr_screen == Screen::InitServer && let Some(ref chat) = chat
            && let Some(ref conn) = conn {
            initServer!(terminal, curr_screen, config, choice, chats, admin_active_section, admin_active_row, admin_active_col, requests, input);
        } else if curr_screen == Screen::InitClient { //dbg
        // } else if curr_screen == Screen::InitClient && let Some(ref chat) = chat
        //     && let Some(ref conn) = conn {
            initClient!(terminal, curr_screen, config, rendezvous_input, anim_tick);
        } else if curr_screen == Screen::Chat && let Some(ref chat) = chat
            && let Some(ref conn) = conn {
            chat!(terminal, curr_screen, config, choice, chats, conn, chat, run_once, vim_mode, seq, input, cursor_pos, persis_y);
        }
        else {
            curr_screen = Screen::Home;
            //TODO: show error message (add error message variable which gets displayed in home!)
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
