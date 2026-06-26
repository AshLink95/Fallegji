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
    layout::{Constraint, Direction, Layout, Margin, Alignment},
    style::{Color, Style, Modifier},
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
    text::{Line, Span},
    Terminal,
};

use crate::{config::ChatChoice, connection::{Accepted, ChatSlot, Connection, Communication, Peermap, RendezVous, get_free_port}, messaging::Chat, auth::{Role, Uid, User, Authentication}, db::Database, vim::{Vim, input_handling}};
use crate::ui_screens::Screen;
use crate::{home, initAdmin, initMember, chat};
use crate::config::Config;

use x25519_dalek::{PublicKey, StaticSecret};
use tokio_util::sync::CancellationToken;

// admin initialization functions
type Requests = Arc<Mutex<Vec<([SocketAddr; 2], String, PublicKey, u32)>>>;

// Admin background tasks: accept direct peer connections, watch our IP, hold the
// rendezvous (fallback), and read incoming join requests. All cancel via `token`.
fn admin_rcv(conn: &Arc<Connection>, slot: ChatSlot, requests: Requests, token: CancellationToken) {
    member_rcv(conn, slot, token.clone());
    let rc = Arc::clone(conn);
    tokio::spawn(async move { let _ = rc.rcv_requests(requests, token, true).await; }); // admin holder
}

/// Wrap an existing chat in a (pre-filled) slot for `listen`.
fn filled_slot(chat: &Arc<Chat>) -> ChatSlot {
    Arc::new(Mutex::new(Some(Accepted { chat: Arc::clone(chat), name: String::new() })))
}

async fn startstuffnew(choice: &str, user_name: &str, rendezvous: &str, iface: Option<String>, requests: Requests, token: CancellationToken, ran: &mut bool) -> Result<(Arc<Connection>, Arc<Chat>, StaticSecret, PublicKey, u64, i32)> {
    if !*ran {
        return Err(anyhow::anyhow!("startstuffnew already ran"));
    }
    let (addr, listener) = get_free_port(iface.as_deref()).await?;
    let (chat, prvkey, pubkey, user_id, peer_id, peermap) = Chat::new(choice, user_name, addr.port()).await?;
    let mut conn = Connection::new(prvkey.clone(), rendezvous.parse::<SocketAddr>()?, (addr, listener), peermap).await;
    conn.set_user(user_id, user_name.to_string(), Uid::getuid());
    conn.bind_rendezvous().await?;
    let conn = Arc::new(conn);
    let chat = Arc::new(chat);
    admin_rcv(&conn, filled_slot(&chat), requests, token);
    *ran = false;
    Ok((conn, chat, prvkey, pubkey, user_id, peer_id))
}
async fn startstuffold(choice: &str, config: &Config, iface: Option<String>, requests: Requests, token: CancellationToken, ran: &mut bool) -> Result<(Arc<Connection>, Arc<Chat>)> {
    if !*ran {
        return Err(anyhow::anyhow!("startstuffold already ran"));
    }
    let socket = get_free_port(iface.as_deref()).await?;
    let prvkey = config.prvkey.as_ref().ok_or_else(|| anyhow::anyhow!("config missing prvkey"))?.clone();
    let user_name = config.user_name.as_ref().ok_or_else(|| anyhow::anyhow!("config missing user_name"))?.clone();
    let user_id = config.user_id.ok_or_else(|| anyhow::anyhow!("config missing user_id"))?;
    let rendezvous = config.rendezvous.ok_or_else(|| anyhow::anyhow!("config missing rendezvous"))?;
    let uid = Uid::getuid();
    let pubkey_hex = hex::encode(PublicKey::from(&prvkey).as_bytes());
    let user = User::new(pubkey_hex.clone(), user_name.clone(), uid);
    if !user.ver_id(pubkey_hex, user_id) {
        return Err(anyhow::anyhow!("config identity mismatch (wrong key/name/machine)"));
    }
    let (chat, peermap) = Chat::old(choice, &user_name, prvkey.clone()).await?;
    let mut conn = Connection::new(prvkey, rendezvous, socket, peermap).await;
    conn.set_user(user_id, user_name, uid);
    // Best-effort: on rejoin a fallback member-holder may be squatting the rendezvous (→ AddrInUse).
    // Don't abort — admin_rcv's rcv_requests(is_admin) evicts the holder and rebinds.
    let _ = conn.bind_rendezvous().await;
    let conn = Arc::new(conn);
    let chat = Arc::new(chat);
    admin_rcv(&conn, filled_slot(&chat), requests, token);
    *ran = false;
    Ok((conn, chat))
}

// Member background tasks: same as admin but without hosting the rendezvous —
// peers don't accept join requests, they just listen, watch their IP, and can
// take over the rendezvous (fallback) if the holder drops. All cancel via `token`.
fn member_rcv(conn: &Arc<Connection>, slot: ChatSlot, token: CancellationToken) {
    tokio::spawn(Arc::clone(conn).listen(Arc::clone(&slot), token.clone()));
    // monitor_ip needs the chat's db; a fresh joiner's chat is only born on accept,
    // so wait for the slot to fill, then watch the IP.
    let sc = Arc::clone(&slot); let mc = Arc::clone(conn); let mt = token.clone();
    tokio::spawn(async move {
        loop {
            if mt.is_cancelled() { return; }
            let db = sc.lock().unwrap().as_ref().map(|a| a.chat.db.clone());
            if let Some(db) = db {
                tokio::select! { _ = mt.cancelled() => {} _ = mc.monitor_ip(db) => {} }
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        }
    });
    let fc = Arc::clone(conn); let ft = token.clone();
    tokio::spawn(async move { tokio::select! { _ = ft.cancelled() => {} _ = fc.fallback(ft.clone()) => {} } });
    let hc = Arc::clone(conn); let ht = token.clone();
    tokio::spawn(async move { tokio::select! { _ = ht.cancelled() => {} _ = hc.heartbeat_loop() => {} } });
}

async fn joinstuffnew(user_name: &str, rendezvous: &str, iface: Option<String>, token: CancellationToken, ran: &mut bool) -> Result<(Arc<Connection>, ChatSlot, StaticSecret, PublicKey, u64)> {
    if !*ran {
        return Err(anyhow::anyhow!("joinstuffnew already ran"));
    }
    // Only the connection comes up here; identity is in-memory, the chat is born on accept.
    let (addr, listener) = get_free_port(iface.as_deref()).await?;
    let (peer, prvkey) = crate::connection::Peer::new_out(-1, addr.port())?;
    let pubkey = peer.get_pubkey();
    let uid = Uid::getuid();
    let pubkey_hex = hex::encode(pubkey.as_bytes());
    let user_id = User::new(pubkey_hex, user_name.to_string(), uid).get_id();
    let mut conn = Connection::new(prvkey.clone(), rendezvous.parse::<SocketAddr>()?, (addr, listener), Peermap::new()).await;
    conn.set_user(user_id, user_name.to_string(), uid);
    let conn = Arc::new(conn);
    let slot: ChatSlot = Arc::new(Mutex::new(None));
    member_rcv(&conn, Arc::clone(&slot), token);
    // Best-effort: if no one holds the rendezvous yet, don't error (that would exit the app) — go
    // to the waitroom, which keeps re-announcing and shows a red button on timeout.
    let _ = conn.snd_requests(user_name.to_string()).await;
    *ran = false;
    Ok((conn, slot, prvkey, pubkey, user_id))
}
async fn joinstuffold(choice: &str, config: &Config, iface: Option<String>, token: CancellationToken, ran: &mut bool) -> Result<(Arc<Connection>, Arc<Chat>)> {
    if !*ran {
        return Err(anyhow::anyhow!("joinstuffold already ran"));
    }
    let socket = get_free_port(iface.as_deref()).await?;
    let prvkey = config.prvkey.as_ref().ok_or_else(|| anyhow::anyhow!("config missing prvkey"))?.clone();
    let user_name = config.user_name.as_ref().ok_or_else(|| anyhow::anyhow!("config missing user_name"))?.clone();
    let user_id = config.user_id.ok_or_else(|| anyhow::anyhow!("config missing user_id"))?;
    let rendezvous = config.rendezvous.ok_or_else(|| anyhow::anyhow!("config missing rendezvous"))?;
    let uid = Uid::getuid();
    let pubkey_hex = hex::encode(PublicKey::from(&prvkey).as_bytes());
    let user = User::new(pubkey_hex.clone(), user_name.clone(), uid);
    if !user.ver_id(pubkey_hex, user_id) {
        return Err(anyhow::anyhow!("config identity mismatch (wrong key/name/machine)"));
    }
    let (chat, peermap) = Chat::old(choice, &user_name, prvkey.clone()).await?;
    let mut conn = Connection::new(prvkey, rendezvous, socket, peermap).await;
    conn.set_user(user_id, user_name, uid);
    let conn = Arc::new(conn);
    let chat = Arc::new(chat);
    member_rcv(&conn, filled_slot(&chat), token);
    // Reconnect straight to peers (Chat::old already dialed them). The rendezvous is only needed
    // when a peer is offline — the `fallback` bg task re-announces then. Best-effort here so an
    // unreachable peer/rendezvous can't crash the rejoin.
    let _ = conn.send_db_req(&chat).await; // re-sync with whoever's reachable
    *ran = false;
    Ok((conn, chat))
}

// Seqeuence parsing regex
lazy_static::lazy_static! { static ref RE_NUM: Regex = Regex::new(r"\d+").unwrap(); }
lazy_static::lazy_static! {
    static ref RE_CHR: Regex = Regex::new(r"[a-zA-Z]+").unwrap();
}


pub async fn app() -> Result<()> {
    // TODO: elegant error handling (Primarily in home.rs)
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
    let mut iface = 0usize; // selected interface index (into `interfaces`)
    let mut chat_name_input = String::new();
    let mut user_name_input = String::new();
    let mut rendezvous_input = String::new();
    let mut chat_2_delete: Option<usize> = None;

    // App meat: Connection and Chat (shared with the spawned admin tasks)
    let mut conn: Option<Arc<Connection>> = None;
    let mut chat: Option<Arc<Chat>> = None;
    // A joiner waits in InitClient until the admin's accept fills this slot with the chat.
    let mut chat_slot: Option<ChatSlot> = None;
    let mut join_keys: Option<(StaticSecret, u64)> = None;
    let mut run_once: bool = true;
    let mut token = CancellationToken::new();

    // Admin rendezvous state
    let mut admin_active_section = 2;
    let mut admin_active_row = false; // notify/kick & accept/delete
    let mut admin_active_col = 0;
    // let token = CancellationToken::new();
    let requests = Arc::new(Mutex::new(Vec::<([SocketAddr; 2], String, PublicKey, u32)>::new()));

    // chat UI state
    let mut vim_mode = Vim::Normal;
    let mut seq = String::new();
    let mut input = String::new();
    let mut cursor_pos: usize = 0; // cursor position
    let mut persis_y: usize = 0;   // peristant y position
    let mut anim_tick: usize = 0; // client animation tick
    let mut client_resend_at = std::time::Instant::now(); // join-request resend CD
    let mut client_resend_n: usize = 0;
    let mut scroll_offset: Option<u16> = None;
    let mut my_addrs: Option<[SocketAddr; 2]> = None; // initMember addrs display
    // (name, ip) per up interface, refreshed each home render for the interface picker.
    let interfaces: Arc<Mutex<Vec<(String, std::net::IpAddr)>>> = Arc::new(Mutex::new(Vec::new()));

    let mut curr_screen = Screen::Home;

    #[allow(unused)] //macros are weird
    #[allow(clippy::collapsible_match)] //TODO: refactor to match
    loop {
        if curr_screen == Screen::Home {
            // Leaving a live session: cancel its background tasks and drop handles.
            if conn.is_some() {
                token.cancel();
                token = CancellationToken::new();
            }
            conn = None;
            chat = None;
            chat_slot = None;
            join_keys = None;
            scroll_offset = None; // re-arm: the next chat entry jumps to the latest message
            my_addrs = None; // drop: re-resolved on the next join
            crate::connection::interfaces(&interfaces); // refresh the list (reflects VPN up/down)
            home!(terminal, curr_screen, config, choice, chats, conn, chat, chat_slot, join_keys, home_active_section, home_active_field, chat_name_input, user_name_input, rendezvous_input, chat_2_delete, anim_tick, run_once, requests, token, interfaces, iface);
        } else if curr_screen == Screen::InitServer && let Some(ref chat) = chat
            && let Some(ref conn) = conn {
            initAdmin!(terminal, curr_screen, config, choice, chats, admin_active_section, admin_active_row, admin_active_col, requests, input, conn, chat);
        } else if curr_screen == Screen::InitClient && let Some(ref conn) = conn {
            let accepted = chat_slot.as_ref().and_then(|s| {
                s.lock().unwrap().as_ref().map(|a| (a.chat.clone(), a.name.clone()))
            });
            if let Some((acc_chat, acc_name)) = accepted {
                choice = acc_name.clone();
                if let Some((prvkey, user_id)) = join_keys.take() {
                    config = Config::save(CONFIG, &acc_name, &user_name_input, &rendezvous_input, user_id, prvkey)?;
                }
                chats = ChatChoice::load(CONFIG)?;
                chat = Some(acc_chat);
                curr_screen = Screen::Chat;
                my_addrs = None; // leaving the waitroom
                continue;
            }
            if my_addrs.is_none() {
                my_addrs = Some(conn.current_addrs());
            }
            initMember!(terminal, curr_screen, config, rendezvous_input, anim_tick, conn, client_resend_at, client_resend_n, my_addrs);
        } else if curr_screen == Screen::Chat && let Some(ref chat) = chat
            && let Some(ref conn) = conn {
            chat!(terminal, curr_screen, config, choice, chats, conn, chat, run_once, vim_mode, seq, input, cursor_pos, persis_y, scroll_offset, requests);
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
