use std::{collections::HashMap, net::SocketAddr, sync::{Arc, RwLock}};
use tokio::net::TcpListener;
use fallegji::{
    messaging::{Message, Chat},
    db::Database,
    auth::{User, Uid, Role},
    connection::{Connection, Peer, KeyGen, Communication, get_free_port},
};
use hex::ToHex;
use x25519_dalek::PublicKey;
use anyhow::Result;

/// RAII auto-cleanup for file-backed test dbs — removes them on Drop, so a panicking test can't
/// leave stale dbs that contaminate the next run.
struct DbGuard(Vec<String>);
impl DbGuard {
    fn new<const N: usize>(files: [&str; N]) -> Self { Self(files.iter().map(|s| s.to_string()).collect()) }
}
impl Drop for DbGuard {
    fn drop(&mut self) { for f in &self.0 { let _ = std::fs::remove_file(f); } }
}

/// In-memory Chat with a linked admin user + sys, for the logic-only tests.
async fn mem_chat() -> Result<(Chat, u64)> {
    let db = Database::new(":memory:")?;
    let (peer, _) = db.create_peer(9000).await?;
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    let mut user = db.create_user(pubkey_hex, "me".to_string(), Uid::getuid()).await?;
    user.set_role(Role::Admin);
    db.update_user_role(user.get_id(), Role::Admin).await?;
    db.update_peer_link_user(peer.get_id(), user.get_id()).await?;
    let sys = db.create_sys().await?;

    let uid = user.get_id();
    let mut members = HashMap::new();
    members.insert(uid, user.clone());
    members.insert(0u64, sys);

    let chat = Chat {
        message_history: Arc::new(RwLock::new(Vec::new())),
        members: Arc::new(RwLock::new(members)),
        current_user: user,
        db,
        notify: std::sync::atomic::AtomicBool::new(false), // no desktop popups during tests
    };
    Ok((chat, uid))
}

/// A connection with no peers — send_msg broadcasts to nobody (no-op), so the
/// send helpers can be exercised for their local effects.
async fn bare_conn() -> Result<Connection> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let rendez = l.local_addr()?;
    drop(l);
    let (_, prvkey) = Peer::keypairgen()?;
    Ok(Connection::new(prvkey, rendez, get_free_port(None).await?, HashMap::new()).await)
}

/// Message: construction, getters, setters, serde roundtrip.
#[test]
fn test_message() {
    let mut m = Message::new(5, 42, "hi".to_string());
    assert_eq!(m.get_id(), 5);
    assert_eq!(m.get_sender_id(), 42);
    assert_eq!(m.get_contents(), "hi");
    assert!(m.get_sent_at() > 0, "new() stamps a real time");

    m.set_date(12345);
    assert_eq!(m.get_sent_at(), 12345);

    // Serde roundtrip (wire format for msg packets).
    let bytes = serde_json::to_vec(&m).unwrap();
    let back: Message = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(m, back);
}

/// get_admin: returns the admin member's id, or None when nobody is admin.
#[tokio::test]
async fn test_get_admin() -> Result<()> {
    let (chat, uid) = mem_chat().await?;
    assert_eq!(chat.get_admin(), Some(uid), "admin found");

    // No admin among members → None.
    {
        let mut m = chat.members.write().unwrap();
        m.clear();
        m.insert(0u64, User::sys()); // sys has no admin role
    }
    assert_eq!(chat.get_admin(), None, "no admin → None");
    Ok(())
}

/// send_message + send_join: append to history and persist to the DB.
#[tokio::test]
async fn test_send_helpers() -> Result<()> {
    let (chat, uid) = mem_chat().await?;
    let conn = bare_conn().await?;

    chat.send_message(&conn, uid, "hello".to_string()).await;
    assert!(chat.message_history.read().unwrap().iter().any(|m| m.get_contents() == "hello"), "in history");
    assert!(chat.db.load_all_messages().await?.iter().any(|m| m.get_contents() == "hello"), "persisted");

    chat.send_join(&conn).await;
    let joined = format!("{} joined the chat", chat.current_user.get_name());
    assert!(chat.message_history.read().unwrap().iter().any(|m| m.get_contents() == joined), "join message");
    Ok(())
}

/// kick: removes the victim from members + the user DB row, keeps their messages
/// ([REDACTED] on render), and posts the "kicked out" system message.
#[tokio::test]
async fn test_kick() -> Result<()> {
    let (chat, _admin) = mem_chat().await?;
    let conn = bare_conn().await?;

    // A victim member with their own peer + message.
    let (vpeer, _) = chat.db.create_peer(9100).await?;
    let vhex = vpeer.get_pubkey().to_bytes().encode_hex::<String>();
    let victim = chat.db.create_user(vhex, "victim".to_string(), Uid::getuid()).await?;
    chat.db.update_peer_link_user(vpeer.get_id(), victim.get_id()).await?;
    let vid = victim.get_id();
    chat.members.write().unwrap().insert(vid, victim);
    chat.send_message(&conn, vid, "bye".to_string()).await; // victim's own message

    chat.kick(&conn, vid).await;

    assert!(!chat.members.read().unwrap().contains_key(&vid), "victim removed from members");
    assert!(chat.db.read_user(vid).await?.is_none(), "victim removed from db (FK refs notwithstanding)");
    assert!(!chat.db.load_all_peers().await?.iter().any(|p| p.get_user_id() == Some(vid)), "victim peer removed from db");
    assert!(chat.message_history.read().unwrap().iter().any(|m| m.get_contents() == "bye"), "victim's message kept");
    assert!(chat.message_history.read().unwrap().iter().any(|m| m.get_contents().contains("kicked out")), "kick system message posted");
    Ok(())
}

/// Chat::new bootstraps DB + members + self-peer; Chat::old reloads from that DB.
#[tokio::test]
async fn test_chat_new_and_old() -> Result<()> {
    let path = "u__msgtest.db";
    let _db = DbGuard::new([path]);

    let (chat, prvkey, _pub, user_id, _peer_id, peermap) = Chat::new("msgtest", "u", 9000).await?;
    {
        let members = chat.members.read().unwrap();
        assert!(members.contains_key(&user_id), "admin member");
        assert!(members.contains_key(&0u64), "sys member");
    }
    assert_eq!(chat.current_user.get_role(), Some(Role::Admin), "creator is admin");
    assert!(chat.message_history.read().unwrap().iter().any(|m| m.get_contents().contains("created by")), "system message");
    assert!(peermap.contains_key(&user_id), "peermap includes self");
    drop(chat); // release the DB file before reopening

    let (old, _peermap) = Chat::old("msgtest", "u", prvkey).await?;
    assert_eq!(old.current_user.get_id(), user_id, "same user reloaded");
    assert!(old.members.read().unwrap().contains_key(&user_id), "members reloaded");
    assert!(old.message_history.read().unwrap().iter().any(|m| m.get_contents().contains("created by")), "history reloaded");
    drop(old);
    Ok(())
}

/// Chat::join builds a member's chat from the admin's DB dump: adopts the admin's state and
/// registers itself (Member, not Admin).
#[tokio::test]
async fn test_chat_join() -> Result<()> {
    let (admin_db, join_db) = ("a__jointest.db", "b__jointest.db");
    let _db = DbGuard::new([admin_db, join_db]);

    let (admin, _prv, _pub, admin_id, _pid, _pm) = Chat::new("jointest", "a", 9000).await?;
    let snapshot = admin.db.dump().await?;
    drop(admin);

    let (_peer, prvkey) = Peer::new_out(-1, 9100)?;
    let chat = Chat::join("jointest", "b", &prvkey, Uid::getuid(), 9100, snapshot).await?;

    assert_eq!(chat.current_user.get_name(), "b", "current user is the joiner");
    assert_ne!(chat.current_user.get_role(), Some(Role::Admin), "joiner is not admin");
    assert!(chat.members.read().unwrap().contains_key(&admin_id), "adopted the admin as a member");
    assert!(chat.members.read().unwrap().values().any(|u| u.get_name() == "b"), "registered itself");
    assert!(chat.message_history.read().unwrap().iter().any(|m| m.get_contents().contains("created by")), "adopted the admin's history");
    drop(chat);
    Ok(())
}

// ----------------------------------------------------------------------------
// Three-copy DB convergence. An admin (alice) + two members (bob, carol), each
// with its OWN db file, chat in pairs (the third "away", composing locally) and
// solo, reconciling after each round via the app's real merge handler
// (read_db_sync). "Convergence" is the distributed-systems sense: three replicas
// edited independently must reconcile to ONE identical state (same messages +
// users) — that's what this asserts.
//
// Driven directly through read_db_sync (no fire-and-forget sockets or sleeps), so
// it's deterministic and instant. The live TCP transport is covered separately by
// connection_testsuite::test_message_exchange.
// ----------------------------------------------------------------------------

struct Node { conn: Connection, chat: Chat, user_id: u64, pubkey: PublicKey, name: String, uid: Uid, addr: SocketAddr, db_path: String }
// Auto-clean each node's file-backed db on drop (panic-safe).
impl Drop for Node {
    fn drop(&mut self) { let _ = std::fs::remove_file(&self.db_path); }
}

/// Throwaway localhost listener (Connection::new needs one; we never accept on it).
async fn bind_local() -> Result<(SocketAddr, TcpListener)> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let addr = l.local_addr()?;
    Ok((addr, l))
}

/// Admin: owns the chat via Chat::new.
async fn admin(name: &str, room: &str) -> Result<Node> {
    let (addr, listener) = bind_local().await?;
    let (chat, prvkey, pubkey, user_id, _pid, peermap) = Chat::new(room, name, addr.port()).await?;
    let uid = Uid::getuid();
    let mut conn = Connection::new(prvkey, "127.0.0.1:65000".parse().unwrap(), (addr, listener), peermap).await;
    conn.set_user(user_id, name.to_string(), uid);
    Ok(Node { conn, chat, user_id, pubkey, name: name.into(), uid, addr, db_path: format!("{name}__{room}.db") })
}

/// Member: db born from the admin's snapshot exactly as acceptance does (Chat::join).
async fn join(admin: &Node, name: &str, room: &str) -> Result<Node> {
    let (addr, listener) = bind_local().await?;
    let (peer, prvkey) = Peer::new_out(-1, addr.port())?;
    let pubkey = peer.get_pubkey();
    let uid = Uid::getuid();
    let snapshot = admin.chat.db.dump().await?;
    let chat = Chat::join(room, name, &prvkey, uid, addr.port(), snapshot).await?;
    let user_id = chat.current_user.get_id();
    let mut conn = Connection::new(prvkey, "127.0.0.1:65000".parse().unwrap(), (addr, listener), HashMap::new()).await;
    conn.set_user(user_id, name.to_string(), uid);
    Ok(Node { conn, chat, user_id, pubkey, name: name.into(), uid, addr, db_path: format!("{name}__{room}.db") })
}

/// Admin learns a member into its db + members (what accept/send_newpeer establishes).
async fn learn(admin: &Node, m: &Node) -> Result<()> {
    let key = m.pubkey.to_bytes().encode_hex::<String>();
    admin.chat.db.create_user(key.clone(), m.name.clone(), m.uid).await?;
    admin.chat.db.create_peer_with(m.pubkey, [m.addr; 2], m.user_id).await?;
    admin.chat.members.write().unwrap().insert(m.user_id, User::new(key, m.name.clone(), m.uid));
    Ok(())
}

/// Author a message straight into a node's own db (what send_message persists locally).
async fn say(n: &Node, msg: &str) -> Result<()> {
    let m = n.chat.db.create_message(n.user_id, msg.to_string(), None).await?;
    n.chat.message_history.write().unwrap().push(m);
    Ok(())
}

/// Build the DBS wire payload from a db exactly as send_db_sync does (3 canonical zipped
/// components, length-framed, then serde-wrapped like the DBS frame), to feed read_db_sync.
async fn sync_payload(db: &Database) -> Result<Vec<u8>> {
    let mut msgs: Vec<(u64, i64, String)> = db.load_all_messages().await?
        .iter().map(|m| (m.get_sender_id(), m.get_sent_at(), m.get_contents())).collect();
    msgs.sort_by_key(|a| (a.1, a.0));
    let mut usrs: Vec<(u64, String, Option<String>, u32)> = db.load_all_users().await?
        .iter().map(|u| (u.get_id(), u.get_name(), u.get_role().map(|r| r.to_string()), u.get_uid().as_raw())).collect();
    usrs.sort_by_key(|u| u.0);
    let mut pirs: Vec<(Option<u64>, [String; 2], [u8; 32])> = db.load_all_peers().await?
        .iter().map(|p| (p.get_user_id(), p.get_addrs().map(|a| a.to_string()), p.get_pubkey().to_bytes())).collect();
    pirs.sort_by_key(|a| a.0);
    let mut framed = Vec::new();
    for blob in [
        lz4_flex::compress_prepend_size(&serde_json::to_vec(&msgs)?),
        lz4_flex::compress_prepend_size(&serde_json::to_vec(&usrs)?),
        lz4_flex::compress_prepend_size(&serde_json::to_vec(&pirs)?),
    ] {
        framed.extend_from_slice(&(blob.len() as u32).to_be_bytes());
        framed.extend_from_slice(&blob);
    }
    Ok(serde_json::to_vec(&framed)?)
}

async fn msg_set(db: &Database) -> Result<Vec<(u64, String, i64)>> {
    let mut v: Vec<_> = db.load_all_messages().await?
        .into_iter().map(|m| (m.get_sender_id(), m.get_contents(), m.get_sent_at())).collect();
    v.sort();
    Ok(v)
}
async fn user_set(db: &Database) -> Result<Vec<(u64, String)>> {
    let mut v: Vec<_> = db.load_all_users().await?
        .into_iter().map(|u| (u.get_id(), u.get_name())).collect();
    v.sort();
    Ok(v)
}

/// The new buffered decider: messages are always the union (additive), the roster follows
/// the admin (the admin keeps its own; a member adopts the admin's). With an empty peermap
/// the online count is 0, so each read_db_sync triggers decide_sync immediately.
#[tokio::test]
async fn test_decide_sync() -> Result<()> {
    let room = "syncroom";
    let alice = admin("alice", room).await?;
    let bob = join(&alice, "bob", room).await?;
    let carol = join(&alice, "carol", room).await?;
    learn(&alice, &bob).await?;   // admin holds the full roster, as accept would establish
    learn(&alice, &carol).await?;

    say(&alice, "a1").await?;
    say(&bob, "b1").await?;
    say(&carol, "c1").await?;

    // Additive on the admin: buffer both members' syncs (empty peermap → online 0, no auto-decide),
    // then collapse → messages union; roster stays alice's.
    let pb = sync_payload(&bob.chat.db).await?;
    alice.conn.read_db_sync(&alice.chat, bob.user_id, pb).await?;
    let pc = sync_payload(&carol.chat.db).await?;
    alice.conn.read_db_sync(&alice.chat, carol.user_id, pc).await?;
    alice.conn.decide_sync(&alice.chat).await?;
    let a = msg_set(&alice.chat.db).await?;
    for c in ["a1", "b1", "c1"] { assert!(a.iter().any(|(_, x, _)| x == c), "admin missing {c} (additive)"); }
    assert_eq!(user_set(&alice.chat.db).await?.len(), 3, "admin kept its own roster (alice, bob, carol)");

    // Admin authority on a member: bob ingests the admin's sync → adopts its roster + all msgs.
    let pa = sync_payload(&alice.chat.db).await?;
    bob.conn.read_db_sync(&bob.chat, alice.user_id, pa).await?;
    bob.conn.decide_sync(&bob.chat).await?;
    assert_eq!(user_set(&bob.chat.db).await?, user_set(&alice.chat.db).await?, "bob adopted the admin's roster");
    let bm = msg_set(&bob.chat.db).await?;
    for c in ["a1", "b1", "c1"] { assert!(bm.iter().any(|(_, x, _)| x == c), "bob missing {c} (additive)"); }

    Ok(())
}

/// A live message present only in the in-memory history (read_msg pushed it; its async db write
/// hasn't landed) must survive a decide_sync, which reloads history from the db. Regression for
/// "history not always loading" — the decider folds in-memory history into the union.
#[tokio::test]
async fn test_decide_keeps_inmemory_message() -> Result<()> {
    let room = "memsync";
    let alice = admin("alice", room).await?;
    let bob = join(&alice, "bob", room).await?;
    learn(&alice, &bob).await?;

    let mut m = Message::new(-1, alice.user_id, "in-memory only".to_string());
    m.set_date(123_456_789);
    alice.chat.message_history.write().unwrap().push(m); // NOT in the db

    let pb = sync_payload(&bob.chat.db).await?;
    alice.conn.read_db_sync(&alice.chat, bob.user_id, pb).await?;
    alice.conn.decide_sync(&alice.chat).await?;

    assert!(alice.chat.message_history.read().unwrap().iter().any(|m| m.get_contents() == "in-memory only"),
        "decider kept the in-memory-only message");
    assert!(msg_set(&alice.chat.db).await?.iter().any(|(_, c, _)| c == "in-memory only"),
        "and persisted it");
    Ok(())
}
