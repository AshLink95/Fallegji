// prompt engineered
use std::{collections::HashMap, net::SocketAddr, sync::{Arc, RwLock}};
use tokio::net::TcpListener;
use fallegji::{
    messaging::{Message, Chat},
    db::Database,
    auth::{User, Uid, Role},
    connection::{Connection, Peer, KeyGen, Communication, get_free_port},
};
use hex::ToHex;
use anyhow::Result;

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
    Ok(Connection::new(prvkey, rendez, get_free_port().await?, HashMap::new()).await)
}

/// Message: construction, getters, setters, serde roundtrip.
#[test]
fn test_message() {
    let mut m = Message::new(5, 42, "hi".to_string());
    assert_eq!(m.get_id(), 5);
    assert_eq!(m.get_sender_id(), 42);
    assert_eq!(m.get_contents(), "hi");
    assert!(m.get_sent_at() > 0, "new() stamps a real time");

    m.set_contents("yo".to_string());
    assert_eq!(m.get_contents(), "yo");
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
    let _ = std::fs::remove_file(path);

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

    let _ = std::fs::remove_file(path);
    Ok(())
}

/// Chat::join builds a member's chat from the admin's DB dump: adopts the admin's state and
/// registers itself (Member, not Admin).
#[tokio::test]
async fn test_chat_join() -> Result<()> {
    let (admin_db, join_db) = ("a__jointest.db", "b__jointest.db");
    let _ = std::fs::remove_file(admin_db);
    let _ = std::fs::remove_file(join_db);

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

    let _ = std::fs::remove_file(admin_db);
    let _ = std::fs::remove_file(join_db);
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

struct Node { conn: Connection, chat: Chat, user_id: u64, db_path: String }

/// Throwaway localhost listener (Connection::new needs one; we never accept on it).
async fn bind_local() -> Result<(SocketAddr, TcpListener)> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let addr = l.local_addr()?;
    Ok((addr, l))
}

/// Admin: owns the chat via Chat::new.
async fn admin(name: &str, room: &str) -> Result<Node> {
    let (addr, listener) = bind_local().await?;
    let (chat, prvkey, _pub, user_id, _pid, peermap) = Chat::new(room, name, addr.port()).await?;
    let mut conn = Connection::new(prvkey, "127.0.0.1:65000".parse().unwrap(), (addr, listener), peermap).await;
    conn.set_user(user_id, name.to_string(), Uid::getuid());
    Ok(Node { conn, chat, user_id, db_path: format!("{name}__{room}.db") })
}

/// Member: db born from the admin's snapshot exactly as acceptance does (Chat::join).
async fn join(admin: &Node, name: &str, room: &str) -> Result<Node> {
    let (addr, listener) = bind_local().await?;
    let (_peer, prvkey) = Peer::new_out(-1, addr.port())?;
    let uid = Uid::getuid();
    let snapshot = admin.chat.db.dump().await?;
    let chat = Chat::join(room, name, &prvkey, uid, addr.port(), snapshot).await?;
    let user_id = chat.current_user.get_id();
    let mut conn = Connection::new(prvkey, "127.0.0.1:65000".parse().unwrap(), (addr, listener), HashMap::new()).await;
    conn.set_user(user_id, name.to_string(), uid);
    Ok(Node { conn, chat, user_id, db_path: format!("{name}__{room}.db") })
}

/// Author a message straight into a node's own db (what send_message persists locally).
async fn say(n: &Node, msg: &str) -> Result<()> {
    let m = n.chat.db.create_message(n.user_id, msg.to_string(), None).await?;
    n.chat.message_history.write().unwrap().push(m);
    Ok(())
}

/// Merge src's whole db into dst through the app's real db-sync handler.
async fn merge(dst: &Node, src: &Node) -> Result<()> {
    let payload = serde_json::to_vec(&src.chat.db.dump().await?)?;
    dst.conn.read_db_sync(&dst.chat, payload).await
}

/// One reconciliation pass for a star around the admin: gather every member into
/// the admin, then push the admin's union back out — leaves all copies identical.
async fn sync(alice: &Node, members: &[&Node]) -> Result<()> {
    for m in members { merge(alice, m).await?; }
    for m in members { merge(m, alice).await?; }
    Ok(())
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

#[tokio::test]
async fn test_three_user_convergence() -> Result<()> {
    let room = "room";
    let alice = admin("alice", room).await?;
    let bob = join(&alice, "bob", room).await?;
    let carol = join(&alice, "carol", room).await?;

    // Pair (alice, bob); carol away.
    say(&alice, "alice: hi bob").await?;
    say(&bob, "bob: hi alice").await?;
    say(&carol, "carol: noted while AB chatted").await?;
    sync(&alice, &[&bob, &carol]).await?;

    // Pair (alice, carol); bob away.
    say(&alice, "alice: hi carol").await?;
    say(&carol, "carol: hi alice").await?;
    say(&bob, "bob: noted while AC chatted").await?;
    sync(&alice, &[&bob, &carol]).await?;

    // Pair (bob, carol); alice away.
    say(&bob, "bob: hi carol").await?;
    say(&carol, "carol: hi bob").await?;
    say(&alice, "alice: noted while BC chatted").await?;
    sync(&alice, &[&bob, &carol]).await?;

    // Each speaking by themselves, then a final reconciliation.
    say(&alice, "alice: solo").await?;
    say(&bob, "bob: solo").await?;
    say(&carol, "carol: solo").await?;
    sync(&alice, &[&bob, &carol]).await?;

    // All three copies are now identical (messages + users).
    let a = msg_set(&alice.chat.db).await?;
    assert_eq!(a, msg_set(&bob.chat.db).await?, "bob's messages match alice's");
    assert_eq!(a, msg_set(&carol.chat.db).await?, "carol's messages match alice's");

    let ua = user_set(&alice.chat.db).await?;
    assert_eq!(ua, user_set(&bob.chat.db).await?, "bob's users match");
    assert_eq!(ua, user_set(&carol.chat.db).await?, "carol's users match");
    assert_eq!(ua.len(), 3, "alice, bob, carol all present");

    // Every authored message (pairs + away + solo) reached all three.
    for content in [
        "alice: hi bob", "bob: hi alice", "carol: noted while AB chatted",
        "alice: hi carol", "carol: hi alice", "bob: noted while AC chatted",
        "bob: hi carol", "carol: hi bob", "alice: noted while BC chatted",
        "alice: solo", "bob: solo", "carol: solo",
    ] {
        assert!(a.iter().any(|(_, c, _)| c == content), "missing message: {content}");
    }

    for n in [&alice, &bob, &carol] { let _ = std::fs::remove_file(&n.db_path); }
    Ok(())
}
