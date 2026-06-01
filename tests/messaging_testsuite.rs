// prompt engineered
use std::{collections::HashMap, sync::{Arc, RwLock}};
use tokio::net::TcpListener;
use fallegji::{
    messaging::{Message, Chat},
    db::Database,
    auth::{User, Uid, Role},
    connection::{Connection, Peer, KeyGen, get_free_port},
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

    chat.send_message(&conn, uid, "hello".to_string()).await?;
    assert!(chat.message_history.read().unwrap().iter().any(|m| m.get_contents() == "hello"), "in history");
    assert!(chat.db.load_all_messages().await?.iter().any(|m| m.get_contents() == "hello"), "persisted");

    chat.send_join(&conn).await?;
    let joined = format!("{} joined the chat", chat.current_user.get_name());
    assert!(chat.message_history.read().unwrap().iter().any(|m| m.get_contents() == joined), "join message");
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
