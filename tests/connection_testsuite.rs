// prompt engineered
use std::{collections::HashMap, net::{IpAddr, Ipv4Addr, SocketAddr}, sync::Arc};
use tokio::{net::{TcpListener, TcpStream}, sync::Mutex, io::AsyncReadExt};

async fn free_rendezvous_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    addr
}
use chacha20poly1305::Key;
use x25519_dalek::{PublicKey, StaticSecret};
use fallegji::{connection::{Connection, KeyGen, Peer, Secrecy, RendezVous, Communication, get_free_port}, messaging::{Message, Chat}, auth::{Uid, User}, db::Database};
use hex::ToHex;
use tokio_util::sync::CancellationToken;
use std::time::Duration;
use anyhow::Result;

// Header bytes (mirror connection.rs private consts)
const HBT_HD: u8 = 0xE2;
const TYP_HD: u8 = 0xD3;

/// Build a Connection holding one peer wired to a live TCP stream.
/// Returns (conn, the other end of that stream, the shared key).
async fn conn_with_peer() -> Result<(Connection, TcpStream, Key)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let laddr = listener.local_addr()?;
    let client = TcpStream::connect(laddr).await?;
    let (server, _) = listener.accept().await?;

    let key = *Key::from_slice(b"0123456789abcdef0123456789abcdef");
    let (peer, _) = Peer::new_out(1, 9000)?;
    let mut peermap = HashMap::new();
    peermap.insert(1u64, (peer, key, Some(Arc::new(Mutex::new(client)))));

    let (_, prvkey) = Peer::keypairgen()?;
    let rendez = free_rendezvous_addr().await;
    let sock = get_free_port().await?;
    let conn = Connection::new(prvkey, rendez, sock, peermap).await;
    Ok((conn, server, key))
}

/// Read one length-prefixed frame.
async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    let mut frame = vec![0u8; n];
    stream.read_exact(&mut frame).await?;
    Ok(frame)
}

/// Minimal in-memory Chat for testing read_* dispatch.
fn test_chat() -> Result<Chat> {
    Ok(Chat {
        message_history: Arc::new(std::sync::RwLock::new(Vec::new())),
        members: Arc::new(std::sync::RwLock::new(HashMap::new())),
        current_user: User::new("dead".to_string(), "me".to_string(), Uid::from(1)),
        db: Database::new(":memory:")?,
    })
}

#[test]
fn test_peer_new_out_creation() {
    let result = Peer::new_out(1, 9000);
    assert!(result.is_ok());

    let (peer, prvkey) = result.unwrap();
    assert_eq!(peer.get_id(), 1);
    assert_eq!(peer.get_user_id(), None);
    assert_eq!(peer.get_addr().port(), 9000);
    assert_eq!(peer.get_last_heartbeat(), None);
    assert_ne!(peer.get_addr().ip(), IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    assert_eq!(prvkey.as_bytes().len(), 32);
}

#[test]
fn test_peer_new_in_creation() {
    let peer_id = 2;
    let peer_name = "TestPeer".to_string();
    let peer_uid = Uid::from(10);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let tmp_secret = StaticSecret::from([1u8; 32]);
    let pubkey = PublicKey::from(&tmp_secret);
    let last_heartbeat = Some(1234567890i64);
    let last_seen_typing = Some(1111111111i64);

    // Real user_id so ver_id passes and new_in succeeds.
    let pubkey_hex: String = pubkey.as_bytes().encode_hex();
    let peer_user_id = User::new(pubkey_hex, peer_name.clone(), peer_uid).get_id();

    let peer = Peer::new_in(
        peer_id,
        peer_name,
        peer_uid,
        peer_user_id,
        addr,
        pubkey,
        last_seen_typing,
        last_heartbeat,
    ).expect("new_in should succeed with a valid user_id");

    assert_eq!(peer.get_id(), peer_id);
    assert_eq!(peer.get_user_id(), Some(peer_user_id));
    assert_eq!(peer.get_addr(), addr);
    assert_eq!(peer.get_last_heartbeat(), last_heartbeat);
    assert_eq!(peer.get_last_seen_typing(), last_seen_typing);

    // Invalid user_id is rejected.
    let bad = Peer::new_in(peer_id, "x".to_string(), peer_uid, 999u64, addr, pubkey, None, None);
    assert!(bad.is_err());
}

#[test]
fn test_peer_getters() {
    let (peer, _prvkey) = Peer::new_out(3, 8080).unwrap();

    assert_eq!(peer.get_id(), 3);
    assert_eq!(peer.get_user_id(), None);
    assert_eq!(peer.get_addr().port(), 8080);
    assert_eq!(peer.get_last_heartbeat(), None);
    assert_eq!(peer.get_last_seen_typing(), None);

    let pubkey = peer.get_pubkey();
    assert_eq!(pubkey.as_bytes().len(), 32);
}

#[test]
fn test_peer_setters() {
    let (mut peer, _prvkey) = Peer::new_out(-1, 8080).unwrap();

    peer.set_id(10);
    assert_eq!(peer.get_id(), 10);

    peer.set_id(20);
    assert_eq!(peer.get_id(), 10);

    let new_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090);
    peer.set_addr(new_addr);
    assert_eq!(peer.get_addr(), new_addr);

    peer.set_last_heartbeat(Some(1234567890));
    assert_eq!(peer.get_last_heartbeat(), Some(1234567890));

    peer.set_last_heartbeat(None);
    assert_eq!(peer.get_last_heartbeat(), None);

    peer.set_last_seen_typing(Some(42));
    assert_eq!(peer.get_last_seen_typing(), Some(42));

    peer.set_last_seen_typing(None);
    assert_eq!(peer.get_last_seen_typing(), None);

    let user_name = "TestUser".to_string();
    let user_id = 999u64;
    let user_uid = Uid::from(11);

    let result = peer.set_user_id(user_name.clone(), user_id, user_uid);

    if result.is_ok() {
        assert_eq!(peer.get_user_id(), Some(user_id));

        let result2 = peer.set_user_id("Another".to_string(), 888, Uid::from(12));
        assert!(result2.is_err());
        assert_eq!(peer.get_user_id(), Some(user_id)); // Should still be original
    }
}

#[test]
fn test_keygen() {
    let result = Peer::keypairgen();
    assert!(result.is_ok());

    let (pubkey1, prvkey1) = result.unwrap();
    assert_eq!(pubkey1.as_bytes().len(), 32);
    assert_eq!(prvkey1.as_bytes().len(), 32);
    let (pubkey2, _prvkey2) = Peer::keypairgen().unwrap();
    assert_ne!(pubkey1.as_bytes(), pubkey2.as_bytes());

    let (peer, peer_prvkey) = Peer::new_out(1, 8080).unwrap();
    let (other_peer, other_prvkey) = Peer::new_out(2, 8081).unwrap();
    let shared1 = peer.shrdkeygen(other_prvkey);
    let shared2 = other_peer.shrdkeygen(peer_prvkey);
    assert_eq!(shared1.as_slice(), shared2.as_slice());
    assert_eq!(shared1.as_slice().len(), 32);
}

// Header bytes (mirror connection.rs private consts)
const MSG_HD: u8 = 0xF1;
const DBS_HD: u8 = 0xC4;

#[test]
fn test_secrecy() {
    let key_bytes: &[u8; 32] = b"super-secret-32-byte-key!!-12345";
    let key = Key::from_slice(key_bytes);
    let wrong_key = Key::from_slice(b"wrong-key-does-not-match-1234567");

    // --- encode/decode: Message roundtrips (uncompressed path) ---
    let test_messages = [
        Message::new(1, 12345, "Hello peer-to-peer world!".to_string()),
        Message::new(2, 0, "".to_string()),
        Message::new(3, 999, "🔥 Complex chars: emojis & unicode 🔥".to_string()),
    ];

    for original in test_messages.iter() {
        let encrypted = Connection::encode(key, MSG_HD, original.clone()).expect("Encode failed");
        // 1B header + plaintext + 12B nonce + 16B tag
        let plaintext_len = serde_json::to_vec(original).unwrap().len();
        assert_eq!(encrypted.len(), 1 + plaintext_len + 12 + 16);

        let (header, bytes) = Connection::decode(key, &encrypted).expect("Decode failed");
        assert_eq!(header, MSG_HD);
        let decrypted: Message = serde_json::from_slice(&bytes).expect("Deserialize failed");
        assert_eq!(original.get_id(), decrypted.get_id());
        assert_eq!(original.get_sender_id(), decrypted.get_sender_id());
        assert_eq!(original.get_contents(), decrypted.get_contents());
        assert_eq!(original.get_sent_at(), decrypted.get_sent_at());
    }

    // --- encode/decode: String roundtrips ---
    let test_strings = [
        "hello world".to_string(),
        "".to_string(),
        "🔥 unicode test 🔥".to_string(),
    ];

    for original in test_strings.iter() {
        let encrypted = Connection::encode(key, MSG_HD, original.clone()).expect("Encode failed");
        let (header, bytes) = Connection::decode(key, &encrypted).expect("Decode failed");
        assert_eq!(header, MSG_HD);
        let decrypted: String = serde_json::from_slice(&bytes).expect("Deserialize failed");
        assert_eq!(original, &decrypted);
    }

    // --- enzip/decode: DB-sync path. listen always decodes; DBS_HD body is decompressed. ---
    let test_messages = [
        Message::new(1, 12345, "Hello peer-to-peer world!".to_string()),
        Message::new(2, 0, "".to_string()),
        Message::new(3, 999, "🔥 Complex chars: emojis & unicode 🔥".to_string()),
    ];

    for original in test_messages.iter() {
        // DBS_HD → encode compresses, decode decompresses, transparently
        let zipped = Connection::encode(key, DBS_HD, original.clone()).expect("Encode failed");
        let (header, body) = Connection::decode(key, &zipped).expect("Decode failed");
        assert_eq!(header, DBS_HD);
        let decrypted: Message = serde_json::from_slice(&body).expect("Deserialize failed");
        assert_eq!(original.get_id(), decrypted.get_id());
        assert_eq!(original.get_contents(), decrypted.get_contents());
    }

    // DBS_HD (compressed) smaller than MSG_HD (raw) for compressible data
    let repetitive = "aaaa".repeat(1000);
    let raw_len = Connection::encode(key, MSG_HD, repetitive.clone()).unwrap().len();
    let zip_len = Connection::encode(key, DBS_HD, repetitive).unwrap().len();
    assert!(zip_len < raw_len);

    // --- Security: wrong key, empty, too short all fail at decode ---
    let mut msg = Message::new(999, 999, "tamper test".to_string());
    msg.set_contents("security test".to_string());
    let encrypted = Connection::encode(key, MSG_HD, msg).unwrap();
    assert!(Connection::decode(wrong_key, &encrypted).is_err());
    assert!(Connection::decode(key, &[]).is_err());
    assert!(Connection::decode(key, &encrypted[..11]).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_connection() -> Result<()> {
    let keypair = Peer::keypairgen()?;
    let rendezvous_addr = free_rendezvous_addr().await;
    let socket = get_free_port().await?;
    let peermap = HashMap::new();
    let mut conn = Connection::new(keypair.1, rendezvous_addr, socket, peermap).await;
    let bind_result = conn.bind_rendezvous().await;
    assert!(bind_result.is_ok(), "Failed to bind rendezvous");
    conn.end_rendezvous();
    let double_bind = conn.bind_rendezvous().await;
    assert!(double_bind.is_ok(), "Double bind failed");

    let keypair2 = Peer::keypairgen()?;
    let socket2 = get_free_port().await?;
    let peermap2 = HashMap::new();
    let mut client_conn = Connection::new(keypair2.1, rendezvous_addr, socket2, peermap2).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let connect_result = client_conn.connect_rendezvous().await;
    assert!(connect_result.is_ok(), "Failed to connect to rendezvous");

    client_conn.end_rendezvous();
    let reconnect = client_conn.connect_rendezvous().await;
    assert!(reconnect.is_ok(), "Reconnect after end failed");

    let monitor_handle = tokio::spawn(async move {
        conn.monitor_ip().await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    monitor_handle.abort();
    let result = tokio::time::timeout(Duration::from_millis(100), monitor_handle).await;
    assert!(result.is_err() || matches!(result, Ok(Err(_))));
    Ok(())
}

#[tokio::test]
async fn test_rendezvous_requests() -> Result<()> {
    let rendezvous_addr = free_rendezvous_addr().await;
    let server_keypair = Peer::keypairgen()?;
    let client_keypair = Peer::keypairgen()?;
    let server_socket = get_free_port().await?;
    let client_socket = get_free_port().await?;
    let client_addr = client_socket.0;
    let server_peermap = HashMap::new();
    let client_peermap = HashMap::new();
    let mut server_conn = Connection::new(server_keypair.1, rendezvous_addr, server_socket, server_peermap).await;
    let mut client_conn = Connection::new(client_keypair.1, rendezvous_addr, client_socket, client_peermap).await;
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_clone = Arc::clone(&requests);
    let token = CancellationToken::new();
    let token_clone = token.clone();

    let server_handle = tokio::spawn(async move {
        let mut reqs = requests_clone.lock().await;
        server_conn.rcv_requests(&mut reqs, token_clone).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_name = "TestUser".to_string();
    let client_handle = tokio::spawn(async move {
        client_conn.snd_requests(client_name).await
    });
    let client_result = tokio::time::timeout(
        Duration::from_secs(5),
        client_handle
    ).await;

    token.cancel();
    let server_result = tokio::time::timeout(
        Duration::from_secs(5),
        server_handle
    ).await;

    assert!(client_result.is_ok(), "Client task timed out");
    let client_success = client_result.unwrap().unwrap()?;
    assert!(client_success, "Client did not receive valid acknowledgment");
    assert!(server_result.is_ok(), "Server task timed out");
    server_result.unwrap().unwrap()?;
    let reqs = requests.lock().await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].1, "TestUser");
    assert_eq!(reqs[0].0, client_addr, "Recorded addr must match client's socket");

    Ok(())
}

#[tokio::test]
async fn test_fallback() -> Result<()> {
    let rendezvous_addr = free_rendezvous_addr().await;
    let (_, prv1) = Peer::keypairgen()?;
    let (_, prv2) = Peer::keypairgen()?;
    let sock1 = get_free_port().await?;
    let sock2 = get_free_port().await?;
    let sock2_addr = sock2.0;

    let mut conn1 = Connection::new(prv1, rendezvous_addr, sock1, HashMap::new()).await;
    let mut conn2 = Connection::new(prv2, rendezvous_addr, sock2, HashMap::new()).await;

    // First caller binds → becomes holder
    let is_holder = conn1.fallback_lookup().await?;
    assert!(is_holder, "first fallback_lookup should bind");

    // Start receiving on conn1 (rendezvous already bound from fallback_lookup)
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_clone = Arc::clone(&requests);
    let token = CancellationToken::new();
    let token_clone = token.clone();
    let hold_handle = tokio::spawn(async move {
        let mut reqs = requests_clone.lock().await;
        conn1.rcv_requests(&mut reqs, token_clone).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second caller finds addr taken → connects
    let is_holder2 = conn2.fallback_lookup().await?;
    assert!(!is_holder2, "second fallback_lookup should connect, not bind");

    // Re-announce presence to the holder
    let acked = conn2.fallback_send("Peer2".to_string()).await?;
    assert!(acked, "fallback_send should receive ack from holder");

    token.cancel();
    hold_handle.await??;

    let reqs = requests.lock().await;
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].1, "Peer2");
    assert_eq!(reqs[0].0, sock2_addr, "Holder must record correct addr for reconnecting peer");

    Ok(())
}

async fn bare_conn() -> Result<Connection> {
    let (_, prvkey) = Peer::keypairgen()?;
    Ok(Connection::new(prvkey, free_rendezvous_addr().await, get_free_port().await?, HashMap::new()).await)
}

// --- send path: each broadcast emits a valid, decryptable frame with the right header ---

#[tokio::test]
async fn test_send_msg_frame() -> Result<()> {
    let (conn, mut server, key) = conn_with_peer().await?;
    conn.send_msg(Message::new(1, 42, "hello".to_string())).await?;

    let frame = read_frame(&mut server).await?;
    let (header, payload) = Connection::decode(&key, &frame)?;
    assert_eq!(header, MSG_HD);
    let got: Message = serde_json::from_slice(&payload)?;
    assert_eq!(got.get_contents(), "hello");
    assert_eq!(got.get_sender_id(), 42);
    Ok(())
}

#[tokio::test]
async fn test_send_heartbeat_frame() -> Result<()> {
    let (conn, mut server, key) = conn_with_peer().await?;
    conn.send_heartbeat().await?;

    let frame = read_frame(&mut server).await?;
    let (header, _payload) = Connection::decode(&key, &frame)?;
    assert_eq!(header, HBT_HD);
    Ok(())
}

#[tokio::test]
async fn test_send_typing_frame() -> Result<()> {
    let (conn, mut server, key) = conn_with_peer().await?;
    conn.send_typing().await?;

    let frame = read_frame(&mut server).await?;
    let (header, _payload) = Connection::decode(&key, &frame)?;
    assert_eq!(header, TYP_HD);
    Ok(())
}

#[tokio::test]
async fn test_send_db_sync_frame() -> Result<()> {
    let (conn, mut server, key) = conn_with_peer().await?;
    let db = Database::new(":memory:")?;
    conn.send_db_sync(&db).await?;

    let frame = read_frame(&mut server).await?;
    let (header, payload) = Connection::decode(&key, &frame)?;
    assert_eq!(header, DBS_HD);
    // payload is the serialized raw sqlite snapshot — non-empty.
    let bytes: Vec<u8> = serde_json::from_slice(&payload)?;
    assert!(!bytes.is_empty());
    Ok(())
}

// --- read path: dispatched reads mutate the shared Chat ---

#[tokio::test]
async fn test_read_msg_appends_history() -> Result<()> {
    let chat = test_chat()?;
    // Sender must exist as a user (create_message joins users).
    let (peer, _) = chat.db.create_peer(9000).await?;
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    let sender = chat.db.create_user(pubkey_hex, "sender".to_string(), Uid::getuid()).await?;
    chat.db.update_peer_link_user(peer.get_id(), sender.get_id()).await?;

    let conn = bare_conn().await?;
    let payload = serde_json::to_vec(&Message::new(7, sender.get_id(), "incoming".to_string()))?;

    conn.read_msg(&chat, payload).await?;

    // In-memory history updated synchronously.
    {
        let hist = chat.message_history.read().unwrap();
        assert!(hist.iter().any(|m| m.get_contents() == "incoming"));
    }
    // DB persist is spawned off the hot path — give it a moment, then verify.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let stored = chat.db.load_all_messages().await?;
    assert!(stored.iter().any(|m| m.get_contents() == "incoming"), "message persisted to db");
    Ok(())
}

#[tokio::test]
async fn test_read_db_sync_adopts_superset() -> Result<()> {
    // Build a source DB with a user + message; its snapshot is the superset.
    let src = Database::new(":memory:")?;
    let (peer, _) = src.create_peer(9000).await?;
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    let user = src.create_user(pubkey_hex, "alice".to_string(), Uid::getuid()).await?;
    src.update_peer_link_user(peer.get_id(), user.get_id()).await?;
    let _ = src.create_message(user.get_id(), "synced".to_string()).await?;
    let snapshot = src.dump().await?;

    // Empty local chat → trivially a subset → snapshot is adopted.
    let chat = test_chat()?;
    let conn = bare_conn().await?;
    let payload = serde_json::to_vec(&snapshot)?;

    conn.read_db_sync(&chat, payload).await?;

    {
        let hist = chat.message_history.read().unwrap();
        assert!(hist.iter().any(|m| m.get_contents() == "synced"), "message adopted (memory)");
        let members = chat.members.read().unwrap();
        assert!(members.values().any(|u| u.get_name() == "alice"), "user adopted (memory)");
    }
    // DB adopted the snapshot too.
    let db_msgs = chat.db.load_all_messages().await?;
    assert!(db_msgs.iter().any(|m| m.get_contents() == "synced"), "message persisted to db");
    Ok(())
}

#[tokio::test]
async fn test_read_db_sync_rejects_conflict() -> Result<()> {
    // Snapshot lacks a message the local DB has → conflict → no adoption.
    let snapshot = Database::new(":memory:")?.dump().await?; // empty snapshot

    let chat = test_chat()?;
    let (peer, _) = chat.db.create_peer(9000).await?;
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    let user = chat.db.create_user(pubkey_hex, "bob".to_string(), Uid::getuid()).await?;
    chat.db.update_peer_link_user(peer.get_id(), user.get_id()).await?;
    let _ = chat.db.create_message(user.get_id(), "local only".to_string()).await?;

    let conn = bare_conn().await?;
    let payload = serde_json::to_vec(&snapshot)?;
    conn.read_db_sync(&chat, payload).await?;

    // Local message must survive (snapshot was missing it).
    let msgs = chat.db.load_all_messages().await?;
    assert!(msgs.iter().any(|m| m.get_contents() == "local only"), "conflict must not clobber local data");
    Ok(())
}

#[tokio::test]
async fn test_read_newpeer_adopts_db() -> Result<()> {
    // Admin's snapshot the newcomer receives via NWP.
    let src = Database::new(":memory:")?;
    let (peer, _) = src.create_peer(9000).await?;
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    let user = src.create_user(pubkey_hex, "admin".to_string(), Uid::getuid()).await?;
    src.update_peer_link_user(peer.get_id(), user.get_id()).await?;
    let snapshot = src.dump().await?;

    let chat = test_chat()?;
    let mut conn = bare_conn().await?;
    conn.set_user(1, "me".to_string(), Uid::from(1)); // needed to register self
    let payload = serde_json::to_vec(&snapshot)?;

    conn.read_newpeer(&chat, payload).await?;

    let users = chat.db.load_all_users().await?;
    assert!(users.iter().any(|u| u.get_name() == "admin"), "newcomer adopts admin's DB");
    Ok(())
}

#[tokio::test]
async fn test_get_peer() -> Result<()> {
    let (conn, _server, _key) = conn_with_peer().await?;
    // conn_with_peer keys the peer under user_id 1.
    assert!(conn.get_peer(&1).is_some(), "known peer returned");
    assert!(conn.get_peer(&999).is_none(), "unknown peer is None");
    Ok(())
}

#[tokio::test]
async fn test_read_heartbeat_updates_and_persists() -> Result<()> {
    let chat = test_chat()?;
    // Peer must exist in the db (with a linked user) so read_peer can read it back.
    let (peer, _) = chat.db.create_peer(9000).await?;
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    let user = chat.db.create_user(pubkey_hex, "p".to_string(), Uid::getuid()).await?;
    chat.db.update_peer_link_user(peer.get_id(), user.get_id()).await?;

    // Wire that peer into the connection peermap, keyed by user_id.
    let key = *Key::from_slice(b"0123456789abcdef0123456789abcdef");
    let mut peermap = HashMap::new();
    peermap.insert(user.get_id(), (peer.clone(), key, None));
    let (_, prvkey) = Peer::keypairgen()?;
    let conn = Connection::new(prvkey, free_rendezvous_addr().await, get_free_port().await?, peermap).await;

    assert!(conn.get_peer(&user.get_id()).unwrap().get_last_heartbeat().is_none());
    conn.read_heartbeat(&chat, user.get_id()).await?;

    // In-memory peermap updated synchronously.
    assert!(conn.get_peer(&user.get_id()).unwrap().get_last_heartbeat().is_some(), "in-memory heartbeat set");

    // DB update is spawned — wait, then verify it landed.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let db_peer = chat.db.read_peer(peer.get_id()).await?.expect("peer in db");
    assert!(db_peer.get_last_heartbeat().is_some(), "heartbeat persisted to db");
    Ok(())
}
