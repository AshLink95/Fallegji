// prompt engineered
use std::{collections::HashMap, net::{IpAddr, Ipv4Addr, SocketAddr}, sync::Arc};
use tokio::{net::{TcpListener, TcpStream}, sync::Mutex, io::{AsyncReadExt, AsyncWriteExt}};

async fn free_rendezvous_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    addr
}
use chacha20poly1305::Key;
use x25519_dalek::{PublicKey, StaticSecret};
use fallegji::{connection::{Connection, KeyGen, Peer, Secrecy, RendezVous, Communication, get_free_port, local_addrs, connect_any}, messaging::{Message, Chat}, auth::{Uid, User, Role}, db::Database};
use hex::ToHex;
use tokio_util::sync::CancellationToken;
use std::time::Duration;
use anyhow::Result;

// Header bytes (mirror connection.rs private consts)
const HBT_HD: u8 = 0xE2;
const DBR_HD: u8 = 0xB5;
const NWP_HD: u8 = 0xA6;
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

// Header bytes (mirror connection.rs private consts)
const MSG_HD: u8 = 0xF1;
const DBS_HD: u8 = 0xC4;

/// Peer lifecycle: creation (new_out/new_in), getters, setters, presence windows.
#[test]
fn test_peer() {
    // new_out: fresh local peer.
    let (peer, prvkey) = Peer::new_out(1, 9000).unwrap();
    assert_eq!(peer.get_id(), 1);
    assert_eq!(peer.get_user_id(), None);
    assert_eq!(peer.get_addr().port(), 9000);
    assert_eq!(peer.get_last_heartbeat(), None);
    assert_eq!(peer.get_last_seen_typing(), None);
    assert_ne!(peer.get_addr().ip(), IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    assert_eq!(peer.get_pubkey().as_bytes().len(), 32);
    assert_eq!(prvkey.as_bytes().len(), 32);

    // new_in: imported peer, valid + invalid user_id.
    let name = "TestPeer".to_string();
    let uid = Uid::from(10);
    let addrs = [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 8080),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8080),
    ];
    let pubkey = PublicKey::from(&StaticSecret::from([1u8; 32]));
    let pubkey_hex: String = pubkey.as_bytes().encode_hex();
    let user_id = User::new(pubkey_hex, name.clone(), uid).get_id();
    let imported = Peer::new_in(2, name, uid, user_id, addrs, pubkey, Some(1111), Some(1234567890))
        .expect("valid new_in");
    assert_eq!(imported.get_id(), 2);
    assert_eq!(imported.get_user_id(), Some(user_id));
    assert_eq!(imported.get_addrs(), addrs, "all 3 addresses preserved");
    assert_eq!(imported.get_addr(), addrs[1], "get_addr returns the LAN one");
    assert_eq!(imported.get_last_heartbeat(), Some(1234567890));
    assert_eq!(imported.get_last_seen_typing(), Some(1111));
    assert!(Peer::new_in(2, "x".to_string(), uid, 999, addrs, pubkey, None, None).is_err(),
        "bad user_id rejected");

    // setters.
    let (mut peer, _) = Peer::new_out(-1, 8080).unwrap();
    peer.set_id(10);
    assert_eq!(peer.get_id(), 10);
    peer.set_id(20); // id only settable while < 0
    assert_eq!(peer.get_id(), 10);
    let new_addrs = [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9090),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 9090),
    ];
    peer.set_addrs(new_addrs);
    assert_eq!(peer.get_addrs(), new_addrs);
    peer.set_last_heartbeat(Some(1));
    assert_eq!(peer.get_last_heartbeat(), Some(1));
    peer.set_last_seen_typing(Some(2));
    assert_eq!(peer.get_last_seen_typing(), Some(2));

    // presence windows: is_online (3s), is_typing (1s); never-seen → false.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let (mut p, _) = Peer::new_out(1, 9000).unwrap();
    assert!(!p.is_online() && !p.is_typing());
    p.set_last_heartbeat(Some(now));
    assert!(p.is_online());
    p.set_last_heartbeat(Some(now - 10));
    assert!(!p.is_online());
    p.set_last_seen_typing(Some(now));
    assert!(p.is_typing());
    p.set_last_seen_typing(Some(now - 10));
    assert!(!p.is_typing());
}

/// The 3-address machinery: local_addrs, addrs_string/parse_addrs roundtrip, connect_any.
#[tokio::test(flavor = "multi_thread")]
async fn test_peer_addresses() -> Result<()> {
    // local_addrs: 3 candidates, all on `port`, first is loopback.
    let addrs = local_addrs(7777)?;
    assert_eq!(addrs.len(), 3);
    assert!(addrs.iter().all(|a| a.port() == 7777), "all share the port");
    assert!(addrs[0].ip().is_loopback(), "first is localhost");
    assert!(!addrs[1].ip().is_unspecified(), "LAN is a real interface ip");

    // new_out fills the 3 addresses with the given port.
    let (peer, _) = Peer::new_out(1, 8080)?;
    assert!(peer.get_addrs().iter().all(|a| a.port() == 8080));
    assert_eq!(peer.get_addr(), peer.get_addrs()[1], "get_addr is the LAN one");

    // addrs_string <-> parse_addrs roundtrip.
    let s = peer.addrs_string();
    assert_eq!(s.split(',').count(), 3, "serialized as 3 comma-joined addrs");
    assert_eq!(Peer::parse_addrs(&s), Some(peer.get_addrs()), "roundtrips");

    // parse_addrs: single-addr fallback + invalid input.
    let one: SocketAddr = "1.2.3.4:5".parse().unwrap();
    assert_eq!(Peer::parse_addrs("1.2.3.4:5"), Some([one; 3]), "single addr repeats");
    assert_eq!(Peer::parse_addrs("not-an-addr"), None);

    // set_addrs updates all three.
    let mut p = peer.clone();
    let na = local_addrs(9001)?;
    p.set_addrs(na);
    assert_eq!(p.get_addrs(), na);

    // connect_any: returns the first reachable, None if none reachable.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let live = listener.local_addr()?;
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    assert!(connect_any(&[dead, live, dead]).await.is_some(), "reaches the live one");
    assert!(connect_any(&[dead, dead]).await.is_none(), "all dead → None");
    Ok(())
}

/// monitor_ip's refresh step persists our refreshed 3 addresses to the db.
#[tokio::test(flavor = "multi_thread")]
async fn test_refresh_addrs_persists() -> Result<()> {
    let (addr, listener) = get_free_port().await?;
    let port = addr.port();
    let db = Database::new(":memory:")?;
    // A db-backed self peer (3 addrs on `port`), linked to a user, placed in the peermap.
    let (peer, prvkey) = db.create_peer(port).await?;
    let db_id = peer.get_id();
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    let user = db.create_user(pubkey_hex, "me".to_string(), Uid::getuid()).await?;
    let user_id = user.get_id();
    db.update_peer_link_user(db_id, user_id).await?;
    let key = peer.shrdkeygen(prvkey.clone());
    let mut peermap = HashMap::new();
    peermap.insert(user_id, (peer, key, None));

    let mut conn = Connection::new(prvkey, free_rendezvous_addr().await, (addr, listener), peermap).await;
    conn.set_user(user_id, "me".to_string(), Uid::getuid());

    conn.refresh_addrs(&db).await?;

    // Our peer's db row now holds 3 addresses, all on the bind port, loopback first.
    let reloaded = db.read_peer(db_id).await?.expect("peer still there");
    let addrs = reloaded.get_addrs();
    assert!(addrs.iter().all(|a| a.port() == port), "all on the chosen port");
    assert!(addrs[0].ip().is_loopback(), "loopback first");
    // In-memory peer was updated too.
    assert_eq!(conn.get_peer(&user_id).unwrap().get_addrs(), addrs, "peermap matches db");
    Ok(())
}

/// Crypto: keypair gen, shared-key agreement, encode/decode roundtrip + compression + tamper.
#[test]
fn test_crypto() {
    // Keypair gen: distinct keys, correct length.
    let (pub1, prv1) = Peer::keypairgen().unwrap();
    assert_eq!(pub1.as_bytes().len(), 32);
    assert_eq!(prv1.as_bytes().len(), 32);
    let (pub2, _) = Peer::keypairgen().unwrap();
    assert_ne!(pub1.as_bytes(), pub2.as_bytes());

    // Shared-key agreement: both sides derive the same key.
    let (peer_a, prv_a) = Peer::new_out(1, 8080).unwrap();
    let (peer_b, prv_b) = Peer::new_out(2, 8081).unwrap();
    let shared1 = peer_a.shrdkeygen(prv_b);
    let shared2 = peer_b.shrdkeygen(prv_a);
    assert_eq!(shared1.as_slice(), shared2.as_slice());
    assert_eq!(shared1.as_slice().len(), 32);

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
    let conn = Connection::new(keypair.1, rendezvous_addr, socket, HashMap::new()).await;
    assert!(conn.bind_rendezvous().await.is_ok(), "Failed to bind rendezvous");
    conn.end_rendezvous();
    assert!(conn.bind_rendezvous().await.is_ok(), "Double bind failed");

    let db = Database::new(":memory:")?;
    let monitor_handle = tokio::spawn(async move { conn.monitor_ip(db).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    monitor_handle.abort();
    let result = tokio::time::timeout(Duration::from_millis(100), monitor_handle).await;
    assert!(result.is_err() || matches!(result, Ok(Err(_))));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_rendezvous_requests() -> Result<()> {
    let rendezvous_addr = free_rendezvous_addr().await;
    let server_keypair = Peer::keypairgen()?;
    let client_keypair = Peer::keypairgen()?;
    let server_socket = get_free_port().await?;
    let client_socket = get_free_port().await?;
    let client_addr = client_socket.0;
    let server_conn = Connection::new(server_keypair.1, rendezvous_addr, server_socket, HashMap::new()).await;
    let client_conn = Connection::new(client_keypair.1, rendezvous_addr, client_socket, HashMap::new()).await;
    #[allow(clippy::complexity)]
    let requests: std::sync::Arc<std::sync::Mutex<Vec<([SocketAddr; 3], String, PublicKey)>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let requests_clone = std::sync::Arc::clone(&requests);
    let token = CancellationToken::new();
    let token_clone = token.clone();

    let server_handle = tokio::spawn(async move {
        server_conn.rcv_requests(requests_clone, token_clone).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_success = client_conn.snd_requests("TestUser".to_string()).await?;
    token.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;

    assert!(client_success, "Client did not receive valid acknowledgment");
    let reqs = requests.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].1, "TestUser");
    assert_eq!(reqs[0].0[1], client_addr, "LAN addr must match client's socket");

    // Handshake side-effect: newcomer derived the admin key and stored it (provisional key 0).
    assert!(client_conn.get_peer(&0).is_some(), "newcomer stored admin in peermap");

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_fallback() -> Result<()> {
    let rendezvous_addr = free_rendezvous_addr().await;
    let (_, prv1) = Peer::keypairgen()?;
    let (_, prv2) = Peer::keypairgen()?;
    let sock1 = get_free_port().await?;
    let sock2 = get_free_port().await?;
    let sock2_addr = sock2.0;

    let conn1 = Connection::new(prv1, rendezvous_addr, sock1, HashMap::new()).await;
    let conn2 = Connection::new(prv2, rendezvous_addr, sock2, HashMap::new()).await;

    // First caller binds → becomes holder
    assert!(conn1.fallback_lookup().await?, "first fallback_lookup should bind");

    #[allow(clippy::complexity)]
    let requests: std::sync::Arc<std::sync::Mutex<Vec<([SocketAddr; 3], String, PublicKey)>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let requests_clone = std::sync::Arc::clone(&requests);
    let token = CancellationToken::new();
    let token_clone = token.clone();
    let hold_handle = tokio::spawn(async move {
        conn1.rcv_requests(requests_clone, token_clone).await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second caller finds addr taken → not the holder.
    assert!(!conn2.fallback_lookup().await?, "second fallback_lookup should not bind");

    // Re-announce presence to the holder.
    assert!(conn2.fallback_send("Peer2".to_string()).await?, "fallback_send should be acked");

    token.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), hold_handle).await;

    let reqs = requests.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].1, "Peer2");
    assert_eq!(reqs[0].0[1], sock2_addr, "Holder must record correct LAN addr");

    Ok(())
}

async fn bare_conn() -> Result<Connection> {
    let (_, prvkey) = Peer::keypairgen()?;
    Ok(Connection::new(prvkey, free_rendezvous_addr().await, get_free_port().await?, HashMap::new()).await)
}

// --- send path: each broadcast emits a valid, decryptable frame with the right header ---

/// All broadcasts emit a valid, decryptable frame with the right header.
#[tokio::test]
async fn test_send_frames() -> Result<()> {
    let (conn, mut server, key) = conn_with_peer().await?;

    // MSG: payload round-trips to the Message.
    conn.send_msg(Message::new(1, 42, "hello".to_string())).await?;
    let (h, payload) = Connection::decode(&key, &read_frame(&mut server).await?)?;
    assert_eq!(h, MSG_HD);
    let got: Message = serde_json::from_slice(&payload)?;
    assert_eq!(got.get_contents(), "hello");
    assert_eq!(got.get_sender_id(), 42);

    // HEARTBEAT.
    conn.send_heartbeat().await?;
    let (h, _) = Connection::decode(&key, &read_frame(&mut server).await?)?;
    assert_eq!(h, HBT_HD);

    // TYPING.
    conn.send_typing().await?;
    let (h, _) = Connection::decode(&key, &read_frame(&mut server).await?)?;
    assert_eq!(h, TYP_HD);

    // DB SYNC: payload is the non-empty raw sqlite snapshot.
    conn.send_db_sync(&Database::new(":memory:")?).await?;
    let (h, payload) = Connection::decode(&key, &read_frame(&mut server).await?)?;
    assert_eq!(h, DBS_HD);
    let bytes: Vec<u8> = serde_json::from_slice(&payload)?;
    assert!(!bytes.is_empty());
    Ok(())
}

// --- read path: dispatched reads mutate the shared Chat ---

/// Receiving data: a message (history + db), db_sync snapshot (adopt + reject),
/// and new-peer bootstrap (adopt admin's db).
#[tokio::test]
async fn test_read_data() -> Result<()> {
    // read_msg: appended to history + persisted.
    let chat = test_chat()?;
    let (peer, _) = chat.db.create_peer(9000).await?;
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    let sender = chat.db.create_user(pubkey_hex, "sender".to_string(), Uid::getuid()).await?;
    chat.db.update_peer_link_user(peer.get_id(), sender.get_id()).await?;
    let conn = bare_conn().await?;
    conn.read_msg(&chat, serde_json::to_vec(&Message::new(7, sender.get_id(), "incoming".to_string()))?).await?;
    assert!(chat.message_history.read().unwrap().iter().any(|m| m.get_contents() == "incoming"));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(chat.db.load_all_messages().await?.iter().any(|m| m.get_contents() == "incoming"), "msg persisted");

    // read_db_sync: superset snapshot adopted (db + members).
    let src = Database::new(":memory:")?;
    let (sp, _) = src.create_peer(9000).await?;
    let sp_hex = sp.get_pubkey().to_bytes().encode_hex::<String>();
    let su = src.create_user(sp_hex, "alice".to_string(), Uid::getuid()).await?;
    src.update_peer_link_user(sp.get_id(), su.get_id()).await?;
    let _ = src.create_message(su.get_id(), "synced".to_string(), None).await?;
    let snapshot = src.dump().await?;
    let chat_a = test_chat()?;
    conn.read_db_sync(&chat_a, serde_json::to_vec(&snapshot)?).await?;
    assert!(chat_a.db.load_all_messages().await?.iter().any(|m| m.get_contents() == "synced"), "snapshot adopted");
    assert!(chat_a.members.read().unwrap().values().any(|u| u.get_name() == "alice"));

    // read_db_sync: conflicting snapshot (missing local data) rejected.
    let empty = Database::new(":memory:")?.dump().await?;
    let chat_b = test_chat()?;
    let (bp, _) = chat_b.db.create_peer(9001).await?;
    let bp_hex = bp.get_pubkey().to_bytes().encode_hex::<String>();
    let bu = chat_b.db.create_user(bp_hex, "bob".to_string(), Uid::getuid()).await?;
    chat_b.db.update_peer_link_user(bp.get_id(), bu.get_id()).await?;
    let _ = chat_b.db.create_message(bu.get_id(), "local only".to_string(), None).await?;
    conn.read_db_sync(&chat_b, serde_json::to_vec(&empty)?).await?;
    assert!(chat_b.db.load_all_messages().await?.iter().any(|m| m.get_contents() == "local only"), "conflict not clobbered");

    // read_newpeer: newcomer adopts admin's db.
    let admin_db = Database::new(":memory:")?;
    let (ap, _) = admin_db.create_peer(9000).await?;
    let ap_hex = ap.get_pubkey().to_bytes().encode_hex::<String>();
    let au = admin_db.create_user(ap_hex, "admin".to_string(), Uid::getuid()).await?;
    admin_db.update_peer_link_user(ap.get_id(), au.get_id()).await?;
    let admin_snap = admin_db.dump().await?;
    let chat_c = test_chat()?;
    let mut conn2 = bare_conn().await?;
    conn2.set_user(1, "me".to_string(), Uid::from(1));
    conn2.read_newpeer(&chat_c, serde_json::to_vec(&admin_snap)?).await?;
    assert!(chat_c.db.load_all_users().await?.iter().any(|u| u.get_name() == "admin"), "newcomer adopted admin db");
    Ok(())
}

/// Presence reads: get_peer lookup, heartbeat (memory + db), typing (memory).
#[tokio::test]
async fn test_read_presence() -> Result<()> {
    let chat = test_chat()?;
    let (peer, _) = chat.db.create_peer(9000).await?;
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    let user = chat.db.create_user(pubkey_hex, "p".to_string(), Uid::getuid()).await?;
    chat.db.update_peer_link_user(peer.get_id(), user.get_id()).await?;
    let uid = user.get_id();

    let key = *Key::from_slice(b"0123456789abcdef0123456789abcdef");
    let mut peermap = HashMap::new();
    peermap.insert(uid, (peer.clone(), key, None));
    let (_, prvkey) = Peer::keypairgen()?;
    let conn = Connection::new(prvkey, free_rendezvous_addr().await, get_free_port().await?, peermap).await;

    // get_peer: known + unknown.
    assert!(conn.get_peer(&uid).is_some(), "known peer");
    assert!(conn.get_peer(&999).is_none(), "unknown peer");

    // heartbeat: in-memory + persisted.
    assert!(conn.get_peer(&uid).unwrap().get_last_heartbeat().is_none());
    conn.read_heartbeat(&chat, uid).await?;
    assert!(conn.get_peer(&uid).unwrap().get_last_heartbeat().is_some(), "in-memory heartbeat");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(chat.db.read_peer(peer.get_id()).await?.unwrap().get_last_heartbeat().is_some(), "heartbeat persisted");

    // typing: in-memory.
    assert!(conn.get_peer(&uid).unwrap().get_last_seen_typing().is_none());
    conn.read_typing(uid).await?;
    assert!(conn.get_peer(&uid).unwrap().get_last_seen_typing().is_some(), "typing set");
    Ok(())
}

#[tokio::test]
async fn test_send_db_req_targets_admin() -> Result<()> {
    // TCP pair: client end goes into the peermap, server end is what we read.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let laddr = listener.local_addr()?;
    let client = TcpStream::connect(laddr).await?;
    let (mut server, _) = listener.accept().await?;

    // Admin member, and an online peer (heartbeat = now) wired to the stream.
    let mut admin = User::new("k".to_string(), "admin".to_string(), Uid::from(1));
    admin.set_role(Role::Admin);
    let admin_id = admin.get_id();

    let key = *Key::from_slice(b"0123456789abcdef0123456789abcdef");
    let (mut peer, _) = Peer::new_out(1, 9000)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    peer.set_last_heartbeat(Some(now)); // online
    let mut peermap = HashMap::new();
    peermap.insert(admin_id, (peer, key, Some(Arc::new(Mutex::new(client)))));

    let (_, prvkey) = Peer::keypairgen()?;
    let conn = Connection::new(prvkey, free_rendezvous_addr().await, get_free_port().await?, peermap).await;

    let chat = test_chat()?;
    chat.members.write().unwrap().insert(admin_id, admin);

    conn.send_db_req(&chat).await?;

    // A DBR_HD request reached the admin.
    let frame = read_frame(&mut server).await?;
    let (header, _) = Connection::decode(&key, &frame)?;
    assert_eq!(header, DBR_HD);
    Ok(())
}

#[tokio::test]
async fn test_read_db_req_responds_with_sync() -> Result<()> {
    // A received db request triggers a db_sync back to the requester.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let laddr = listener.local_addr()?;
    let client = TcpStream::connect(laddr).await?;
    let (mut server, _) = listener.accept().await?;

    let key = *Key::from_slice(b"0123456789abcdef0123456789abcdef");
    let (peer, _) = Peer::new_out(1, 9000)?;
    let mut peermap = HashMap::new();
    peermap.insert(5u64, (peer, key, Some(Arc::new(Mutex::new(client)))));
    let (_, prvkey) = Peer::keypairgen()?;
    let conn = Connection::new(prvkey, free_rendezvous_addr().await, get_free_port().await?, peermap).await;

    let chat = test_chat()?;
    conn.read_db_req(&chat).await?;

    let (header, _) = Connection::decode(&key, &read_frame(&mut server).await?)?;
    assert_eq!(header, DBS_HD, "db request answered with a db sync");
    Ok(())
}

#[tokio::test]
async fn test_send_newpeer() -> Result<()> {
    // Admin dials the newcomer and seeds it with an NWP frame (raw db snapshot).
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let laddr = listener.local_addr()?;

    let (_, admin_prv) = Peer::keypairgen()?;
    let (new_pub, new_prv) = Peer::keypairgen()?;
    let db = Database::new(":memory:")?;
    let conn = Connection::new(admin_prv.clone(), free_rendezvous_addr().await, get_free_port().await?, HashMap::new()).await;

    let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
    conn.send_newpeer([laddr; 3], new_pub, &db).await?;
    let mut server = accept.await?;

    // Reconstruct the shared key the newcomer would derive: DH(new_prv, admin_pub).
    let admin_pub = PublicKey::from(&admin_prv);
    let admin_hex: String = admin_pub.as_bytes().encode_hex();
    let aid = User::new(admin_hex, "a".to_string(), Uid::from(1)).get_id();
    let admin_peer = Peer::new_in(-1, "a".to_string(), Uid::from(1), aid, [laddr; 3], admin_pub, None, None).unwrap();
    let key = admin_peer.shrdkeygen(new_prv);

    let (header, payload) = Connection::decode(&key, &read_frame(&mut server).await?)?;
    assert_eq!(header, NWP_HD);
    let bytes: Vec<u8> = serde_json::from_slice(&payload)?;
    assert!(!bytes.is_empty(), "NWP carries the db snapshot");
    Ok(())
}

/// Integration: spawn listen as a background task, push a burst of frames over one
/// connection, and verify every header dispatched to the right handler (state mutated).
#[tokio::test(flavor = "multi_thread")]
async fn test_listen_dispatch() -> Result<()> {
    let chat = Arc::new(test_chat()?);
    // Sender must exist (read_msg joins users; heartbeat reads the peer back).
    let (peer, _) = chat.db.create_peer(9000).await?;
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    let sender = chat.db.create_user(pubkey_hex, "sender".to_string(), Uid::getuid()).await?;
    chat.db.update_peer_link_user(peer.get_id(), sender.get_id()).await?;
    let sid = sender.get_id();

    // Connection knows this peer's key, so listen can decode its frames.
    let key = *Key::from_slice(b"0123456789abcdef0123456789abcdef");
    let mut peermap = HashMap::new();
    peermap.insert(sid, (peer.clone(), key, None));
    let (_, prvkey) = Peer::keypairgen()?;
    let socket = get_free_port().await?;
    let addr = socket.0;
    let conn = Arc::new(Connection::new(prvkey, free_rendezvous_addr().await, socket, peermap).await);

    // Background listen loop.
    let lconn = Arc::clone(&conn);
    let lchat = Arc::clone(&chat);
    tokio::spawn(async move { let _ = lconn.listen(lchat, CancellationToken::new()).await; });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Burst of frames: message, heartbeat, typing.
    let mut client = TcpStream::connect(addr).await?;
    for frame in [
        Connection::encode(&key, MSG_HD, Message::new(1, sid, "live".to_string()))?,
        Connection::encode(&key, HBT_HD, ())?,
        Connection::encode(&key, TYP_HD, ())?,
    ] {
        client.write_all(&(frame.len() as u32).to_be_bytes()).await?;
        client.write_all(&frame).await?;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // MSG dispatched → history.
    assert!(chat.message_history.read().unwrap().iter().any(|m| m.get_contents() == "live"), "message dispatched");
    // HBT + TYP dispatched → peer presence updated.
    let p = conn.get_peer(&sid).expect("peer present");
    assert!(p.get_last_heartbeat().is_some(), "heartbeat dispatched");
    assert!(p.get_last_seen_typing().is_some(), "typing dispatched");
    Ok(())
}
