// prompt engineered
use std::{collections::HashMap, net::{IpAddr, Ipv4Addr, SocketAddr}, sync::Arc};
use tokio::{net::TcpListener, sync::Mutex};

async fn free_rendezvous_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    addr
}
use chacha20poly1305::Key;
use x25519_dalek::{PublicKey, StaticSecret};
use fallegji::{connection::{Connection, KeyGen, Peer, Secrecy, RendezVous, get_free_port}, messaging::Message, auth::{Uid, User}};
use hex::ToHex;
use tokio_util::sync::CancellationToken;
use std::time::Duration;
use anyhow::Result;

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
    let peer_user_id = 12345u64;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let tmp_secret = StaticSecret::from([1u8; 32]);
    let pubkey = PublicKey::from(&tmp_secret);
    let last_heartbeat = Some(1234567890i64);

    let result = Peer::new_in(
        peer_id,
        peer_name,
        peer_uid,
        peer_user_id,
        addr,
        pubkey,
        last_heartbeat
    );

    if let Ok(peer) = result {
        assert_eq!(peer.get_id(), peer_id);
        assert_eq!(peer.get_user_id(), None);
        assert_eq!(peer.get_addr(), addr);
        assert_eq!(peer.get_last_heartbeat(), last_heartbeat);
    }
}

#[test]
fn test_peer_getters() {
    let (peer, _prvkey) = Peer::new_out(3, 8080).unwrap();

    assert_eq!(peer.get_id(), 3);
    assert_eq!(peer.get_user_id(), None);
    assert_eq!(peer.get_addr().port(), 8080);
    assert_eq!(peer.get_last_heartbeat(), None);

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

#[test]
fn test_secrecy() {
    // Arrange
    let key_bytes: &[u8; 32] = b"super-secret-32-byte-key!!-12345";
    let key = Key::from_slice(key_bytes);
    let wrong_key = Key::from_slice(b"wrong-key-does-not-match-1234567");

    // Test cases using Message::new() with private fields
    let test_messages = [
        Message::new(1, 12345, "Hello peer-to-peer world!".to_string()),
        Message::new(2, 0, "".to_string()),
        Message::new(3, 999, "🔥 Complex chars: emojis & unicode 🔥".to_string()),
    ];

    // Act & Assert: Roundtrip all messages
    for original_msg in test_messages.iter() {
        // Encode
        let encrypted = Connection::encode(key, original_msg.clone()).expect("Encode failed");

        // Structure checks using getters
        assert!(encrypted.len() >= 12 + 16, "Too short: {}", encrypted.len());
        let plaintext_len = serde_json::to_vec(&original_msg).unwrap().len();
        assert_eq!(encrypted.len(), plaintext_len + 12 + 16,
                  "Size mismatch: expected {} got {}",
                  plaintext_len + 12 + 16, encrypted.len());

        // Decode
        let decrypted = Connection::decode(key, &encrypted).expect("Decode failed");

        // Perfect roundtrip using getters
        assert_eq!(original_msg.get_id(), decrypted.get_id(), "ID mismatch");
        assert_eq!(original_msg.get_sender_id(), decrypted.get_sender_id(), "Sender mismatch");
        assert_eq!(original_msg.get_contents(), decrypted.get_contents(), "Contents mismatch");
        assert_eq!(original_msg.get_sent_at(), decrypted.get_sent_at(), "Timestamp mismatch");
    }

    // Security tests: Wrong key (1) and Invalid data (2 & 3) fail
    let mut msg = Message::new(999, 999, "tamper test".to_string());
    msg.set_contents("security test".to_string());  // Using setter
    let encrypted = Connection::encode(key, msg).unwrap();
    assert!(Connection::decode(wrong_key, &encrypted).is_err(), "Wrong key should fail");
    assert!(Connection::decode(key, &[]).is_err(), "Empty data should fail");
    assert!(Connection::decode(key, &encrypted[..11]).is_err(), "Too short should fail");
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

#[tokio::test(flavor = "multi_thread")]
async fn test_init_accept_peer() -> Result<()> {
    let rendezvous_addr = free_rendezvous_addr().await;

    let (admin_pub, admin_prv) = Peer::keypairgen()?;
    let (new_pub,   new_prv)   = Peer::keypairgen()?;

    let admin_uid = Uid::from(1u32);
    let new_uid   = Uid::from(2u32);
    let admin_pubkey_hex: String = admin_pub.as_bytes().encode_hex();
    let new_pubkey_hex:   String = new_pub.as_bytes().encode_hex();
    let admin_user_id = User::new(admin_pubkey_hex, "Admin".to_string(),   admin_uid).get_id();
    let new_user_id   = User::new(new_pubkey_hex,   "NewPeer".to_string(), new_uid).get_id();

    let sock_admin = get_free_port().await?;
    let sock_new   = get_free_port().await?;
    let new_addr   = sock_new.0;

    let mut conn_admin = Connection::new(admin_prv, rendezvous_addr, sock_admin, HashMap::new()).await;
    let mut conn_new   = Connection::new(new_prv,   rendezvous_addr, sock_new,   HashMap::new()).await;

    conn_admin.set_user(admin_user_id, "Admin".to_string(),   admin_uid);
    conn_new.set_user(new_user_id,     "NewPeer".to_string(), new_uid);

    // New peer listens for one inbound (accept_one drives socket.1)
    let accept_handle = tokio::spawn(async move {
        conn_new.accept_one().await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Admin accepts the request and connects to new peer
    let mut requests = vec![(new_addr, "NewPeer".to_string())];
    conn_admin.init_peer(&mut requests, 0).await?;
    assert!(requests.is_empty(), "init_peer should remove the request on success");

    accept_handle.await??;

    Ok(())
}

// 1 for listening, sending and receiving frames
// 1 for new peer
// 1 for communication messages,
// 1 for comm heartbeat
// 1 for comm typing
// 1 for comm db sync
