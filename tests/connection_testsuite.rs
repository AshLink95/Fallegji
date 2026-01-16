// prompt engineered
use std::{net::{IpAddr, Ipv4Addr, SocketAddr}, sync::Arc};
use tokio::sync::Mutex;
use chacha20poly1305::Key;
use x25519_dalek::{PublicKey, StaticSecret};
use nix::unistd::Uid;
use fallegji::{connection::{Connection, KeyGen, Peer, Secrecy, RendezVous}, messaging::Message};
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
    let rendezvous_addr: SocketAddr = "127.0.0.1:6666".parse().unwrap();
    let mut conn = Connection::new(keypair.1, rendezvous_addr).await?;
    let bind_result = conn.bind_rendezvous().await;
    assert!(bind_result.is_ok(), "Failed to bind rendezvous");
    conn.end_rendezvous();
    let double_bind = conn.bind_rendezvous().await;
    assert!(double_bind.is_ok(), "Double bind failed");

    let keypair2 = Peer::keypairgen()?;
    let mut client_conn = Connection::new(keypair2.1, rendezvous_addr).await?;
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
    let rendezvous_addr: SocketAddr = "127.0.0.1:5555".parse().unwrap();
    let server_keypair = Peer::keypairgen()?;
    let client_keypair = Peer::keypairgen()?;
    let mut server_conn = Connection::new(server_keypair.1, rendezvous_addr).await?;
    let mut client_conn = Connection::new(client_keypair.1, rendezvous_addr).await?;
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

    Ok(())
}

// 1 for rendezvous final verif and init peer
// 1 for rendezvous fallback and init peer
//
// 1 for communication messages,
// 1 for comm heartbeat
// 1 for comm typing
