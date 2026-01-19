// prompt engineered
use std::net::SocketAddr;
use fallegji::db::Database;
use fallegji::auth::{Authentication, Role, User, Uid};
use fallegji::messaging::Message;
use fallegji::connection::Peer;
use hex::ToHex;
use anyhow::Result;
use x25519_dalek::StaticSecret;

#[tokio::test]
async fn test_create_read_user() -> Result<()> {
    let db_path = "test.db";
    let db: Database = Database::new(db_path)?;
    
    // Create peer first (needed for user verification)
    let (peer, _) = db.create_peer(8080).await?;
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    
    // Create user with peer's pubkey
    let created: User = db.create_user(pubkey_hex.clone(), "alice".to_string(), Uid::getuid()).await?;
    assert!(created.ver_id(pubkey_hex.clone(), created.get_id()));
    assert_eq!(created.get_name(), "alice");
    
    db.update_peer_link_user(peer.get_id(), created.get_id()).await?;
    
    // Read user
    let user_id = created.get_id();
    let read_user = db.read_user(user_id).await?;
    assert!(read_user.is_some());
    let user = read_user.unwrap();
    assert_eq!(user.get_id(), user_id);
    assert_eq!(user.get_name(), "alice");
    
    Ok(())
}

#[tokio::test]
async fn test_create_read_peer() -> Result<()> {
    let db_path = "test.db";
    let db: Database = Database::new(db_path)?;
    
    // Create peer and associated user
    let (created, prv_key): (Peer, StaticSecret) = db.create_peer(6967).await?;
    let pubkey_hex = created.get_pubkey().to_bytes().encode_hex::<String>();
    let user = db.create_user(pubkey_hex.clone(), "charlie".to_string(), Uid::getuid()).await?;
    
    db.update_peer_link_user(created.get_id(), user.get_id()).await?;
    
    // Create peer with linked user
    assert!(created.get_id() > 0);
    assert!(!created.get_addr().ip().is_loopback());
    assert_eq!(created.get_addr().port(), 6967);
    assert_eq!(created.get_user_id(), None);
    assert_eq!(created.get_last_heartbeat(), None);
    let prvkey = prv_key.to_bytes();
    let pubkey = created.get_pubkey().to_bytes();
    assert!(!pubkey.iter().all(|&b| b == 0));
    assert!(!prvkey.iter().all(|&b| b == 0));
    
    // Read peer
    let peer_id = created.get_id();
    let read_peer = db.read_peer(peer_id).await?;
    assert!(read_peer.is_some());
    let peer = read_peer.unwrap();
    assert_eq!(peer.get_id(), peer_id);
    assert_eq!(peer.get_addr().port(), 6967);
    
    Ok(())
}

#[tokio::test]
async fn test_create_read_message() -> Result<()> {
    let db_path = "test.db";
    let db: Database = Database::new(db_path)?;
    
    // Setup user with linked peer (needed for read_user to work)
    let (peer, _) = db.create_peer(8080).await?;
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    let user = db.create_user(pubkey_hex.clone(), "bob".to_string(), Uid::getuid()).await?;
    db.update_peer_link_user(peer.get_id(), user.get_id()).await?;
    
    // Create message
    let msg: Message = db.create_message(user.get_id(), "Hello world!".to_string()).await?;
    assert_eq!(msg.get_contents(), "Hello world!");
    assert!(msg.get_id() > 0);
    assert!(msg.get_sent_at() > 0);
    
    // Read message
    let msg_id = msg.get_id();
    let read_msg = db.read_message(msg_id).await?;
    assert!(read_msg.is_some());
    let full_msg = read_msg.unwrap();
    assert_eq!(full_msg.get_id(), msg_id);
    assert_eq!(full_msg.get_contents(), "Hello world!");
    assert_eq!(full_msg.get_sender_id(), user.get_id());
    
    Ok(())
}

#[tokio::test]
async fn test_update_user() -> Result<()> {
    let db_path = "test.db";
    let db = Database::new(db_path)?;
    
    // Setup
    let (peer, _) = db.create_peer(8080).await?;
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    let user = db.create_user(pubkey_hex, "alice".to_string(), Uid::getuid()).await?;
    db.update_peer_link_user(peer.get_id(), user.get_id()).await?;
    
    // Update role
    let updated = db.update_user_role(user.get_id(), Role::Admin).await?;
    assert!(updated);
    
    // Verify update
    let read_user = db.read_user(user.get_id()).await?.unwrap();
    assert_eq!(read_user.get_role(), Some(Role::Admin));
    
    // Update non-existent user returns false
    let result = db.update_user_role(99999, Role::Member).await?;
    assert!(!result);
    
    Ok(())
}

#[tokio::test]
async fn test_update_peer() -> Result<()> {
    let db_path = "test.db";
    let db = Database::new(db_path)?;
    
    // Setup
    let (peer, _) = db.create_peer(7070).await?;
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    let user = db.create_user(pubkey_hex, "bob".to_string(), Uid::getuid()).await?;
    
    // Update link to user
    let linked = db.update_peer_link_user(peer.get_id(), user.get_id()).await?;
    assert!(linked);
    
    // Update address
    let new_addr: SocketAddr = "192.168.1.100:9090".parse()?;
    let updated = db.update_peer_addr(peer.get_id(), new_addr).await?;
    assert!(updated);
    
    // Update heartbeat
    let heartbeat_updated = db.update_peer_last_heartbeat(peer.get_id(), Some(1234567890)).await?;
    assert!(heartbeat_updated);
    
    // Verify updates
    let read_peer = db.read_peer(peer.get_id()).await?.unwrap();
    assert_eq!(read_peer.get_user_id(), Some(user.get_id()));
    assert_eq!(read_peer.get_addr(), new_addr);
    assert_eq!(read_peer.get_last_heartbeat(), Some(1234567890));
    
    // Update non-existent peer returns false
    let result = db.update_peer_addr(99999, new_addr).await?;
    assert!(!result);
    
    Ok(())
}

#[tokio::test]
async fn test_update_message() -> Result<()> {
    let db_path = "test.db";
    let db = Database::new(db_path)?;
    
    // Setup
    let (peer, _) = db.create_peer(8080).await?;
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    let user = db.create_user(pubkey_hex, "charlie".to_string(), Uid::getuid()).await?;
    db.update_peer_link_user(peer.get_id(), user.get_id()).await?;
    let msg = db.create_message(user.get_id(), "Original message".to_string()).await?;
    
    // Update contents
    let updated = db.update_message_contents(msg.get_id(), "Updated message".to_string()).await?;
    assert!(updated);
    
    // Update date
    let new_date = 9876543210i64;
    let date_updated = db.update_message_date(msg.get_id(), new_date).await?;
    assert!(date_updated);
    
    // Verify updates
    let read_msg = db.read_message(msg.get_id()).await?.unwrap();
    assert_eq!(read_msg.get_contents(), "Updated message");
    assert_eq!(read_msg.get_sent_at(), new_date);
    
    // Update non-existent message returns false
    let result = db.update_message_contents(99999, "test".to_string()).await?;
    assert!(!result);
    
    Ok(())
}

#[tokio::test]
async fn test_delete() -> Result<()> {
    let db_path = "test.db";
    let db = Database::new(db_path)?;
    
    // Setup: Create user, peer, and message
    let (peer, _) = db.create_peer(8080).await?;
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    let user = db.create_user(pubkey_hex, "delete_test".to_string(), Uid::getuid()).await?;
    db.update_peer_link_user(peer.get_id(), user.get_id()).await?;
    let msg = db.create_message(user.get_id(), "Test message".to_string()).await?;
    
    // Delete message
    let msg_deleted = db.delete_message(msg.get_id()).await?;
    assert!(msg_deleted);
    assert!(db.read_message(msg.get_id()).await?.is_none());
    
    // Delete non-existent message returns false
    let result = db.delete_message(99999).await?;
    assert!(!result);
    
    // Delete peer
    let peer_deleted = db.delete_peer(peer.get_id()).await?;
    assert!(peer_deleted);
    assert!(db.read_peer(peer.get_id()).await?.is_none());
    
    // Delete non-existent peer returns false
    let result = db.delete_peer(99999).await?;
    assert!(!result);
    
    // Delete user
    let user_deleted = db.delete_user(user.get_id()).await?;
    assert!(user_deleted);
    assert!(db.read_user(user.get_id()).await?.is_none());
    
    // Delete non-existent user returns false
    let result = db.delete_user(99999).await?;
    assert!(!result);
    
    Ok(())
}

#[tokio::test]
async fn test_load_all() -> Result<()> { //randomly fails for some bs reason
    let db_path = "test.db";
    let db = Database::new(db_path)?;
    
    // Setup: Create multiple users, peers, and messages
    let (peer1, _) = db.create_peer(8080).await?;
    let pubkey1_hex = peer1.get_pubkey().to_bytes().encode_hex::<String>();
    let user1 = db.create_user(pubkey1_hex, "alice".to_string(), Uid::getuid()).await?;
    db.update_peer_link_user(peer1.get_id(), user1.get_id()).await?;
    
    let (peer2, _) = db.create_peer(8081).await?;
    let pubkey2_hex = peer2.get_pubkey().to_bytes().encode_hex::<String>();
    let user2 = db.create_user(pubkey2_hex, "bob".to_string(), Uid::getuid()).await?;
    db.update_peer_link_user(peer2.get_id(), user2.get_id()).await?;
    
    let _ = db.create_message(user1.get_id(), "First message".to_string()).await?;
    let _ = db.create_message(user2.get_id(), "Second message".to_string()).await?;
    
    // Load all users
    let users = db.load_all_users().await?;
    assert!(users.len() >= 2);
    assert!(users.iter().any(|u| u.get_name() == "alice"));
    assert!(users.iter().any(|u| u.get_name() == "bob"));
    
    // Load all peers
    let peers = db.load_all_peers().await?;
    assert!(peers.len() >= 2);
    assert!(peers.iter().any(|p| p.get_addr().port() == 8080));
    assert!(peers.iter().any(|p| p.get_addr().port() == 8081));
    
    // Load all messages (ordered by sent_at)
    let messages = db.load_all_messages().await?;
    assert!(messages.len() >= 2);
    assert!(messages.iter().any(|m| m.get_contents() == "First message"));
    assert!(messages.iter().any(|m| m.get_contents() == "Second message"));
    // Verify ordering
    assert!(messages[0].get_sent_at() <= messages[1].get_sent_at());
    
    Ok(())
}

#[tokio::test]
async fn test_save_all() -> Result<()> {
    let db_path = "test.db";
    let db = Database::new(db_path)?;
    
    // Start with peers - mix of DB and memory
    let (peer1, _) = db.create_peer(9000).await?; // In DB
    let (peer2, _) = db.create_peer(9001).await?; // In DB (will be deleted)
    let (mut peer3, _) = Peer::new_out(-1, 9002)?; // Memory only (will be added)
    peer3.set_id(100); // Mock ID
    
    // Create users in memory and link to peers
    let pubkey1_hex = peer1.get_pubkey().to_bytes().encode_hex::<String>();
    let mut user1 = User::new(pubkey1_hex.clone(), "charlie".to_string(), Uid::getuid()); // Memory
    user1.set_role(Role::Admin);
    
    let pubkey3_hex = peer3.get_pubkey().to_bytes().encode_hex::<String>();
    let user2 = User::new(pubkey3_hex.clone(), "dave".to_string(), Uid::getuid()); // Memory
    
    // Link peers to users in memory (no DB touch)
    let mut peer1_linked = peer1.clone();
    peer1_linked.set_user_id(user1.get_name(), user1.get_id(), user1.get_uid())?;
    
    peer3.set_user_id(user2.get_name(), user2.get_id(), user2.get_uid())?;
    
    // Save peers first (update peer1 with user_id, add peer3, delete peer2)
    let peers_saved = db.save_all_peers(vec![peer1_linked.clone(), peer3.clone()]).await?;
    assert_eq!(peers_saved, 2);
    
    // Save users (add user1 and user2, both new)
    let users_saved = db.save_all_users(vec![user1.clone(), user2.clone()]).await?;
    assert_eq!(users_saved, 2);
    
    // Create messages - one in DB, two in memory
    let _ = db.create_message(user1.get_id(), "In DB".to_string()).await?; // In DB (will be deleted)
    let msg2 = Message::new(-1, user1.get_id(), "Memory 1".to_string()); // Memory (will be added)
    let mut msg3 = Message::new(-2, user2.get_id(), "Memory 2".to_string()); // Memory (will be added)
    msg3.set_date(time::OffsetDateTime::now_utc().unix_timestamp() + 100);
    
    // Save messages (add msg2 and msg3, delete msg1)
    let messages_saved = db.save_all_messages(vec![msg2.clone(), msg3.clone()]).await?;
    assert_eq!(messages_saved, 2);
    
    // NOW load and verify everything
    
    // Verify peers
    let loaded_peers = db.load_all_peers().await?;
    assert_eq!(loaded_peers.len(), 2);
    assert!(loaded_peers.iter().any(|p| p.get_id() == peer1.get_id() && p.get_user_id() == Some(user1.get_id())));
    assert!(loaded_peers.iter().any(|p| p.get_id() == peer3.get_id() && p.get_user_id() == Some(user2.get_id())));
    assert!(!loaded_peers.iter().any(|p| p.get_id() == peer2.get_id()));
    
    // Verify users
    let loaded_users = db.load_all_users().await?;
    assert_eq!(loaded_users.len(), 2);
    assert!(loaded_users.iter().any(|u| u.get_name() == "charlie" && u.get_role() == Some(Role::Admin)));
    assert!(loaded_users.iter().any(|u| u.get_name() == "dave"));
    
    // Verify messages
    let loaded_messages = db.load_all_messages().await?;
    assert_eq!(loaded_messages.len(), 2);
    assert!(loaded_messages.iter().any(|m| m.get_contents() == "Memory 1"));
    assert!(loaded_messages.iter().any(|m| m.get_contents() == "Memory 2"));
    assert!(!loaded_messages.iter().any(|m| m.get_contents() == "In DB"));
    
    Ok(())
}
