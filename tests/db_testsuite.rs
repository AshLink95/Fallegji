// prompt engineered
use fallegji::db::Database;
use fallegji::auth::{User, Authentication};
use fallegji::messaging::Message;
use fallegji::connection::Peer;
use hex::ToHex;
use nix::unistd::getuid;
use anyhow::Result;
use x25519_dalek::StaticSecret;

#[tokio::test]
async fn test_create_read_user() -> Result<()> {
    let db_path = "test.db";
    let db: Database = Database::new(db_path)?;
    
    // Create peer first (needed for user verification)
    let (peer, _prvkey) = db.create_peer(8080).await?;
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    
    // Create user with peer's pubkey
    let created: User = db.create_user(pubkey_hex.clone(), "alice".to_string(), getuid()).await?;
    assert!(created.ver_id(pubkey_hex.clone(), created.get_id()));
    assert_eq!(created.get_name(), "alice");
    
    db.placeholder_linkp2u(&created, &peer)?; //TODO: change with proper update
    
    // Read user (now works because peer exists with matching pubkey)
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
    let user = db.create_user(pubkey_hex.clone(), "charlie".to_string(), getuid()).await?;
    
    db.placeholder_linkp2u(&user, &created)?; //TODO: change with proper update
    
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
    let (peer, _prvkey) = db.create_peer(8080).await?;
    let pubkey_hex = peer.get_pubkey().to_bytes().encode_hex::<String>();
    let user = db.create_user(pubkey_hex.clone(), "bob".to_string(), getuid()).await?;
    db.placeholder_linkp2u(&user, &peer)?;
    
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

// #[tokio::test]
// async fn test_update_user() -> Result<()> {
//     let db_path = "test_update_user.db";
//
//     let db: Database = Database::new(db_path)?;
//     let user_id = 1u64;
//
//     // Create
//     db.create_user(user_id, "old_name".to_string(), None, None).await?;
//
//     // Update
//     let addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080);
//     db.update_user(user_id, Some("new_name".to_string()), Some(Role::Server), Some(addr)).await?;
//
//     // Verify update
//     let user = db.read_user(user_id).await?.unwrap();
//     assert_eq!(user.name, "new_name");
//     assert_eq!(user.role, Some(Role::Server));
//
//     Ok(())
// }
//
// #[tokio::test]
// async fn test_update_message() -> Result<()> {
//     let db_path = "test_update_msg.db";
//
//     let db: Database = Database::new(db_path)?;
//     let user_id = 1u64;
//
//     // Setup
//     db.create_user(user_id, "test".to_string(), None, None).await?;
//     let msg = db.create_message(user_id, "old content".to_string()).await?;
//
//     // Update
//     db.update_message(msg.id, "new content".to_string()).await?;
//
//     // Verify
//     let updated = db.read_message(msg.id).await?.unwrap();
//     assert_eq!(updated.contents, "new content");
//
//     Ok(())
// }
//
// #[tokio::test]
// async fn test_delete_user() -> Result<()> {
//     let db_path = "test_delete_user.db";
//
//     let db: Database = Database::new(db_path)?;
//     let user_id = 1u64;
//
//     // Create
//     db.create_user(user_id, "delete me".to_string(), None, None).await?;
//
//     // Delete
//     db.delete_user(user_id).await?;
//
//     // Verify gone
//     let user = db.read_user(user_id).await?;
//     assert!(user.is_none());
//
//     Ok(())
// }
//
// #[tokio::test]
// async fn test_delete_message() -> Result<()> {
//     let db_path = "test_delete_msg.db";
//
//     let db: Database = Database::new(db_path)?;
//     let user_id = 1u64;
//
//     // Setup
//     db.create_user(user_id, "test".to_string(), None, None).await?;
//     let msg = db.create_message(user_id, "bye".to_string()).await?;
//
//     // Delete
//     db.delete_message(msg.id).await?;
//
//     // Verify gone
//     let msg_read = db.read_message(msg.id).await?;
//     assert!(msg_read.is_none());
//
//     Ok(())
// }
//
// #[tokio::test]
// async fn test_cascade_delete() -> Result<()> {
//     let db_path = "test_cascade.db";
//
//     let db: Database = Database::new(db_path)?;
//     let user_id = 1u64;
//
//     // Setup
//     db.create_user(user_id, "cascade".to_string(), None, None).await?;
//     let msg1 = db.create_message(user_id, "msg1".to_string()).await?;
//     let msg2 = db.create_message(user_id, "msg2".to_string()).await?;
//
//     // Delete user (messages should be gone due to FK)
//     db.delete_user(user_id).await?;
//
//     assert!(db.read_user(user_id).await?.is_none());
//     assert!(db.read_message(msg1.id).await?.is_none());
//     assert!(db.read_message(msg2.id).await?.is_none());
//
//     Ok(())
// }
//
// #[tokio::test]
// async fn test_foreign_key_constraint() -> Result<()> {
//     let db_path = "test_fk_constraint.db";
//
//     let db: Database = Database::new(db_path)?;
//
//     // Try to create message with non-existent user (should fail)
//     let result = db.create_message(999u64, "orphan".to_string()).await;
//     assert!(result.is_err());
//
// }
