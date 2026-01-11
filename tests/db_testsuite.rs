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

