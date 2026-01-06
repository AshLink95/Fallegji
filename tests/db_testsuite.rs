// prompt engineered
use fallegji::db::Database;
use fallegji::auth::{User, Role, Authentication};
use fallegji::messaging::Message;
use std::net::{SocketAddr, Ipv4Addr};
use tokio::fs;
use anyhow::Result;

#[tokio::test]
async fn test_create_read_user() -> Result<()> {
    let db_path = "test.db";
    fs::remove_file(db_path).await.ok();
    
    let db: Database = Database::new(db_path)?;
    
    // Create
    let created: User = db.create_user("alice".to_string()).await?;
    assert!(created.ver_id("alice".to_string()));
    assert_eq!(created.get_name(), "alice");
    
    // // Read
    // let read_user = db.read_user(user_id).await?;
    // assert!(read_user.is_some());
    // let user = read_user.unwrap();
    // assert_eq!(user.id, user_id);
    // assert_eq!(user.name, "alice");
    //
    // fs::remove_file(db_path).await?;
    Ok(())
}

#[tokio::test]
async fn test_create_read_message() -> Result<()> {
    let db_path = "test.db";
    fs::remove_file(db_path).await.ok();
    
    let db: Database = Database::new(db_path)?;
    
    // Setup user first
    let user = db.create_user("bob".to_string()).await?;
    
    // Create message
    let msg: Message = db.create_message(user, "Hello world!".to_string()).await?;
    assert_eq!(msg.contents, "Hello world!");
    assert!(msg.id > 0);
    assert!(msg.created_at > 0);
    
    // // Read message
    // let read_msg = db.read_message(msg.id).await?;
    // assert!(read_msg.is_some());
    // let full_msg = read_msg.unwrap();
    // assert_eq!(full_msg.contents, "Hello world!");
    //
    // fs::remove_file(db_path).await?;
    Ok(())
}

// #[tokio::test]
// async fn test_update_user() -> Result<()> {
//     let db_path = "test_update_user.db";
//     fs::remove_file(db_path).await.ok();
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
//     fs::remove_file(db_path).await?;
//     Ok(())
// }
//
// #[tokio::test]
// async fn test_update_message() -> Result<()> {
//     let db_path = "test_update_msg.db";
//     fs::remove_file(db_path).await.ok();
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
//     fs::remove_file(db_path).await?;
//     Ok(())
// }
//
// #[tokio::test]
// async fn test_delete_user() -> Result<()> {
//     let db_path = "test_delete_user.db";
//     fs::remove_file(db_path).await.ok();
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
//     fs::remove_file(db_path).await?;
//     Ok(())
// }
//
// #[tokio::test]
// async fn test_delete_message() -> Result<()> {
//     let db_path = "test_delete_msg.db";
//     fs::remove_file(db_path).await.ok();
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
//     fs::remove_file(db_path).await?;
//     Ok(())
// }
//
// #[tokio::test]
// async fn test_cascade_delete() -> Result<()> {
//     let db_path = "test_cascade.db";
//     fs::remove_file(db_path).await.ok();
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
//     fs::remove_file(db_path).await?;
//     Ok(())
// }
//
// #[tokio::test]
// async fn test_foreign_key_constraint() -> Result<()> {
//     let db_path = "test_fk_constraint.db";
//     fs::remove_file(db_path).await.ok();
//
//     let db: Database = Database::new(db_path)?;
//
//     // Try to create message with non-existent user (should fail)
//     let result = db.create_message(999u64, "orphan".to_string()).await;
//     assert!(result.is_err());
//
//     fs::remove_file(db_path).await?;
//     Ok(())
// }
