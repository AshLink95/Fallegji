use fallegji::auth::{User, Role, Authentication, Uid};
use anyhow::Result;

#[test]
fn test_role_parsing_and_display() -> Result<()> {
    // Display
    assert_eq!(format!("{}", Role::Admin), "admin");
    assert_eq!(format!("{}", Role::Member), "member");
    
    // FromStr (case-insensitive)
    assert_eq!("admin".parse::<Role>()?, Role::Admin);
    assert_eq!("MEMBER".parse::<Role>()?, Role::Member);
    
    // Invalid
    assert!("invalid".parse::<Role>().is_err());
    
    Ok(())
}

#[test]
fn test_authentication_deterministic_and_verifiable() {
    let key = "test_pubkey_123";
    let name = "alice";
    let uid = Uid::from(1000);
    
    // Deterministic: same inputs → same ID
    let id1 = User::gen_id(key.to_string(), name, uid);
    let id2 = User::gen_id(key.to_string(), name, uid);
    assert_eq!(id1, id2);
    
    // Verification works
    let user = User::new(key.to_string(), name.to_string(), uid);
    assert!(user.ver_id(key.to_string(), user.get_id()));
    
    // Wrong key fails
    assert!(!user.ver_id("wrong_key".to_string(), user.get_id()));
    
    // Different name → different ID
    let user2 = User::new(key.to_string(), "bob".to_string(), uid);
    assert_ne!(user.get_id(), user2.get_id());
}

#[test]
fn test_user_new_creates_valid_user() {
    let key = "pubkey_xyz";
    let name = "charlie";
    let uid = Uid::from(500);
    
    let user = User::new(key.to_string(), name.to_string(), uid);
    
    assert_eq!(user.get_name(), name);
    assert_eq!(user.get_uid(), uid);
    assert_eq!(user.get_role(), None);
    assert!(user.get_id() != 0); // Non-zero ID generated
    assert!(user.ver_id(key.to_string(), user.get_id()));
}

#[test]
fn test_user_getters() {
    let user = User::new("key".to_string(), "dave".to_string(), Uid::from(100));
    
    assert_eq!(user.get_name(), "dave");
    assert_eq!(user.get_uid(), Uid::from(100));
    assert_eq!(user.get_role(), None);
    assert!(user.get_id() > 0);
}

#[test]
fn test_user_setters() {
    let mut user = User::new("key".to_string(), "eve".to_string(), Uid::from(200));
    let original_id = user.get_id();
    
    // Set role
    user.set_role(Role::Admin);
    assert_eq!(user.get_role(), Some(Role::Admin));
    
    // ID remains stable after setter
    assert_eq!(user.get_id(), original_id);
    
    // Can change role
    user.set_role(Role::Member);
    assert_eq!(user.get_role(), Some(Role::Member));
}
