// prompt engineered
use fallegji::auth::{User, Role, Authentication};
use anyhow::Result;
use std::net::{SocketAddr, Ipv4Addr};

#[test]
fn test_role_display() {
    assert_eq!("admin".to_string(), format!("{}", Role::Admin));
    assert_eq!("member".to_string(), format!("{}", Role::Member));
}

#[test]
fn test_role_fromstr_valid() -> Result<()> {
    assert_eq!("admin".parse::<Role>()?, Role::Admin);
    assert_eq!("ADMIN".parse::<Role>()?, Role::Admin);
    assert_eq!("member".parse::<Role>()?, Role::Member);
    assert_eq!("MEMBER".parse::<Role>()?, Role::Member);
    Ok(())
}

#[test]
fn test_role_fromstr_invalid() {
    let result = "server".parse::<Role>();
    assert!(result.is_err());
    let result = " ".parse::<Role>();
    assert!(result.is_err());
}

#[test]
fn test_user_new_generates_id() {
    let wg_key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYuiG44Nel4xo=".to_string();
    let user = User::new(wg_key.clone(), "alice".to_string());
    
    assert_eq!(user.get_name(), "alice");
    assert!(user.get_id() != 0); // Non-zero ID generated
    assert_eq!(user.get_role(), None);
}

#[test]
fn test_user_ver_id_roundtrip() {
    let wg_key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYuiG44Nel4xo=".to_string();
    let name = "alice";
    
    let user = User::new(wg_key.clone(), name.to_string());
    let id = user.get_id();
    
    // Verify with same key+name
    assert!(user.ver_id(wg_key.clone(), name));
    
    // Verify deterministic: same inputs = same ID
    let user2 = User::new(wg_key.clone(), name.to_string());
    assert_eq!(user2.get_id(), id);
    
    // Different name → different ID
    let user3 = User::new(wg_key.clone(), "bob".to_string());
    assert_ne!(user3.get_id(), id);
}

#[test]
fn test_user_ver_id_wrong_key() {
    let user = User::new("key1".to_string(), "alice".to_string());
    
    // Wrong key → fails
    assert!(!user.ver_id("wrong_key".to_string(), "alice"));
    
    // Wrong name → fails  
    assert!(!user.ver_id("key1".to_string(), "bob"));
}

#[test]
fn test_user_ver_id_same_uid() {
    let wg_key = "test_key_123";
    let name = "alice";
    
    let user1 = User::new(wg_key.to_string(), name.to_string());
    let user2 = User::new(wg_key.to_string(), name.to_string());
    
    // Same key+name+uid → same ID
    assert_eq!(user1.get_id(), user2.get_id());
    assert!(user1.ver_id(wg_key.to_string(), name));
    assert!(user2.ver_id(wg_key.to_string(), name));
}

#[test]
fn test_user_setters() {
    let mut user = User::new("key".to_string(), "initial".to_string());
    
    // Test setters work
    user.set_role(Role::Member);
    
    // Verify getters
    assert_eq!(user.get_role(), Some(Role::Member));
}

#[test]
fn test_user_setters_dont_change_id() {
    let mut user = User::new("key".to_string(), "initial".to_string());
    let original_id = user.get_id();
    
    user.set_role(Role::Admin);
    
    // ID remains stable (computed at creation from key+name)
    assert_eq!(user.get_id(), original_id);
}

#[test]
fn test_authentication_trait_consistency() {
    let wg_key = "wg_pubkey_xyz789";
    let name = "test_user";
    
    // Direct trait call vs User::new consistency
    let trait_id = User::gen_id(wg_key.to_string(), name);
    let user = User::new(wg_key.to_string(), name.to_string());
    
    assert_eq!(trait_id, user.get_id());
}

#[test]
fn test_gen_id_determinism() {
    let inputs = [
        ("key1", "alice"),
        ("key1", "bob"), 
        ("key2", "alice"),
        ("wg:Y29kZQ==", "test")  // Base64 WireGuard key example
    ];
    
    for (key, name) in inputs {
        let id1 = User::gen_id(key.to_string(), name);
        let id2 = User::gen_id(key.to_string(), name);
        assert_eq!(id1, id2, "gen_id must be deterministic for same inputs");
    }
}

#[test]
fn test_ver_id_symmetry() {
    let wg_key = "symmetric_test_key";
    let name = "symmetric_user";
    
    let user = User::new(wg_key.to_string(), name.to_string());
    let computed_id = User::gen_id(wg_key.to_string(), name);
    
    assert_eq!(user.get_id(), computed_id);
    assert!(user.ver_id(wg_key.to_string(), name));
}
