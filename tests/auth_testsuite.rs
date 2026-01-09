// prompt engineered
use fallegji::auth::{User, Role, Authentication};
use anyhow::Result;
use nix::unistd::{Uid, getuid};

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
    let pub_key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYuiG44Nel4xo=".to_string();
    let uid = Uid::from_raw(0);
    let user = User::new(pub_key.clone(), "alice".to_string(), uid);
    
    assert_eq!(user.get_name(), "alice");
    assert!(user.get_id() != 0); // Non-zero ID generated
    assert_eq!(user.get_role(), None);
}

#[test]
fn test_user_ver_id_roundtrip() {
    let pub_key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYuiG44Nel4xo=".to_string();
    let uid = Uid::from_raw(0);
    let name = "alice";
    
    let user = User::new(pub_key.clone(), name.to_string(), uid);
    let id = user.get_id();
    
    // Verify with same key+name
    assert!(user.ver_id(pub_key.clone(), id));
    
    // Verify deterministic: same inputs = same ID
    let user2 = User::new(pub_key.clone(), name.to_string(), uid);
    assert_eq!(user2.get_id(), id);
    
    // Different name → different ID
    let user3 = User::new(pub_key.clone(), "bob".to_string(), uid);
    assert_ne!(user3.get_id(), id);
}

#[test]
fn test_user_ver_id_wrong_key() {
    let user = User::new("key1".to_string(), "alice".to_string(), Uid::from_raw(0));
    
    // Wrong key → fails
    assert!(!user.ver_id("wrong_key".to_string(), user.get_id()));
}

#[test]
fn test_user_ver_id_same_uid() {
    let pub_key = "test_key_123";
    let uid = Uid::from_raw(1);
    let name = "alice";
    
    let user1 = User::new(pub_key.to_string(), name.to_string(), uid);
    let user2 = User::new(pub_key.to_string(), name.to_string(), uid);
    
    // Same key+name+uid → same ID
    assert_eq!(user1.get_id(), user2.get_id());
    assert!(user1.ver_id(pub_key.to_string(), user1.get_id()));
    assert!(user2.ver_id(pub_key.to_string(), user2.get_id()));
}

#[test]
fn test_user_setters() {
    let mut user = User::new("key".to_string(), "initial".to_string(), Uid::from_raw(1));
    
    // Test setters work
    user.set_role(Role::Member);
    
    // Verify getters
    assert_eq!(user.get_role(), Some(Role::Member));
}

#[test]
fn test_user_setters_dont_change_id() {
    let mut user = User::new("key".to_string(), "initial".to_string(), Uid::from_raw(1));
    let original_id = user.get_id();
    
    user.set_role(Role::Admin);
    
    // ID remains stable (computed at creation from key+name)
    assert_eq!(user.get_id(), original_id);
}

#[test]
fn test_authentication_trait_consistency() {
    let pub_key = "wg_pubkey_xyz789";
    let uid = getuid();
    let name = "test_user";
    
    // Direct trait call vs User::new consistency
    let trait_id = User::gen_id(pub_key.to_string(), name, uid);
    let user = User::new(pub_key.to_string(), name.to_string(), uid);
    
    assert_eq!(trait_id, user.get_id());
}

#[test]
fn test_gen_id_determinism() {
    let inputs = [
        ("key1", "alice", Uid::from(0)),
        ("key1", "bob", Uid::from(10)), 
        ("key2", "alice", Uid::from(100)),
        ("wg:Y29kZQ==", "test", Uid::from(1000))  // Base64 WireGuard key example
    ];
    
    for (key, name, uid) in inputs {
        let id1 = User::gen_id(key.to_string(), name, uid);
        let id2 = User::gen_id(key.to_string(), name, uid);
        assert_eq!(id1, id2, "gen_id must be deterministic for same inputs");
    }
}

#[test]
fn test_ver_id_symmetry() {
    let pub_key = "symmetric_test_key";
    let uid = Uid::from_raw(1020);
    let name = "symmetric_user";
    
    let user = User::new(pub_key.to_string(), name.to_string(), uid);
    let computed_id = User::gen_id(pub_key.to_string(), name, uid);
    
    assert_eq!(user.get_id(), computed_id);
    assert!(user.ver_id(pub_key.to_string(), computed_id));
}
