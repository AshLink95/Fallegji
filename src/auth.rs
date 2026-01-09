use std::{fmt, str};
use nix::unistd::{getuid, Uid};
use sha2::{Digest, Sha256};
use anyhow::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Role { Admin, Member }
impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::Member => write!(f, "member"),
        }
    }
}
impl str::FromStr for Role {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "admin" => Ok(Role::Admin),
            "member" => Ok(Role::Member),
            _ => anyhow::bail!("Invalid role: {}", s),
        }
    }
}

pub struct User {
    id: u64,
    name: String,
    role: Option<Role>,
    uid: Uid
}

/// Authentication Trait, contains `gen_id` and `ver_id`
pub trait Authentication { // currently only works on linux
    /// method to generate id
    /// The key argument needs to be the tunnel (wireguard/boringTUN) public key
    fn gen_id(key: String, name: &str, uid: Uid) -> u64;
    /// method to verify id
    /// The key argument needs to be the tunnel (wireguard/boringTUN) public key
    fn ver_id(&self, key: String, user_id: u64) -> bool;
}

impl User {
    pub fn new(key: String, name: String, uid: Uid) -> Self {
        let id = Self::gen_id(key, &name, uid);
        Self { id, name, role: None, uid }
    }

    pub fn get_id(&self) -> u64 { self.id }
    pub fn get_name(&self) -> String { self.name.clone() }
    pub fn get_role(&self) -> Option<Role> { self.role.clone() }
    pub fn get_uid(&self) -> Uid { self.uid }

    pub fn set_role(&mut self, role: Role) { self.role = Some(role); }
}

impl Authentication for User {
    fn gen_id(key: String, name: &str, uid: Uid) -> u64 {
        let to_hash = key + name + &uid.to_string();
        let mut hasher = Sha256::new();
        hasher.update(to_hash.as_bytes());
        let res = hasher.finalize();

        let mut id = 0u64;
        for chunk in res.chunks(8) {
            let bytes: [u8; 8] = chunk.try_into().unwrap_or([0; 8]);
            id ^= u64::from_be_bytes(bytes);
        }

        id
    }

    fn ver_id(&self, key: String, user_id: u64) -> bool {
        let uid = self.uid;
        let to_hash = key + &self.name + &uid.to_string();
        let mut hasher = Sha256::new();
        hasher.update(to_hash.as_bytes());
        let res = hasher.finalize();

        let mut id = 0u64;
        for chunk in res.chunks(8) {
            let bytes: [u8; 8] = chunk.try_into().unwrap_or([0; 8]);
            id ^= u64::from_be_bytes(bytes);
        }

        id == self.id && id == user_id
    }
}
