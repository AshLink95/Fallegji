use std::{fmt, str};
use std::net::SocketAddr;
use nix::unistd::getuid;
use sha2::{Digest, Sha256};
use anyhow::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Role { Server, Client }
impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Server => write!(f, "server"),
            Role::Client => write!(f, "client"),
        }
    }
}
impl str::FromStr for Role {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "server" => Ok(Role::Server),
            "client" => Ok(Role::Client),
            _ => anyhow::bail!("Invalid role: {}", s),
        }
    }
}

pub struct User {
    id: u64,
    name: String,
    role: Option<Role>,
    addr: Option<SocketAddr>
}

/// Authentication Trait, contains `gen_id` and `ver_id`
pub trait Authentication { // currently only works on linux
    /// method to generate id
    /// The key argument needs to be the tunnel (wireguard/boringTUN) public key
    fn gen_id(key: String, name: &str) -> u64;
    /// method to verify id
    /// The key argument needs to be the tunnel (wireguard/boringTUN) public key
    fn ver_id(&self, key: String, name: &str) -> bool;
}

/// Contains server user-sepcific methods
pub trait Server {
    fn init_server(&mut self); //updates addr
}

/// Contains client user-sepcific methods
pub trait Client {
    fn connect_client(&mut self); //updates addr
}

impl User {
    pub fn new(key: String, name: String) -> Self {
        let id = Self::gen_id(key, &name);
        Self { id, name, role: None, addr: None }
    }

    pub fn get_id(&self) -> u64 { self.id }
    pub fn get_name(&self) -> String { self.name.clone() }
    pub fn get_role(&self) -> Option<Role> { self.role.clone() }
    pub fn get_addr(&self) -> Option<SocketAddr> { self.addr }

    pub fn set_name(&mut self, name: String) { self.name = name; }
    pub fn set_role(&mut self, role: Role) { self.role = Some(role); }
    pub fn set_addr(&mut self, addr: SocketAddr) { self.addr = Some(addr) }
}

impl Authentication for User {
    fn gen_id(key: String, name: &str) -> u64 {
        let uid = getuid().as_raw();
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

    fn ver_id(&self, key: String, name: &str) -> bool {
        let uid = getuid().as_raw();
        let to_hash = key + name + &uid.to_string();
        let mut hasher = Sha256::new();
        hasher.update(to_hash.as_bytes());
        let res = hasher.finalize();

        let mut id = 0u64;
        for chunk in res.chunks(8) {
            let bytes: [u8; 8] = chunk.try_into().unwrap_or([0; 8]);
            id ^= u64::from_be_bytes(bytes);
        }

        id == self.id
    }
}
