use std::{fmt, str};
use sha2::{Digest, Sha256};
use anyhow::Result;

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER},
    System::Threading::{GetCurrentProcess, OpenProcessToken}
};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uid(u32);
impl Uid {
    pub fn from(uid: u32) -> Self { Self(uid) }
    
    pub fn as_raw(&self) -> u32 { self.0 }

    #[cfg(unix)]
    pub fn getuid() -> Self {
        Self(nix::unistd::getuid().as_raw())
    }

    #[cfg(windows)]
    pub fn getuid() -> Self {
        unsafe {
            let mut token: HANDLE = 0 as HANDLE;
            
            // Open process token
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                panic!("Failed to open process token");
            }
            
            // Get token user info
            let mut buffer = vec![0u8; 256];
            let mut return_length = 0u32;
            
            if GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut return_length,
            ) == 0 {
                CloseHandle(token);
                panic!("Failed to get token information");
            }
            
            let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
            let sid = token_user.User.Sid;
            
            // Get RID (last subauthority)
            let sub_authority_count = *sid.cast::<u8>().add(1);
            let rid_ptr = sid
                .cast::<u8>()
                .add(8 + (sub_authority_count as usize - 1) * 4)
                .cast::<u32>();
            let rid = *rid_ptr;
            
            CloseHandle(token);
            
            Self::from(rid)
        }
    }
}
impl fmt::Display for Uid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
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

    pub fn sys() -> Self {
        Self { id: 0u64, name: "System".to_string(), role: None, uid: Uid::from(0) }
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
