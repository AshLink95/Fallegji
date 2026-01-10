use std::{collections::HashMap, net::{UdpSocket, SocketAddr}, sync::{Arc, Mutex}};
use anyhow::{Context, Error, Result};
use hex::ToHex;
use nix::unistd::Uid;
use sha2::Sha256;
use zeromq::{DealerSocket, RouterSocket};
use x25519_dalek::{PublicKey, StaticSecret};
use hkdf::Hkdf;
use chacha20poly1305::Key;
// use tokio::{task, time::{sleep, Duration, interval}};
// use sha2::{Sha256, Digest};
// use serde::{Serialize, Deserialize};
// use serde_json;
// use time::OffsetDateTime;

use crate::auth::{Authentication, User};

pub struct Peer {
    id: i32,
    user_id: Option<u64>, // Users get created after peers
    addr: SocketAddr,
    pubkey: PublicKey,
    last_heartbeat: Option<i64> // peer online if None
}

/// key generation
pub trait KeyGen {
    fn keypairgen() -> Result<(PublicKey, StaticSecret)>;
    fn shrdkeygen(&self, prvkey: StaticSecret) -> Key;
}

/// user_id -> peer, key, socket
type Peermap = HashMap<u64, (Peer, Key, DealerSocket)>;

pub struct Connection {
    prvkey: StaticSecret,
    peers: Arc<Mutex<Peermap>>,
    rendezvous: (SocketAddr, Option<RouterSocket>)
}

/// rendez-vous server fallback (where to meet and automatically route) [TODO]
trait RendezVous { }
/// initial verification and checking of new peers [TODO]
trait Verif { }
/// direct connection, keepalive and reconnect (default mode) [TODO]
trait Stable { }
/// Encryption/Decryption and Serialization/Deserialization [TODO]
trait Communication { }

impl Peer {
    /// new created peer
    pub fn new_out(id: i32, port: u16) -> Result<(Self, StaticSecret)> {
        // using UDP trick to get appropriate local IP peers can use
        let tmpsock = UdpSocket::bind("0.0.0.0:0").context("UDP trick failed")?;
        tmpsock.connect("8.8.8.8:80").context("UDP trick failed")?;
        let ip = tmpsock.local_addr().context("UDP trick failed")?.ip();
        let addr = SocketAddr::new(ip, port);

        let keypair = Self::keypairgen()?;
        Ok(( Self {
            id,
            user_id: None,
            addr,
            pubkey: keypair.0,
            last_heartbeat: None
        }, keypair.1 ))
    }

    /// new imported peer
    pub fn new_in(id:i32, peer_name: String, peer_uid: Uid, peer_user_id: u64, addr: SocketAddr, pubkey: PublicKey, last_heartbeat: Option<i64>) -> Result<Self> {
        let key: String = pubkey.encode_hex();
        let user = User::new(key.clone(), peer_name.clone(), peer_uid);
        if user.ver_id(key, peer_user_id) {
            Ok(Self {id, user_id: None, addr, pubkey, last_heartbeat})
        } else {
            Err(Error::msg("Invalid key or user"))
        }
    }
    
    pub fn get_id(&self) -> i32 { self.id }
    pub fn get_user_id(&self) -> Option<u64> { self.user_id }
    pub fn get_addr(&self) -> SocketAddr { self.addr }
    pub fn get_pubkey(&self) -> PublicKey { self.pubkey }
    pub fn get_last_heartbeat(&self) -> Option<i64> { self.last_heartbeat }

    pub fn set_id(&mut self, id: i32) { if self.id < 0 { self.id = id } }
    pub fn set_user_id(&mut self, user_name: String, user_id: u64, user_uid: Uid) -> Result<()> {
        if self.user_id.is_some() {
            return Err(Error::msg("User ID already set"))
        }
        let key: String = self.pubkey.encode_hex();
        let user = User::new(key.clone(), user_name, user_uid);
        if !user.ver_id(key, user_id) {
            return Err(Error::msg("Invalid user data"))
        }
        self.user_id = Some(user_id);
        Ok(())
    }
    pub fn set_addr(&mut self, addr: SocketAddr) { self.addr = addr }
    pub fn set_last_heartbeat(&mut self, last_heartbeat: Option<i64>) {
        self.last_heartbeat = last_heartbeat;
    }
}

impl KeyGen for Peer {
    fn keypairgen() -> Result<(PublicKey, StaticSecret)> {
        let mut noise = [0u8; 32];
        getrandom::fill(&mut noise[..]).map_err(Error::new)?;
        let prvkey = StaticSecret::from(noise);
        let pubkey = PublicKey::from(&prvkey);
        Ok((pubkey, prvkey))
    }

    fn shrdkeygen(&self, prvkey: StaticSecret) -> Key {
        let pubkey = self.pubkey;
        let x_shrdkey = prvkey.diffie_hellman(&pubkey);
        let hkdf = Hkdf::<Sha256>::new(None, x_shrdkey.as_bytes());
        let mut shrdkey_b = [0u8; 32];
        hkdf.expand(b"fallegji", &mut shrdkey_b).unwrap();
        *Key::from_slice(&shrdkey_b)
    }
}
