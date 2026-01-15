use std::{collections::HashMap, net::{UdpSocket, SocketAddr}, sync::{Arc, Mutex}};
use anyhow::{Context, Error, Result};
use hex::ToHex;
use nix::unistd::Uid;
use sha2::Sha256;
use tokio_util::sync::CancellationToken;
use zeromq::{DealerSocket, RouterSocket, Socket, SocketRecv};
use x25519_dalek::{PublicKey, StaticSecret};
use hkdf::Hkdf;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce, aead::{Aead, OsRng}};
// use tokio::{task, time::{sleep, Duration, interval}};
// use sha2::{Sha256, Digest};
// use serde::{Serialize, Deserialize};
// use serde_json;
// use time::OffsetDateTime;

use crate::{auth::{Authentication, User}, messaging::Message};

#[derive(Debug, Clone)]
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

/// Encryption/Decryption and Serialization/Deserialization
pub trait Secrecy {
    fn encode(key: &Key, msg: Message) -> Result<Vec<u8>>;
    fn decode(key: &Key, cip: &[u8]) -> Result<Message>;
}
/// rendez-vous address meetup and fallback (peer setup and routing)
#[allow(async_fn_in_trait)]
pub trait RendezVous {
    async fn rcv_requests(&mut self, requests: &mut Vec<(SocketAddr, String)>, token: CancellationToken) -> Result<()>;
    async fn snd_requests(&self, name:String) -> Result<()>;

    async fn request_final_verif(&self) -> Result<()>;
    async fn confirm_final_verif(&self) -> Result<()>;
    async fn init_peer(&self) -> Result<()>;

    async fn fallback_lookup(&self) -> Result<()>;
    async fn fallback_send(&self) -> Result<()>;
}
/// direct communication, keepalive checking and typing (default mode)
#[allow(async_fn_in_trait)]
pub trait Communication {
    async fn send_msg(&self, msg: Message) -> Result<()>;
    async fn read_msg(&self) -> Result<Message>;

    async fn send_heartbeat(&self) -> Result<()>;
    async fn read_heartbeat(&self) -> Result<bool>;

    async fn send_typing(&self, typing: bool) -> Result<()>;
    async fn read_typing(&self) -> Result<bool>;
}

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
            Ok(Self {id, user_id: Some(peer_user_id), addr, pubkey, last_heartbeat})
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

impl Connection {
    pub fn new(prvkey: StaticSecret, rendezvous_addr: SocketAddr) -> Self {
        Self {
            prvkey,
            peers: Arc::new(Mutex::new(HashMap::new())),
            rendezvous: (rendezvous_addr, Some(RouterSocket::new()))
        }
    }

    pub async fn bind_rendezvous(&mut self) -> Result<()> {
        if self.rendezvous.1.is_none() { self.rendezvous.1 = Some(RouterSocket::new()) };
        if let Some(rs) = &mut self.rendezvous.1 {
            rs.bind(&format!("tcp://{}", &self.rendezvous.0)).await?;
        };

        Ok(())
    }

    pub async fn connect_rendezvous(&mut self) -> Result<()> {
        if self.rendezvous.1.is_none() { self.rendezvous.1 = Some(RouterSocket::new()) };
        if let Some(rs) = &mut self.rendezvous.1 {
            rs.connect(&format!("tcp://{}", &self.rendezvous.0)).await?;
        };

        Ok(())
    }

    pub fn end_rendezvous(&mut self) { self.rendezvous.1 = None; }
}

impl Secrecy for Connection {
    fn encode(key: &Key, msg: Message) -> Result<Vec<u8>> {
        let plaintxt: Vec<u8> = serde_json::to_vec(&msg)?;
        let cipher = ChaCha20Poly1305::new(key);
        let mut rng = OsRng;
        let nonce: Nonce = ChaCha20Poly1305::generate_nonce(&mut rng);
        let mut ciphertxt = cipher.encrypt(&nonce, plaintxt.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        let mut res = nonce.as_slice().to_vec();
        res.append(&mut ciphertxt);
        Ok(res)
    }

    fn decode(key: &Key, cip: &[u8]) -> Result<Message> {
        if cip.len() < 12 {
            return Err(anyhow::anyhow!("Data too short for nonce"));
        }
        let nonce = Nonce::from_slice(&cip[..12]);
        let ciphertext = &cip[12..];
        let cipher = ChaCha20Poly1305::new(key);
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
        let msg: Message = serde_json::from_slice(&plaintext)?;
        Ok(msg)
    }
}

impl RendezVous for Connection { //TODO: deal with the rendezvous field
    async fn rcv_requests(&mut self, requests: &mut Vec<(SocketAddr, String)>, token: CancellationToken) -> Result<()> {
        self.bind_rendezvous().await?;
        while let Some(socket) = &mut self.rendezvous.1 { tokio::select! {
            _ = token.cancelled() => { break; }
            res = socket.recv() => {
                match res {
                    Ok(msg) => {
                        let payload: String = msg.try_into()
                            .map_err(|e| anyhow::anyhow!("message parsing error: {}", e))?;

                        let start = payload.find('[').context("Missing '['")?;
                        let end = payload.find(']').context("Missing ']'")?;
                        if start >= end { continue; }
                        let name = &payload[..start];
                        let addr_str = &payload[start+1..end];
                        let fallegji = &payload[end+1..];
                        if fallegji != "fallegji" { continue; }
                        let addr: SocketAddr = addr_str.parse()
                            .context("Invalid address format")?;

                        requests.push((addr, String::from(name)));
                    }
                    Err(zeromq::ZmqError::NoMessage) => {
                        // No message - yield control briefly
                        tokio::task::yield_now().await;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        } }
        Ok(())
    }
    async fn snd_requests(&self, name:String) -> Result<()> {
        let _ = name;
        Ok(())
    }

    async fn request_final_verif(&self) -> Result<()> {
        Ok(())
    }
    async fn confirm_final_verif(&self) -> Result<()> {
        Ok(())
    }
    async fn init_peer(&self) -> Result<()> {
        Ok(())
    }

    async fn fallback_lookup(&self) -> Result<()> {
        //once a user stops receiving heart beats from someone, they will (if not admin, wait a couple ms and then) try to bind to the router socket. If someone is already binded, it will simply connect.
        Ok(())
    }
    async fn fallback_send(&self) -> Result<()> {
        Ok(())
    }
}

impl Communication for Connection { //TODO: send to all, receive from all
    async fn send_msg(&self, msg: Message) -> Result<()> {
        let _ = msg;
        Ok(())
    }
    async fn read_msg(&self) -> Result<Message> {
        Ok(Message::new(0, 0, "".to_string()))
    }

    async fn send_heartbeat(&self) -> Result<()> {
        Ok(())
    }
    async fn read_heartbeat(&self) -> Result<bool> {
        Ok(false)
    }

    async fn send_typing(&self, typing: bool) -> Result<()> {
        let _ = typing;
        Ok(())
    }
    async fn read_typing(&self) -> Result<bool> {
        Ok(false)
    }
}
