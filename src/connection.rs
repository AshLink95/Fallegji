use std::{collections::HashMap, net::{self, SocketAddr}, sync::{Arc, Mutex}};
use anyhow::{Context, Error, Result};
use hex::ToHex;
use nix::unistd::Uid;
use sha2::Sha256;
use tokio_util::sync::CancellationToken;
use x25519_dalek::{PublicKey, StaticSecret};
use hkdf::Hkdf;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce, aead::{Aead, OsRng}};
use tokio::{task, time::{sleep, Duration, interval}, net::UdpSocket};
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
type Peermap = HashMap<u64, (Peer, Key, UdpSocket)>;

pub struct Connection {
    prvkey: StaticSecret,
    socket: (SocketAddr, UdpSocket),
    peers: Arc<Mutex<Peermap>>,
    rendezvous: (SocketAddr, Option<UdpSocket>)
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
    async fn snd_requests(&mut self, name:String) -> Result<bool>;

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
        let tmpsock = net::UdpSocket::bind("0.0.0.0:0").context("UDP trick failed")?;
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
    pub async fn new(prvkey: StaticSecret, rendezvous_addr: SocketAddr) -> Result<Self> {
        let tmpsock = net::UdpSocket::bind("0.0.0.0:0").context("UDP trick failed")?;
        tmpsock.connect("8.8.8.8:80").context("UDP trick failed")?;
        let ip = tmpsock.local_addr().context("UDP trick failed")?.ip();

        let mut port = 1952;
        let max = 74;

        for _ in 0..max {
            let addr = SocketAddr::new(ip, port);
            
            match UdpSocket::bind(addr).await {
                Ok(rs) => {
                    let socket = (addr, rs);
                    return Ok(Self {
                        prvkey,
                        socket,
                        peers: Arc::new(Mutex::new(HashMap::new())),
                        rendezvous: (rendezvous_addr, None)
                    });
                }
                Err(e) if e.to_string().contains("Address already in use") => {
                    port += 1;
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }

        Err(anyhow::anyhow!("Too many ports in use"))

    }

    pub async fn monitor_ip(&mut self) -> Result<()> { // bg task
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;

            let curr_ip = self.socket.0.ip();
            let tmpsock = net::UdpSocket::bind("0.0.0.0:0").context("UDP trick failed")?;
            tmpsock.connect("8.8.8.8:80").context("UDP trick failed")?;
            let ip = tmpsock.local_addr().context("UDP trick failed")?.ip();

            if ip != curr_ip {
                let addr = SocketAddr::new(ip, 1952);
                self.socket.0 = addr;
                self.socket.1 = UdpSocket::bind(&addr).await?;
            }
        }
    }

    pub async fn bind_rendezvous(&mut self) -> Result<()> {
        if self.rendezvous.1.is_none() {
            self.rendezvous.1 = Some(UdpSocket::bind(&self.rendezvous.0).await?)
        };

        Ok(())
    }

    pub async fn connect_rendezvous(&mut self) -> Result<()> {
        if self.rendezvous.1.is_none() {
            let tmpaddr = "127.0.0.0:0".parse::<SocketAddr>()?;
            let sock = UdpSocket::bind(tmpaddr).await?;
            sock.connect(&self.rendezvous.0).await?;
            self.rendezvous.1 = Some(sock);
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

// impl RendezVous for Connection { //TODO: deal with the rendezvous field
//     async fn rcv_requests(&mut self, requests: &mut Vec<(SocketAddr, String)>, token: CancellationToken) -> Result<()> {
//         self.bind_rendezvous().await?;
//         while let Some(RendezVousSocket::Dealer(socket)) = &mut self.rendezvous.1 { tokio::select! {
//             _ = token.cancelled() => { break; }
//             res = socket.recv() => {
//                 match res {
//                     Ok(msg) => {
//                         let payload: String = msg.try_into()
//                             .map_err(|e| anyhow::anyhow!("message parsing error: {}", e))?;
//
//                         let start = payload.find('[').context("Missing '['")?;
//                         let end = payload.find(']').context("Missing ']'")?;
//                         if start >= end { continue; }
//                         let name = &payload[..start];
//                         let addr_str = &payload[start+1..end];
//                         let fallegji = &payload[end+1..];
//                         if fallegji != "fallegji" { continue; }
//                         let addr: SocketAddr = addr_str.parse()
//                             .context("Invalid address format")?;
//
//                         requests.push((addr, String::from(name)));
//                         let send_reply = socket.send(format!("received[({}, {})]fallegji", addr_str, name).into());
//                         drop(send_reply);
//                     }
//                     Err(zeromq::ZmqError::NoMessage) => {
//                         // No message - yield control briefly
//                         tokio::task::yield_now().await;
//                     }
//                     Err(e) => return Err(e.into()),
//                 }
//             }
//         } }
//         Ok(())
//     }
//     async fn snd_requests(&mut self, name:String) -> Result<bool> {
//         if self.rendezvous.1.is_none() { self.rendezvous.1 = Some(RendezVousSocket::Dealer(DealerSocket::new())) };
//
//         if let Some(RendezVousSocket::Dealer(socket)) = &mut self.rendezvous.1 {
//             socket.connect(&format!("tcp://{}", &self.rendezvous.0)).await?;
//             socket.send(format!("{}[{}]fallegji", name, self.socket.0).into()).await?;
//             let timeout = tokio::time::Duration::from_secs(5);
//             let start_time = tokio::time::Instant::now();
//             loop {
//                 if start_time.elapsed() > timeout {
//                     return Ok(false); // Timeout
//                 }
//                 match tokio::time::timeout(
//                     tokio::time::Duration::from_millis(500),
//                     socket.recv()
//                 ).await {
//                     Ok(Ok(resp)) => {
//                         let repl: String = resp.try_into()
//                             .map_err(|e| anyhow::anyhow!("message parsing error: {}", e))?;
//                         let start = repl.find('[').context("Missing '['")?;
//                         let end = repl.find(']').context("Missing ']'")?;
//                         if start >= end { continue; }
//                         let prefix = &repl[..start];
//                         let tuple_content = &repl[start+1..end];
//                         let suffix = &repl[end+1..];
//                         if prefix != "received" || suffix != "fallegji" { continue; }
//                         if !tuple_content.starts_with('(') || !tuple_content.ends_with(')') { continue; }
//                         let inner = &tuple_content[1..tuple_content.len()-1];
//                         let parts: Vec<&str> = inner.splitn(2, ", ").collect();
//                         if parts.len() != 2 { continue; }
//                         let received_addr = parts[0];
//                         let received_name = parts[1];
//                         if received_addr == self.socket.0.to_string() && received_name == name { return Ok(true); }
//                         continue;
//                     }
//                     Ok(Err(zeromq::ZmqError::NoMessage)) => {
//                         tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
//                         continue;
//                     }
//                     Ok(Err(e)) => return Err(e.into()),
//                     Err(_) => {
//                         continue;
//                     }
//                 }
//             }
//         }
//         Ok(false)
//     }
//
//     async fn request_final_verif(&self) -> Result<()> {
//         Ok(())
//     }
//     async fn confirm_final_verif(&self) -> Result<()> {
//         Ok(())
//     }
//     async fn init_peer(&self) -> Result<()> {
//         //when we initialize a peer, we tell him about preexisting peers and update the peermap of all other peers by sending his peer info to everyone in a special packet
//         Ok(())
//     }
//
//     async fn fallback_lookup(&self) -> Result<()> {
//         //once a user stops receiving heart beats from someone, they will (if not admin, wait a couple ms and then) try to bind to the router socket. If someone is already binded, it will simply connect.
//         Ok(())
//     }
//     async fn fallback_send(&self) -> Result<()> {
//         Ok(())
//     }
// }

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
