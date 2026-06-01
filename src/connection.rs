use std::{collections::HashMap, net::{UdpSocket, SocketAddr}, sync::{Arc, Mutex}, time::{SystemTime, UNIX_EPOCH}};
use anyhow::{Context, Error, Result};
use hex::ToHex;
use sha2::Sha256;
use serde::Serialize;
use lz4_flex::{compress_prepend_size, decompress_size_prepended};
use tokio_util::sync::CancellationToken;
use x25519_dalek::{PublicKey, StaticSecret};
use hkdf::Hkdf;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce, aead::{Aead, OsRng}};
use tokio::{net::{TcpStream, TcpListener}, io::{AsyncReadExt, AsyncWriteExt}, sync::Mutex as TokioMutex};
use crate::{auth::{Authentication, User, Uid}, db::Database, messaging::{Message, Chat}};

// Packet header bytes
const MSG_HD: u8 = 0xF1;
const HBT_HD: u8 = 0xE2;
const TYP_HD: u8 = 0xD3;
const DBS_HD: u8 = 0xC4;
const DBR_HD: u8 = 0xB5;
const NWP_HD: u8 = 0xA6;

#[derive(Debug, Clone)]
pub struct Peer {
    id: i32,
    user_id: Option<u64>, // Users get created after peers
    addr: SocketAddr,
    pubkey: PublicKey,
    last_heartbeat: Option<i64>,
    last_seen_typing: Option<i64>
}

/// key generation
pub trait KeyGen {
    fn keypairgen() -> Result<(PublicKey, StaticSecret)>;
    fn shrdkeygen(&self, prvkey: StaticSecret) -> Key;
}

/// user_id -> peer, key, socket
pub type Peermap = HashMap<u64, (Peer, Key, Option<Arc<TokioMutex<TcpStream>>>)>;
enum RendezVousSocket { Listner(TcpListener), Streamer(TcpStream) }

pub struct Connection {
    prvkey: StaticSecret,
    socket: (SocketAddr, TcpListener),
    peers: Arc<Mutex<Peermap>>,
    rendezvous: (SocketAddr, Option<RendezVousSocket>),
    user: Option<(u64, String, Uid)>,
}

/// Encryption/Decryption and Serialization/Deserialization
pub trait Secrecy {
    fn encode<T: Serialize>(key: &Key, header: u8, plain: T) -> Result<Vec<u8>>;
    fn decode(key: &Key, cipher: &[u8]) -> Result<(u8, Vec<u8>)>;
}

/// Rendezvous discovery, peer setup, and fallback reconnection routing.
/// `rcv/snd_requests` handle initial discovery via the rendezvous address.
/// `fallback_lookup/send` re-establish routing when the rendezvous holder drops.
#[allow(async_fn_in_trait)]
pub trait RendezVous {
    /// Admin-side handshake responder. Binds the rendezvous addr and loops accepting
    /// join requests. For each: parse `name`, `addr`, `pubkey` from the request, push it
    /// onto `requests` (the accept/reject queue), and reply with the admin's own pubkey so
    /// the newcomer can immediately derive a shared key and treat the admin as its sole peer
    /// while it waits to be accepted or refused. Cancelable via `token`.
    async fn rcv_requests(&mut self, requests: &mut Vec<(SocketAddr, String, PublicKey)>, token: CancellationToken) -> Result<()>;
    /// Newcomer-side handshake initiator. Connects to the rendezvous addr and sends its
    /// `name` + addr + pubkey. Receives the admin's pubkey in response, derives the shared
    /// key, and registers the admin as its only peer — then waits for the admin's accept/refuse.
    /// Returns true once the admin acknowledges the request.
    async fn snd_requests(&mut self, name: String) -> Result<bool>;

    /// Try to become the new rendezvous holder. If address is taken, connect instead.
    /// Returns true if we bound (became holder), false if we connected.
    async fn fallback_lookup(&mut self) -> Result<bool>;
    /// Re-announce presence to rendezvous holder so they can accept_peer and update our info.
    async fn fallback_send(&mut self, name: String) -> Result<bool>;
}

/// direct communication, keepalive checking and typing (default mode)
#[allow(async_fn_in_trait)]
pub trait Communication {
    /// Accept inbound connections on our bound socket and dispatch decrypted packets.
    async fn listen(self: Arc<Self>, chat: Arc<Chat>) -> Result<()>;

    async fn send_newpeer(&self, addr: SocketAddr, pubkey: PublicKey, db: &Database) -> Result<()>;
    async fn read_newpeer(&self, chat: &Chat, payload: Vec<u8>) -> Result<()>;

    async fn send_msg(&self, msg: Message) -> Result<()>;
    async fn read_msg(&self, chat: &Chat, payload: Vec<u8>) -> Result<()>;

    async fn send_heartbeat(&self) -> Result<()>;
    async fn read_heartbeat(&self, chat: &Chat, peer_id: u64) -> Result<()>;

    async fn send_typing(&self) -> Result<()>;
    async fn read_typing(&self, peer_id: u64) -> Result<()>;

    async fn send_db_sync(&self, db: &Database) -> Result<()>;
    async fn read_db_sync(&self, chat: &Chat, payload: Vec<u8>) -> Result<()>;

    async fn send_db_req(&self, chat: &Chat) -> Result<()>;
    async fn read_db_req(&self, chat: &Chat) -> Result<()>;
}

impl Peer {
    /// new created peer
    pub fn new_out(id: i32, port: u16) -> Result<(Self, StaticSecret)> {
        // using UDP trick to get appropriate network IP peers can use
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
            last_heartbeat: None,
            last_seen_typing: None
        }, keypair.1 ))
    }

    /// new imported peer
    pub fn new_in(id:i32, peer_name: String, peer_uid: Uid, peer_user_id: u64, addr: SocketAddr, pubkey: PublicKey, last_seen_typing: Option<i64>, last_heartbeat: Option<i64>) -> Result<Self> {
        let key: String = pubkey.encode_hex();
        let user = User::new(key.clone(), peer_name.clone(), peer_uid);
        if user.ver_id(key, peer_user_id) {
            Ok(Self {id, user_id: Some(peer_user_id), addr, pubkey, last_heartbeat, last_seen_typing})
        } else {
            Err(Error::msg("Invalid key or user"))
        }
    }

    /// check if a peer is online
    pub fn is_online(&self) -> bool {
        if let Some(time) = self.last_heartbeat {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            time + 3 > now
        } else {
            false
        }
    }

    /// check if a peer is typing
    pub fn is_typing(&self) -> bool {
        if let Some(time) = self.last_seen_typing {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            time + 1 > now
        } else {
            false
        }
    }

    pub fn get_id(&self) -> i32 { self.id }
    pub fn get_user_id(&self) -> Option<u64> { self.user_id }
    pub fn get_addr(&self) -> SocketAddr { self.addr }
    pub fn get_pubkey(&self) -> PublicKey { self.pubkey }
    pub fn get_last_heartbeat(&self) -> Option<i64> { self.last_heartbeat }
    pub fn get_last_seen_typing(&self) -> Option<i64> { self.last_seen_typing }

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
    pub fn set_last_seen_typing(&mut self, last_seen_typing: Option<i64>) {
        self.last_seen_typing = last_seen_typing;
    }
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

pub async fn get_free_port() -> Result<(SocketAddr, TcpListener)> {
    let tmpsock = UdpSocket::bind("0.0.0.0:0").context("UDP trick failed")?;
    tmpsock.connect("8.8.8.8:80").context("UDP trick failed")?;
    let ip = tmpsock.local_addr().context("UDP trick failed")?.ip();

    let mut port = 1952;
    let max = 74;

    for _ in 0..max {
        let addr = SocketAddr::new(ip, port);

        match TcpListener::bind(addr).await {
            Ok(sock) => return Ok((addr, sock)),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                port += 1;
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }

    Err(anyhow::anyhow!("Too many ports in use"))
}

impl Connection {
    pub async fn new(prvkey: StaticSecret, rendezvous_addr: SocketAddr, socket: (SocketAddr, TcpListener), peermap: Peermap) -> Self {
        Self {
            prvkey,
            socket,
            peers: Arc::new(Mutex::new(peermap)),
            rendezvous: (rendezvous_addr, None),
            user: None,
        }
    }

    pub fn set_user(&mut self, user_id: u64, name: String, uid: Uid) {
        self.user = Some((user_id, name, uid));
    }

    pub async fn monitor_ip(&mut self) -> Result<()> { // bg task
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;

            let curr_ip = self.socket.0.ip();
            let tmpsock = UdpSocket::bind("0.0.0.0:0").context("UDP trick failed")?;
            tmpsock.connect("8.8.8.8:80").context("UDP trick failed")?;
            let ip = tmpsock.local_addr().context("UDP trick failed")?.ip();

            if ip != curr_ip {
                let addr = SocketAddr::new(ip, 1952);
                self.socket.0 = addr;
                self.socket.1 = TcpListener::bind(&addr).await?;
            }
        }
    }

    pub async fn bind_rendezvous(&mut self) -> Result<()> {
        if self.rendezvous.1.is_none() {
            self.rendezvous.1 = Some(RendezVousSocket::Listner(TcpListener::bind(&self.rendezvous.0).await?))
        };
        Ok(())
    }

    pub async fn connect_rendezvous(&mut self) -> Result<()> {
        if self.rendezvous.1.is_none() {
            self.rendezvous.1 = Some(RendezVousSocket::Streamer(TcpStream::connect(&self.rendezvous.0).await?))
        };
        Ok(())
    }

    pub fn end_rendezvous(&mut self) { self.rendezvous.1 = None; }

    pub fn get_addr(&self) -> SocketAddr { self.socket.0 }

    pub fn get_peer(&self, user_id: &u64) -> Option<Peer> {
        if let Some(peer_entry) = self.peers.lock().unwrap().get(user_id) {
            return Some(peer_entry.0.clone());
        }
        None
    }
}

impl Secrecy for Connection {
    fn encode<T: Serialize>(key: &Key, header: u8, plain: T) -> Result<Vec<u8>> {
        let mut packet: Vec<u8> = serde_json::to_vec(&plain)?;
        if header == DBS_HD || header == NWP_HD {
            packet = compress_prepend_size(&packet);
        }
        let mut plaintxt: Vec<u8> = Vec::with_capacity(1+packet.len());
        plaintxt.push(header);
        plaintxt.extend_from_slice(&packet);
        let cipher = ChaCha20Poly1305::new(key);
        let mut rng = OsRng;
        let nonce: Nonce = ChaCha20Poly1305::generate_nonce(&mut rng);
        let mut ciphertxt = cipher.encrypt(&nonce, plaintxt.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        let mut res = nonce.as_slice().to_vec();
        res.append(&mut ciphertxt);
        Ok(res)
    }

    fn decode(key: &Key, cipher: &[u8]) -> Result<(u8, Vec<u8>)> {
        if cipher.len() < 12 {
            return Err(anyhow::anyhow!("Data too short for nonce"));
        }
        let nonce = Nonce::from_slice(&cipher[..12]);
        let ciphertext = &cipher[12..];
        let cipher = ChaCha20Poly1305::new(key);
        let mut plaintxt = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
        if plaintxt.is_empty() {
            return Err(anyhow::anyhow!("Decrypted frame missing header"));
        }
        let header = plaintxt.remove(0);
        if header == DBS_HD || header == NWP_HD {
            plaintxt = decompress_size_prepended(&plaintxt)
                .map_err(|e| anyhow::anyhow!("Decompression failed: {}", e))?;
        }
        Ok((header, plaintxt))
    }
}

impl RendezVous for Connection {
    async fn rcv_requests(&mut self, requests: &mut Vec<(SocketAddr, String, PublicKey)>, token: CancellationToken) -> Result<()> {
        self.bind_rendezvous().await?;

        if let Some(RendezVousSocket::Listner(listener)) = &self.rendezvous.1 {
            loop {
                tokio::select! {
                    _ = token.cancelled() => { break; }
                    result = listener.accept() => {
                        match result {
                            Ok((mut stream, _peer_addr)) => {
                                let mut buffer = vec![0u8; 4096];
                                match stream.read(&mut buffer).await {
                                    Ok(n) if n > 0 => {
                                        let payload = String::from_utf8_lossy(&buffer[..n]);
                                        let start = match payload.find('[') {
                                            Some(s) => s,
                                            None => continue,
                                        };
                                        let end = match payload.find(']') {
                                            Some(e) => e,
                                            None => continue,
                                        };
                                        if start >= end { continue; }
                                        let name = &payload[..start];
                                        let addr_str = &payload[start+1..end];
                                        let tail = payload[end+1..].trim();
                                        let pubkey_hex = match tail.strip_suffix("fallegji") {
                                            Some(p) => p,
                                            None => continue,
                                        };
                                        let pubkey = match hex::decode(pubkey_hex)
                                            .ok()
                                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                                            .map(PublicKey::from)
                                        {
                                            Some(pk) => pk,
                                            None => continue,
                                        };
                                        let addr: SocketAddr = match addr_str.parse() {
                                            Ok(a) => a,
                                            Err(_) => continue,
                                        };
                                        requests.push((addr, String::from(name), pubkey));
                                        let admin_pubkey_hex = hex::encode(PublicKey::from(&self.prvkey).as_bytes());
                                        let reply = format!("received[({}, {})]{}fallegji", addr_str, name, admin_pubkey_hex);
                                        let _ = stream.write_all(reply.as_bytes()).await;
                                    }
                                    _ => continue,
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn snd_requests(&mut self, name: String) -> Result<bool> {
        self.connect_rendezvous().await?;

        let prvkey = self.prvkey.clone();
        let peers = Arc::clone(&self.peers);
        let admin_addr = self.rendezvous.0;

        if let Some(RendezVousSocket::Streamer(stream)) = &mut self.rendezvous.1 {
            let my_pubkey_hex = hex::encode(PublicKey::from(&self.prvkey).as_bytes());
            let request = format!("{}[{}]{}fallegji", name, self.socket.0, my_pubkey_hex);
            stream.write_all(request.as_bytes()).await?;
            let timeout = tokio::time::Duration::from_secs(5);
            let start_time = tokio::time::Instant::now();
            let mut buffer = vec![0u8; 4096];
            loop {
                if start_time.elapsed() > timeout { return Ok(false); }
                match tokio::time::timeout(
                    tokio::time::Duration::from_millis(500),
                    stream.read(&mut buffer)
                ).await {
                    Ok(Ok(n)) if n > 0 => {
                        let repl = String::from_utf8_lossy(&buffer[..n]);
                        let start = match repl.find('[') {
                            Some(s) => s,
                            None => continue,
                        };
                        let end = match repl.find(']') {
                            Some(e) => e,
                            None => continue,
                        };
                        if start >= end { continue; }
                        let prefix = &repl[..start];
                        let tuple_content = &repl[start+1..end];
                        // tail = {admin_pubkey_hex}fallegji
                        let admin_pubkey_hex = match repl[end+1..].trim().strip_suffix("fallegji") {
                            Some(p) => p,
                            None => continue,
                        };
                        if prefix != "received" { continue; }
                        if !tuple_content.starts_with('(') || !tuple_content.ends_with(')') {
                            continue;
                        }
                        let inner = &tuple_content[1..tuple_content.len()-1];
                        let parts: Vec<&str> = inner.splitn(2, ", ").collect();
                        if parts.len() != 2 { continue; }
                        let received_addr = parts[0];
                        let received_name = parts[1];
                        if received_addr == self.socket.0.to_string() && received_name == name {
                            let admin_pubkey = match hex::decode(admin_pubkey_hex)
                                .ok()
                                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                                .map(PublicKey::from)
                            {
                                Some(pk) => pk,
                                None => continue,
                            };
                            let admin_peer = Peer {
                                id: -1, user_id: None, addr: admin_addr,  pubkey: admin_pubkey,
                                last_heartbeat: None, last_seen_typing: None
                            };
                            let key = admin_peer.shrdkeygen(prvkey.clone());
                            peers.lock().unwrap().insert(0, (admin_peer, key, None));
                            return Ok(true);
                        }
                        continue;
                    }
                    Ok(Ok(_)) => {
                        return Ok(false);
                    }
                    Ok(Err(e)) => return Err(e.into()),
                    Err(_) => {
                        continue;
                    }
                }
            }
        }

        Ok(false)
    }

    async fn fallback_lookup(&mut self) -> Result<bool> {
        match TcpListener::bind(&self.rendezvous.0).await {
            Ok(listener) => {
                self.rendezvous.1 = Some(RendezVousSocket::Listner(listener));
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                self.connect_rendezvous().await?;
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn fallback_send(&mut self, name: String) -> Result<bool> {
        self.snd_requests(name).await
    }
}

impl Communication for Connection {
    async fn listen(self: Arc<Self>, chat: Arc<Chat>) -> Result<()> {
        loop {
            let (mut stream, _) = self.socket.1.accept().await?;
            let me = Arc::clone(&self);
            let chat = Arc::clone(&chat);
            tokio::spawn(async move {
                let mut peer_key: Option<(u64, Key)> = None;
                loop {
                    let mut len_buf = [0u8; 4];
                    if stream.read_exact(&mut len_buf).await.is_err() { break; }
                    let len = u32::from_be_bytes(len_buf) as usize;
                    let mut frame = vec![0u8; len];
                    if stream.read_exact(&mut frame).await.is_err() { break; }

                    let (peer_id, header, payload) = if let Some((pid, key)) = peer_key {
                        match Connection::decode(&key, &frame) {
                            Ok((h, p)) => (pid, h, p),
                            Err(_) => continue,
                        }
                    } else {
                        let candidates: Vec<(u64, Key)> = {
                            let guard = me.peers.lock().unwrap();
                            guard.iter().map(|(uid, (_, k, _))| (*uid, *k)).collect()
                        };
                        let mut found = None;
                        for (uid, k) in candidates {
                            if let Ok((h, p)) = Connection::decode(&k, &frame) {
                                found = Some((uid, k, h, p));
                                break;
                            }
                        }
                        match found {
                            Some((uid, k, h, p)) => { peer_key = Some((uid, k)); (uid, h, p) }
                            None => continue,
                        }
                    };

                    let _ = match header {
                        MSG_HD => me.read_msg(&chat, payload).await,
                        HBT_HD => me.read_heartbeat(&chat, peer_id).await,
                        TYP_HD => me.read_typing(peer_id).await,
                        DBS_HD => me.read_db_sync(&chat, payload).await,
                        DBR_HD => me.read_db_req(&chat).await,
                        NWP_HD => me.read_newpeer(&chat, payload).await,
                        _ => Ok(()),
                    };
                }
            });
        }
    }

    async fn send_newpeer(&self, addr: SocketAddr, pubkey: PublicKey, db: &Database) -> Result<()> {
        let shared = self.prvkey.diffie_hellman(&pubkey);
        let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut key_bytes = [0u8; 32];
        hkdf.expand(b"fallegji", &mut key_bytes).map_err(|e| anyhow::anyhow!("HKDF: {}", e))?;
        let key = *Key::from_slice(&key_bytes);
        let frame = Connection::encode(&key, NWP_HD, db.dump().await?)?;
        let mut stream = TcpStream::connect(addr).await?;
        stream.write_all(&(frame.len() as u32).to_be_bytes()).await?;
        stream.write_all(&frame).await?;
        Ok(())
    }
    async fn read_newpeer(&self, chat: &Chat, payload: Vec<u8>) -> Result<()> {
        let db_bytes: Vec<u8> = serde_json::from_slice(&payload)?;
        chat.db.load(db_bytes).await?;
        let me = self.user.as_ref().map(|(id, _, _)| *id);
        let peers = chat.db.load_all_peers().await?;
        {
            let mut guard = self.peers.lock().unwrap();
            guard.clear();
            for peer in peers {
                let uid = match peer.get_user_id() { Some(u) => u, None => continue };
                if Some(uid) == me { continue; }
                let key = peer.shrdkeygen(self.prvkey.clone());
                guard.insert(uid, (peer, key, None));
            }
            if let Some(my_id) = me {
                let me_peer = Peer {
                    id: -1, user_id: Some(my_id), addr: self.socket.0,
                    pubkey: PublicKey::from(&self.prvkey), last_heartbeat: None, last_seen_typing: None
                };
                let me_key = me_peer.shrdkeygen(self.prvkey.clone());
                guard.insert(my_id, (me_peer, me_key, None));
            }
        }
        if let Some((_, my_name, my_uid)) = self.user.clone() {
            let my_pub_hex = hex::encode(PublicKey::from(&self.prvkey).as_bytes());
            let _ = chat.db.create_user(my_pub_hex, my_name, my_uid).await;
        }
        self.send_db_sync(&chat.db).await?;
        Ok(())
    }

    async fn send_msg(&self, msg: Message) -> Result<()> {
        let targets: Vec<(Key, Arc<TokioMutex<TcpStream>>)> = {
            let me = self.user.as_ref().map(|(id, _, _)| *id);
            let guard = self.peers.lock().unwrap();
            guard.iter()
                .filter(|(uid, _)| Some(**uid) != me)
                .filter_map(|(_, (_, k, s))| s.as_ref().map(|arc| (*k, Arc::clone(arc))))
                .collect()
        };
        for (key, stream_arc) in targets {
            let frame = Connection::encode(&key, MSG_HD, msg.clone())?;
            tokio::spawn(async move {
                let mut s = stream_arc.lock().await;
                let _ = s.write_all(&(frame.len() as u32).to_be_bytes()).await;
                let _ = s.write_all(&frame).await;
            });
        }
        Ok(())
    }
    async fn read_msg(&self, chat: &Chat, payload: Vec<u8>) -> Result<()> {
        let msg: Message = serde_json::from_slice(&payload)?;
        let db = chat.db.clone();
        let sender_id = msg.get_sender_id();
        let contents = msg.get_contents();
        let sent_at = msg.get_sent_at();
        chat.message_history.write().unwrap().push(msg);
        tokio::spawn(async move {
            // Preserve the sender's timestamp so the message has a stable cross-peer identity.
            let _ = db.create_message(sender_id, contents, Some(sent_at)).await;
        });
        Ok(())
    }

    async fn send_heartbeat(&self) -> Result<()> {
        let targets: Vec<(Key, Arc<TokioMutex<TcpStream>>)> = {
            let me = self.user.as_ref().map(|(id, _, _)| *id);
            let guard = self.peers.lock().unwrap();
            guard.iter()
                .filter(|(uid, _)| Some(**uid) != me)
                .filter_map(|(_, (_, k, s))| s.as_ref().map(|arc| (*k, Arc::clone(arc))))
                .collect()
        };
        for (key, stream_arc) in targets {
            let frame = Connection::encode(&key, HBT_HD, ())?;
            tokio::spawn(async move {
                let mut s = stream_arc.lock().await;
                let _ = s.write_all(&(frame.len() as u32).to_be_bytes()).await;
                let _ = s.write_all(&frame).await;
            });
        }
        Ok(())
    }
    async fn read_heartbeat(&self, chat: &Chat, peer_id: u64) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as i64;
        // Update in-memory presence, capture the db peer id.
        let db_id = {
            let mut guard = self.peers.lock().unwrap();
            guard.get_mut(&peer_id).map(|entry| {
                entry.0.set_last_heartbeat(Some(now));
                entry.0.get_id()
            })
        };
        // Persist off the hot path.
        if let Some(id) = db_id {
            let db = chat.db.clone();
            tokio::spawn(async move {
                let _ = db.update_peer_last_heartbeat(id, Some(now)).await;
            });
        }
        Ok(())
    }

    async fn send_typing(&self) -> Result<()> {
        let targets: Vec<(Key, Arc<TokioMutex<TcpStream>>)> = {
            let me = self.user.as_ref().map(|(id, _, _)| *id);
            let guard = self.peers.lock().unwrap();
            guard.iter()
                .filter(|(uid, _)| Some(**uid) != me)
                .filter_map(|(_, (_, k, s))| s.as_ref().map(|arc| (*k, Arc::clone(arc))))
                .collect()
        };
        for (key, stream_arc) in targets {
            let frame = Connection::encode(&key, TYP_HD, ())?;
            tokio::spawn(async move {
                let mut s = stream_arc.lock().await;
                let _ = s.write_all(&(frame.len() as u32).to_be_bytes()).await;
                let _ = s.write_all(&frame).await;
            });
        }
        Ok(())
    }
    async fn read_typing(&self, peer_id: u64) -> Result<()> {
        if let Some(peermap_entry) = self.peers.lock().unwrap().get_mut(&peer_id) {
            let peer = &mut peermap_entry.0;
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs() as i64;
            peer.set_last_seen_typing(Some(timestamp));
        }
        Ok(())
    }

    async fn send_db_sync(&self, db: &Database) -> Result<()> {
        let bytes = db.dump().await?;
        let targets: Vec<(Key, Arc<TokioMutex<TcpStream>>)> = {
            let me = self.user.as_ref().map(|(id, _, _)| *id);
            let guard = self.peers.lock().unwrap();
            guard.iter()
                .filter(|(uid, _)| Some(**uid) != me)
                .filter_map(|(_, (_, k, s))| s.as_ref().map(|arc| (*k, Arc::clone(arc))))
                .collect()
        };
        for (key, stream_arc) in targets {
            let frame = Connection::encode(&key, DBS_HD, bytes.clone())?;
            tokio::spawn(async move {
                let mut s = stream_arc.lock().await;
                let _ = s.write_all(&(frame.len() as u32).to_be_bytes()).await;
                let _ = s.write_all(&frame).await;
            });
        }
        Ok(())
    }
    async fn read_db_sync(&self, chat: &Chat, payload: Vec<u8>) -> Result<()> {
        let bytes: Vec<u8> = serde_json::from_slice(&payload)?;
        let incoming = Database::new(":memory:")?;
        incoming.load(bytes).await?;
        let in_users = incoming.load_all_users().await?;
        let in_peers = incoming.load_all_peers().await?;
        let in_msgs  = incoming.load_all_messages().await?;
        let my_users = chat.db.load_all_users().await?;
        let my_peers = chat.db.load_all_peers().await?;
        let my_msgs  = chat.db.load_all_messages().await?;
        let mut users: HashMap<u64, User> = HashMap::new();
        for u in my_users.into_iter().chain(in_users) {
            users.entry(u.get_id()).or_insert(u);
        }
        let merged_users: Vec<User> = users.into_values().collect();
        let mut peers: HashMap<u64, Peer> = HashMap::new();
        for p in my_peers.into_iter().chain(in_peers) {
            if let Some(uid) = p.get_user_id() { peers.entry(uid).or_insert(p); }
        }
        let merged_peers: Vec<Peer> = peers.into_values().collect();
        let mut seen = std::collections::HashSet::new();
        let mut merged_msgs = Vec::new();
        for m in my_msgs.into_iter().chain(in_msgs) {
            if seen.insert((m.get_sender_id(), m.get_sent_at(), m.get_contents())) {
                let mut nm = Message::new(-1, m.get_sender_id(), m.get_contents());
                nm.set_date(m.get_sent_at());
                merged_msgs.push(nm);
            }
        }
        chat.db.save_all_users(merged_users).await?;
        chat.db.save_all_peers(merged_peers).await?;
        chat.db.save_all_messages(merged_msgs).await?;
        *chat.message_history.write().unwrap() = chat.db.load_all_messages().await?;
        let users_now = chat.db.load_all_users().await?;
        let mut members = chat.members.write().unwrap();
        members.clear();
        for u in users_now { members.insert(u.get_id(), u); }
        Ok(())
    }

    async fn send_db_req(&self, chat: &Chat) -> Result<()> {
        let admin_id = chat.get_admin();
        let target: Option<(Key, Arc<TokioMutex<TcpStream>>)> = {
            let me = self.user.as_ref().map(|(id, _, _)| *id);
            let guard = self.peers.lock().unwrap();
            let admin = admin_id
                .and_then(|aid| guard.get(&aid))
                .filter(|(p, _, _)| p.is_online())
                .and_then(|(_, k, s)| s.as_ref().map(|arc| (*k, Arc::clone(arc))));
            admin.or_else(|| guard.iter()
                .filter(|(uid, _)| Some(**uid) != me)
                .filter(|(_, (p, _, _))| p.is_online())
                .find_map(|(_, (_, k, s))| s.as_ref().map(|arc| (*k, Arc::clone(arc)))))
        };

        if let Some((key, stream_arc)) = target {
            let frame = Connection::encode(&key, DBR_HD, ())?;
            tokio::spawn(async move {
                let mut s = stream_arc.lock().await;
                let _ = s.write_all(&(frame.len() as u32).to_be_bytes()).await;
                let _ = s.write_all(&frame).await;
            });
        }
        Ok(())
    }
    async fn read_db_req(&self, chat: &Chat) -> Result<()> {
        self.send_db_sync(&chat.db).await
    }
}
