use std::{collections::HashMap, net::{UdpSocket, SocketAddr}, sync::{Arc, Mutex}};
use anyhow::{Context, Error, Result};
use hex::ToHex;
use sha2::Sha256;
use serde::{Serialize, Deserialize};
use tokio_util::sync::CancellationToken;
use x25519_dalek::{PublicKey, StaticSecret};
use hkdf::Hkdf;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce, aead::{Aead, OsRng}};
use tokio::{net::{TcpStream, TcpListener}, io::{AsyncReadExt, AsyncWriteExt}, sync::Mutex as TokioMutex};
use crate::auth::Uid;

use crate::{auth::{Authentication, User}, messaging::Message};

// Packet type bytes (plaintext header inside encrypted frame)
const PKT_DB_SYNC:   u8 = 0x01;
const PKT_PEERMAP:   u8 = 0x02;
const PKT_NEWPEER:   u8 = 0x03;
const PKT_READY:     u8 = 0x04;
const PKT_MSG:       u8 = 0x10;
const PKT_HEARTBEAT: u8 = 0x11;
const PKT_TYPING:    u8 = 0x12;

#[derive(Serialize, Deserialize)]
struct HandshakeInfo {
    name: String,
    uid: u32,
    addr: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PeerEntry {
    pub addr: String,
    pub pubkey_hex: String,
    pub last_heartbeat: Option<i64>,
}

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
    fn encode(key: &Key, msg: Message) -> Result<Vec<u8>>;
    fn decode(key: &Key, cip: &[u8]) -> Result<Message>;
}

/// Rendezvous discovery, peer setup, and fallback reconnection routing.
/// `rcv/snd_requests` handle initial discovery via the rendezvous address.
/// `init_peer` (admin) and `accept_peer` (new/existing peer) establish direct encrypted connections.
/// `fallback_lookup/send` re-establish routing when the rendezvous holder drops.
#[allow(async_fn_in_trait)]
pub trait RendezVous {
    async fn rcv_requests(&mut self, requests: &mut Vec<(SocketAddr, String)>, token: CancellationToken) -> Result<()>;
    async fn snd_requests(&mut self, name: String) -> Result<bool>;
    /// Admin-side: connect to new peer, exchange keys + handshake, send full peermap,
    /// add new peer to our peermap, broadcast PKT_NEWPEER to all existing peers.
    async fn init_peer(&self, requests: &mut Vec<(SocketAddr, String)>, idx: usize) -> Result<()>;
    /// Called by the dispatcher when a new inbound TCP connection arrives on self.socket.1.
    /// Handles both cases:
    ///   - Admin connecting to us (sends PKT_PEERMAP) → we process peermap and connect to each listed peer
    ///   - Existing peer connecting to us (sends PKT_READY) → we just add them to peermap
    async fn accept_peer(&self, stream: TcpStream) -> Result<()>;

    /// Try to become the new rendezvous holder. If address is taken, connect instead.
    /// Returns true if we bound (became holder), false if we connected.
    async fn fallback_lookup(&mut self) -> Result<bool>;
    /// Re-announce presence to rendezvous holder so they can accept_peer and update our info.
    async fn fallback_send(&mut self, name: String) -> Result<bool>;
}

/// direct communication, keepalive checking and typing (default mode)
#[allow(async_fn_in_trait)]
pub trait Communication {
    /// Connect to all peers and listen for incoming messages and packets.
    async fn listen(&self) -> Result<()>;
    /// Send \[4B len]\[12B nonce]\[ciphertext of \[1B type]\[payload]]
    async fn send_frame(stream: &mut TcpStream, key: &Key, type_byte: u8, payload: &[u8]) -> Result<()>;
    /// Receive and decrypt \[4B len]\[12B nonce]\[ciphertext] → (type_byte, payload)
    async fn recv_frame(stream: &mut TcpStream, key: &Key) -> Result<(u8, Vec<u8>)>;

    /// Called by dispatcher when PKT_NEWPEER received from admin.
    /// Connects to new peer, performs handshake, inserts into peermap.
    async fn read_newpeer(&self, payload: Vec<u8>) -> Result<()>;

    async fn send_msg(&self, msg: Message) -> Result<()>;
    async fn read_msg(&self) -> Result<Message>;

    async fn send_heartbeat(&self) -> Result<()>;
    async fn read_heartbeat(&self) -> Result<bool>;

    async fn send_typing(&self, typing: bool) -> Result<()>;
    async fn read_typing(&self) -> Result<bool>;

    /// Broadcast compressed DB bytes to all peers
    async fn send_db_sync(&self, db: Vec<u8>) -> Result<()>;
    async fn read_db_sync(&self) -> Result<()>;
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

    pub async fn accept_one(&self) -> Result<()> {
        let (stream, _) = self.socket.1.accept().await?;
        self.accept_peer(stream).await
    }

    /// Connect outbound to an existing peer (called after receiving PKT_PEERMAP from admin).
    /// Plain pubkey+HS exchange, derive key via shrdkeygen, send PKT_READY, insert into peermap.
    async fn connect_peer_simple(peers: Arc<Mutex<Peermap>>, prvkey: StaticSecret, user: Option<(u64, String, Uid)>, my_addr: SocketAddr, entry: PeerEntry) -> Result<()> {
        let (my_id, my_name, my_uid) = user.as_ref()
            .map(|(id, n, u)| (*id, n.clone(), *u))
            .ok_or_else(|| anyhow::anyhow!("No user info"))?;
        let my_pubkey = PublicKey::from(&prvkey);
        let peer_addr: SocketAddr = entry.addr.parse()?;

        let mut stream = TcpStream::connect(peer_addr).await?;

        // Exchange pubkeys plaintext
        stream.write_all(my_pubkey.as_bytes()).await?;
        let mut their_bytes = [0u8; 32];
        stream.read_exact(&mut their_bytes).await?;
        let their_pubkey = PublicKey::from(their_bytes);
        if hex::encode(their_pubkey.as_bytes()) != entry.pubkey_hex {
            return Err(anyhow::anyhow!("Pubkey mismatch for {}", entry.addr));
        }

        // Exchange HandshakeInfo plaintext
        let my_hs = serde_json::to_vec(&HandshakeInfo { name: my_name, uid: my_uid.as_raw(), addr: my_addr.to_string() })?;
        stream.write_all(&(my_hs.len() as u32).to_be_bytes()).await?;
        stream.write_all(&my_hs).await?;
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let mut their_hs_bytes = vec![0u8; u32::from_be_bytes(len_buf) as usize];
        stream.read_exact(&mut their_hs_bytes).await?;
        let their_hs: HandshakeInfo = serde_json::from_slice(&their_hs_bytes)?;

        // Create peer, derive shared key via KeyGen
        let their_pubkey_hex = hex::encode(their_pubkey.as_bytes());
        let their_user_id = User::new(their_pubkey_hex, their_hs.name.clone(), Uid::from(their_hs.uid)).get_id();
        let their_addr: SocketAddr = their_hs.addr.parse()?;
        let peer = Peer::new_in(-1, their_hs.name, Uid::from(their_hs.uid), their_user_id, their_addr, their_pubkey, entry.last_heartbeat)?;
        let key = peer.shrdkeygen(prvkey);

        Connection::send_frame(&mut stream, &key, PKT_READY, &[]).await?;
        let stream_arc = Arc::new(TokioMutex::new(stream));
        peers.lock().unwrap().insert(their_user_id, (peer, key, Some(stream_arc)));

        Ok(())
    }
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

impl RendezVous for Connection {
    async fn rcv_requests(&mut self, requests: &mut Vec<(SocketAddr, String)>, token: CancellationToken) -> Result<()> {
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
                                        let fallegji = &payload[end+1..];
                                        if fallegji.trim() != "fallegji" { continue; }
                                        let addr: SocketAddr = match addr_str.parse() {
                                            Ok(a) => a,
                                            Err(_) => continue,
                                        };
                                        requests.push((addr, String::from(name)));
                                        let reply = format!("received[({}, {})]fallegji", addr_str, name);
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

        if let Some(RendezVousSocket::Streamer(stream)) = &mut self.rendezvous.1 {
            let request = format!("{}[{}]fallegji", name, self.socket.0);
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
                        let suffix = &repl[end+1..];
                        if prefix != "received" || suffix.trim() != "fallegji" {
                            continue;
                        }
                        if !tuple_content.starts_with('(') || !tuple_content.ends_with(')') {
                            continue;
                        }
                        let inner = &tuple_content[1..tuple_content.len()-1];
                        let parts: Vec<&str> = inner.splitn(2, ", ").collect();
                        if parts.len() != 2 { continue; }
                        let received_addr = parts[0];
                        let received_name = parts[1];
                        if received_addr == self.socket.0.to_string() && received_name == name {
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

    async fn init_peer(&self, requests: &mut Vec<(SocketAddr, String)>, idx: usize) -> Result<()> {
        let (peer_addr, _) = requests[idx].clone();
        let (_, my_name, my_uid) = self.user.as_ref()
            .map(|(id, n, u)| (*id, n.clone(), *u))
            .ok_or_else(|| anyhow::anyhow!("No user info on Connection"))?;
        let my_pubkey = PublicKey::from(&self.prvkey);

        let mut stream = TcpStream::connect(peer_addr).await?;

        // Exchange pubkeys plaintext
        stream.write_all(my_pubkey.as_bytes()).await?;
        let mut their_bytes = [0u8; 32];
        stream.read_exact(&mut their_bytes).await?;
        let their_pubkey = PublicKey::from(their_bytes);

        // Exchange HandshakeInfo plaintext
        let my_hs = serde_json::to_vec(&HandshakeInfo { name: my_name, uid: my_uid.as_raw(), addr: self.socket.0.to_string() })?;
        stream.write_all(&(my_hs.len() as u32).to_be_bytes()).await?;
        stream.write_all(&my_hs).await?;
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let mut their_hs_bytes = vec![0u8; u32::from_be_bytes(len_buf) as usize];
        stream.read_exact(&mut their_hs_bytes).await?;
        let their_hs: HandshakeInfo = serde_json::from_slice(&their_hs_bytes)?;

        // Create peer, derive shared key via KeyGen (user_id derived locally, never transmitted)
        let their_pubkey_hex = hex::encode(their_pubkey.as_bytes());
        let their_user_id = User::new(their_pubkey_hex, their_hs.name.clone(), Uid::from(their_hs.uid)).get_id();
        let their_addr: SocketAddr = their_hs.addr.parse()?;
        let new_peer = Peer::new_in(-1, their_hs.name.clone(), Uid::from(their_hs.uid), their_user_id, their_addr, their_pubkey, None)?;
        let key = new_peer.shrdkeygen(self.prvkey.clone());

        // Snapshot existing peers before adding new one
        let (peermap_entries, existing_streams): (Vec<PeerEntry>, Vec<(Key, Arc<TokioMutex<TcpStream>>)>) = {
            let guard = self.peers.lock().unwrap();
            let entries = guard.values().map(|(p, _, _)| PeerEntry {
                addr: p.get_addr().to_string(),
                pubkey_hex: hex::encode(p.get_pubkey().as_bytes()),
                last_heartbeat: p.get_last_heartbeat(),
            }).collect();
            let streams = guard.values()
                .filter_map(|(_, k, s)| s.as_ref().map(|arc| (*k, Arc::clone(arc))))
                .collect();
            (entries, streams)
        };

        Connection::send_frame(&mut stream, &key, PKT_PEERMAP, &serde_json::to_vec(&peermap_entries)?).await?;

        let stream_arc = Arc::new(TokioMutex::new(stream));
        {
            let mut guard = self.peers.lock().unwrap();
            guard.insert(their_user_id, (new_peer, key, Some(Arc::clone(&stream_arc))));
        }

        // Broadcast PKT_NEWPEER to all existing peers
        let newpeer_bytes = serde_json::to_vec(&PeerEntry {
            addr: their_hs.addr,
            pubkey_hex: hex::encode(their_pubkey.as_bytes()),
            last_heartbeat: None,
        })?;
        for (peer_key, peer_stream_arc) in existing_streams {
            let bytes = newpeer_bytes.clone();
            tokio::spawn(async move {
                let mut s = peer_stream_arc.lock().await;
                let _ = Connection::send_frame(&mut *s, &peer_key, PKT_NEWPEER, &bytes).await;
            });
        }

        requests.remove(idx);
        Ok(())
    }

    async fn accept_peer(&self, mut stream: TcpStream) -> Result<()> {
        let my_pubkey = PublicKey::from(&self.prvkey);
        let (_, my_name, my_uid) = self.user.as_ref()
            .map(|(id, n, u)| (*id, n.clone(), *u))
            .ok_or_else(|| anyhow::anyhow!("No user info on Connection"))?;

        // Exchange pubkeys plaintext (acceptor receives first)
        let mut their_bytes = [0u8; 32];
        stream.read_exact(&mut their_bytes).await?;
        stream.write_all(my_pubkey.as_bytes()).await?;
        let their_pubkey = PublicKey::from(their_bytes);

        // Exchange HandshakeInfo plaintext (acceptor receives first)
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let mut their_hs_bytes = vec![0u8; u32::from_be_bytes(len_buf) as usize];
        stream.read_exact(&mut their_hs_bytes).await?;
        let their_hs: HandshakeInfo = serde_json::from_slice(&their_hs_bytes)?;
        let my_hs = serde_json::to_vec(&HandshakeInfo { name: my_name, uid: my_uid.as_raw(), addr: self.socket.0.to_string() })?;
        stream.write_all(&(my_hs.len() as u32).to_be_bytes()).await?;
        stream.write_all(&my_hs).await?;

        // Create peer, derive shared key via KeyGen (user_id derived locally, never transmitted)
        let their_pubkey_hex = hex::encode(their_pubkey.as_bytes());
        let their_user_id = User::new(their_pubkey_hex, their_hs.name.clone(), Uid::from(their_hs.uid)).get_id();
        let their_addr: SocketAddr = their_hs.addr.parse()?;
        let new_peer = Peer::new_in(-1, their_hs.name, Uid::from(their_hs.uid), their_user_id, their_addr, their_pubkey, None)?;
        let key = new_peer.shrdkeygen(self.prvkey.clone());

        // Receive PKT_PEERMAP or PKT_READY (encrypted)
        let (pkt, payload) = Connection::recv_frame(&mut stream, &key).await?;
        let stream_arc = Arc::new(TokioMutex::new(stream));
        {
            let mut guard = self.peers.lock().unwrap();
            guard.insert(their_user_id, (new_peer, key, Some(Arc::clone(&stream_arc))));
        }

        if pkt == PKT_PEERMAP {
            let entries: Vec<PeerEntry> = serde_json::from_slice(&payload)?;
            for entry in entries {
                let peers_arc = Arc::clone(&self.peers);
                let prvkey = self.prvkey.clone();
                let user = self.user.clone();
                let socket_addr = self.socket.0;
                tokio::spawn(async move {
                    let _ = Connection::connect_peer_simple(peers_arc, prvkey, user, socket_addr, entry).await;
                });
            }
        }

        Ok(())
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
    async fn listen(&self) -> Result<()> {
        Ok(())
    }
    async fn send_frame(stream: &mut TcpStream, key: &Key, type_byte: u8, payload: &[u8]) -> Result<()> {
        let mut plaintext = vec![type_byte];
        plaintext.extend_from_slice(payload);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = ChaCha20Poly1305::new(key)
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| anyhow::anyhow!("Encrypt: {}", e))?;
        let mut frame = nonce.as_slice().to_vec();
        frame.extend_from_slice(&ciphertext);
        stream.write_all(&(frame.len() as u32).to_be_bytes()).await?;
        stream.write_all(&frame).await?;
        Ok(())
    }
    async fn recv_frame(stream: &mut TcpStream, key: &Key) -> Result<(u8, Vec<u8>)> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut frame = vec![0u8; len];
        stream.read_exact(&mut frame).await?;
        if frame.len() < 12 { return Err(anyhow::anyhow!("Frame too short")); }
        let nonce = Nonce::from_slice(&frame[..12]);
        let plaintext = ChaCha20Poly1305::new(key)
            .decrypt(nonce, &frame[12..])
            .map_err(|e| anyhow::anyhow!("Decrypt: {}", e))?;
        if plaintext.is_empty() { return Err(anyhow::anyhow!("Empty frame")); }
        Ok((plaintext[0], plaintext[1..].to_vec()))
    }

    async fn read_newpeer(&self, payload: Vec<u8>) -> Result<()> {
        let entry: PeerEntry = serde_json::from_slice(&payload)?;
        Connection::connect_peer_simple(
            Arc::clone(&self.peers),
            self.prvkey.clone(),
            self.user.clone(),
            self.socket.0,
            entry,
        ).await
    }

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

    async fn send_db_sync(&self, db: Vec<u8>) -> Result<()> {
        let _ = db;
        Ok(())
    }
    async fn read_db_sync(&self) -> Result<()>{
        Ok(())
    }
}
