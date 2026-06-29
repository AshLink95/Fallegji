use std::{collections::{HashMap, LinkedList}, net::{IpAddr, Ipv4Addr, SocketAddr}, sync::{Arc, Mutex}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use anyhow::{Context, Error, Result};
use hex::ToHex;
use sha2::Sha256;
use serde::Serialize;
use lz4_flex::{compress_prepend_size, decompress_size_prepended};
use tokio_util::sync::CancellationToken;
use x25519_dalek::{PublicKey, StaticSecret};
use hkdf::Hkdf;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce, aead::{Aead, OsRng}};
use tokio::{net::{TcpStream, TcpListener, UdpSocket}, io::{AsyncReadExt, AsyncWriteExt}, sync::Mutex as TokioMutex};
use crate::{auth::{Authentication, User, Uid, Role}, db::Database, messaging::{Message, Chat}};

const MSG_HD: u8 = 0xF1;
const HBT_HD: u8 = 0xE2;
const TYP_HD: u8 = 0xD3;
const DBS_HD: u8 = 0xC4;
const DBR_HD: u8 = 0xB5;
const NWP_HD: u8 = 0xA6;
const KCK_HD: u8 = 0x97;
const AVP_HD: u8 = 0x88;
const EVI_HD: u8 = 0x79;
const OWN_HD: u8 = 0x6A;
const REJ_HD: u8 = 0x5B;

const SYNC_COOLDOWN: Duration = Duration::from_millis(1200);
const MAX_FRAME: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Peer {
    id: i32,
    user_id: Option<u64>, // Users get created after peers
    addrs: [SocketAddr; 2], // [localhost, LAN]
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
type OPeermap = HashMap<[u8; 32], ([SocketAddr; 2], Option<Arc<TokioMutex<TcpStream>>>, Option<i64>, Option<i64>)>;

/// Pending join requests awaiting admin accept/reject: (addrs, name, pubkey, uid).
pub type Requests = Arc<Mutex<Vec<([SocketAddr; 2], String, PublicKey, u32)>>>;

/// A joiner's chat is born only once the admin accepts (the NWP carries the DB).
/// Until then the joiner has just its `Connection` up; `listen` fills this slot.
pub struct Accepted { pub chat: Arc<Chat>, pub name: String }
pub type ChatSlot = Arc<Mutex<Option<Accepted>>>;

struct DbSyncBuf {
    msgs: LinkedList<Vec<u8>>,
    usrs: LinkedList<Vec<u8>>,
    pirs: LinkedList<Vec<u8>>,
    admin_rank: Option<u8>,
    rcv_count: u8,
    first_at: Option<Instant>,
}

pub struct Connection {
    prvkey: StaticSecret,
    socket: Mutex<(SocketAddr, Arc<TcpListener>)>,
    peers: Arc<Mutex<Peermap>>,
    rendezvous: (SocketAddr, Mutex<Option<Arc<UdpSocket>>>),
    db_sync_buf: Mutex<DbSyncBuf>,
    user: Option<(u64, String, Uid)>,
    rcv_rate: Mutex<HashMap<(u64, u8), (Instant, u32)>>, // per-(peer, packet-type) receive rate (anti-flood)
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
    /// Rendezvous **holder** loop (UDP). Serves new-member join requests (plaintext handshake)
    /// AND recovery packets from known peers: an `OWN_HD` (a peer's fresh 2 IPs) → update that
    /// peer's entry; an `EVI_HD` from the admin → unbind and yield the rendezvous.
    async fn rcv_requests(&self, requests: Requests, token: CancellationToken, is_admin: bool) -> Result<()>;
    /// Newcomer-side join handshake initiator (plaintext name/addrs/pubkey → admin key).
    async fn snd_requests(&self, name: String) -> Result<bool>;

    /// Try to become the rendezvous holder by binding the UDP address. true = we hold it
    /// (and wait for peers' info), false = it's taken (someone else holds it).
    async fn fallback_lookup(&self) -> Result<bool>;
    /// Send our own info to the current holder: an encrypted `OWN_HD` (our 2 IPs) so the holder
    /// updates + relays our entry. (If we're the admin facing a peer-held rendezvous, evict first.)
    async fn fallback_send(&self, name: String) -> Result<bool>;
}

/// direct communication, keepalive checking and typing (default mode)
#[allow(async_fn_in_trait)]
pub trait Communication {
    /// Accept inbound connections on our bound socket and dispatch decrypted packets.
    /// Stops the accept loop and every per-connection reader when `token` is cancelled.
    // `reject` is set when an admin sends us a REJ frame, so the app loop can bounce us Home with the reason.
    async fn listen(self: Arc<Self>, slot: ChatSlot, reject: Arc<Mutex<Option<String>>>, token: CancellationToken) -> Result<()>;

    async fn send_newpeer(&self, addrs: [SocketAddr; 2], pubkey: PublicKey, name: &str, uid: u32, chat_name: &str, chat: &Chat) -> Result<()>;

    async fn send_msg(&self, msg: Message) -> Result<()>;
    async fn read_msg(&self, chat: &Chat, payload: Vec<u8>) -> Result<()>;

    async fn send_heartbeat(&self) -> Result<()>;
    /// Records the heartbeat and returns whether the peer just came online (offline → online
    /// transition). The caller pushes a db sync on a transition (a (re)join) — done off the reader
    /// loop so the heavy sync doesn't stall frame reading.
    async fn read_heartbeat(&self, chat: &Chat, peer_id: u64) -> Result<bool>;

    async fn send_typing(&self) -> Result<()>;
    async fn read_typing(&self, peer_id: u64) -> Result<()>;

    /// Send three separately-zipped components — messages, users, peers, in that order —
    /// length-framed as [u32 len][zip]×3. Each is serialized from canonical (sorted) rows
    /// stripped of volatile/local fields (autoincrement id, heartbeat) so identical logical
    /// state produces identical bytes — the buffer/decider votes on these.
    async fn send_db_sync(&self, db: &Database) -> Result<()>;
    /// Classifier: split the length-framed [u32 len][zip]×3 (messages, users, peers) and stash
    /// each zip into `db_sync_buf`, tagging the admin's entry via `admin_rank`. The bg decider
    /// collapses the buffer later (admin-authoritative roster, union messages).
    async fn read_db_sync(&self, chat: &Chat, peer_id: u64, payload: Vec<u8>) -> Result<()>;
    /// Collapse the buffered syncs into the db. Roster (users+peers): the admin's copy if we
    /// got one, else the most common version (our own included). Messages: always the union of
    /// everyone's (new ones never dropped), deduped by identity. Persisted via save_all_*.
    async fn decide_sync(&self, chat: &Chat) -> Result<()>;

    async fn send_db_req(&self, chat: &Chat) -> Result<()>;
    async fn read_db_req(&self, chat: &Chat, peer_id: u64, payload: Vec<u8>) -> Result<()>;
    /// Broadcast a kick (the kicked user_id) so every peer drops that user/peer in real time.
    async fn send_kick(&self, user_id: u64) -> Result<()>;
    async fn read_kick(&self, chat: &Chat, user_id: u64) -> Result<()>;
}

impl Peer {
    /// new created peer (loopback + LAN; public defaults to LAN until STUN refines it)
    pub fn new_out(id: i32, port: u16) -> Result<(Self, StaticSecret)> {
        let addrs = local_addrs(port)?;
        let keypair = Self::keypairgen()?;
        Ok(( Self {
            id,
            user_id: None,
            addrs,
            pubkey: keypair.0,
            last_heartbeat: None,
            last_seen_typing: None
        }, keypair.1 ))
    }

    /// new imported peer
    #[allow(clippy::too_many_arguments)]
    pub fn new_in(id:i32, peer_name: String, peer_uid: Uid, peer_user_id: u64, addrs: [SocketAddr; 2], pubkey: PublicKey, last_seen_typing: Option<i64>, last_heartbeat: Option<i64>) -> Result<Self> {
        let key: String = pubkey.encode_hex();
        let user = User::new(key.clone(), peer_name.clone(), peer_uid);
        if user.ver_id(key, peer_user_id) {
            Ok(Self {id, user_id: Some(peer_user_id), addrs, pubkey, last_heartbeat, last_seen_typing})
        } else {
            Err(Error::msg("Invalid key or user"))
        }
    }

    /// Serialize the 2 addresses ([localhost, LAN]) for the db (`addr` column) and the wire.
    pub fn addrs_string(&self) -> String {
        self.addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(",")
    }
    /// Parse 2 comma-joined addresses; falls back to repeating a single one.
    pub fn parse_addrs(s: &str) -> Option<[SocketAddr; 2]> {
        let v: Vec<SocketAddr> = s.split(',').filter_map(|x| x.trim().parse().ok()).collect();
        match v.len() {
            2 => Some([v[0], v[1]]),
            1 => Some([v[0], v[0]]),
            _ => None,
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
        if self.is_online() && let Some(time) = self.last_seen_typing {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
            time + 1000 > now
        } else {
            false
        }
    }

    pub fn get_id(&self) -> i32 { self.id }
    pub fn get_user_id(&self) -> Option<u64> { self.user_id }
    pub fn get_addrs(&self) -> [SocketAddr; 2] { self.addrs }
    pub fn get_pubkey(&self) -> PublicKey { self.pubkey }
    pub fn get_last_heartbeat(&self) -> Option<i64> { self.last_heartbeat }
    #[allow(unused)]
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
    pub fn set_addrs(&mut self, addrs: [SocketAddr; 2]) { self.addrs = addrs }
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

impl Connection {
    pub async fn new(prvkey: StaticSecret, rendezvous_addr: SocketAddr, socket: (SocketAddr, TcpListener), peermap: Peermap) -> Self {
        Self {
            prvkey,
            socket: Mutex::new((socket.0, Arc::new(socket.1))),
            peers: Arc::new(Mutex::new(peermap)),
            rendezvous: (rendezvous_addr, Mutex::new(None)),
            db_sync_buf: Mutex::new(DbSyncBuf {
                msgs: LinkedList::new(), usrs: LinkedList::new(), pirs: LinkedList::new(), admin_rank: None, rcv_count: 0, first_at: None,
            }),
            user: None,
            rcv_rate: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_user(&mut self, user_id: u64, name: String, uid: Uid) {
        self.user = Some((user_id, name, uid));
    }

    /// Anti-flood: per-peer, per-packet-type cap (drop the excess). Caps: messages 100/min, db
    /// syncs 50/min, heartbeat & typing 1/sec (we only send those once a second anyway). Unlisted
    /// headers are unlimited. Keyed by the authenticated peer_id, so spoofing sender_id can't dodge.
    fn recv_ok(&self, peer_id: u64, header: u8) -> bool {
        let (window, cap) = match header {
            MSG_HD => (60, crate::messaging::RATE_PER_MIN),
            DBS_HD | DBR_HD => (60, 50),          // db_req follows db_sync (it replies with our whole db)
            AVP_HD | OWN_HD | KCK_HD => (60, 20),  // address relays + kick: rare control packets
            HBT_HD | TYP_HD => (1, 1),
            _ => return true,
        };
        let mut guard = self.rcv_rate.lock().unwrap();
        let entry = guard.entry((peer_id, header)).or_insert((Instant::now(), 0));
        if entry.0.elapsed() >= Duration::from_secs(window) { *entry = (Instant::now(), 0); }
        if entry.1 >= cap { return false; }
        entry.1 += 1;
        true
    }


    pub async fn monitor_ip(&self, db: Database) -> Result<()> {
        loop {
            let _ = self.refresh_addrs(&db).await;
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    }

    /// One refresh pass: recompute our 3 addresses (LAN via UDP trick, public via icanhazip),
    /// rebind if the IP moved (picking a free port in 1952–2025, like the initial bind, since the
    /// old port may be taken on the new interface), update our peer in the peermap + db, and
    /// re-announce on change.
    pub async fn refresh_addrs(&self, db: &Database) -> Result<()> {
        let (curr_ip, mut port) = { let g = self.socket.lock().unwrap(); (g.0.ip(), g.0.port()) };
        let name = if_addrs::get_if_addrs().ok()
            .and_then(|a| a.into_iter().find(|i| i.ip() == curr_ip).map(|i| i.name));
        let lan_ip = bind_ip(name.as_deref()).unwrap_or(curr_ip);

        if lan_ip != curr_ip {
            for p in std::iter::once(port).chain(1952..=2025) {
                if let Ok(listener) = bind_listener(SocketAddr::new(lan_ip, p)) {
                    *self.socket.lock().unwrap() = (SocketAddr::new(lan_ip, p), Arc::new(listener));
                    port = p;
                    break;
                }
            }
        }

        let lan = SocketAddr::new(lan_ip, port);
        let addrs = [SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port), lan];
        if let Some(my_id) = self.user.as_ref().map(|u| u.0) {
            let db_id = {
                let mut guard = self.peers.lock().unwrap();
                guard.get_mut(&my_id).map(|e| { e.0.set_addrs(addrs); e.0.get_id() })
            };
            if let Some(id) = db_id {
                let _ = db.update_peer_addrs(id, addrs).await;
            }
        }

        if lan_ip != curr_ip {
            let name = self.user.as_ref().map(|u| u.1.clone()).unwrap_or_default();
            let _ = self.fallback_send(name).await;
        }
        Ok(())
    }

    /// bg task: broadcast a keep-alive to peers once a second, and heal the mesh.
    pub async fn heartbeat_loop(self: Arc<Self>) -> Result<()> {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = self.send_heartbeat().await;
            let me = Arc::clone(&self);
            tokio::spawn(async move { me.connect_peers().await; });
        }
    }

    pub fn rendezvous_addr(&self) -> SocketAddr { self.rendezvous.0 }

    pub async fn bind_rendezvous(&self) -> Result<()> {
        let bound = self.rendezvous.1.lock().unwrap().is_some();
        if !bound {
            let sock = Arc::new(UdpSocket::bind(self.rendezvous.0).await?);
            *self.rendezvous.1.lock().unwrap() = Some(sock);
        }
        Ok(())
    }

    /// bg task: if *any* peer is offline, try to become the rendezvous holder; if the address
    /// is already taken, re-announce ourselves to whoever holds it. (The offline peer reaches
    /// the holder — the admin, if present — who updates its entry.)
    pub async fn fallback(&self, token: CancellationToken) -> Result<()> {
        let name = self.user.as_ref().map(|u| u.1.clone()).unwrap_or_default();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let me = self.user.as_ref().map(|(id, _, _)| *id);
            let any_offline = self.peers.lock().unwrap().iter()
                .filter(|(uid, _)| Some(**uid) != me)
                .any(|(_, (p, _, _))| !p.is_online());
            if !any_offline { continue; }
            match self.fallback_lookup().await {
                Ok(true) => { let _ = self.rcv_requests(Arc::new(Mutex::new(Vec::new())), token.clone(), false).await; }
                Ok(false) => { let _ = self.fallback_send(name.clone()).await; }
                Err(_) => {}
            }
        }
    }

    /// Our 2 addresses: [loopback, LAN] (the bound socket). No public — post-NAT isn't reachable.
    pub fn current_addrs(&self) -> [SocketAddr; 2] {
        let bound = self.socket.lock().unwrap().0;
        [SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bound.port()), bound]
    }

    /// Snapshot of the peermap as (user_id, peer). The caller reads whatever it needs
    /// (addrs, presence, …) and filters out itself when appropriate.
    pub fn peer_list(&self) -> Vec<(u64, Peer)> {
        self.peers.lock().unwrap().iter().map(|(uid, (p, _, _))| (*uid, p.clone())).collect()
    }

    /// "Met up + synced": every ONLINE peer is also REACHED (we hold a send stream to it), there's
    /// at least one such peer, and no db-sync round is mid-flight. Truthful: an online peer we can't
    /// actually send to (no stream) → None. Offline peers don't block it (they're gone / at the
    /// rendezvous). Returns the online peer count, else None — drives the "connected to peers" line.
    pub fn reached_and_synced(&self) -> Option<usize> {
        if self.db_sync_buf.lock().unwrap().first_at.is_some() { return None; }
        let me = self.user.as_ref().map(|(id, _, _)| *id);
        let online: Vec<bool> = self.peers.lock().unwrap().iter()
            .filter(|(uid, _)| Some(**uid) != me)
            .filter(|(_, (p, _, _))| p.is_online())
            .map(|(_, (_, _, s))| s.is_some()) // reached = we have a send stream
            .collect();
        (!online.is_empty() && online.iter().all(|&reached| reached)).then_some(online.len())
    }

    /// First NWP for a chat-less joiner: build the chat from the admin's DB, fill the slot (the app loop enters the chat), wire up peers, and announce ourselves.
    pub async fn accept_chat(&self, slot: &ChatSlot, payload: Vec<u8>) -> Result<()> {
        let (chat_name, db_bytes): (String, Vec<u8>) = serde_json::from_slice(&payload)?;
        let (_user_id, user_name, uid) = self.user.clone()
            .ok_or_else(|| anyhow::anyhow!("accept_chat: no local user"))?;
        let port = self.socket.lock().unwrap().0.port();
        let chat = Arc::new(Chat::join(&chat_name, &user_name, &self.prvkey, uid, port, db_bytes).await?);
        *slot.lock().unwrap() = Some(Accepted { chat: chat.clone(), name: chat_name });
        self.rebuild_peermap(&chat.db).await?;
        self.connect_peers().await;
        chat.send_join(self).await;
        self.send_db_req(&chat).await?;
        self.send_db_sync(&chat.db).await?;
        Ok(())
    }

    /// Auto-reject a would-be joiner whose username is taken: one REJ frame so their `listen` surfaces it.
    pub async fn send_reject(&self, addrs: [SocketAddr; 2], pubkey: PublicKey, name: &str) -> Result<()> {
        let peer = Peer { id: -1, user_id: None, addrs, pubkey, last_heartbeat: None, last_seen_typing: None };
        let key = peer.shrdkeygen(self.prvkey.clone());
        let rej = Connection::encode(&key, REJ_HD, format!("username '{name}' already exists in this chat"))?;
        if let Some(mut stream) = connect_any(&addrs).await {
            stream.write_all(&(rej.len() as u32).to_be_bytes()).await?;
            stream.write_all(&rej).await?;
        }
        Ok(())
    }

    /// Rebuild the peermap from the db (deriving each peer's shared key), keeping any
    /// already-open streams, and re-adding ourselves.
    pub async fn rebuild_peermap(&self, db: &Database) -> Result<()> {
        let me = self.user.as_ref().map(|(id, _, _)| *id);
        let peers = db.load_all_peers().await?;
        let mut guard = self.peers.lock().unwrap();
        let old: OPeermap = guard.values().map(|(p, _, s)| (p.get_pubkey().to_bytes(), (p.get_addrs(), s.clone(), p.get_last_heartbeat(), p.get_last_seen_typing()))).collect();
        guard.clear();
        for mut peer in peers {
            let uid = match peer.get_user_id() { Some(u) => u, None => continue };
            if Some(uid) == me { continue; }
            let key = peer.shrdkeygen(self.prvkey.clone());
            let prev = old.get(&peer.get_pubkey().to_bytes());
            let stream = match prev {
                Some((old_addrs, s, _, _)) if *old_addrs == peer.get_addrs() => s.clone(),
                _ => None,
            };
            if let Some((_, _, hb, typ)) = prev { peer.set_last_heartbeat(*hb); peer.set_last_seen_typing(*typ); }
            guard.insert(uid, (peer, key, stream));
        }
        if let Some(my_id) = me {
            let me_pub = PublicKey::from(&self.prvkey);
            let my_addrs = old.get(&me_pub.to_bytes()).map(|(a, _, _, _)| *a).unwrap_or_else(|| {
                let a = self.socket.lock().unwrap().0;
                [SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), a.port()), a]
            });
            let me_peer = Peer {
                id: -1, user_id: Some(my_id), addrs: my_addrs,
                pubkey: me_pub, last_heartbeat: None, last_seen_typing: None
            };
            let me_key = me_peer.shrdkeygen(self.prvkey.clone());
            guard.insert(my_id, (me_peer, me_key, old.get(&me_pub.to_bytes()).and_then(|(_, s, _, _)| s.clone())));
        }
        Ok(())
    }

    /// A known peer re-announced (rejoin / IP change): refresh its address and drop the
    /// stale stream so `connect_peers` re-dials it.
    pub async fn reconnect_peer(&self, pubkey: PublicKey, addrs: [SocketAddr; 2]) {
        {
            let mut guard = self.peers.lock().unwrap();
            match guard.values_mut().find(|(p, _, _)| p.get_pubkey().as_bytes() == pubkey.as_bytes()) {
                Some((p, _, s)) => { p.set_addrs(addrs); p.set_last_heartbeat(None); p.set_last_seen_typing(None); *s = None; }
                None => return,
            }
        }
        self.connect_peers().await;
        self.broadcast_peer_table().await;
    }

    async fn broadcast_peer_table(&self) {
        let me = self.user.as_ref().map(|(id, _, _)| *id);
        let me_pub = PublicKey::from(&self.prvkey).to_bytes();
        let mut table: Vec<([u8; 32], [SocketAddr; 2])> = self.peers.lock().unwrap().values()
            .map(|(p, _, _)| (p.get_pubkey().to_bytes(), p.get_addrs()))
            .filter(|(pk, _)| *pk != me_pub).collect();
        table.push((me_pub, self.current_addrs()));
        let targets: Vec<(Key, Arc<TokioMutex<TcpStream>>)> = self.peers.lock().unwrap().iter()
            .filter(|(uid, _)| Some(**uid) != me)
            .filter_map(|(_, (_, k, s))| s.as_ref().map(|arc| (*k, Arc::clone(arc)))).collect();
        for (key, arc) in targets {
            if let Ok(frame) = Connection::encode(&key, AVP_HD, &table) {
                tokio::spawn(async move {
                    let mut s = arc.lock().await;
                    let _ = s.write_all(&(frame.len() as u32).to_be_bytes()).await;
                    let _ = s.write_all(&frame).await;
                });
            }
        }
    }

    /// Open an outbound stream (trying each peer's 3 addresses) to every peer that
    /// doesn't have one yet, so messages can actually flow after a sync.
    pub async fn connect_peers(&self) {
        let me = self.user.as_ref().map(|(id, _, _)| *id);
        let own = self.current_addrs();
        let to_dial: Vec<(u64, [SocketAddr; 2])> = {
            self.peers.lock().unwrap().iter()
                .filter(|(uid, (_, _, s))| Some(**uid) != me && s.is_none())
                .map(|(uid, (p, _, _))| (*uid, p.get_addrs()))
                .collect()
        };
        let mut table: Vec<([u8; 32], [SocketAddr; 2])> = self.peers.lock().unwrap().iter()
            .filter(|(uid, _)| Some(**uid) != me)
            .map(|(_, (p, _, _))| (p.get_pubkey().to_bytes(), p.get_addrs())).collect();
        table.push((PublicKey::from(&self.prvkey).to_bytes(), own));
        for (uid, addrs) in to_dial {
            let dialable: Vec<SocketAddr> = addrs.iter().copied().filter(|a| !own.contains(a)).collect();
            if dialable.is_empty() { continue; }
            if let Some(stream) = connect_any(&dialable).await {
                let arc = Arc::new(TokioMutex::new(stream));
                let key = {
                    let mut guard = self.peers.lock().unwrap();
                    match guard.get_mut(&uid) {
                        Some(e) if e.2.is_none() => { e.2 = Some(Arc::clone(&arc)); Some(e.1) }
                        _ => None,
                    }
                };
                if let Some(key) = key {
                    let mut s = arc.lock().await;
                    for frame in [Connection::encode(&key, OWN_HD, own), Connection::encode(&key, AVP_HD, &table)].into_iter().flatten() {
                        let _ = s.write_all(&(frame.len() as u32).to_be_bytes()).await;
                        let _ = s.write_all(&frame).await;
                    }
                }
            }
        }
    }
}

impl Secrecy for Connection {
    fn encode<T: Serialize>(key: &Key, header: u8, plain: T) -> Result<Vec<u8>> {
        let mut packet: Vec<u8> = serde_json::to_vec(&plain)?;
        if header == DBS_HD || header == NWP_HD || header == DBR_HD || header == AVP_HD {
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
        if header == DBS_HD || header == NWP_HD || header == DBR_HD || header == AVP_HD {
            // Zip-bomb guard: decompress_size_prepended trusts the prepended LE-u32 size, so cap it.
            if plaintxt.len() >= 4 && u32::from_le_bytes(plaintxt[..4].try_into().unwrap()) as usize > MAX_FRAME {
                return Err(anyhow::anyhow!("decompressed size exceeds cap"));
            }
            plaintxt = decompress_size_prepended(&plaintxt)
                .map_err(|e| anyhow::anyhow!("Decompression failed: {}", e))?;
        }
        Ok((header, plaintxt))
    }
}

impl RendezVous for Connection {
    async fn rcv_requests(&self, requests: Requests, token: CancellationToken, is_admin: bool) -> Result<()> {
        if is_admin { loop {
            if self.bind_rendezvous().await.is_ok() { break; }
            let me = self.user.as_ref().map(|(id, _, _)| *id);
            let keys: Vec<Key> = self.peers.lock().unwrap().iter()
                .filter(|(uid, _)| Some(**uid) != me).map(|(_, (_, k, _))| *k).collect();
            let s = UdpSocket::bind("0.0.0.0:0").await?;
            for key in &keys {
                if let Ok(f) = Connection::encode(key, EVI_HD, ()) { let _ = s.send_to(&f, self.rendezvous.0).await; }
            }
            tokio::select! {
                _ = token.cancelled() => return Ok(()),
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
        } } else if self.bind_rendezvous().await.is_err() { return Ok(()); }
        let sock = self.rendezvous.1.lock().unwrap().clone();

        if let Some(sock) = sock {
            let mut buffer = vec![0u8; 4096];
            loop {
                let (n, peer_addr) = tokio::select! {
                    _ = token.cancelled() => break,
                    r = sock.recv_from(&mut buffer) => match r { Ok(v) => v, Err(_) => continue },
                };
                if n == 0 { continue; }
                let recovered = {
                    let guard = self.peers.lock().unwrap();
                    guard.values()
                        .find_map(|(p, k, _)| Connection::decode(k, &buffer[..n]).ok().map(|(h, pl)| (p.get_pubkey(), *k, h, pl)))
                };
                if let Some((pubkey, key, header, pl)) = recovered {
                    match header {
                        OWN_HD => {
                            if let Ok(addrs) = serde_json::from_slice::<[SocketAddr; 2]>(&pl) {
                                self.reconnect_peer(pubkey, addrs).await;
                            }
                        }
                        AVP_HD => {
                            let me_pub = PublicKey::from(&self.prvkey).to_bytes();
                            if let Ok(table) = serde_json::from_slice::<Vec<([u8; 32], [SocketAddr; 2])>>(&pl) {
                                for (pk, addrs) in table {
                                    if pk != me_pub { self.reconnect_peer(PublicKey::from(pk), addrs).await; }
                                }
                            }
                            let mut reply: Vec<([u8; 32], [SocketAddr; 2])> = self.peers.lock().unwrap().values()
                                .map(|(p, _, _)| (p.get_pubkey().to_bytes(), p.get_addrs()))
                                .filter(|(pk, _)| *pk != me_pub).collect();
                            reply.push((me_pub, self.current_addrs()));
                            if let Ok(f) = Connection::encode(&key, AVP_HD, &reply) { let _ = sock.send_to(&f, peer_addr).await; }
                        }
                        EVI_HD => {
                            *self.rendezvous.1.lock().unwrap() = None;
                            if let Ok(f) = Connection::encode(&key, OWN_HD, self.current_addrs()) {
                                let _ = sock.send_to(&f, peer_addr).await;
                            }
                            break;
                        }
                        _ => {}
                    }
                    continue;
                }
                if !is_admin { continue; }
                {
                    {
                        {
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
                                        let body = match tail.strip_suffix("fallegji") {
                                            Some(p) => p,
                                            None => continue,
                                        };
                                        let (pubkey_hex, uid_raw) = match body.split_once(';') {
                                            Some((pk, u)) => (pk, u.parse::<u32>().unwrap_or(0)),
                                            None => (body, 0),
                                        };
                                        let pubkey = match hex::decode(pubkey_hex)
                                            .ok()
                                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                                            .map(PublicKey::from)
                                        {
                                            Some(pk) => pk,
                                            None => continue,
                                        };
                                        let addrs = match Peer::parse_addrs(addr_str) {
                                            Some(a) => a,
                                            None => continue,
                                        };
                                        let addrs = [SocketAddr::new(peer_addr.ip(), addrs[1].port()), addrs[1]];
                                        let my_pub = PublicKey::from(&self.prvkey);
                                        if pubkey.as_bytes() == my_pub.as_bytes() { continue; }
                                        let known = self.peers.lock().unwrap().values()
                                            .any(|(p, _, _)| p.get_pubkey().as_bytes() == pubkey.as_bytes());
                                        if known {
                                            self.reconnect_peer(pubkey, addrs).await;
                                            continue;
                                        }
                                        {
                                            let mut guard = requests.lock().unwrap();
                                            if let Some(existing) = guard.iter_mut().find(|r| r.2.as_bytes() == pubkey.as_bytes()) {
                                                existing.0 = addrs;
                                            } else {
                                                guard.push((addrs, String::from(name), pubkey, uid_raw));
                                            }
                                        }
                                        let admin_pubkey_hex = hex::encode(PublicKey::from(&self.prvkey).as_bytes());
                                        let reply = format!("received[({}, {})]{}fallegji", addr_str, name, admin_pubkey_hex);
                                        let _ = sock.send_to(reply.as_bytes(), peer_addr).await;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn snd_requests(&self, name: String) -> Result<bool> {
        let prvkey = self.prvkey.clone();
        let peers = Arc::clone(&self.peers);
        let admin_addr = self.rendezvous.0;
        let my_addrs_str = self.current_addrs().iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",");

        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        let my_pubkey_hex = hex::encode(PublicKey::from(&self.prvkey).as_bytes());
        let my_uid = self.user.as_ref().map(|(_, _, u)| u.as_raw()).unwrap_or(0);
        let request = format!("{}[{}]{};{}fallegji", name, my_addrs_str, my_pubkey_hex, my_uid);
        sock.send_to(request.as_bytes(), admin_addr).await?;
        let timeout = tokio::time::Duration::from_secs(5);
        let start_time = tokio::time::Instant::now();
        let mut buffer = vec![0u8; 4096];
        loop {
            if start_time.elapsed() > timeout { return Ok(false); }
            match tokio::time::timeout(
                tokio::time::Duration::from_millis(500),
                sock.recv_from(&mut buffer)
            ).await {
                Ok(Ok((n, _src))) if n > 0 => {
                    let repl = String::from_utf8_lossy(&buffer[..n]);
                    let start = match repl.find('[') { Some(s) => s, None => continue };
                    let end = match repl.find(']') { Some(e) => e, None => continue };
                    if start >= end { continue; }
                    let prefix = &repl[..start];
                    let tuple_content = &repl[start+1..end];
                    let admin_pubkey_hex = match repl[end+1..].trim().strip_suffix("fallegji") {
                        Some(p) => p,
                        None => continue,
                    };
                    if prefix != "received" { continue; }
                    if !tuple_content.starts_with('(') || !tuple_content.ends_with(')') { continue; }
                    let inner = &tuple_content[1..tuple_content.len()-1];
                    let parts: Vec<&str> = inner.splitn(2, ", ").collect();
                    if parts.len() != 2 { continue; }
                    if parts[0] == my_addrs_str && parts[1] == name {
                        let admin_pubkey = match hex::decode(admin_pubkey_hex)
                            .ok()
                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                            .map(PublicKey::from)
                        {
                            Some(pk) => pk,
                            None => continue,
                        };
                        let admin_peer = Peer {
                            id: -1, user_id: None, addrs: [admin_addr; 2], pubkey: admin_pubkey,
                            last_heartbeat: None, last_seen_typing: None
                        };
                        let key = admin_peer.shrdkeygen(prvkey.clone());
                        peers.lock().unwrap().insert(0, (admin_peer, key, None));
                        return Ok(true);
                    }
                    continue;
                }
                Ok(Ok(_)) => return Ok(false),
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => continue,
            }
        }
    }

    async fn fallback_lookup(&self) -> Result<bool> {
        match UdpSocket::bind(self.rendezvous.0).await {
            Ok(sock) => {
                *self.rendezvous.1.lock().unwrap() = Some(Arc::new(sock));
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    async fn fallback_send(&self, _name: String) -> Result<bool> {
        let addrs = self.current_addrs();
        let me = self.user.as_ref().map(|(id, _, _)| *id);
        let mut table: Vec<([u8; 32], [SocketAddr; 2])> = self.peers.lock().unwrap().iter()
            .filter(|(uid, _)| Some(**uid) != me)
            .map(|(_, (p, _, _))| (p.get_pubkey().to_bytes(), p.get_addrs())).collect();
        table.push((PublicKey::from(&self.prvkey).to_bytes(), addrs));
        let keys: Vec<Key> = self.peers.lock().unwrap().iter()
            .filter(|(uid, _)| Some(**uid) != me)
            .map(|(_, (_, k, _))| *k).collect();
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        for key in &keys {
            if let Ok(frame) = Connection::encode(key, OWN_HD, addrs) {
                let _ = sock.send_to(&frame, self.rendezvous.0).await;
            }
            if let Ok(frame) = Connection::encode(key, AVP_HD, &table) {
                let _ = sock.send_to(&frame, self.rendezvous.0).await;
            }
        }
        let me_pub = PublicKey::from(&self.prvkey).to_bytes();
        let mut buf = vec![0u8; 4096];
        while let Ok(Ok((n, _))) = tokio::time::timeout(Duration::from_millis(800), sock.recv_from(&mut buf)).await {
            let decoded = keys.iter().find_map(|k| Connection::decode(k, &buf[..n]).ok());
            if let Some((AVP_HD, pl)) = decoded
                && let Ok(reply) = serde_json::from_slice::<Vec<([u8; 32], [SocketAddr; 2])>>(&pl) {
                for (pk, a) in reply {
                    if pk != me_pub { self.reconnect_peer(PublicKey::from(pk), a).await; }
                }
                break;
            }
        }
        Ok(true)
    }
}

impl Communication for Connection {
    async fn listen(self: Arc<Self>, slot: ChatSlot, reject: Arc<Mutex<Option<String>>>, token: CancellationToken) -> Result<()> {
        let mut cooldown = tokio::time::interval(Duration::from_millis(500));
        loop {
            let listener = self.socket.lock().unwrap().1.clone();
            let (mut stream, _) = tokio::select! {
                _ = token.cancelled() => return Ok(()),
                _ = cooldown.tick() => {
                    let chat = slot.lock().unwrap().as_ref().map(|a| a.chat.clone());
                    if let Some(chat) = chat {
                        let due = self.db_sync_buf.lock().unwrap().first_at.is_some_and(|t| t.elapsed() >= SYNC_COOLDOWN);
                        if due { let _ = self.decide_sync(&chat).await; }
                    }
                    continue;
                }
                res = listener.accept() => res?,
            };
            let me = Arc::clone(&self);
            let slot = Arc::clone(&slot);
            let reject = Arc::clone(&reject);
            let conn_token = token.clone();
            tokio::spawn(async move {
                loop {
                    let mut len_buf = [0u8; 4];
                    let read_len = tokio::select! {
                        _ = conn_token.cancelled() => break,
                        r = stream.read_exact(&mut len_buf) => r,
                    };
                    if read_len.is_err() { break; }
                    let len = u32::from_be_bytes(len_buf) as usize;
                    if len > MAX_FRAME { break; }
                    let mut frame = vec![0u8; len];
                    let read_frame = tokio::select! {
                        _ = conn_token.cancelled() => break,
                        r = stream.read_exact(&mut frame) => r,
                    };
                    if read_frame.is_err() { break; }

                    let candidates: Vec<(u64, Key)> = {
                        let guard = me.peers.lock().unwrap();
                        guard.iter().map(|(uid, (_, k, _))| (*uid, *k)).collect()
                    };
                    let mut found = None;
                    for (uid, k) in candidates {
                        if let Ok((h, p)) = Connection::decode(&k, &frame) {
                            found = Some((uid, h, p));
                            break;
                        }
                    }
                    let (peer_id, header, payload) = match found {
                        Some(x) => x,
                        None => continue,
                    };

                    let chat = slot.lock().unwrap().as_ref().map(|a| a.chat.clone());
                    let _ = match (header, chat) {
                        (NWP_HD, None) => me.accept_chat(&slot, payload).await,
                        // Admin rejected our join (e.g. duplicate username): stash the reason; the app loop bounces us Home.
                        (REJ_HD, _) => {
                            if let Ok(reason) = serde_json::from_slice::<String>(&payload) { *reject.lock().unwrap() = Some(reason); }
                            Err(anyhow::anyhow!("join rejected"))
                        }
                        (OWN_HD, _) => {
                            if me.recv_ok(peer_id, OWN_HD) && let Ok(addrs) = serde_json::from_slice::<[SocketAddr; 2]>(&payload) && let Some(e) = me.peers.lock().unwrap().get_mut(&peer_id) { e.0.set_addrs(addrs); }
                            Ok(())
                        }
                        (AVP_HD, _) if me.recv_ok(peer_id, AVP_HD) => {
                            if let Ok(table) = serde_json::from_slice::<Vec<([u8; 32], [SocketAddr; 2])>>(&payload) {
                                let me_pub = PublicKey::from(&me.prvkey).to_bytes();
                                {
                                    let mut guard = me.peers.lock().unwrap();
                                    for (pk, addrs) in table {
                                        if pk != me_pub && let Some(e) = guard.values_mut().find(|(p, _, _)| p.get_pubkey().to_bytes() == pk) { e.0.set_addrs(addrs); }
                                    }
                                }
                                me.connect_peers().await;
                            }
                            Ok(())
                        }
                        (_, None) => Ok(()),
                        (MSG_HD, Some(chat)) => if me.recv_ok(peer_id, MSG_HD) { me.read_msg(&chat, payload).await } else { Ok(()) },
                        (HBT_HD, Some(chat)) => {
                            if me.recv_ok(peer_id, HBT_HD) && let Ok(true) = me.read_heartbeat(&chat, peer_id).await {
                                let (me2, db) = (Arc::clone(&me), chat.db.clone());
                                tokio::spawn(async move { let _ = me2.send_db_sync(&db).await; });
                            }
                            Ok(())
                        }
                        (TYP_HD, Some(_)) => if me.recv_ok(peer_id, TYP_HD) { me.read_typing(peer_id).await } else { Ok(()) },
                        (DBS_HD, Some(chat)) => if me.recv_ok(peer_id, DBS_HD) { me.read_db_sync(&chat, peer_id, payload).await } else { Ok(()) },
                        (DBR_HD, Some(chat)) => if me.recv_ok(peer_id, DBR_HD) { me.read_db_req(&chat, peer_id, payload).await } else { Ok(()) },
                        (KCK_HD, Some(chat)) => match serde_json::from_slice::<u64>(&payload) {
                            Ok(uid) if Some(peer_id) == chat.get_admin() && me.recv_ok(peer_id, KCK_HD) => me.read_kick(&chat, uid).await,
                            Ok(_) => Ok(()),
                            Err(e) => Err(e.into()),
                        },
                        (_, Some(_)) => Ok(()),
                    };
                }
            });
        }
    }

    async fn send_newpeer(&self, addrs: [SocketAddr; 2], pubkey: PublicKey, name: &str, uid: u32, chat_name: &str, chat: &Chat) -> Result<()> {
        let uid = Uid::from(uid);
        let pubkey_hex = hex::encode(pubkey.as_bytes());
        let mut joiner = User::new(pubkey_hex.clone(), name.to_string(), uid);
        joiner.set_role(Role::Member);
        let joiner_id = joiner.get_id();
        let peer = Peer { id: -1, user_id: Some(joiner_id), addrs, pubkey, last_heartbeat: None, last_seen_typing: None };
        let key = peer.shrdkeygen(self.prvkey.clone());

        let frame = Connection::encode(&key, NWP_HD, (chat_name.to_string(), chat.db.dump().await?))?;
        let mut stream = connect_any(&addrs).await
            .ok_or_else(|| anyhow::anyhow!("could not reach new peer on any address"))?;
        stream.write_all(&(frame.len() as u32).to_be_bytes()).await?;
        stream.write_all(&frame).await?;

        if !chat.members.read().unwrap().contains_key(&joiner_id) {
            let _ = chat.db.create_user(pubkey_hex, name.to_string(), uid).await;
            let _ = chat.db.update_user_role(joiner_id, Role::Member).await;
            let _ = chat.db.create_peer_with(pubkey, addrs, joiner_id).await;
            chat.members.write().unwrap().insert(joiner_id, joiner);
        }
        self.peers.lock().unwrap().insert(joiner_id, (peer, key, Some(Arc::new(TokioMutex::new(stream)))));
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
        {
            let mut hist = chat.message_history.write().unwrap();
            if hist.iter().any(|m| m.get_sender_id() == sender_id && m.get_sent_at() == sent_at && m.get_contents() == contents) {
                return Ok(());
            }
            hist.push(msg);
        }
        // Desktop notification for a genuinely-new received message (skip system + our own); no-op if notify-send is absent.
        if chat.should_notify() && sender_id != 0 && sender_id != chat.current_user.get_id() {
            let who = chat.members.read().unwrap().get(&sender_id).map(|u| u.get_name()).unwrap_or_else(|| "someone".to_string());
            let body = format!("{}: {}", who, contents);
            let _ = std::process::Command::new("notify-send")
                .arg("Fallegji").arg(body)
                .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
                .spawn();
        }
        tokio::spawn(async move {
            let _ = db.create_message(sender_id, contents, Some(sent_at)).await;
        });
        Ok(())
    }

    async fn send_heartbeat(&self) -> Result<()> {
        let targets: Vec<(u64, Key, Arc<TokioMutex<TcpStream>>)> = {
            let me = self.user.as_ref().map(|(id, _, _)| *id);
            let guard = self.peers.lock().unwrap();
            guard.iter()
                .filter(|(uid, _)| Some(**uid) != me)
                .filter_map(|(uid, (_, k, s))| s.as_ref().map(|arc| (*uid, *k, Arc::clone(arc))))
                .collect()
        };
        for (uid, key, stream_arc) in targets {
            let frame = Connection::encode(&key, HBT_HD, ())?;
            let peers = Arc::clone(&self.peers);
            tokio::spawn(async move {
                let mut s = stream_arc.lock().await;
                let ok = s.write_all(&(frame.len() as u32).to_be_bytes()).await.is_ok()
                    && s.write_all(&frame).await.is_ok();
                drop(s);
                if !ok && let Some(e) = peers.lock().unwrap().get_mut(&uid)
                    && e.2.as_ref().is_some_and(|cur| Arc::ptr_eq(cur, &stream_arc)) {
                    e.2 = None;
                    e.0.set_last_heartbeat(None);
                    e.0.set_last_seen_typing(None);
                }
            });
        }
        Ok(())
    }
    async fn read_heartbeat(&self, chat: &Chat, peer_id: u64) -> Result<bool> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as i64;
        let (db_id, came_online) = {
            let mut guard = self.peers.lock().unwrap();
            match guard.get_mut(&peer_id) {
                Some(entry) => {
                    let was_online = entry.0.is_online();
                    entry.0.set_last_heartbeat(Some(now));
                    (Some(entry.0.get_id()), !was_online)
                }
                None => (None, false),
            }
        };
        if let Some(id) = db_id {
            let db = chat.db.clone();
            tokio::spawn(async move {
                let _ = db.update_peer_last_heartbeat(id, Some(now)).await;
            });
        }
        Ok(came_online)
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
                .as_millis() as i64;
            peer.set_last_seen_typing(Some(timestamp));
        }
        Ok(())
    }

    async fn send_db_sync(&self, db: &Database) -> Result<()> {
        let mut msgs: Vec<(u64, i64, String)> = db.load_all_messages().await?
            .iter().map(|m| (m.get_sender_id(), m.get_sent_at(), m.get_contents())).collect();
        msgs.sort_by_key(|a| (a.1, a.0));
        let mut usrs: Vec<(u64, String, Option<String>, u32)> = db.load_all_users().await?
            .iter().map(|u| (u.get_id(), u.get_name(), u.get_role().map(|r| r.to_string()), u.get_uid().as_raw())).collect();
        usrs.sort_by_key(|u| u.0);
        let mut pirs: Vec<(Option<u64>, [String; 2], [u8; 32])> = db.load_all_peers().await?
            .iter().map(|p| (p.get_user_id(), p.get_addrs().map(|a| a.to_string()), p.get_pubkey().to_bytes())).collect();
        pirs.sort_by_key(|a| a.0);

        let mut bytes = Vec::new();
        for blob in [
            compress_prepend_size(&serde_json::to_vec(&msgs)?),
            compress_prepend_size(&serde_json::to_vec(&usrs)?),
            compress_prepend_size(&serde_json::to_vec(&pirs)?),
        ] {
            bytes.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&blob);
        }

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
    async fn read_db_sync(&self, chat: &Chat, peer_id: u64, payload: Vec<u8>) -> Result<()> {
        let framed: Vec<u8> = serde_json::from_slice(&payload)?;
        let mut blobs: Vec<Vec<u8>> = Vec::with_capacity(3);
        let mut i = 0usize;
        for _ in 0..3 {
            if i + 4 > framed.len() { return Err(anyhow::anyhow!("db sync: truncated frame")); }
            let len = u32::from_be_bytes(framed[i..i + 4].try_into().unwrap()) as usize;
            i += 4;
            if i + len > framed.len() { return Err(anyhow::anyhow!("db sync: short component")); }
            blobs.push(framed[i..i + len].to_vec());
            i += len;
        }
        let msg_rows: Vec<(u64, i64, String)> =
            serde_json::from_slice(&decompress_size_prepended(&blobs[0]).map_err(|e| anyhow::anyhow!("{e}"))?)?;
        if !msg_rows.is_empty() {
            let incoming: Vec<Message> = msg_rows.iter().map(|(sid, ts, c)| {
                let mut m = Message::new(-1, *sid, c.clone()); m.set_date(*ts); m
            }).collect();
            chat.db.save_all_messages(incoming).await?;
            let reloaded = chat.db.load_all_messages().await?;
            let mut hist = chat.message_history.write().unwrap();
            let mut have: std::collections::HashSet<(u64, i64, String)> = hist.iter()
                .map(|m| (m.get_sender_id(), m.get_sent_at(), m.get_contents())).collect();
            for m in reloaded {
                if have.insert((m.get_sender_id(), m.get_sent_at(), m.get_contents())) { hist.push(m); }
            }
            hist.sort_by_key(|m| (m.get_sent_at(), m.get_sender_id()));
        }

        let online = {
            let me = self.user.as_ref().map(|(id, _, _)| *id);
            self.peers.lock().unwrap().iter()
                .filter(|(uid, (p, _, _))| Some(**uid) != me && p.is_online()).count()
        };
        let from_admin = Some(peer_id) == chat.get_admin();
        let trigger = {
            let mut it = blobs.into_iter();
            let mut buf = self.db_sync_buf.lock().unwrap();
            let idx = buf.msgs.len() as u8;
            buf.msgs.push_back(it.next().unwrap());
            buf.usrs.push_back(it.next().unwrap());
            buf.pirs.push_back(it.next().unwrap());
            if buf.rcv_count == 0 { buf.first_at = Some(Instant::now()); }
            buf.rcv_count += 1;
            if from_admin { buf.admin_rank = Some(idx); }
            from_admin || (online > 0 && buf.rcv_count as usize >= online)
        };
        if trigger { self.decide_sync(chat).await?; }
        Ok(())
    }

    async fn decide_sync(&self, chat: &Chat) -> Result<()> {
        let (msg_blobs, usr_blobs, pir_blobs, admin_rank) = {
            let mut buf = self.db_sync_buf.lock().unwrap();
            buf.rcv_count = 0;
            buf.first_at = None;
            (
                std::mem::take(&mut buf.msgs).into_iter().collect::<Vec<_>>(),
                std::mem::take(&mut buf.usrs).into_iter().collect::<Vec<_>>(),
                std::mem::take(&mut buf.pirs).into_iter().collect::<Vec<_>>(),
                buf.admin_rank.take(),
            )
        };
        if usr_blobs.is_empty() { return Ok(()); }

        let mut my_u: Vec<(u64, String, Option<String>, u32)> = chat.db.load_all_users().await?
            .iter().map(|u| (u.get_id(), u.get_name(), u.get_role().map(|r| r.to_string()), u.get_uid().as_raw())).collect();
        my_u.sort_by_key(|u| u.0);
        let my_usrs = compress_prepend_size(&serde_json::to_vec(&my_u)?);
        let live: HashMap<u64, [SocketAddr; 2]> = self.peers.lock().unwrap().iter()
            .map(|(uid, (p, _, _))| (*uid, p.get_addrs())).collect();
        let mut my_p: Vec<(Option<u64>, [String; 2], [u8; 32])> = chat.db.load_all_peers().await?
            .iter().map(|p| {
                let addrs = p.get_user_id().and_then(|u| live.get(&u)).copied().unwrap_or_else(|| p.get_addrs());
                (p.get_user_id(), addrs.map(|a| a.to_string()), p.get_pubkey().to_bytes())
            }).collect();
        my_p.sort_by_key(|a| a.0);
        let my_pirs = compress_prepend_size(&serde_json::to_vec(&my_p)?);

        let i_am_admin = chat.get_admin() == self.user.as_ref().map(|(id, _, _)| *id);
        let winner = |blobs: &[Vec<u8>], mine: &Vec<u8>| -> Vec<u8> {
            if let Some(i) = admin_rank && (i as usize) < blobs.len() {
                return blobs[i as usize].clone();
            }
            if i_am_admin { return mine.clone(); }
            let mut pool = blobs.to_vec();
            pool.push(mine.clone());
            pool.iter().max_by_key(|b| pool.iter().filter(|x| x == b).count()).cloned().unwrap()
        };
        let chosen_usrs = winner(&usr_blobs, &my_usrs);
        let chosen_pirs = winner(&pir_blobs, &my_pirs);
        let urows: Vec<(u64, String, Option<String>, u32)> =
            serde_json::from_slice(&decompress_size_prepended(&chosen_usrs).map_err(|e| anyhow::anyhow!("{e}"))?)?;
        let prows: Vec<(Option<u64>, [String; 2], [u8; 32])> =
            serde_json::from_slice(&decompress_size_prepended(&chosen_pirs).map_err(|e| anyhow::anyhow!("{e}"))?)?;

        let mut my_m: Vec<(u64, i64, String)> = chat.db.load_all_messages().await?
            .iter().map(|m| (m.get_sender_id(), m.get_sent_at(), m.get_contents())).collect();
        my_m.sort_by_key(|a| (a.1, a.0));
        let my_msgs = compress_prepend_size(&serde_json::to_vec(&my_m)?);
        let mut seen = std::collections::HashSet::new();
        let mut messages = Vec::new();
        for blob in msg_blobs.iter().chain(std::iter::once(&my_msgs)) {
            let rows: Vec<(u64, i64, String)> = serde_json::from_slice(&decompress_size_prepended(blob).map_err(|e| anyhow::anyhow!("{e}"))?)?;
            for (sid, ts, c) in rows {
                if seen.insert((sid, ts, c.clone())) {
                    let mut m = Message::new(-1, sid, c);
                    m.set_date(ts);
                    messages.push(m);
                }
            }
        }
        for m in chat.message_history.read().unwrap().iter() {
            if seen.insert((m.get_sender_id(), m.get_sent_at(), m.get_contents())) {
                let mut nm = Message::new(-1, m.get_sender_id(), m.get_contents());
                nm.set_date(m.get_sent_at());
                messages.push(nm);
            }
        }

        let me = self.user.as_ref().map(|(id, _, _)| *id);
        let current: HashMap<u64, ([SocketAddr; 2], bool)> = self.peers.lock().unwrap().iter()
            .map(|(uid, (p, _, s))| (*uid, (p.get_addrs(), s.is_some()))).collect();
        let mut keys: HashMap<u64, [u8; 32]> = HashMap::new();
        let mut peers = Vec::new();
        for (user_id, addrs, pk) in prows {
            let pick = |uid: u64| {
                let cur = current.get(&uid);
                let keep_current = Some(uid) == me || cur.map(|(_, online)| *online).unwrap_or(false);
                if keep_current {
                    cur.map(|(a, _)| *a).or_else(|| Peer::parse_addrs(&addrs.join(",")))
                } else {
                    Peer::parse_addrs(&addrs.join(",")).or_else(|| cur.map(|(a, _)| *a))
                }
            };
            if let Some(uid) = user_id && let Some(a) = pick(uid) {
                keys.insert(uid, pk);
                peers.push(Peer { id: -1, user_id, addrs: a, pubkey: PublicKey::from(pk), last_heartbeat: None, last_seen_typing: None });
            }
        }
        let mut users = Vec::new();
        for (id, name, role, uid) in urows {
            let Some(pk) = keys.get(&id) else { continue };
            let mut u = User::new(hex::encode(pk), name, Uid::from(uid));
            if let Some(r) = role.and_then(|r| r.parse().ok()) { u.set_role(r); }
            users.push(u);
        }
        users.push(User::sys());
        let gained_msgs = messages.len() > my_m.len();
        chat.db.save_all_users(users).await?;
        chat.db.save_all_peers(peers).await?;
        chat.db.save_all_messages(messages).await?;

        {
            let reloaded = chat.db.load_all_messages().await?;
            let mut hist = chat.message_history.write().unwrap();
            let mut have: std::collections::HashSet<(u64, i64, String)> = hist.iter()
                .map(|m| (m.get_sender_id(), m.get_sent_at(), m.get_contents())).collect();
            for m in reloaded {
                if have.insert((m.get_sender_id(), m.get_sent_at(), m.get_contents())) { hist.push(m); }
            }
            hist.sort_by_key(|m| (m.get_sent_at(), m.get_sender_id()));
        }
        let users_now = chat.db.load_all_users().await?;
        {
            let mut members = chat.members.write().unwrap();
            members.clear();
            members.insert(0, User::sys());
            for u in users_now { members.insert(u.get_id(), u); }
        }
        self.rebuild_peermap(&chat.db).await?;
        self.connect_peers().await;
        if chosen_usrs != my_usrs || chosen_pirs != my_pirs || gained_msgs {
            let _ = self.send_db_sync(&chat.db).await;
        }
        Ok(())
    }

    async fn send_db_req(&self, chat: &Chat) -> Result<()> {
        let admin_id = chat.get_admin();
        let target: Option<(Key, Arc<TokioMutex<TcpStream>>)> = {
            let me = self.user.as_ref().map(|(id, _, _)| *id);
            let guard = self.peers.lock().unwrap();
            let admin = admin_id
                .and_then(|aid| guard.get(&aid))
                .and_then(|(_, k, s)| s.as_ref().map(|arc| (*k, Arc::clone(arc))));
            admin.or_else(|| guard.iter()
                .filter(|(uid, _)| Some(**uid) != me)
                .find_map(|(_, (_, k, s))| s.as_ref().map(|arc| (*k, Arc::clone(arc)))))
        };

        if let Some((key, stream_arc)) = target {
            let frame = Connection::encode(&key, DBR_HD, Vec::<u8>::new())?;
            tokio::spawn(async move {
                let mut s = stream_arc.lock().await;
                let _ = s.write_all(&(frame.len() as u32).to_be_bytes()).await;
                let _ = s.write_all(&frame).await;
            });
        }
        Ok(())
    }
    async fn read_db_req(&self, chat: &Chat, peer_id: u64, _payload: Vec<u8>) -> Result<()> {
        let mut msgs: Vec<(u64, i64, String)> = chat.db.load_all_messages().await?
            .iter().map(|m| (m.get_sender_id(), m.get_sent_at(), m.get_contents())).collect();
        msgs.sort_by_key(|a| (a.1, a.0));
        let mut usrs: Vec<(u64, String, Option<String>, u32)> = chat.db.load_all_users().await?
            .iter().map(|u| (u.get_id(), u.get_name(), u.get_role().map(|r| r.to_string()), u.get_uid().as_raw())).collect();
        usrs.sort_by_key(|u| u.0);
        let mut pirs: Vec<(Option<u64>, [String; 2], [u8; 32])> = chat.db.load_all_peers().await?
            .iter().map(|p| (p.get_user_id(), p.get_addrs().map(|a| a.to_string()), p.get_pubkey().to_bytes())).collect();
        pirs.sort_by_key(|a| a.0);
        let mut bytes = Vec::new();
        for blob in [
            compress_prepend_size(&serde_json::to_vec(&msgs)?),
            compress_prepend_size(&serde_json::to_vec(&usrs)?),
            compress_prepend_size(&serde_json::to_vec(&pirs)?),
        ] {
            bytes.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&blob);
        }
        let target = self.peers.lock().unwrap().get(&peer_id)
            .and_then(|(_, k, s)| s.as_ref().map(|arc| (*k, Arc::clone(arc))));
        if let Some((key, stream_arc)) = target {
            let frame = Connection::encode(&key, DBS_HD, bytes)?;
            let mut s = stream_arc.lock().await;
            s.write_all(&(frame.len() as u32).to_be_bytes()).await?;
            s.write_all(&frame).await?;
        }
        Ok(())
    }

    async fn send_kick(&self, user_id: u64) -> Result<()> {
        let targets: Vec<(Key, Arc<TokioMutex<TcpStream>>)> = {
            let me = self.user.as_ref().map(|(id, _, _)| *id);
            let guard = self.peers.lock().unwrap();
            guard.iter()
                .filter(|(uid, _)| Some(**uid) != me)
                .filter_map(|(_, (_, k, s))| s.as_ref().map(|arc| (*k, Arc::clone(arc))))
                .collect()
        };
        for (key, stream_arc) in targets {
            let frame = Connection::encode(&key, KCK_HD, user_id)?;
            tokio::spawn(async move {
                let mut s = stream_arc.lock().await;
                let _ = s.write_all(&(frame.len() as u32).to_be_bytes()).await;
                let _ = s.write_all(&frame).await;
            });
        }
        Ok(())
    }

    async fn read_kick(&self, chat: &Chat, user_id: u64) -> Result<()> {
        if self.user.as_ref().map(|(id, _, _)| *id) == Some(user_id) { return Ok(()); }
        let peer_db_id = chat.db.load_all_peers().await.ok()
            .and_then(|ps| ps.into_iter().find(|p| p.get_user_id() == Some(user_id)).map(|p| p.get_id()));
        if let Some(pid) = peer_db_id { let _ = chat.db.delete_peer(pid).await; }
        let _ = chat.db.delete_user(user_id).await;
        chat.members.write().unwrap().remove(&user_id);
        self.rebuild_peermap(&chat.db).await?;
        Ok(())
    }
}

//TODO: put these functions in some connection impl

/// Fill `out` with every up non-loopback IPv4 interface as (name, ip) — feeds the home-screen
/// interface picker. Cross-platform via if-addrs (getifaddrs on Unix, GetAdaptersAddresses on
/// Windows); the UDP trick can only ever report one (the default-route) address.
pub fn interfaces(out: &Arc<Mutex<Vec<(String, IpAddr)>>>) {
    let found = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| i.ip().is_ipv4() && !i.is_loopback())
        .map(|i| (i.name.clone(), i.ip()))
        .collect();
    *out.lock().unwrap() = found;
}

/// This machine's three candidate addresses for `port`: loopback, LAN (UDP trick),
/// and public (defaults to LAN until STUN refines it — see `public_addr`).
pub fn local_addrs(port: u16) -> Result<[SocketAddr; 2]> {
    let lan_ip = bind_ip(None).context("no usable network interface")?;
    let localhost = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let lan = SocketAddr::new(lan_ip, port);
    Ok([localhost, lan])
}


/// Race all candidate addresses concurrently, returning the first that connects.
pub async fn connect_any(addrs: &[SocketAddr]) -> Option<TcpStream> {
    let mut set = tokio::task::JoinSet::new();
    for &addr in addrs {
        set.spawn(async move {
            tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(addr)).await.ok()?.ok()
        });
    }
    while let Some(res) = set.join_next().await {
        if let Ok(Some(stream)) = res {
            return Some(stream);
        }
    }
    None
}

/// Bind a TCP listener with SO_REUSEADDR so a recently-used port (still in TIME_WAIT)
/// rebinds without an "address already in use" error.
pub fn bind_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = if addr.is_ipv4() { tokio::net::TcpSocket::new_v4()? } else { tokio::net::TcpSocket::new_v6()? };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(1024)
}

/// Bind IP for the chosen interface `iface` (by name), else the first up non-loopback IPv4.
/// if-addrs based — replaces the old UDP trick, which only ever saw the default-route interface.
pub fn bind_ip(iface: Option<&str>) -> Option<IpAddr> {
    let addrs = if_addrs::get_if_addrs().ok()?;
    if let Some(name) = iface &&
        let Some(i) = addrs.iter().find(|i| i.name == name && i.ip().is_ipv4()) {
        return Some(i.ip());
    }
    addrs.into_iter().find(|i| i.ip().is_ipv4() && !i.is_loopback()).map(|i| i.ip())
}

pub async fn get_free_port(iface: Option<&str>) -> Result<(SocketAddr, TcpListener)> {
    let ip = bind_ip(iface).context("no usable network interface")?;
    let mut port = 1952;
    for _ in 0..74 {
        let addr = SocketAddr::new(ip, port);
        match bind_listener(addr) {
            Ok(sock) => return Ok((addr, sock)),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => { port += 1; continue; }
            Err(e) => return Err(e.into()),
        }
    }
    Err(anyhow::anyhow!("Too many ports in use"))
}
