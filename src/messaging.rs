use std::{collections::HashMap, sync::{Arc, RwLock}, time::Duration};
use anyhow::Result;
use tokio::{net::TcpStream, sync::Mutex as TokioMutex, time::timeout};
use x25519_dalek::{PublicKey, StaticSecret};
use time::OffsetDateTime;
use crate::{auth::{Role, Uid, User}, connection::{KeyGen, Peer, Peermap}, db::Database};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Message {
    id: i32,
    sender_id: u64,
    contents: String,
    sent_at: i64
}

pub struct Chat {
    pub message_history: Arc<RwLock<Vec<Message>>>,
    pub members: Arc<RwLock<HashMap<u64, User>>>, // user_id -> User
    pub peers: Arc<RwLock<HashMap<u64, Peer>>>, // user_id -> Peer
    pub current_user: User,
    db: Database
}

impl Message {
    pub fn new(id: i32, sender_id: u64, contents: String) -> Self {
        let sent_at = OffsetDateTime::now_utc().unix_timestamp();
        Self { id, sender_id, contents, sent_at }
    }

    pub fn get_id(&self) -> i32 { self.id }
    pub fn get_sender_id(&self) -> u64 { self.sender_id }
    pub fn get_contents(&self) -> String { self.contents.clone() }
    pub fn get_sent_at(&self) -> i64 { self.sent_at }

    pub fn set_contents(&mut self, contents: String) { self.contents = contents; }
    pub fn set_date(&mut self, date: i64) { self.sent_at = date; }
}

impl Chat {
    pub async fn new(chat_name: &str, user_name: &str, port: u16) -> Result<(Self, StaticSecret, PublicKey, u64, i32, Peermap)> {
        let db_path = format!("{}.db", chat_name);
        let db = Database::new(&db_path)?;

        let (peer, prvkey) = db.create_peer(port).await?;
        let peer_id = peer.get_id();
        let pubkey = peer.get_pubkey();
        let pubkey_hex = hex::encode(pubkey.as_bytes());

        let uid = Uid::getuid();
        let mut current_user = db.create_user(pubkey_hex, user_name.to_string(), uid).await?;
        current_user.set_role(Role::Admin);
        let user_id = current_user.get_id();
        db.update_user_role(user_id, Role::Admin).await?;
        db.update_peer_link_user(peer.get_id(), user_id).await?;

        db.delete_user(0).await?;
        let sys = db.create_sys().await?;
        let mut members = HashMap::new();
        members.insert(user_id, current_user.clone());
        members.insert(0u64, sys);

        let system_message = db.create_message(0, format!("Chat '{}' created by {}", chat_name, user_name)).await?;
        let message_history = vec![system_message];

        let peermap = Peermap::new();
        let mut peers = HashMap::new();
        peers.insert(user_id, peer);

        Ok((Self {
            message_history: Arc::new(RwLock::new(message_history)),
            members: Arc::new(RwLock::new(members)),
            peers: Arc::new(RwLock::new(peers)),
            current_user,
            db
        }, prvkey, pubkey, user_id, peer_id, peermap))
    }

    pub async fn old(chat_name: &str, user_name: &str, prvkey: StaticSecret) -> Result<(Self, Peermap)> {
        let db_path = format!("{}.db", chat_name);
        let db = Database::new(&db_path)?;
        let message_history = db.load_all_messages().await?;
        let all_users = db.load_all_users().await?;
        let all_peers = db.load_all_peers().await?;

        let mut current_user_id: u64 = 0;
        let mut members = HashMap::new();
        members.insert(0u64, User::sys());
        for user in all_users {
            if user.get_name() == user_name { current_user_id = user.get_id(); }
            members.insert(user.get_id(), user);
        }

        let current_user = db.read_user(current_user_id).await?
            .ok_or_else(|| anyhow::anyhow!("User not found in database"))?;

        let mut peers = HashMap::new();
        let mut peersmap = HashMap::new();
        let mut connect_tasks = Vec::new();
        for peer in all_peers {
            if let Some(peer_user_id) = peer.get_user_id() {
                peers.insert(peer_user_id, peer.clone());
                let shared_key = peer.shrdkeygen(prvkey.clone());
                let addr = peer.get_addr();
                connect_tasks.push((peer_user_id, peer, shared_key, tokio::spawn(async move {
                    timeout(Duration::from_secs(1), TcpStream::connect(addr)).await.ok().and_then(|r| r.ok())
                })));
            }
        }
        for (peer_user_id, peer, shared_key, task) in connect_tasks {
            let tcp_stream = task.await.unwrap_or(None)
                .map(|s| Arc::new(TokioMutex::new(s)));
            peersmap.insert(peer_user_id, (peer, shared_key, tcp_stream));
        }

        let join_message = db.create_message(0, format!("{} joined the chat", user_name)).await?;
        let mut message_history_vec = message_history;
        message_history_vec.push(join_message);

        Ok((Self {
            message_history: Arc::new(RwLock::new(message_history_vec)),
            members: Arc::new(RwLock::new(members)),
            peers: Arc::new(RwLock::new(peers)),
            current_user,
            db
        }, peersmap))
    }
}


//TODO: sending and receiving messages
//TODO: presence update (if last heartbeat is None, users are online)
//TODO: typing_indicators - show when peer is typing (special message packets)
//TODO: read_receipts - notify when messages are seen (last heartbeat time > sent time)
//TODO: db updates and syncs (when connecting and when exiting only)
