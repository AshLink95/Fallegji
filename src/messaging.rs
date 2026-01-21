use std::{collections::HashMap, sync::{Arc, RwLock}};
use anyhow::Result;
use x25519_dalek::StaticSecret;
use time::OffsetDateTime;
use crate::{auth::{User, Uid}, connection::{Peer, Peermap}, db::Database};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Message {
    id: i32,
    sender_id: u64,
    contents: String,
    sent_at: i64
}

pub struct Chat {
    message_history: Arc<RwLock<Vec<Message>>>,
    members: Arc<RwLock<HashMap<u64, User>>>, // user_id -> User
    peers: Arc<RwLock<HashMap<u64, Peer>>>, // user_id -> Peer
    current_user: User,
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
    pub async fn new(chat_name: &str, user_name: &str, port: u16) -> Result<(Self, StaticSecret, Peermap)> {
        let db_path = format!("{}.db", chat_name);
        let db = Database::new(&db_path)?;

        let (peer, prvkey) = db.create_peer(port).await?;
        let pubkey_hex = hex::encode(peer.get_pubkey().as_bytes());

        let uid = Uid::getuid();
        let current_user = db.create_user(pubkey_hex, user_name.to_string(), uid).await?;
        let user_id = current_user.get_id();

        let system_message = db.create_message(0, format!("Chat '{}' created by {}", chat_name, user_name)).await?;
        
        let message_history = vec![system_message];
        let mut members = HashMap::new();
        members.insert(user_id, current_user.clone());
        let peermap = Peermap::new();

        Ok((Self {
            message_history: Arc::new(RwLock::new(message_history)),
            members: Arc::new(RwLock::new(members)),
            peers: Arc::new(RwLock::new(HashMap::new())),
            current_user,
            db
        }, prvkey, peermap))
    }

    pub async fn old(chat_name: &str, user_name: &str) -> Result<Self> {
        let db_path = format!("{}.db", chat_name);
        let db = Database::new(&db_path)?;
        let message_history = db.load_all_messages().await?;
        let all_users = db.load_all_users().await?;
        let all_peers = db.load_all_peers().await?;
        
        let mut members = HashMap::new();
        members.insert(0u64, User::sys());
        for user in all_users {
            members.insert(user.get_id(), user);
        }
        
        let uid = Uid::getuid();
        let current_user = db.read_user(uid.as_raw() as u64).await?
            .ok_or_else(|| anyhow::anyhow!("User not found in database"))?;

        let mut peers_map = HashMap::new();
        for peer in all_peers {
            if let Some(peer_user_id) = peer.get_user_id() {
                peers_map.insert(peer_user_id, peer);
            }
        }

        let join_message = db.create_message(0, format!("{} joined the chat", user_name)).await?;
        let mut message_history_vec = message_history;
        message_history_vec.push(join_message);

        Ok(Self {
            message_history: Arc::new(RwLock::new(message_history_vec)),
            members: Arc::new(RwLock::new(members)),
            peers: Arc::new(RwLock::new(peers_map)),
            current_user,
            db
        })
    }
}


//TODO: sending and receiving messages
//TODO: presence update (if last heartbeat is None, users are online)
//TODO: typing_indicators - show when peer is typing (special message packets)
//TODO: read_receipts - notify when messages are seen (last heartbeat time > sent time)
//TODO: db syncs (when connecting and when exiting only)
