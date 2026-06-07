use std::{collections::HashMap, sync::{Arc, RwLock}};
use anyhow::Result;
use tokio::sync::Mutex as TokioMutex;
use x25519_dalek::{PublicKey, StaticSecret};
use time::OffsetDateTime;
use crate::{auth::{Role, Uid, User}, connection::{Communication, Connection, KeyGen, Peermap}, db::Database};

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
    pub current_user: User,
    pub db: Database
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
        let db_path = format!("{}__{}.db", user_name, chat_name);
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

        let system_message = db.create_message(0, format!("Chat '{}' created by {}", chat_name, user_name), None).await?;
        let message_history = vec![system_message];

        let mut peermap = Peermap::new();
        let self_key = peer.shrdkeygen(prvkey.clone());
        peermap.insert(user_id, (peer.clone(), self_key, None));

        Ok((Self {
            message_history: Arc::new(RwLock::new(message_history)),
            members: Arc::new(RwLock::new(members)),
            current_user,
            db
        }, prvkey, pubkey, user_id, peer_id, peermap))
    }

    /// Non-admin joiner: like `new`, but the local user is a Member and there's no
    /// "created" notice. Real chat state arrives via the admin's DB sync once accepted.
    pub async fn join(chat_name: &str, user_name: &str, port: u16) -> Result<(Self, StaticSecret, PublicKey, u64, i32, Peermap)> {
        let db_path = format!("{}__{}.db", user_name, chat_name);
        let db = Database::new(&db_path)?;

        let (peer, prvkey) = db.create_peer(port).await?;
        let peer_id = peer.get_id();
        let pubkey = peer.get_pubkey();
        let pubkey_hex = hex::encode(pubkey.as_bytes());

        let uid = Uid::getuid();
        let current_user = db.create_user(pubkey_hex, user_name.to_string(), uid).await?;
        let user_id = current_user.get_id();
        db.update_peer_link_user(peer.get_id(), user_id).await?;

        db.delete_user(0).await?;
        let sys = db.create_sys().await?;
        let mut members = HashMap::new();
        members.insert(user_id, current_user.clone());
        members.insert(0u64, sys);

        let mut peermap = Peermap::new();
        let self_key = peer.shrdkeygen(prvkey.clone());
        peermap.insert(user_id, (peer.clone(), self_key, None));

        Ok((Self {
            message_history: Arc::new(RwLock::new(Vec::new())),
            members: Arc::new(RwLock::new(members)),
            current_user,
            db
        }, prvkey, pubkey, user_id, peer_id, peermap))
    }

    pub async fn old(chat_name: &str, user_name: &str, prvkey: StaticSecret) -> Result<(Self, Peermap)> {
        let db_path = format!("{}__{}.db", user_name, chat_name);
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

        let mut peersmap = HashMap::new();
        let mut connect_tasks = Vec::new();
        for peer in all_peers {
            if let Some(peer_user_id) = peer.get_user_id() {
                let shared_key = peer.shrdkeygen(prvkey.clone());
                let addrs = peer.get_addrs();
                connect_tasks.push((peer_user_id, peer, shared_key, tokio::spawn(async move {
                    crate::connection::connect_any(&addrs).await
                })));
            }
        }
        for (peer_user_id, peer, shared_key, task) in connect_tasks {
            let tcp_stream = task.await.unwrap_or(None)
                .map(|s| Arc::new(TokioMutex::new(s)));
            peersmap.insert(peer_user_id, (peer, shared_key, tcp_stream));
        }

        Ok((Self {
            message_history: Arc::new(RwLock::new(message_history)),
            members: Arc::new(RwLock::new(members)),
            current_user,
            db
        }, peersmap))
    }

    pub fn get_admin(&self) -> Option<u64> {
        self.members.read().unwrap().iter().find(
            |(_, user)| user.get_role().is_some_and(|r| r == Role::Admin)
        ).map(|(id, _)| *id)
    }

    pub async fn send_message(&self, conn: &Connection, sender_id: u64, contents: String) -> Result<()> {
        let message = self.db.create_message(sender_id, contents, None).await?;
        self.message_history.write().unwrap().push(message.clone());
        conn.send_msg(message).await?;
        Ok(())
    }

    pub async fn send_join(&self, conn: &Connection) -> Result<()> {
        let user_name = self.current_user.get_name();
        self.send_message(conn, 0, format!("{} joined the chat", user_name)).await
    }
}
