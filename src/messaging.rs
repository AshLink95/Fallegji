use std::collections::HashMap;
use chacha20poly1305::Key;
// use zeromq;
// use tokio::task;
use time::OffsetDateTime;
use crate::{auth::User, connection::Peer, db::Database};

pub struct Message {
    id: i32,
    sender_id: u64,
    contents: String,
    sent_at: i64
}

pub struct Chat {
    message_history: Vec<Message>,
    members: HashMap<u64, User>, // user_id -> User
    peers: HashMap<u64, (Peer, Key)>, // user_id -> Peer, shrdkey
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


//TODO: listening for messages
//TODO: sending messages
//TODO: presence update
//TODO: typing_indicators - show when peer is typing
//TODO: read_receipts - notify when messages are seen
//TODO: db syncs (when connecting and when exiting only)
