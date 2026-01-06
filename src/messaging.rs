use zeromq;
use tokio::task;
use time::OffsetDateTime;
use crate::auth::User;

pub struct Message {
    id: i32,
    sender_id: u64,
    contents: String,
    created_at: i64
}

//TODO: make actual messaging traits and finish writing them

impl Message {
    pub fn new(id: i32, sender_id: u64, contents: String) -> Self {
        let created_at = OffsetDateTime::now_utc().unix_timestamp();
        Self { id, sender_id, contents, created_at }
    }

    pub fn get_id(&self) -> i32 { self.id }
    pub fn get_sender_id(&self) -> u64 { self.sender_id }
    pub fn get_contents(&self) -> String { self.contents.clone() }
    pub fn get_created_at(&self) -> i64 { self.created_at }

    pub fn set_contents(&mut self, contents: String) { self.contents = contents; }
    pub fn contents_display(&self) -> String { self.contents.clone() }
}
