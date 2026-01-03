// This will be responsible for Socket communication (0MQ + tokio)
use crate::auth::User;

pub struct Message {
    pub id: i32,
    pub sender: User,
    pub contents: String,
    pub created_at: i64
}
