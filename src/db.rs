use hex::ToHex;
use nix::unistd::Uid;
use rusqlite::{Connection, params};
use tokio::task;
use anyhow::{Result, bail};
use x25519_dalek::StaticSecret;
use std::sync::{Arc, Mutex};

use crate::{auth::{Authentication, User}, messaging::Message, connection::Peer};

pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    /// Database initialization
    /// Exceptionally sync, not async
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                role TEXT CHECK(role IN ('admin', 'member')),
                uid INTEGER NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS peers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                addr TEXT NOT NULL,
                pubkey BLOB NOT NULL,
                last_heartbeat INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id TEXT NOT NULL,
                contents TEXT NOT NULL,
                sent_at INTEGER DEFAULT (strftime('%s', 'now')),
                FOREIGN KEY (sender_id) REFERENCES users(id)
            )",
            [],
        )?;

        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    // Creation
    /// User creation
    pub async fn create_user(&self, key: String, name: String, uid: Uid) -> Result<User> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let user = User::new(key, name.clone(), uid);
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT INTO users (id, name, role, uid) VALUES (?1, ?2, ?3, ?4)",
                params![ user.get_id().to_string(), name, None::<&str>, uid.as_raw() ],
            )?;
            Ok( user )
        }).await?
    }
    /// Peer creation
    pub async fn create_peer(&self, port: u16) -> Result<(Peer, StaticSecret)> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let (mut peer, prvkey) = Peer::new_out(-1, port)?;
            let pubkey = peer.get_pubkey().to_bytes().encode_hex::<String>();

            conn.execute(
                "INSERT INTO peers (user_id, addr, pubkey) VALUES (?1, ?2, ?3)",
                params![None::<String>, peer.get_addr().to_string(), pubkey]
            )?;
            let id = conn.last_insert_rowid() as i32;
            peer.set_id(id);
            
            Ok((peer, prvkey))
        }). await?
    }
    /// Message creation
    pub async fn create_message(&self, sender_id: u64, contents: String) -> Result<Message> {
        let conn = Arc::clone(&self.conn);
        let sender_id_str = sender_id.to_string();
        let contents_clone = contents.clone();
        
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();

            conn.execute(
                "INSERT INTO messages (sender_id, contents) VALUES (?1, ?2)",
                params![sender_id_str, contents_clone],
            )?;

            let message_id = conn.last_insert_rowid() as i32;
            let mut stmt = conn.prepare(
                "SELECT m.sent_at, u.id, u.name, u.role
                 FROM messages m 
                 JOIN users u ON m.sender_id = u.id 
                 WHERE m.id = ?1"
            )?;

            let message = stmt.query_row(params![message_id], |_| {
                Ok(Message::new(message_id, sender_id, contents))
            })?;
            
            Ok(message)
        }).await?
    }

    // Read instance from id
    /// User instance reader from id
    pub async fn read_user(&self, id: u64) -> Result<User> {
        let conn = Arc::clone(&self.conn);
        let id_str = id.to_string();
        
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT id, name, role, uid FROM users WHERE id = ?1"
            )?;

            let key = String::from("rand"); //dbg: key will be fetched from peers, using corresponding user id
            
            let (user, user_id) = stmt.query_row(params![id_str], |row| {
                let name: String = row.get(1)?;
                let uid: Uid = row.get::<_, Option<u32>>(3)?.map(Uid::from).unwrap();
                let mut user = User::new(
                    key.clone(),
                    name,
                    uid
                );
                if let Some(r) = row.get::<_, Option<String>>(2)?.map(|s| s.parse().unwrap()) { user.set_role(r); }
                let user_id: u64 = row.get::<_, Option<String>>(0)?.map(|s| s.parse::<u64>().unwrap()).unwrap();
                Ok((user, user_id))
            })?;

            if !user.ver_id(key, user_id) {
                bail!("Invalid key or user");
            }
            
            Ok(user)
        }).await?
    }
    //TODO: Peer instance reader from id
    /// Message instance reader from id
    pub async fn read_message(&self, id: i32) -> Result<Message> {
        let conn = Arc::clone(&self.conn);
        
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT id, sender_id, contents, sent_at FROM messages WHERE id = ?1"
            )?;
            
            let message = stmt.query_row(params![id], |row| {
                let id = row.get(0)?;
                let sender_id = row.get::<_, String>(1)?.parse().unwrap();
                let contents = row.get(2)?;
                let sent_at = row.get(3)?;
                let mut message = Message::new(id, sender_id, contents);
                message.set_date(sent_at);
                Ok(message)
            })?;
            
            Ok(message)
        }).await?
    }

    //TODO: (CR)UD & list_all/load_all for both users and messages
}

// impl ServerDB for Database {
//     fn sync_clients(&self) -> Result<()> {
//         Ok(())
//     }
//     fn listen_to_clients(&self) -> Result<()> {
//         Ok(())
//     }
// }

// impl ClientDB for Database {
//     fn sync_with_server(&self) -> Result<()> {
//         Ok(())
//     }
//
//     fn lock_client_copy(&self) -> Result<()> {
//         match self.conn.lock() {
//             Ok(guard) => {
//                 guard.execute_batch("PRAGMA query_only = 1")?;
//                 Ok(())
//             },
//             Err(poisoned) => {
//                 let conn = poisoned.into_inner();
//                 conn.execute_batch("PRAGMA query_only = 1")?;
//                 Ok(())
//             }
//         }
//     }
// }
