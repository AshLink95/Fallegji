use rusqlite::{Connection, params};
use tokio::task;
use anyhow::Result;
use std::sync::{Arc, Mutex};

use crate::{auth::User, messaging::Message}; //TODO: will include tunneling also

pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

pub trait ServerDB { //TODO: requires messaging and tunneling
    fn sync_clients(&self) -> Result<()>;
    fn listen_to_clients(&self) -> Result<()>;
}

pub trait ClientDB { //TODO: requires messaging and tunneling
    fn sync_with_server(&self) -> Result<()>;
    /// Method invoked after closing chat room to keep clients from manipulating it
    fn lock_client_copy(&self) -> Result<()>;
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
                role TEXT CHECK(role IN ('server', 'client')),
                addr TEXT
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id TEXT NOT NULL,
                contents TEXT NOT NULL,
                created_at INTEGER DEFAULT (strftime('%s', 'now')),
                FOREIGN KEY (sender_id) REFERENCES users(id)
            )",
            [],
        )?;

        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    // Creation
    /// User creation
    pub async fn create_user(&self, key: String, name: String) -> Result<User> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let user = User::new(key, name.clone());
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT INTO users (id, name, role, addr) VALUES (?1, ?2, ?3, ?4)",
                params![ user.get_id().to_string(), name, None::<&str>, None::<&str> ],
            )?;
            Ok( user )
        }).await?
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
                "SELECT m.created_at, u.id, u.name, u.role, u.addr 
                 FROM messages m 
                 JOIN users u ON m.sender_id = u.id 
                 WHERE m.id = ?1"
            )?;

            let message = stmt.query_row(params![message_id], |row| {
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
                "SELECT id, name, role, addr FROM users WHERE id = ?1"
            )?;

            let key = String::from("rand"); //dbg: key will be fetched from tunnels, using corresponding user id
            
            let user = stmt.query_row(params![id_str], |row| {
                let name: String = row.get(1)?;
                let mut user = User::new(key, name);
                if let Some(r) = row.get::<_, Option<String>>(2)?.map(|s| s.parse().unwrap()) { user.set_role(r); }
                if let Some(a) = row.get::<_, Option<String>>(3)?.and_then(|s| s.parse().ok()) { user.set_addr(a); }
                Ok(user)
            })?;
            
            Ok(user)
        }).await?
    }

    /// Message instance reader from id
    pub async fn read_message(&self, id: i32) -> Result<Message> {
        let conn = Arc::clone(&self.conn);
        
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT id, sender_id, contents, created_at FROM messages WHERE id = ?1"
            )?;
            
            let message = stmt.query_row(params![id], |row| {
                let id = row.get(0)?;
                let sender_id = row.get::<_, String>(1)?.parse().unwrap();
                let contents = row.get(2)?;
                let created_at = row.get(3)?;
                let mut message = Message::new(id, sender_id, contents);
                message.set_date(created_at);
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
