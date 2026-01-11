use std::sync::{Arc, Mutex};
use anyhow::{Result, bail};
use hex::encode;
use nix::unistd::Uid;
use rusqlite::{Connection, params};
use tokio::task;
use x25519_dalek::{PublicKey, StaticSecret};

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
            let pubkey = peer.get_pubkey().to_bytes();

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
    pub async fn read_user(&self, id: u64) -> Result<Option<User>> {
        let conn = Arc::clone(&self.conn);
        let id_str = id.to_string();
        
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT name, role, uid FROM users WHERE id = ?1"
            )?;

            let mut stmt_k = conn.prepare(
                "SELECT pubkey FROM peers WHERE user_id = ?1"
            )?;
            let key: String = match stmt_k.query_row(params![id_str], |row| {
                let pubkey_bytes: Vec<u8> = row.get(0)?;
                Ok(encode(pubkey_bytes))
            }) {
                Ok(k) => k,
                Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
                Err(e) => return Err(e.into()),
            };

            let user: User = match stmt.query_row(params![id_str], |row| {
                let name: String = row.get(0)?;
                let uid: Uid = Uid::from(row.get::<_, u32>(2)?);
                let mut user = User::new(
                    key.clone(),
                    name,
                    uid
                );
                if let Some(r) = row.get::<_, Option<String>>(1)?.map(|s| s.parse().unwrap()) { user.set_role(r); }
                Ok(user)
            }) {
                Ok(u) => u,
                Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
                Err(e) => return Err(e.into()),
            };

            if !user.ver_id(key, id) {
                bail!("Invalid key or user");
            }
            
            Ok(Some(user))
        }).await?
    }
    ///Peer instance reader from id
    pub async fn read_peer(&self, id: i32) -> Result<Option<Peer>> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT user_id, addr, pubkey, last_heartbeat FROM peers WHERE id = ?1"
            )?;

            let peer: Peer = match stmt.query_row(params![id], |row| {
                let mut stmt_u = conn.prepare(
                    "SELECT name, uid FROM users WHERE id = ?1"
                )?;
                let peer_user_id: u64 = match row.get::<_, Option<String>>(0)? {
                    Some(s) => s.parse::<u64>().map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?,
                    None => return Err(rusqlite::Error::InvalidParameterName("Missing user_id".into())),
                };
                let user_id: String = peer_user_id.to_string();
                let (peer_name, peer_uid): (String, Uid) = match stmt_u.query_row(params![user_id], |row| {
                    let name: String = row.get::<_, String>(0)?;
                    let uid: Uid = Uid::from(row.get::<_, u32>(1)?);
                    Ok((name, uid))
                }) {
                    Ok((n, u)) => (n,u),
                    Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
                    Err(e) => return Err(e),
                };

                let addr_str: String = row.get(1)?;
                let addr = addr_str.parse().map_err(|e: std::net::AddrParseError| rusqlite::Error::InvalidParameterName(e.to_string()))?;
                let pubkey = PublicKey::from(row.get::<_, [u8; 32]>(2)?);
                let last_heartbeat = row.get::<_, Option<i64>>(3)?;

                let peer = Peer::new_in(id, peer_name, peer_uid, peer_user_id, addr, pubkey, last_heartbeat).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                Ok(Some(peer))
            }) {
                Ok(p) => p.unwrap(),
                Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
                Err(e) => return Err(e.into()),
            };


            Ok(Some(peer))
        }).await?
    }
    /// Message instance reader from id
    pub async fn read_message(&self, id: i32) -> Result<Option<Message>> {
        let conn = Arc::clone(&self.conn);
        
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT sender_id, contents, sent_at FROM messages WHERE id = ?1"
            )?;
            
            let message: Message = match stmt.query_row(params![id], |row| {
                let sender_id = row.get::<_, String>(0)?.parse().unwrap();
                let contents = row.get(1)?;
                let sent_at = row.get(2)?;
                let mut message = Message::new(id, sender_id, contents);
                message.set_date(sent_at);
                Ok(message)
            }) {
                Ok(m) => m,
                Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            
            Ok(Some(message))
        }).await?
    }

    //TODO: (CR)UD [atomic updates] & list_all/load_all for users, peers and messages
    pub fn placeholder_linkp2u(&self, user: &User, peer: &Peer) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE peers SET user_id = ?1 WHERE id = ?2",
            params![user.get_id().to_string(), peer.get_id()],
        )?;

        Ok(())
    }
}
