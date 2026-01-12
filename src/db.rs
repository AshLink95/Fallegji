use std::{collections::HashSet, net::SocketAddr, sync::{Arc, Mutex}};
use anyhow::{Result, bail};
use hex::{ToHex, encode};
use nix::unistd::Uid;
use rusqlite::{Connection, params};
use tokio::task;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{auth::{Authentication, Role, User}, connection::Peer, messaging::Message};

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

            let mut stmt_u = conn.prepare(
                "SELECT name, uid FROM users WHERE id = ?1"
            )?;

            let peer: Peer = match stmt.query_row(params![id], |row| {
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

    // Update
    /// Update role in a user
    pub async fn update_user_role(&self, id: u64, role: Role) -> Result<bool> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE users SET role = ?1 WHERE id = ?2",
                params![role.to_string(), id.to_string()],
            )?;

            Ok(conn.changes() > 0)
        }).await?
    }
    /// Update user_id in a peer
    pub async fn update_peer_link_user(&self, id: i32, user_id: u64 ) -> Result<bool> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt_p = conn.prepare(
                "SELECT pubkey FROM peers WHERE id = ?1"
            )?;
            let mut stmt_u = conn.prepare(
                "SELECT name, uid FROM users WHERE id = ?1"
            )?;

            let key: String = match stmt_p.query_row(params![id], |row| {
                Ok(row.get::<_, [u8; 32]>(0)?.encode_hex())
            }) {
                Ok(m) => m,
                Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(false),
                Err(e) => return Err(e.into()),
            };
            let (name, uid): (String, Uid) = match stmt_u.query_row(params![user_id.to_string()], |row| {
                Ok((row.get(0)?, Uid::from(row.get::<_, u32>(1)?)))
            }) {
                Ok(m) => m,
                Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(false),
                Err(e) => return Err(e.into()),
            };
            let user = User::new(key.clone(), name, uid);
            if !user.ver_id(key, user_id) {
                return Ok(false)
            }

            conn.execute(
                "UPDATE peers SET user_id = ?1 WHERE id = ?2",
                params![user_id.to_string(), id],
            )?;

            Ok(conn.changes() > 0)
        }).await?
    }
    /// Update address in a peer
    pub async fn update_peer_addr(&self, id: i32, addr: SocketAddr) -> Result<bool> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE peers SET addr = ?1 WHERE id = ?2",
                params![addr.to_string(), id],
            )?;

            Ok(conn.changes() > 0)
        }).await?
    }
    /// Update last heartbeat in a peer
    pub async fn update_peer_last_heartbeat(&self, id: i32, last_heartbeat: Option<i64>) -> Result<bool> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE peers SET last_heartbeat = ?1 WHERE id = ?2",
                params![last_heartbeat, id],
            )?;

            Ok(conn.changes() > 0)
        }).await?
    }
    /// Update contents in a message
    pub async fn update_message_contents(&self, id: i32, contents: String) -> Result<bool> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE messages SET contents = ?1 WHERE id = ?2",
                params![contents, id],
            )?;

            Ok(conn.changes() > 0)
        }).await?
    }
    /// Update date in a message
    pub async fn update_message_date(&self, id: i32, date: i64) -> Result<bool> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE messages SET sent_at = ?1 WHERE id = ?2",
                params![date, id],
            )?;

            Ok(conn.changes() > 0)
        }).await?
    }

    // Deletion
    /// Delete user by id
    pub async fn delete_user(&self, id: u64) -> Result<bool> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "DELETE FROM users WHERE id = ?1",
                params![id.to_string()],
            )?;
            Ok(conn.changes() > 0)
        }).await?
    }
    /// Delete peer by id
    pub async fn delete_peer(&self, id: i32) -> Result<bool> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "DELETE FROM peers WHERE id = ?1",
                params![id],
            )?;
            Ok(conn.changes() > 0)
        }).await?
    }
    /// Delete message by id
    pub async fn delete_message(&self, id: i32) -> Result<bool> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "DELETE FROM messages WHERE id = ?1",
                params![id],
            )?;
            Ok(conn.changes() > 0)
        }).await?
    }

    // Loading
    /// Loading all users from DB
    pub async fn load_all_users(&self) -> Result<Vec<User>> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT id FROM users"
            )?;
            
            let user_ids: Vec<String> = stmt
                .query_map([], |row| row.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            
            let mut users = Vec::new();
            for id_str in user_ids {
                let id: u64 = id_str.parse().unwrap();
                
                // Get pubkey from peers
                let mut stmt_k = conn.prepare(
                    "SELECT pubkey FROM peers WHERE user_id = ?1"
                )?;
                let key: String = match stmt_k.query_row(params![&id_str], |row| {
                    let pubkey_bytes: Vec<u8> = row.get(0)?;
                    Ok(hex::encode(pubkey_bytes))
                }) {
                    Ok(k) => k,
                    Err(rusqlite::Error::QueryReturnedNoRows) => continue,
                    Err(e) => return Err(e.into()),
                };
                
                // Get user data
                let mut stmt_u = conn.prepare(
                    "SELECT name, role, uid FROM users WHERE id = ?1"
                )?;
                let user: User = match stmt_u.query_row(params![&id_str], |row| {
                    let name: String = row.get(0)?;
                    let uid: Uid = Uid::from(row.get::<_, u32>(2)?);
                    let mut user = User::new(key.clone(), name, uid);
                    if let Some(r) = row.get::<_, Option<String>>(1)?.map(|s| s.parse().unwrap()) {
                        user.set_role(r);
                    }
                    Ok(user)
                }) {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                
                if user.ver_id(key, id) {
                    users.push(user);
                }
            }
            
            Ok(users)
        }).await?
    }
    /// Loading all peers from DB
    pub async fn load_all_peers(&self) -> Result<Vec<Peer>> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT id FROM peers"
            )?;
            
            let peer_ids: Vec<i32> = stmt
                .query_map([], |row| row.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            
            let mut peers = Vec::new();
            for id in peer_ids {
                let mut stmt_p = conn.prepare(
                    "SELECT user_id, addr, pubkey, last_heartbeat FROM peers WHERE id = ?1"
                )?;
                
                let peer: Option<Peer> = stmt_p.query_row(params![id], |row| {
                       let peer_user_id: u64 = match row.get::<_, Option<String>>(0)? {
                           Some(s) => s.parse::<u64>().map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?,
                           None => return Err(rusqlite::Error::InvalidParameterName("Missing user_id".into())),
                       };
                       
                       let mut stmt_u = conn.prepare(
                           "SELECT name, uid FROM users WHERE id = ?1"
                       )?;
                       let user_id: String = peer_user_id.to_string();
                       let (peer_name, peer_uid): (String, Uid) = match stmt_u.query_row(params![user_id], |row| {
                           let name: String = row.get::<_, String>(0)?;
                           let uid: Uid = Uid::from(row.get::<_, u32>(1)?);
                           Ok((name, uid))
                       }) {
                           Ok((n, u)) => (n, u),
                           Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
                           Err(e) => return Err(e),
                       };
                       
                       let addr_str: String = row.get(1)?;
                       let addr = addr_str.parse().map_err(|e: std::net::AddrParseError| rusqlite::Error::InvalidParameterName(e.to_string()))?;
                       let pubkey_bytes: Vec<u8> = row.get(2)?;
                       let pubkey_array: [u8; 32] = pubkey_bytes.try_into()
                           .map_err(|_| rusqlite::Error::InvalidParameterName("Invalid pubkey length".into()))?;
                       let pubkey = PublicKey::from(pubkey_array);
                       let last_heartbeat = row.get::<_, Option<i64>>(3)?;
                       
                       let peer = Peer::new_in(id, peer_name, peer_uid, peer_user_id, addr, pubkey, last_heartbeat)
                           .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
                       Ok(Some(peer))
                   }).unwrap_or_default();
                
                if let Some(p) = peer {
                    peers.push(p);
                }
            }
            
            Ok(peers)
        }).await?
    }
    /// Loading all messages from DB (ordered by sent_at)
    pub async fn load_all_messages(&self) -> Result<Vec<Message>> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT id FROM messages ORDER BY sent_at ASC"
            )?;
            
            let message_ids: Vec<i32> = stmt
                .query_map([], |row| row.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            
            let mut messages = Vec::new();
            for id in message_ids {
                let mut stmt_m = conn.prepare(
                    "SELECT sender_id, contents, sent_at FROM messages WHERE id = ?1"
                )?;
                
                let message: Message = match stmt_m.query_row(params![id], |row| {
                    let sender_id = row.get::<_, String>(0)?.parse().unwrap();
                    let contents = row.get(1)?;
                    let sent_at = row.get(2)?;
                    let mut message = Message::new(id, sender_id, contents);
                    message.set_date(sent_at);
                    Ok(message)
                }) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                
                messages.push(message);
            }
            
            Ok(messages)
        }).await?
    }

    // Saving
    /// Saving all users to DB
    pub async fn save_all_users(&self, users: Vec<User>) -> Result<usize> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            
            // Get existing user IDs
            let mut stmt = conn.prepare("SELECT id FROM users")?;
            let existing_ids: HashSet<String> = stmt
                .query_map([], |row| row.get(0))?
                .collect::<Result<_, _>>()?;
            
            // Build set of new user IDs
            let new_ids: HashSet<String> = users.iter()
                .map(|u| u.get_id().to_string())
                .collect();
            
            // Update existing users first
            for user in &users {
                let id_str = user.get_id().to_string();
                if existing_ids.contains(&id_str) {
                    // Get pubkey for verification
                    let mut stmt_k = conn.prepare(
                        "SELECT pubkey FROM peers WHERE user_id = ?1"
                    )?;
                    let key: String = match stmt_k.query_row(params![&id_str], |row| {
                        let pubkey_bytes: Vec<u8> = row.get(0)?;
                        Ok(hex::encode(pubkey_bytes))
                    }) {
                        Ok(k) => k,
                        Err(_) => continue, // Skip if no peer found
                    };
                    
                    // Verify user before update
                    if !user.ver_id(key, user.get_id()) {
                        continue; // Skip invalid users
                    }
                    
                    // Update existing
                    conn.execute(
                        "UPDATE users SET name = ?1, role = ?2, uid = ?3 WHERE id = ?4",
                        params![
                            user.get_name(),
                            user.get_role().map(|r| r.to_string()),
                            user.get_uid().as_raw(),
                            id_str
                        ],
                    )?;
                }
            }
            
            // Delete users not in new set
            for old_id in existing_ids.difference(&new_ids) {
                conn.execute("DELETE FROM users WHERE id = ?1", params![old_id])?;
            }
            
            // Insert new users
            for user in &users {
                let id_str = user.get_id().to_string();
                if !existing_ids.contains(&id_str) {
                    // Get pubkey for verification
                    let mut stmt_k = conn.prepare(
                        "SELECT pubkey FROM peers WHERE user_id = ?1"
                    )?;
                    let key: String = match stmt_k.query_row(params![&id_str], |row| {
                        let pubkey_bytes: Vec<u8> = row.get(0)?;
                        Ok(hex::encode(pubkey_bytes))
                    }) {
                        Ok(k) => k,
                        Err(_) => continue, // Skip if no peer found
                    };
                    
                    // Verify user before insert
                    if !user.ver_id(key, user.get_id()) {
                        continue; // Skip invalid users
                    }
                    
                    // Insert new
                    conn.execute(
                        "INSERT INTO users (id, name, role, uid) VALUES (?1, ?2, ?3, ?4)",
                        params![
                            id_str,
                            user.get_name(),
                            user.get_role().map(|r| r.to_string()),
                            user.get_uid().as_raw()
                        ],
                    )?;
                }
            }
            
            // Count total users in DB
            let mut count_stmt = conn.prepare("SELECT COUNT(*) FROM users")?;
            let count = count_stmt.query_row([], |row| row.get::<_, u32>(0))?;
            
            Ok(count as usize)
        }).await?
    }
    /// Saving all peers to DB
    pub async fn save_all_peers(&self, peers: Vec<Peer>) -> Result<usize> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            
            // Get existing peer IDs
            let mut stmt = conn.prepare("SELECT id FROM peers")?;
            let existing_ids: HashSet<i32> = stmt
                .query_map([], |row| row.get(0))?
                .collect::<Result<_, _>>()?;
            
            // Build set of new peer IDs
            let new_ids: HashSet<i32> = peers.iter()
                .map(|p| p.get_id())
                .collect();
            
            // Update existing peers first
            for peer in &peers {
                let id = peer.get_id();
                if existing_ids.contains(&id) {
                    // Update existing
                    conn.execute(
                        "UPDATE peers SET user_id = ?1, addr = ?2, pubkey = ?3, last_heartbeat = ?4 WHERE id = ?5",
                        params![
                            peer.get_user_id().map(|u| u.to_string()),
                            peer.get_addr().to_string(),
                            peer.get_pubkey().to_bytes(),
                            peer.get_last_heartbeat(),
                            id
                        ],
                    )?;
                }
            }
            
            // Delete peers not in new set
            for old_id in existing_ids.difference(&new_ids) {
                conn.execute("DELETE FROM peers WHERE id = ?1", params![old_id])?;
            }
            
            // Insert new peers
            for peer in &peers {
                let id = peer.get_id();
                if !existing_ids.contains(&id) {
                    // Insert new
                    conn.execute(
                        "INSERT INTO peers (id, user_id, addr, pubkey, last_heartbeat) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            id,
                            peer.get_user_id().map(|u| u.to_string()),
                            peer.get_addr().to_string(),
                            peer.get_pubkey().to_bytes(),
                            peer.get_last_heartbeat()
                        ],
                    )?;
                }
            }
            
            // Count total peers in DB
            let mut count_stmt = conn.prepare("SELECT COUNT(*) FROM peers")?;
            let count = count_stmt.query_row([], |row| row.get::<_, u32>(0))?;
            
            Ok(count as usize)
        }).await?
    }
    /// Saving all messages to DB
    pub async fn save_all_messages(&self, messages: Vec<Message>) -> Result<usize> {
        let conn = Arc::clone(&self.conn);
        task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            
            // Get existing message IDs
            let mut stmt = conn.prepare("SELECT id FROM messages")?;
            let existing_ids: HashSet<i32> = stmt
                .query_map([], |row| row.get(0))?
                .collect::<Result<_, _>>()?;
            
            // Build set of new message IDs
            let new_ids: HashSet<i32> = messages.iter()
                .map(|m| m.get_id())
                .collect();
            
            // Update existing messages first
            for message in &messages {
                let id = message.get_id();
                if existing_ids.contains(&id) {
                    // Update existing
                    conn.execute(
                        "UPDATE messages SET sender_id = ?1, contents = ?2, sent_at = ?3 WHERE id = ?4",
                        params![
                            message.get_sender_id().to_string(),
                            message.get_contents(),
                            message.get_sent_at(),
                            id
                        ],
                    )?;
                }
            }
            
            // Delete messages not in new set
            for old_id in existing_ids.difference(&new_ids) {
                conn.execute("DELETE FROM messages WHERE id = ?1", params![old_id])?;
            }
            
            // Insert new messages
            for message in &messages {
                let id = message.get_id();
                if !existing_ids.contains(&id) {
                    // Insert new
                    conn.execute(
                        "INSERT INTO messages (id, sender_id, contents, sent_at) VALUES (?1, ?2, ?3, ?4)",
                        params![
                            id,
                            message.get_sender_id().to_string(),
                            message.get_contents(),
                            message.get_sent_at()
                        ],
                    )?;
                }
            }
            
            // Count total messages in DB
            let mut count_stmt = conn.prepare("SELECT COUNT(*) FROM messages")?;
            let count = count_stmt.query_row([], |row| row.get::<_, u32>(0))?;
            
            Ok(count as usize)
        }).await?
    }
}
