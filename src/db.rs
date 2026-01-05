use rusqlite::{Connection, params};
use tokio::task;
use anyhow::Result;
use std::sync::{Arc, Mutex};

use crate::{auth::User, messaging::Message};

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
                role TEXT CHECK(role IN ('Server', 'Client')),
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

    //TODO: CRUD for both users and messages
    
    // // CREATE template
    // pub fn create_user( &self, id:i64) -> Result<i64> {
    //     let notif_times_json = serde_json::to_string(&notif_times)?;
    //     let created_at = time::OffsetDateTime::now_utc().unix_timestamp();
    //
    //     self.conn.execute(
    //         "INSERT INTO notifs (title, detail, deadline, notif_times, created_at) 
    //          VALUES (?1, ?2, ?3, ?4, ?5)",
    //         params![
    //             title,
    //             detail,
    //             deadline,
    //             notif_times_json,
    //             created_at
    //         ]
    //     )?;
    //
    //     Ok(self.conn.last_insert_rowid())
    // }
    //
    // // READ template
    // pub fn read(&self, id: i64) -> Result<Notif> {
    //     let mut stmt = self.conn.prepare(
    //         "SELECT title, detail, deadline, notif_times, created_at 
    //          FROM notifs 
    //          WHERE id = ?1"
    //     )?;
    //
    //     let notif = stmt.query_row([id], |row| {
    //         let notif_times_str: String = row.get(3)?;
    //         let notif_times = serde_json::from_str(&notif_times_str)
    //             .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
    //                 3,
    //                 rusqlite::types::Type::Text,
    //                 Box::new(e),
    //             ))?;
    //
    //         Ok(Notif {
    //             id,
    //             title: row.get(0)?,
    //             detail: row.get(1)?,
    //             deadline: row.get(2)?,
    //             notif_times,
    //             created_at: row.get(4)?,
    //         })
    //     })?;
    //
    //     Ok(notif)
    // }
    //
    // // LIST ALL template
    // pub fn list_all(&self) -> Result<Vec<Notif>> {
    //     let mut stmt = self.conn.prepare(
    //         "SELECT id, title, detail, deadline, notif_times, created_at FROM notifs"
    //     )?;
    //
    //     let notifs = stmt.query_map([], |row| {
    //         let notif_times_str: String = row.get(4)?;
    //         let notif_times = serde_json::from_str(&notif_times_str)
    //             .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
    //                 4,
    //                 rusqlite::types::Type::Text,
    //                 Box::new(e),
    //             ))?;
    //
    //         Ok(Notif {
    //             id: row.get(0)?,
    //             title: row.get(1)?,
    //             detail: row.get(2)?,
    //             deadline: row.get(3)?,
    //             notif_times,
    //             created_at: row.get(5)?,
    //         })
    //     })?
    //     .collect::<Result<Vec<_>, _>>()?;
    //
    //     Ok(notifs)
    // }

    //TODO: update and delete
}
