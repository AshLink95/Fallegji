use anyhow::Result;
use zmq::{Context, Socket, CurveKeyPair, DEALER, ROUTER};
use std::{collections::HashMap, sync::Arc, net::SocketAddr};
use tokio::{sync::Mutex, task, time::{sleep, Duration, interval}};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use serde_json;
use time::OffsetDateTime;

pub struct Peer {
    id: i32,
    user_id: u64,
    pubkey: String,
    addr: SocketAddr,
    last_heartbeat: Option<i64> // peer online if None
}

pub struct Connection {
    context: Arc<Context>,
    peers: Arc<Mutex<HashMap<u64, Peer>>>, // user_id -> Peer
    socket: Socket, // Lives in one thread/task
    rendezvous: SocketAddr
}

//TODO: key generation
//TODO: verification and checking of peers
//TODO: rendez-vous server fallback (where to meet and automatically route)
//TODO: direct connection, keepalive and reconnect (default mode)
