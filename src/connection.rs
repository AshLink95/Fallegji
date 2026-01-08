use anyhow::{Context, Error, Result};
use hex::ToHex;
use nix::unistd::Uid;
use zmq::{Socket, CurveKeyPair};
use std::{collections::HashMap, net::{UdpSocket, SocketAddr}, sync::{Arc, Mutex}};
// use tokio::{task, time::{sleep, Duration, interval}};
// use sha2::{Sha256, Digest};
// use serde::{Serialize, Deserialize};
// use serde_json;
// use time::OffsetDateTime;

use crate::auth::{Authentication, User};

pub struct Peer {
    id: i32,
    user_id: Option<u64>, // Users get created after peers
    addr: SocketAddr,
    pubkey: [u8; 32],
    last_heartbeat: Option<i64> // peer online if None
}

pub struct Connection {
    prvkey: [u8; 32],
    context: Arc<zmq::Context>,
    peers: Arc<Mutex<HashMap<u64, Peer>>>, // user_id -> Peer
    socket: Socket, // Lives in one thread/task
    rendezvous: SocketAddr
}

/// key generation
pub trait KeyGen {
    fn keypairgen() -> Result<CurveKeyPair>;
}

/// verification and checking of new peers
trait Verif { }
/// rendez-vous server fallback (where to meet and automatically route)
trait RendezVous { }
/// direct connection, keepalive and reconnect (default mode)
trait Stable { }

impl Peer {
    /// new created peer
    pub fn new_out(id: i32, port: u16) -> Result<(Self, [u8; 32])> {
        // using UDP trick to get appropriate local IP peers can use
        let tmpsock = UdpSocket::bind("0.0.0.0:0").context("UDP trick failed")?;
        tmpsock.connect("8.8.8.8:80").context("UDP trick failed")?;
        let ip = tmpsock.local_addr().context("UDP trick failed")?.ip();
        let addr = SocketAddr::new(ip, port);

        let keypair = Self::keypairgen()?;
        Ok(( Self {
            id,
            user_id: None,
            addr,
            pubkey: keypair.public_key,
            last_heartbeat: None
        }, keypair.secret_key ))
    }

    /// new imported peer
    pub fn new_in(id:i32, peer_name: String, peer_uid: Uid, addr: SocketAddr, pubkey: [u8; 32], last_heartbeat: Option<i64>) -> Result<Self> {
        let key: String = pubkey.encode_hex();
        let user = User::new(key.clone(), peer_name.clone(), peer_uid);
        if user.ver_id(key, &peer_name) {
            Ok(Self {id, user_id: None, addr, pubkey, last_heartbeat})
        } else {
            Err(Error::msg("Invalid key or user"))
        }
    }
}

impl KeyGen for Peer {
    fn keypairgen() -> Result<CurveKeyPair> {
        CurveKeyPair::new().map_err(Error::new)
    }
}
