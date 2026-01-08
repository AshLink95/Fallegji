use anyhow::Result;
use zmq::{Context, Socket, CurveKeyPair, DEALER};
use std::sync::Arc;
use tokio::{sync::Mutex, task};
// use getrandom;

//TODO: key generation
//TODO: verification and checking of peers
//TODO: rendez-vous server fallback (where to meet and automatically route)
//TODO: direct connection, keepalive and reconnect (default mode)
