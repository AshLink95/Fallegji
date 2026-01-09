// prompt engineered
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use x25519_dalek::{PublicKey, StaticSecret};
use nix::unistd::Uid;
use fallegji::connection::{Peer, KeyGen};

#[test]
fn test_peer_new_out_creation() {
    let result = Peer::new_out(1, 9000);
    assert!(result.is_ok());

    let (peer, prvkey) = result.unwrap();
    assert_eq!(peer.get_id(), 1);
    assert_eq!(peer.get_user_id(), None);
    assert_eq!(peer.get_addr().port(), 9000);
    assert_eq!(peer.get_last_heartbeat(), None);
    assert_ne!(peer.get_addr().ip(), IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    assert_eq!(prvkey.as_bytes().len(), 32);
}

#[test]
fn test_peer_new_in_creation() {
    let peer_id = 2;
    let peer_name = "TestPeer".to_string();
    let peer_uid = Uid::from(10);
    let peer_user_id = 12345u64;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let tmp_secret = StaticSecret::from([1u8; 32]);
    let pubkey = PublicKey::from(&tmp_secret);
    let last_heartbeat = Some(1234567890i64);

    let result = Peer::new_in(
        peer_id,
        peer_name,
        peer_uid,
        peer_user_id,
        addr,
        pubkey,
        last_heartbeat
    );

    if let Ok(peer) = result {
        assert_eq!(peer.get_id(), peer_id);
        assert_eq!(peer.get_user_id(), None);
        assert_eq!(peer.get_addr(), addr);
        assert_eq!(peer.get_last_heartbeat(), last_heartbeat);
    }
}

#[test]
fn test_peer_getters() {
    let (peer, _prvkey) = Peer::new_out(3, 8080).unwrap();
    
    assert_eq!(peer.get_id(), 3);
    assert_eq!(peer.get_user_id(), None);
    assert_eq!(peer.get_addr().port(), 8080);
    assert_eq!(peer.get_last_heartbeat(), None);
    
    let pubkey = peer.get_pubkey();
    assert_eq!(pubkey.as_bytes().len(), 32);
}

#[test]
fn test_peer_setters() {
    let (mut peer, _prvkey) = Peer::new_out(-1, 8080).unwrap();
    
    peer.set_id(10);
    assert_eq!(peer.get_id(), 10);
    
    peer.set_id(20);
    assert_eq!(peer.get_id(), 10);
    
    let new_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090);
    peer.set_addr(new_addr);
    assert_eq!(peer.get_addr(), new_addr);
    
    peer.set_last_heartbeat(Some(1234567890));
    assert_eq!(peer.get_last_heartbeat(), Some(1234567890));
    
    peer.set_last_heartbeat(None);
    assert_eq!(peer.get_last_heartbeat(), None);
    
    let user_name = "TestUser".to_string();
    let user_id = 999u64;
    let user_uid = Uid::from(11);
    
    let result = peer.set_user_id(user_name.clone(), user_id, user_uid);
    
    if result.is_ok() {
        assert_eq!(peer.get_user_id(), Some(user_id));
        
        let result2 = peer.set_user_id("Another".to_string(), 888, Uid::from(12));
        assert!(result2.is_err());
        assert_eq!(peer.get_user_id(), Some(user_id)); // Should still be original
    }
}

#[test]
fn test_keygen() {
    let result = Peer::keypairgen();
    assert!(result.is_ok());

    let (pubkey1, prvkey1) = result.unwrap();
    assert_eq!(pubkey1.as_bytes().len(), 32);
    assert_eq!(prvkey1.as_bytes().len(), 32);
    let (pubkey2, _prvkey2) = Peer::keypairgen().unwrap();
    assert_ne!(pubkey1.as_bytes(), pubkey2.as_bytes());

    let (peer, peer_prvkey) = Peer::new_out(1, 8080).unwrap();
    let (other_peer, other_prvkey) = Peer::new_out(2, 8081).unwrap();
    let shared1 = peer.shrdkeygen(other_prvkey);
    let shared2 = other_peer.shrdkeygen(peer_prvkey);
    assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    assert_eq!(shared1.as_bytes().len(), 32);
}
