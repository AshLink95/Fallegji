#[derive(PartialEq, Eq)]
pub enum Screen { Home, InitServer, InitClient, Chat }

pub mod home;
pub mod initialization;
pub mod chat;
