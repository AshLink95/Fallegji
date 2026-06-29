#[derive(PartialEq, Eq)]
// Quit lets home!'s Ctrl+q signal exit without a `break` (can't break across the loop's async catch-block).
pub enum Screen { Home, InitServer, InitClient, Chat, Quit }

pub mod home;
pub mod initialization;
pub mod chat;
