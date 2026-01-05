#[derive(PartialEq, Eq)]
pub enum Screen { Onboarding, InitServer, InitClient, Chat }

pub mod onboarding;
pub mod initialization;
pub mod chat;
