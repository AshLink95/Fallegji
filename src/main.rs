mod connection;
mod messaging;
mod ui_screens;
mod app;

mod db;
mod auth;
mod vim;
mod config;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    app::app().await?;

    Ok(())
}

// Initial Connection (requires: name, direct/group chat, host/connect, host WiFi IP)
