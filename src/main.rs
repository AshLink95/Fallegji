mod db;
mod auth;
mod messaging;
mod tunneling;
mod logging;
mod app;

use anyhow::Result;

fn main() -> Result<()> {
    println!("Hello, world!");
    app::app()?;

    Ok(())
}

// Initial Connection (requires: name, direct/group chat, host/connect, host WiFi IP)
