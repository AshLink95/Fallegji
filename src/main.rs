mod db;         //TODO
mod auth;       //TODO
mod messaging;  //TODO
mod tunneling;  //TODO
mod logging;    //TODO
mod vim;
mod app;

use anyhow::Result;

fn main() -> Result<()> {
    println!("Coming down the mountain...");
    app::app()?;
    println!("Went back up the mountain...");

    Ok(())
}

// Initial Connection (requires: name, direct/group chat, host/connect, host WiFi IP)
