mod db;         //TODO
mod auth;       //TODO
mod messaging;  //TODO
mod tunneling;  //TODO
mod logging;    //TODO
mod vim;
mod ui_screens;
mod app;

use anyhow::Result;

fn main() -> Result<()> {
    app::app()?;

    Ok(())
}

// Initial Connection (requires: name, direct/group chat, host/connect, host WiFi IP)
