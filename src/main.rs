mod db;         //TODO: (will change again to add connection)
mod connection; //TODO
mod messaging;  //TODO: dependant on connection
mod ui_screens; //TODO: dependant on messaging
mod app;        //TODO: dependant on everything (might build a manager)

mod auth;
mod vim;

use anyhow::Result;

fn main() -> Result<()> {
    app::app()?;

    Ok(())
}

// Initial Connection (requires: name, direct/group chat, host/connect, host WiFi IP)
