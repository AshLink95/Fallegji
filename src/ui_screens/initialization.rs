// Server: A menu with every user and a box that allows selection (can come back to it from chat and vice-versa)
// Client: 1 box saying pending approval if the request went through, otherwise tells the user the address may not be valid. Retry option available after 3 minutes.

#[macro_export]
macro_rules! initServer {
    ($terminal:ident, $curr_screen: ident, $config: ident, $choice: ident, $chats: ident, $requests: ident) => {
        $terminal.draw(|frame| {
        //TODO: border, chat name in the middle of the border, at the top. A tiny box just after where users can click enter when on to go to the chat (can do that with a key stroke as well). 2 sections after: available peers and requests.
            let size = frame.area();
        })?;
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => {

                        $chats = ChatChoice::load(CONFIG)?;
                        $curr_screen = Screen::Home;
                    },
                    KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        $curr_screen = Screen::Chat;
                    },
                    _ => {}

                }
            }
        }
    };
}

#[macro_export]
macro_rules! initClient {
    ($terminal:ident, $curr_screen: ident, $config: ident) => {
        //TODO
    };
}

