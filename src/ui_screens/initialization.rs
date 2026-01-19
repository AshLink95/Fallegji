// Server: A menu with every user and a box that allows selection (can come back to it from chat and vice-versa)
// Client: 1 box saying pending approval if the request went through, otherwise tells the user the address may not be valid. Retry option available after 3 minutes.

#[macro_export]
macro_rules! initServer {
    ($terminal:ident, $requests: ident, $config: ident, $choice: ident) => {
        //TODO: border, chat name in the middle of the border, at the top. A tiny box just after where users can click enter when on to go to the chat (can do that with a key stroke as well). 2 sections after: available peers and requests.
    };
}

#[macro_export]
macro_rules! initClient {
    ($terminal:ident, $config: ident) => {
        //TODO
    };
}

