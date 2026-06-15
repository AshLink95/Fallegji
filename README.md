<!-- TODO: add shields upon public release -->

<div align="center"> <h1>Fallegji</h1> </div> <!-- Might replace with a logo -->

Fallegji is a terminal-based chat app written in Rust. It's inspired by the Fallega of north Africa who were responsible for the armed resistance against colonialism and operated in total secrecy.

The way this app works is by setting up a VPN tunnel for encrypted, fast TCP communication. This ensures that the communication remains fast, secure and serverless.

<!-- Have a centered diagram here -->

<!-- Connection Types (P2P and group chats) -->

# advanced VIM motions checklist:
- [ ] allow messages scrolling (`<C-j/k>`)
- [ ] Implement `iw`, `i(`, `aw`, `a[` and such sequences
- [ ] Implement `f`, `F`, `t` and `T`
- [ ] replace and replace mode
- [ ] Visual mode
- [ ] undo/redo
- [ ] Implement searching with `/` and `?`
- [ ] input scrolling (more natural)
- [ ] Macros (might be a stretch)

# General checklist
- [ ] Impose name (user and chat) size limit along with msg size
- [ ] Elegant error handling. Show red text instead of exisiting the app
- [ ] auto rename when new user shares an existing user's name
- [ ] make delete db merges only valid from admin (user kicked for example)
- [ ] send notifications
- [ ] allow `\` commands in-text
- [ ] allow sending files
- [ ] allow sending videostream and soundstream (allowing for vc with cam by opening a browser)


# Home Menu
This is the menu where users can choose which chat to go with and they have the option to create a chat here.

Add a splash art

# Initial Connection
When a user decides to be a server, they can choose the number of endpoints allowed and they have their endpoint IP (almost always wifi IP) displayed for clients to enter.

A user who chooses to be a client, on the other hand, need to input the endpoint IP.

## Automatic peer setup
To ensure a secure automatatic peer setup, the server starts listening on a socket that allows for the maximum of connected users with a limited buffer window, using a port of their choosing which puts the server in a waitroom (initserver screen). Note that this is the rendezvous address.

Then, the clients inputs that rendezvous address which will automatically bring them to the waitroom and send their name and public key. Note that only the server sees these names and keys. They only see these informations when sent in a valid format.

Afterwards, the last identity check is initiated in which both users input a string that should match. This string is set by the server and the verification message sent by everyone is only shown to users who sent theirs once the server sends his.

Once someone is verified, they get to enter the chatroom and the socket accepts 1 less connection. Since the server has access to both the waitroom and chatroom at all times, they will be notified of every message in the waitroom when they're in the chatroom and vice-versa, unless, they decide to mute a certain room.

## DB sync
The admin(s) have writable copies of the DB and the trusted versions. At the start and end of member connections, they request syncs. When admins initiate and end connections, they send out syncs. When members chat without an admin, they sync to themselves. When an admin reconnects, if the DBs of all members who chatted (doesn't agree with him) agree on everything and include every message in the admins' DB, the admin(s) sync its messages to those in these DBs.

## Keep-alive and reconnect
During a chat, users constantly send heartbeats indicating they're online. If the IP of one user changes, said user will stop receiving heartbeats and will have to send something on the rendezvous address. The users who can't find an address anymore, i.e. also lost a heart beat since they alow only a few addresses in the chat, will now listen on the rendezvous address. the one who got lost, will send an encrypted message to each in a certain format, that message contains the new address and is encrypted. Once that address is read, the connection will automatically get reestablished and the peer with the changed address will have its DB entry changed to reflect the new address.

# Logging
Logs will be always be present if users want to continue their chat. To prevent malicious and fraudulent logs, a hashed copy will be saved along the plaintext version. If the conversation is sensitive to the extent that plaintext logs aren't safe, users can choose to encrypt their logs. The option should be accessible from the onboarding menu.
