<!-- TODO: add shields upon public release -->

<div align="center"> <h1>Fallegji</h1> </div> <!-- Might replace with a logo -->

Fallegji is a terminal-based chat app written in Rust. It's inspired by the Fallega of north Africa who were responsible for the armed resistance against colonialism and operated in total secrecy.

The way this app works is by setting up a VPN tunnel for encrypted, fast TCP communication. This ensures that the communication remains fast, secure and serverless.

<!-- Have a centered diagram here -->

<!-- Connection Types (P2P and group chats) -->

# advanced VIM motions checklist:
- [ ] Implement `iw`, `i(`, `aw`, `a[` and such sequences
- [ ] Implement `f`, `F`, `t` and `T`
- [ ] replace and replace mode
- [ ] Visual mode
- [ ] undo/redo
- [ ] scrolling (requires flexible scrolling in `chat!`)
- [ ] Macros (might be a stretch)

# General checklist
- [ ] make config.rs which is responsible for config files (contains a struct initialized in main based on the config dotfile and passed to `app()`. Based on what's configured and whether or not there's errors, app will decide to either move to onboarding or skip it). This file is necessary and gets automatically generated as it also contains the wireguard/boringTUN public keys per chat
- [ ] allow `/` commands in-text. Start with the ability to send files


# Onboarding Menu
This is a screen users are greated with, which prompts them to choose their name, preferred tunnel ip range among other options like vim motions, colorscheme and layout. Note that these configurable settings are saved in `.config/fallegji` or `.fallegji`. yet to decide

Certain configurations can only be set in this config file. Namely, private keys, granular colorschemes and input height. These configurations are per-chat. Users can select which chat to go to, directly, effectively skipping the menu directly when there are no syntax errors.

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
