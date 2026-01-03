<div align="center"> <h1>Fallegji</h1> </div> <!-- Might replace with a logo -->

Fallegji is a terminal-based chat app written in Rust. It's inspired by the Fallega of north Africa who were responsible for the armed resistance against colonialism and operated in total secrecy.

The way this app works is by setting up a VPN tunnel for encrypted, fast TCP communication. This ensures that the communication remains fast, secure and serverless.

<!-- Have a centered diagram here -->

<!-- Connection Types (P2P and group chats) -->

# Onboarding Menu
This is a screen users are greated with, which prompts them to choose their name, preferred tunnel ip range among other options like vim motions, colorscheme and layout. Note that these configurable settings are saved in `.config/fallegji`.

Certain configurations can only be set in this config file. Namely, granular colorschemes, custom `.vimrc` scripts, and avatars.

# Initial Connection
When a user decides to be a server, they can choose the number of endpoints allowed and they have their endpoint IP (almost always wifi IP) displayed for clients to enter.

A user who chooses to be a client, on the other hand, need to input the endpoint IP.

## Automatic peer setup
To ensure a secure automatatic peer setup, the server starts listening on a socket that allows for the maximum of connected users with a limited buffer window, using a port of their choosing which puts the server in a waitroom. Note that this is an unprotected socket on their wifi IP.

Then, the clients inputs that port number which will automatically bring them to the waitroom and send their name and public key. Note that only the server sees these names and keys.

Afterwards, the last identity check is initiated in which both users input a string that should match. This string is set by the server and the verification message sent by everyone is only shown to users who sent theirs once the server sends his.

Once someone is verified, they get to enter the chatroom and the socket accepts 1 less connection. Since the server has access to both the waitroom and chatroom at all times, they will be notified of every message in the waitroom when they're in the chatroom and vice-versa, unless, they decide to mute a certain room.

# Logging
Logs will be always be present if users want to continue their chat. To prevent malicious and fraudulent logs, a hashed copy will be saved along the plaintext version. If the conversation is sensitive to the extent that plaintext logs aren't safe, users can choose to encrypt their logs. The option should be accessible from the onboarding menu.
