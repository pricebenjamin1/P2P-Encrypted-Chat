# P2P-Encrypted-Chat
P2P encrypted chat program with authentication server.

This project is a solution for any group that wants the security of an authorization server but also the privacy of a client to client service.

HOW DOES IT WORK?

Each client will connect to the server using an ip address. Clients receive the server's public RSA key, and use that to securely provide user credentials for confidentiality. After this authentication, the server saves the clients randomly generated public key to a list, that all clients get updated for. Each client can then see who is online, and they are then able to initiate or receive chats. This is achieved by the initiating client using the receiving client's public RSA key for encrypting. The initiator encrypts their own public RSA key with the receiver's public RSA key for authentication to the client. All clients know all active users and their nicknames, IPs, and public RSA's. This makes it incredibly difficult for a threat actor to execute a man in the middle attack or skip authentication.

HOW FAR ALONG IS THIS SOLUTION?

This project is not meant to be implemented in a production environment at this time. It is 95% complete and will be completely functional by 6/8/22.
Security will be tested over the following months and updates will appear here.

ADDITIONAL NOTES

I am continuously improving my coding and security knowledge and I hope to continuously show this by updating and improving this project. I chose this project because I wanted something to show for my years of effort involving scripting and coding. Here is a list of some of the ideas and tools within this project:

-CIA Triad

-Cryptography: RSA PKI, symmetric

-Advanced Data Types: encoding, object types, key objects

-Socket

-Pickling

-Tkinter
