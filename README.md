# PeerNet
A P2P file-sharing application written using socket programming in c.

PeerNet is a simple application built using socket programming in c which is capable of transferring files over TCP/UDP with SHA256 hash verification. One can also list the contents of the remote directory and get the hash of all files and compare it with his directory to sync across both the peers.

## INSTRUCTIONS:
- All commands starting with `r` are remote commands, which either run on the other peer or display details about the peer.  
- The port for server thread will be choosen at random from the available/accessible ports.
- The convention followed in the comments is that, the 'client' is actually the other peer to whom one is connected. For a person, the other peer is like a client.
- The default shared directory is `shared_dir_GRIM`, which needs to be present alongside the SERVER executable.

The given app can be used both as a `Server VS Client` application or a normal `P2P` app.
The details on how to configure are below.

Common commands -
- run `make withoutWarnings` to get the executables. (This just supresses all the warnings. You can also run `make all` to see the warnings.)
- There would be two of them, namely, `SERVER` and `CLIENT`


### Server & Client
- **SERVER** -> the Server code. Run `./SERVER` to start the server. You would get the port no as displayed on the screen. Note the server IP and the port as displayed on screen.  


- Now, **CLIENT** is the Client code.  Run it using the command `./CLIENT <SERVER_IP> <SERVER_PORT>` and you should be able to access the remote directory of the server.  
![Client](http://i.imgur.com/p1J1pNf.png)  
while the server would display the stats of connections. 
![Server](http://i.imgur.com/fZOGPiT.png)

### P2P
- **SERVER**  
This is the Server code. Run using `./SERVER`. Actually, it is the peer code which runs on all the devices. Just due to naming convention i call it server. Run it to start the server + client daemon on a peer. You would get the port no as displayed on the screen. Note the peer's IP and the port as displayed on screen. Let us call this peer1 for the sake on convenience.  
![Peer1](http://i.imgur.com/oct8aJB.png)

- Now, again run **SERVER**, but this time using this command, `./SERVER <PEER1_IP> <PEER1_PORT>`. The client or Peer2 will connect to Peer1, followed by Peer1 connecting to Peer2. This would create a bi-directional communication stream.  
![Peer2](http://i.imgur.com/1s8JA1J.png)  
![Peer1 Connected](http://i.imgur.com/if7sF9T.png)  

- Both, Peer1 and Peer2 should be able to run commands and share files.


## Supported Commands.  

#### Native Commands
● $> `filehash verify <filename>` - Get the hash of the file specified in the argument.  
● $> `filehash checkall` - Get the hash of all the files in the shared directory with their date modified.  
● $> `clear`  - Clear the contents of the screen  
● $> `ls`    - Run <b>ls</b> on the same pc's shared directory  
● $> `hash` - Prints the hash of the text given in the input.  


#### Remote Commands
- To run these commands, both the peers ust be connected over a network.  
● $> `getfile tcp/udp <filename>` - Get the file with the given filename from the remote peer. You can choose between the two protocols, i.e. `TCP` or `UDP`.
● $> `rfind regex './sha.*'`  -  Find all the files in the shared directory of the remote peer that match a particuler regex. (NOTE: The regex must begin with `./`)  
● $> `rfind longlist` - Get a list of all the files in the shared directory with thier filesize(in bytes), filetype, and last modified dates.  
● $> `rfind shortlist TIMESTAMP TIMESTAMP`  // Segfault if timestamp not given  
● $> `rls` - Remote ls on remote peer's shared directory  


## SampleExecutable

The `bin` directory contains a simple structure of a P2P setup with 2 peers, **Peer1** and **Peer2**. Each of them have a shared directory named, `shared_dir_GRIM`. Each of them have a executable named `SERVER` which can be used to create a connection between each other.

## Licence
**GNU GENERAL PUBLIC LICENSE**  
Version 3, 29 June 2007  
The GNU General Public License is a free, copyleft license for software and other kinds of works.
