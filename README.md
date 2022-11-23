# mitnick-attack
Mitnick Attack for course Networking &amp; Data Security 

In an SEED Ubuntu Virtual Box

# Setup The Docker Container

Close down all the docker containers running

docker-compose down

docker-compose build

docker-compose up

docker ps

1. Configure .rhosts file on X-Terminal to allow access to Trusted Server

docker exec -it X_terminal_container_ID /bin/bash

//On X-Terminal

su seed

cd

touch .rhosts

echo Trusted_Server_IP > .rhosts

chmod 644 .rhosts

2. Check the configuration from Trusted Server

docker exec docker exec -it Trusted_Server_container_ID /bin/bash

//On Trusted Server

rsh X_Terminal_IP date  

//You will be able to run a remote shell command DATE on X-Terminal without authentication

3. Stop the Trusted Server to listen to by SYN flood attack or stopping it

docker container stop Trusted_Server_container_ID

The Setup is complete to execute the Mitnick Attack

# Steps to run the attack

//On Seed-Attacker container

1. Run spoofSYN.py  

// Send a Spoofed SYN packet to the X-Terminal 

2. Run respondSYN_ACK.py

// Wait and receive the SYN + ACK packet from X - Terminal along with rsh data packet to create a temp file in X-Terminal

// Respond with ACK packet to X-terminal to perform a TCP handshake with X-Terminal

// After this, X-terminal will send a SYN packet to establish rsh session from it's side, send SYN + ACK message as a response

// You can check that there is a temp file created in /tmp in X-Terminal. 

3. Run mitnick_backdoor.py  

// Implant a backdoor in X-terminal to access the X-Terminal from any IP without authentication and the attacker can do anything!!!


# Detect Mitnick Attack

//On X-Terminal

Run mitnick_detection.py

Perform the attack steps again.

// You will find that the detection script will alert the X-Terminal system.

// You will get a message saying that it has received spoofed packets from the attacker's MAC address.
