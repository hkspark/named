#!/bin/bash
#Have to run as sudo
#Closes all ports except 22 (SSH), 20(FTP), 21(FTP), 443 (HTTPS)
#Can modify ports for different services

echo "Applying firewall rules..."

# Flush existing rules
ufw reset

# Default deny policy
ufw default deny incoming
ufw default deny outgoing

# Allow localhost
ufw allow from 127.0.0.1 to 127.0.0.1 port 80 proto tcp
ufw allow from 10.10.10.5 to any port 443
ufw allow from 10.10.10.6 to any port 443
ufw allow from 10.10.10.7 to any port 443
ufw allow from 10.10.10.10 to any port 443
ufw allow from 10.10.10.11 to any port 443
# Allow FTP ports
ufw allow 22/tcp
ufw allow 20/tcp
ufw allow 21/tcp

#Apply chagnes
ufw reload


echo "All non-FTP ports blocked."
