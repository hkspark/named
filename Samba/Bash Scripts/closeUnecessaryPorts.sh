#!/bin/bash
#Have to run as sudo
#Closes all ports except 22 (SSH), 80/443 (HTTP/HTTPS), and Samba (139/445).
#Can modify ports for different services

echo "Applying firewall rules..."

# Flush existing rules
ufw reset

# Default deny policy
ufw default deny incoming
ufw default deny outgoing

# Allow localhost
ufw allow from 127.0.0.1 to 127.0.0.1 port 80 proto tcp
# Allow web ports
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp

# Allow Samba (SMB over TCP) and NetBIOS discovery (UDP)
ufw allow 139/tcp
ufw allow 445/tcp
ufw allow 137/udp
ufw allow 138/udp

#Apply chagnes
ufw reload


echo "All non-web/non-Samba ports blocked."
