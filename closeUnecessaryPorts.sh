#!/bin/bash
#Have to run as sudo

echo "Applying firewall rules..."

# Flush existing rules
ufw reset

# Default deny policy
ufw default deny incoming
ufw default deny outgoing

# Allow localhost
ufw allow from 127.0.0.1 to 127.0.0.1 port 80 proto tcp
# Allow FTP ports
ufw allow 22/tcp
ufw allow 20/tcp
ufw allow 21/tcp
ufw allow 443/tcp

#Apply chagnes
ufw reload


echo "All non-FTP ports blocked."
