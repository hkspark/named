#!/bin/bash

echo "Applying firewall rules..."

# Flush existing rules
iptables -F
iptables -X

# Default deny policy
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow localhost
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow FTP ports
iptables -A INPUT -p tcp --dport 21 -j ACCEPT
iptables -A INPUT -p tcp --dport 20 -j ACCEPT

# Allow passive FTP range
iptables -A INPUT -p tcp --dport 40000:40100 -j ACCEPT

echo "All non-FTP ports blocked."
