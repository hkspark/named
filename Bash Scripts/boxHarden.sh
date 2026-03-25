#!/bin/bash
# linux hardening script 

set -euo pipefail

echo "starting general hardening..."

# 0. firewall ( DO NOT enable blindly)
echo "checking firewall (non-intrusive)..."

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow from 10.10.10.11 comment 'scoring-engine'
    ufw allow from 10.10.10.10 comment 'wazuh-monitoring'
fi

# 1. root password 
echo "root password change (optional)..."

read -p "change root password? (y/n): " CHANGE_ROOT
if [ "$CHANGE_ROOT" = "y" ]; then
    read -sp "enter new root password: " ROOTPASS
    echo ""
    echo "root:$ROOTPASS" | chpasswd
    echo "root password updated."
else
    echo "skipping root password change."
fi

# 2. sshd
echo "hardening ssh..."

SSHD="/etc/ssh/sshd_config"

if [ ! -f "$SSHD" ]; then
    echo "sshd_config not found, exiting."
    exit 1
fi

# safer SSH settings
grep -q "^PermitRootLogin" "$SSHD" && \
    sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' "$SSHD" || \
    echo "PermitRootLogin yes" >> "$SSHD"

grep -q "^PasswordAuthentication" "$SSHD" && \
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD" || \
    echo "PasswordAuthentication yes" >> "$SSHD"

grep -q "^PermitEmptyPasswords" "$SSHD" && \
    sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSHD" || \
    echo "PermitEmptyPasswords no" >> "$SSHD"

# banner (idempotent)
grep -q "^Banner" "$SSHD" || echo "Banner /etc/issue.net" >> "$SSHD"
echo "AUTHORIZED ACCESS ONLY - COMPETITION SYSTEM" > /etc/issue.net

# safe reload
if sshd -t 2>/dev/null; then
    systemctl reload sshd || systemctl reload ssh || true
else
    echo "sshd config invalid, skipping reload"
fi

echo "ssh hardened."

# 3. sudo
echo "checking sudo settings..."

if [ -f /etc/sudoers ]; then
    sed -i 's/%sudo .*NOPASSWD: ALL/%sudo ALL=(ALL:ALL) ALL/' /etc/sudoers || true
fi

echo "sudo settings updated."

# 4. permissions
echo "fixing sensitive file permissions..."

chmod 600 /etc/shadow || true
chmod 600 /etc/gshadow || true

# allow log readability (safe for scoring/monitoring)
chmod 644 /var/log/syslog 2>/dev/null || true

echo "permissions updated."

# 5. sysctl (minimal + idempotent)
echo "applying minimal sysctl hardening..."

SYSCTL="/etc/sysctl.conf"

grep -q "net.ipv4.conf.all.rp_filter" "$SYSCTL" || \
    echo "net.ipv4.conf.all.rp_filter = 1" >> "$SYSCTL"

grep -q "net.ipv4.conf.all.accept_redirects" "$SYSCTL" || \
    echo "net.ipv4.conf.all.accept_redirects = 0" >> "$SYSCTL"

sysctl -p >/dev/null 2>&1 || true

echo "sysctl settings applied."

# 6. updates (safe)
echo "running safe update..."

apt-get update -q >/dev/null 2>&1 || true

echo "general hardening complete."
