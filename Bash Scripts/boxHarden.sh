#!/bin/bash
# general linux hardening script

set -euo pipefail

echo "starting general hardening..."

# 1. root password
echo "setting root password..."

read -sp "enter new root password: " ROOTPASS
echo ""
echo "root:$ROOTPASS" | chpasswd
echo "root password updated."

# 2. sshd
echo "hardening ssh..."

SSHD="/etc/ssh/sshd_config"

if [ ! -f "$SSHD" ]; then
    echo "sshd_config not found, exiting."
    exit 1
fi

# safer edits 
grep -q "^PermitRootLogin" "$SSHD" && \
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSHD" || \
    echo "PermitRootLogin no" >> "$SSHD"

grep -q "^PasswordAuthentication" "$SSHD" && \
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD" || \
    echo "PasswordAuthentication yes" >> "$SSHD"

grep -q "^PermitEmptyPasswords" "$SSHD" && \
    sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSHD" || \
    echo "PermitEmptyPasswords no" >> "$SSHD"

grep -q "^ChallengeResponseAuthentication" "$SSHD" && \
    sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$SSHD" || \
    echo "ChallengeResponseAuthentication no" >> "$SSHD"

if sshd -t 2>/dev/null; then
    systemctl reload sshd || systemctl reload ssh || true
else
    echo "sshd config invalid, skipping reload"
fi

# 3. sudo
echo "checking sudo settings..."

if [ -f /etc/sudoers ]; then
    sed -i 's/^%sudo ALL=(ALL:ALL) NOPASSWD: ALL/%sudo ALL=(ALL:ALL) ALL/' /etc/sudoers || true
fi

echo "sudo settings updated."

# 4. permissions
echo "fixing sensitive file permissions..."

chmod 600 /etc/shadow || true
chmod 600 /etc/gshadow || true
chmod 600 /etc/ssh/ssh_host_* || true

echo "permissions updated."

# 5. sysctl
echo "applying minimal sysctl hardening..."

SYSCTL="/etc/sysctl.conf"

grep -q "^net.ipv4.conf.all.rp_filter" "$SYSCTL" || \
    echo "net.ipv4.conf.all.rp_filter = 1" >> "$SYSCTL"

sysctl -p >/dev/null 2>&1 || true

echo "sysctl settings applied."

# 6. updates 
echo "running safe update (no upgrades)..."

apt-get update -y >/dev/null 2>&1 || true

echo "general hardening complete."
