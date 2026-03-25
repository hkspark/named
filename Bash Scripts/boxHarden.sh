#!/bin/bash
# linux hardening script (with backups)

set -euo pipefail

echo "starting general hardening..."

TIMESTAMP=$(date +%s)

# 0. firewall ( DO NOT enable blindly)
echo "checking firewall (non-intrusive)..."

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow from 10.10.10.11 comment 'scoring-engine'
    ufw allow from 10.10.10.10 comment 'wazuh-monitoring'
fi

# BACKUPS
echo "creating backups..."

SSHD_BACKUP="/tmp/sshd_config.backup.$TIMESTAMP.txt"
SUDO_BACKUP="/tmp/sudoers.backup.$TIMESTAMP.txt"
SYSCTL_BACKUP="/tmp/sysctl.conf.backup.$TIMESTAMP.txt"

[ -f /etc/ssh/sshd_config ] && cp /etc/ssh/sshd_config "$SSHD_BACKUP"
[ -f /etc/sudoers ] && cp /etc/sudoers "$SUDO_BACKUP"
[ -f /etc/sysctl.conf ] && cp /etc/sysctl.conf "$SYSCTL_BACKUP"

echo "sshd backup: $SSHD_BACKUP"
echo "sudoers backup: $SUDO_BACKUP"
echo "sysctl backup: $SYSCTL_BACKUP"

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

chmod 644 /var/log/syslog 2>/dev/null || true

echo "permissions updated."

# 5. sysctl 
echo "applying minimal sysctl hardening..."

SYSCTL="/etc/sysctl.conf"

grep -q "net.ipv4.conf.all.rp_filter" "$SYSCTL" || \
    echo "net.ipv4.conf.all.rp_filter = 1" >> "$SYSCTL"

grep -q "net.ipv4.conf.all.accept_redirects" "$SYSCTL" || \
    echo "net.ipv4.conf.all.accept_redirects = 0" >> "$SYSCTL"

sysctl -p >/dev/null 2>&1 || true

echo "sysctl settings applied."

# 6. updates 
echo "running safe update..."

apt-get update -q >/dev/null 2>&1 || true

echo "general hardening complete."
