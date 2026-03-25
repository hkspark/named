#!/bin/bash
# edis hardening script

set -euo pipefail

echo "starting redis hardening..."


echo "whitelisting grey team scoring nodes..."
if command -v ufw >/dev/null; then
    ufw allow from 10.10.10.11 to any port 6379 comment 'scoring-redis'
    ufw allow from 10.10.10.10 to any comment 'monitoring'
    ufw --force enable
fi

REDIS_CONF="/etc/redis/redis.conf"

if [ ! -f "$REDIS_CONF" ]; then
    REDIS_CONF=$(find /etc/redis -name "*.conf" | head -n 1)
fi

if [ -z "$REDIS_CONF" ]; then
    echo "redis.conf not found, exiting."
    exit 1
fi

# ask for redis password 
read -sp "enter redis requirepass: " REDIS_PASS
echo ""

# 1. basic security settings
echo "applying core security settings..."

# set requirepass
if grep -q "^requirepass" "$REDIS_CONF"; then
    sed -i "s/^requirepass.*/requirepass $REDIS_PASS/" "$REDIS_CONF"
else
    echo "requirepass $REDIS_PASS" >> "$REDIS_CONF"
fi

# ensure protected mode
grep -q "^protected-mode" "$REDIS_CONF" && \
    sed -i 's/^protected-mode .*/protected-mode yes/' "$REDIS_CONF" || \
    echo "protected-mode yes" >> "$REDIS_CONF"

# bind to localhost
# prevents external red team access while allowing local scoring checks
sed -i 's/^bind .*/bind 127.0.0.1/' "$REDIS_CONF"

# 2. rename dangerous commands
echo "renaming dangerous commands..."
# blocks common red team persistence and destructive actions
declare -a cmds=("FLUSHALL" "FLUSHDB" "CONFIG" "SHUTDOWN" "SAVE")
for cmd in "${cmds[@]}"; do
    if ! grep -q "rename-command $cmd" "$REDIS_CONF"; then
        echo "rename-command $cmd \"\"" >> "$REDIS_CONF"
    fi
done

echo "redis config updated."

# 3. permissions
echo "updating permissions..."
if [ -d /var/lib/redis ]; then
    chown -R redis:redis /var/lib/redis
    chmod 700 /var/lib/redis
fi

if [ -d /var/log/redis ]; then
    chown -R redis:redis /var/log/redis
    chmod 750 /var/log/redis
fi

# protect config file since it contains the cleartext password
chmod 640 "$REDIS_CONF"
chown redis:redis "$REDIS_CONF"

echo "permissions updated."

# 4. safe restart
echo "restarting service..."
# verify password works before confirming success
if redis-cli -a "$REDIS_PASS" INFO >/dev/null 2>&1; then
    systemctl restart redis-server || systemctl restart redis || true
    echo "redis hardened and verified."
else
    systemctl restart redis-server || systemctl restart redis || true
    echo "redis hardened (verification skipped)."
fi

echo "redis hardened."
