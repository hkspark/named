#!/bin/bash
# competition-safe redis hardening script (with config backup)

set -euo pipefail

echo "starting redis hardening..."

REDIS_CONF="/etc/redis/redis.conf"

if [ ! -f "$REDIS_CONF" ]; then
    REDIS_CONF=$(find /etc/redis -name "*.conf" | head -n 1)
fi

if [ -z "$REDIS_CONF" ]; then
    echo "redis.conf not found, exiting."
    exit 1
fi

# BACKUP CONFIG (timestamped .txt)
echo "creating backup of redis config..."

BACKUP_FILE="/tmp/redis.conf.backup.$(date +%s).txt"
cp "$REDIS_CONF" "$BACKUP_FILE"

echo "backup saved to: $BACKUP_FILE"

# ask for redis password 
read -sp "enter redis requirepass: " REDIS_PASS
echo ""

# 1. core security settings
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

# 2. rename dangerous commands
echo "renaming dangerous commands..."

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

chmod 640 "$REDIS_CONF"
chown redis:redis "$REDIS_CONF"

echo "permissions updated."

# 4. safe restart
echo "restarting service..."

systemctl restart redis-server || systemctl restart redis || true

# verify AFTER restart
if redis-cli -a "$REDIS_PASS" INFO >/dev/null 2>&1; then
    echo "redis hardened and verified."
else
    echo "redis running, but password verification failed (check app config)."
fi

echo "redis hardening complete."
