#!/bin/bash
# redis hardening script

set -euo pipefail

echo "starting redis hardening..."

REDIS_CONF="/etc/redis/redis.conf"

if [ ! -f "$REDIS_CONF" ]; then
    echo "redis.conf not found, exiting."
    exit 1
fi

# ask for redis password
read -sp "enter redis requirepass: " REDIS_PASS
echo ""

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

# rename dangerous commands
echo "renaming dangerous commands..."

sed -i 's/^#* *rename-command CONFIG.*/rename-command CONFIG ""/' "$REDIS_CONF" || true
sed -i 's/^#* *rename-command FLUSHALL.*/rename-command FLUSHALL ""/' "$REDIS_CONF" || true
sed -i 's/^#* *rename-command FLUSHDB.*/rename-command FLUSHDB ""/' "$REDIS_CONF" || true

echo "redis config updated."

# permissions
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

# restart
systemctl restart redis-server || systemctl restart redis || true

echo "redis hardened."
