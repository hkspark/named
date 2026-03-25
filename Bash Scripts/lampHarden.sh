#!/bin/bash
# LAMP hardening script (with backups)

set -euo pipefail

echo "starting LAMP hardening..."

TIMESTAMP=$(date +%s)


# 1. apache
echo "hardening apache..."

APACHE_CONF="/etc/apache2/apache2.conf"
SEC_CONF="/etc/apache2/conf-available/security.conf"

# BACKUPS
APACHE_BACKUP="/tmp/apache2.conf.backup.$TIMESTAMP.txt"
SEC_BACKUP="/tmp/security.conf.backup.$TIMESTAMP.txt"

cp "$APACHE_CONF" "$APACHE_BACKUP"
[ -f "$SEC_CONF" ] && cp "$SEC_CONF" "$SEC_BACKUP"

echo "apache config backup: $APACHE_BACKUP"
echo "security.conf backup: $SEC_BACKUP"

# disable directory listing 
if ! grep -q "<Directory /var/www/>" "$APACHE_CONF"; then
cat <<EOF >> "$APACHE_CONF"
<Directory /var/www/>
    Options -Indexes
</Directory>
EOF
fi

# hide version info safely
grep -q "^ServerTokens" "$SEC_CONF" && \
    sed -i 's/^ServerTokens.*/ServerTokens Prod/' "$SEC_CONF" || \
    echo "ServerTokens Prod" >> "$SEC_CONF"

grep -q "^ServerSignature" "$SEC_CONF" && \
    sed -i 's/^ServerSignature.*/ServerSignature Off/' "$SEC_CONF" || \
    echo "ServerSignature Off" >> "$SEC_CONF"

# enable useful modules
a2enmod headers >/dev/null 2>&1 || true
a2enmod rewrite >/dev/null 2>&1 || true

# add basic security headers
SEC_FILE="/etc/apache2/conf-available/security-headers.conf"
if [ ! -f "$SEC_FILE" ]; then
cat <<EOF > "$SEC_FILE"
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
</IfModule>
EOF
    a2enconf security-headers >/dev/null 2>&1 || true
fi

# safe apache reload
if apache2ctl configtest >/dev/null 2>&1; then
    systemctl reload apache2
else
    echo "apache config invalid, skipping reload"
fi

echo "apache hardened."

# 2. php
echo "hardening php..."

for PHPINI in $(find /etc/php -name "php.ini"); do
    if [ -f "$PHPINI" ]; then
        PHP_BACKUP="/tmp/$(basename $PHPINI).backup.$TIMESTAMP.txt"
        cp "$PHPINI" "$PHP_BACKUP"
        echo "php backup: $PHP_BACKUP"

        sed -i 's/^expose_php.*/expose_php = Off/' "$PHPINI" || true
        sed -i 's/^display_errors.*/display_errors = Off/' "$PHPINI" || true
        sed -i 's/^allow_url_include.*/allow_url_include = Off/' "$PHPINI" || true
        sed -i 's/^session.cookie_httponly.*/session.cookie_httponly = 1/' "$PHPINI" || true
        sed -i 's/^session.use_strict_mode.*/session.use_strict_mode = 1/' "$PHPINI" || true
    fi
done

# reload apache for php changes
if apache2ctl configtest >/dev/null 2>&1; then
    systemctl reload apache2
else
    echo "apache config invalid after php changes, skipping reload"
fi

echo "php hardened."

# 3. mysql
echo "hardening mysql..."

MYSQL_BACKUP="/tmp/mysql_state.backup.$TIMESTAMP.txt"

# simple snapshot (users + databases)
{
    echo "=== USERS ==="
    mysql -e "SELECT User,Host FROM mysql.user;" 2>/dev/null || true
    echo ""
    echo "=== DATABASES ==="
    mysql -e "SHOW DATABASES;" 2>/dev/null || true
} > "$MYSQL_BACKUP"

echo "mysql state backup: $MYSQL_BACKUP"

# remove anonymous users
mysql -e "DELETE FROM mysql.user WHERE User='';" 2>/dev/null || true

# remove test database
mysql -e "DROP DATABASE IF EXISTS test;" 2>/dev/null || true

mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true

echo "mysql hardened."

# 4. permissions
echo "skipping /var/www ownership changes to avoid breaking apps..."

# 5. logs
echo "securing apache logs..."

chmod 750 /var/log/apache2 || true

echo "LAMP hardening complete."
