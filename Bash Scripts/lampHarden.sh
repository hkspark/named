#!/bin/bash
# competition-safe polished LAMP hardening script

set -euo pipefail

echo "starting LAMP hardening..."

# 0. firewall ( dont enable blindly )
echo "checking firewall..."

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow from 10.10.10.11 comment 'scoring-engine'
    ufw allow from 10.10.10.10 comment 'wazuh-monitoring'
fi

# 1. apache
echo "hardening apache..."

APACHE_CONF="/etc/apache2/apache2.conf"
SEC_CONF="/etc/apache2/conf-available/security.conf"

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

# find all php.ini files
for PHPINI in $(find /etc/php -name "php.ini"); do
    if [ -f "$PHPINI" ]; then
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
