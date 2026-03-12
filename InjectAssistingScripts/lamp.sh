# Author: Andrew Xie
# Date: 03/12/2026
# Create MySQL databases/users, deploy PHP apps, configure Apache vhosts

# Create variables
DB_NAME = "newdb"
DB_USER = "newdbuser"
DB_PASS = "newdbpass"

# Create Database and User
mysql -u root <<EOF
CREATE DATABASE IF NOT EXISTS $DB_NAME;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
EOF

# Create Apache vhost
cat > /etc/apache2/sites-available/inject-site.conf <<'EOF'
<VirtualHost *:80>
    ServerName inject.lab.local
    DocumentRoot /var/www/inject-site
    <Directory /var/www/inject-site>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF

mkdir -p /var/www/inject-site
a2ensite inject-site.conf
a2enmod rewrite
systemctl reload apache2
echo "[+] LAMP inject complete"
