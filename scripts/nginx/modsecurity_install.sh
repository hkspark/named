#!/usr/bin/env bash

set -e

if apt list --installed libnginx-mod-http-modsecurity | grep -q "installed"; then
    cp /etc/nginx/nginx.conf.bak /etc/nginx/nginx.conf
    apt purge -y libnginx-mod-http-modsecurity
fi
apt update
apt install -y libnginx-mod-http-modsecurity

if ! grep -q "modsecurity" /etc/nginx/nginx.conf; then
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
    sed -i "0,/http {/s/http {/http {\n\tmodsecurity on;\n\tmodsecurity_rules_file \/etc\/nginx\/modsecurity_includes.conf;/" /etc/nginx/nginx.conf
fi
if ! grep -q "SecRuleEngine On" /etc/nginx/modsecurity.conf; then
    cp /etc/nginx/modsecurity.conf /etc/nginx/modsecurity.conf.bak
    sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/" /etc/nginx/modsecurity.conf
fi
if ! grep -q "include /etc/modsecurity/crs/crs-setup.conf\ninclude /usr/share/modsecurity-crs/rules/*.conf\n" /etc/nginx/modsecurity_includes.conf; then
    printf "include /etc/modsecurity/crs/crs-setup.conf\ninclude /usr/share/modsecurity-crs/rules/*.conf\n" | tee -a /etc/nginx/modsecurity_includes.conf
fi

if ! nginx -t; then
    echo "Nginx Configuration Error: Aborting..."
    exit
fi

systemctl restart nginx

wget --method=HEAD --output-document - http://localhost
wget --method=HEAD --output-document - http://localhost/?q=/bin/bash
