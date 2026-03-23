ufw reset
ufw enable

ufw default deny

ufw allow ssh
ufw allow out 53/udp
ufw allow http

ufw reload