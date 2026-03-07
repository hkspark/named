sudo openssl req -x509 -nodes -days 365 \
-newkey rsa:2048 \
-keyout /etc/ssl/private/vsftpd.pem \
-out /etc/ssl/certs/vsftpd.pem
sudo systemctl restart vsftpd
