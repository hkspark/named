# Author: Andrew Xie
# Date: 03/12/2026
# Create new System FTP user and set ownership for chroot

# Set FTP user Variables
FTP_USER = "newftpuser"
FTP_PASS = "password"
FTP_DIR = "/var/ftp/$FTP_USER"

# Create System user for FTP
useradd -m -d "$FTP_DIR" -s /usr/sbin/nologin "$FTP_USER"
echo "$FTP_USER:$FTP_PASS" | chpasswd

# Set ownership for chroot
chown root:root "$FTP_DIR"
chmod 755 "$FTP_DIR"
mkdir -p "$FTP_DIR/uploads"
chown "$FTP_USER:$FTP_USER" "$FTP_DIR/uploads"

# Add to vsftpd userlist
echo "$FTP_USER" >> /etc/vsftpd.userlist

# Reload vsftpd
systemctl restart vsftpd
echo "[+] FTP user $FTP_USER created"
