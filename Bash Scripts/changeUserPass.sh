#!/bin/bash
#Will output password to console, can change if need be
#Changes all users passwords except cyberrange and greyteam to random string

EXCLUDE="GREYTEAM | scoring | ansible"

for user in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | grep -Ev "$EXCLUDE")
do
    newpass=$(openssl rand -base64 12)
    echo "User: $user | New Password: $newpass"
    echo "$user:$newpass" | chpasswd
done
