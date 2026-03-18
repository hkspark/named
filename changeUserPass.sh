#!/bin/bash

EXCLUDE="cyberrange"

for user in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | grep -Ev "$EXCLUDE")
do
    newpass=$(openssl rand -base64 12)
    echo "$user:$newpass" | chpasswd
done
