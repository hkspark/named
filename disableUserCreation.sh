#!/bin/bash
#Have to run with sudo
#Gets rid of adduser cmd

echo "Disabling user creation tools..."

tools=(
/usr/sbin/useradd
/usr/sbin/adduser
/usr/sbin/usermod
/usr/sbin/groupadd
/usr/sbin/groupmod
)

for tool in "${tools[@]}"
do
    if [ -f "$tool" ]; then
        chmod 000 "$tool"
        echo "Disabled $tool"
    fi
done

echo "User creation disabled."
