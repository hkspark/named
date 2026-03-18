#!/bin/bash

echo "Scanning processes..."

# Allowed processes
allowed=("vsftpd" "ftp" "ftpd" "systemd" "init" "bash" "sshd" "ssh" "dbus" "NetworkManager" "polkit" "qemu-guest-agent" )

for pid in $(ps -eo pid=); do
    proc=$(ps -p $pid -o comm= 2>/dev/null)

    keep=false
    for a in "${allowed[@]}"; do
        if [[ "$proc" == "$a" ]]; then
            keep=true
            break
        fi
    done

    # Skip PID 1 and this script
    if [[ "$pid" -eq 1 ]] || [[ "$pid" -eq $$ ]]; then
        keep=true
    fi

    if [ "$keep" = false ]; then
        echo "Killing $proc (PID $pid)"
        kill -9 $pid 2>/dev/null
    fi
done

echo "Only FTP-related processes remain."
