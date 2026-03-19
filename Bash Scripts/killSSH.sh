#!/bin/bash

echo "Terminating SSH sessions (excluding trusted IPs)..."

# Add trusted IPs here
#Allows all grey team and ubuntu workstation 1 (can modify if needed)
allowed_ips=("10.10.10.5" "10.10.10.6" "10.10.10.7" "10.10.10.11" "10.10.10.10" "10.10.10.106")

# Get sshd session processes
ps -eo pid,cmd | grep "sshd:" | grep "@" | while read -r pid cmd; do
    keep=false

    for ip in "${allowed_ips[@]}"; do
        if echo "$cmd" | grep -q "$ip"; then
            keep=true
            break
        fi
    done

    if [ "$keep" = false ]; then
        echo "Killing PID $pid ($cmd)"
        kill "$pid"
    else
        echo "Keeping PID $pid ($cmd)"
    fi
done

echo "Done."
