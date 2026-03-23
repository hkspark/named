#!/bin/bash
# Terminates SSH sessions that are not in the trusted IP list.
# Safer behavior:
# - Keeps your current SSH client IP automatically.
# - Only targets sshd child sessions with a remote peer.

echo "Terminating SSH sessions (excluding trusted IPs)..."

# Add trusted IPs here
#Allows all grey team and ubuntu workstation 1 (can modify if needed)
allowed_ips=("10.10.10.5" "10.10.10.6" "10.10.10.7" "10.10.10.11" "10.10.10.10" "10.10.10.106" "10.10.10.101")

# Keep the current SSH source IP automatically (if script is run via SSH).
if [[ -n "${SSH_CONNECTION:-}" ]]; then
    current_ip=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    if [[ -n "$current_ip" ]]; then
        allowed_ips+=("$current_ip")
        echo "Auto-allowing current SSH source IP: $current_ip"
    fi
fi

# Build a quick membership check map for allowed IPs.
declare -A allow_map
for ip in "${allowed_ips[@]}"; do
    allow_map["$ip"]=1
done

# Find sshd session PIDs and remote peer IPs from `ss` output.
ss -tnp | awk '/sshd/ && /ESTAB/ {print $5, $NF}' | while read -r peer procinfo; do
    # peer is usually "IP:port" or "[IPv6]:port"
    peer_ip=${peer%:*}
    peer_ip=${peer_ip#[}
    peer_ip=${peer_ip%]}

    # Extract numeric pid from users:(("sshd",pid=1234,fd=...))
    pid=$(echo "$procinfo" | sed -n 's/.*pid=\([0-9]\+\).*/\1/p')
    if [[ -z "$pid" ]]; then
        continue
    fi

    # Double-check this is an sshd process before acting.
    comm=$(ps -p "$pid" -o comm= 2>/dev/null | tr -d ' ')
    if [[ "$comm" != "sshd" ]]; then
        continue
    fi

    keep=false

    if [[ -n "${allow_map[$peer_ip]:-}" ]]; then
        keep=true
    fi

    if [ "$keep" = false ]; then
        echo "Killing PID $pid (remote $peer_ip)"
        kill -TERM "$pid" 2>/dev/null || true
        sleep 0.2
        kill -KILL "$pid" 2>/dev/null || true
    else
        echo "Keeping PID $pid (remote $peer_ip)"
    fi
done

echo "Done."
