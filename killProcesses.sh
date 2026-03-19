#!/bin/bash

echo "Scanning processes..."

# Allowed process names (NOT .service names)
allowed=(
"systemd"
"systemd-journald"
"systemd-udevd"
"systemd-resolved"
"systemd-timesyncd"
"systemd-logind"
"cloud"
"rsyslogd"
"dbus-daemon"
"NetworkManager"
"wpa_supplicant"
"sshd"
"ssh"
"bash"
"sd-pam"
"polkitd"
"qemu-guest-agent"
"udisksd"
"upowerd"
"wazuh-agentd"
"vsftpd"
"scsi_eh_0"
"systemd-journal"
"systemd-timesyn"
"dbus"
"sddm"
"ssh-agent"
"sudo"
)

for pid in $(ps -eo pid=); do
    proc=$(ps -p "$pid" -o comm= 2>/dev/null)

    keep=false
    for a in "${allowed[@]}"; do
        if [[ "$proc" == "$a" ]]; then
            keep=true
            break
        fi
    done

    # Skip critical PIDs
    if [[ "$pid" -eq 1 ]] || [[ "$pid" -eq $$ ]] || [[ "$pid" -eq $PPID ]]; then
        keep=true
    fi

    if [ "$keep" = false ] && [ -n "$proc" ]; then
        echo "Killing $proc (PID $pid)"
        # kill -9 "$pid" 2>/dev/null   # 🔴 COMMENTED FOR SAFETY
    fi
done

echo "Scan complete."
