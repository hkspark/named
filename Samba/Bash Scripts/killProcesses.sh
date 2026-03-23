#!/bin/bash
#Kills all processes that aren't needed for services to run.
#Tuned for a LAMP stack + Samba (Apache/MySQL + smbd/nmbd).

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

# Web + PHP
"apache2"
"php-fpm"

# MySQL/MariaDB
"mysqld"
"mariadbd"

# Samba
"smbd"
"nmbd"

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

    # Allow common versioned variants without having to enumerate them all.
    if [[ "$proc" == php-fpm* ]]; then
        keep=true
    fi

    # Skip critical PIDs
    if [[ "$pid" -eq 1 ]] || [[ "$pid" -eq $$ ]] || [[ "$pid" -eq $PPID ]]; then
        keep=true
    fi

    if [ "$keep" = false ] && [ -n "$proc" ]; then
        echo "Killing $proc (PID $pid)"
        kill -9 "$pid" 2>/dev/null
    
        service=$(ps -p "$pid" -o unit= 2>/dev/null | awk '{print $1}')

        if [[ -n "$service" && "$service" != "-" ]]; then
            echo "Stopping + disabling service: $service"
            systemctl stop "$service" 2>/dev/null
            systemctl disable "$service" 2>/dev/null
        fi
    fi
done

systemctl stop cups
systemctl disable cups

echo "Scan complete."
