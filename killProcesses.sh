#!/bin/bash

echo "Scanning processes..."

# Allowed processes
allowed=("apparmor.service" | 
"cloud-config.service" | 
"cloud-final.service" | 
"keyboard-setup.service" | 
"networkd-dispatcher.service" | 
"kmod-static-nodes.service" | 
"fwupd.service" | 
"cloud-init-local.service" | 
"cloud-init.service" | 
"console-setup.service" | 
"vsftpd.service" | 
"systemd-journald.service" | 
"systemd-udevd" |
"systemd-resolved.service" | 
"systemd-timesyn" | 
"systemd-binfmt.service" | 
"systemd-journal-flush.service" | 
"systemd-logind.service" | 
"systemd-modules-load.service" | 
"systemd-remount-fs.service" | 
"systemd-sysctl.service" | 
"systemd-tmpfiles-setup-dev-early.service" |
"systemd-tmpfiles-setup-dev.service" |
"systemd-tmpfiles-setup.service" |
"systemd-udev-settle.service" |
"systemd-udev-trigger.service" |
"systemd-udevd.service" |
"systemd-update-utmp.service" |
"systemd-user-sessions.service" |
"udisks2.service" |
"ufw.service" |
"upower.service" |
"wazuh-agent.service" |
"wpa_supplicant.service" |
"dbus-daemon"  |
"systemd-logind" |
"rsyslogd" |
"sd-pam" |
"scsi_eh_0" | 
"scsi_eh_1" |
"bash" |
"sshd" |
"ssh" |
"dbus.service" |
"NetworkManager" |
"polkit.service" |
"qemu-guest-agent.service"  
"polkitd.service" | 
"rsyslog.service" | )

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
