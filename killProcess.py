#!/usr/bin/env python3
import subprocess
import os
import sys

ALLOWED = {
    "systemd", "systemd-journald", "systemd-udevd", "systemd-resolved",
    "systemd-timesyncd", "systemd-logind", "cloud", "rsyslogd",
    "dbus-daemon", "NetworkManager", "wpa_supplicant", "sshd", "ssh",
    "bash", "sd-pam", "polkitd", "qemu-guest-agent", "udisksd",
    "upowerd", "wazuh-agentd", "vsftpd", "scsi_eh_0",
    "systemd-journal", "systemd-timesyn", "dbus", "sddm",
    "ssh-agent", "sudo"
}

def run_cmd(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
    except Exception:
        return ""

def get_pids():
    output = run_cmd(["ps", "-eo", "pid="])
    return [pid.strip() for pid in output.splitlines() if pid.strip().isdigit()]

def get_process_name(pid):
    return run_cmd(["ps", "-p", pid, "-o", "comm="])

def get_service(pid):
    return run_cmd(["ps", "-p", pid, "-o", "unit="]).split()[0] if run_cmd(["ps", "-p", pid, "-o", "unit="]) else ""

def main():
    if os.geteuid() != 0:
        print("This script must be run as root.")
        sys.exit(1)

    print("Scanning processes...")

    current_pid = str(os.getpid())
    parent_pid = str(os.getppid())

    for pid in get_pids():
        proc = get_process_name(pid)
        keep = False

        # Check whitelist
        if proc in ALLOWED:
            keep = True

        # Skip critical PIDs
        if pid in ("1", current_pid, parent_pid):
            keep = True

        if not keep and proc:
            print(f"Killing {proc} (PID {pid})")

            try:
                os.kill(int(pid), 9)
            except Exception:
                continue

            service = get_service(pid)

            if service and service != "-":
                print(f"Stopping + disabling service: {service}")
                subprocess.run(["systemctl", "stop", service], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["systemctl", "disable", service], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Explicitly stop cups
    subprocess.run(["systemctl", "stop", "cups"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["systemctl", "disable", "cups"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print("Scan complete.")

if __name__ == "__main__":
    main()
