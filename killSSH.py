#!/usr/bin/env python3
import subprocess
import os
import sys

# Trusted IPs (modify as needed)
ALLOWED_IPS = {
    "10.10.10.5",
    "10.10.10.6",
    "10.10.10.7",
    "10.10.10.11",
    "10.10.10.10",
    "10.10.10.106"
}

def get_ssh_sessions():
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,cmd"],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.splitlines()
        sessions = []

        for line in lines:
            if "sshd:" in line and "@" in line:
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    pid, cmd = parts
                    sessions.append((pid, cmd))
        return sessions

    except subprocess.CalledProcessError as e:
        print(f"Error getting processes: {e}")
        sys.exit(1)

def main():
    if os.geteuid() != 0:
        print("This script must be run as root.")
        sys.exit(1)

    print("Terminating SSH sessions (excluding trusted IPs)...")

    sessions = get_ssh_sessions()

    for pid, cmd in sessions:
        keep = False

        for ip in ALLOWED_IPS:
            if ip in cmd:
                keep = True
                break

        if not keep:
            print(f"Killing PID {pid} ({cmd})")
            try:
                os.kill(int(pid), 15)  # SIGTERM first (safer than SIGKILL)
            except Exception as e:
                print(f"Failed to kill {pid}: {e}")
        else:
            print(f"Keeping PID {pid} ({cmd})")

    print("Done.")

if __name__ == "__main__":
    main()
