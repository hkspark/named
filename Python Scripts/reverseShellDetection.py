#!/usr/bin/env python3
import subprocess
import datetime
import os
import sys
import re

LOGFILE = "/var/log/reverse_shell_detection.log"

SUSPICIOUS_PATTERNS = re.compile(
    r"nc|netcat|ncat|socat|bash -i|python -c|perl -e|php -r"
)

def run_command(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError:
        return ""

def append_log(text):
    try:
        with open(LOGFILE, "a") as f:
            f.write(text + "\n")
    except PermissionError:
        print(f"Permission denied writing to {LOGFILE}. Run as sudo.")
        sys.exit(1)

def main():
    if os.geteuid() != 0:
        print("This script should be run as root for full visibility.")
        sys.exit(1)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    append_log(f"==== Reverse Shell Scan {timestamp} ====")

    # Suspicious processes
    append_log("--- Suspicious Processes ---")
    ps_output = run_command(["ps", "aux"])
    for line in ps_output.splitlines():
        if SUSPICIOUS_PATTERNS.search(line) and "grep" not in line:
            append_log(line)

    # All established connections
    append_log("--- Suspicious Network Connections ---")
    ss_output = run_command(["ss", "-tunap"])
    for line in ss_output.splitlines():
        if "ESTAB" in line:
            append_log(line)

    # External connections (exclude localhost)
    append_log("--- Connections to External IPs ---")
    for line in ss_output.splitlines():
        if "ESTAB" in line and "127.0.0.1" not in line:
            append_log(line)

    # Active listeners
    append_log("--- Active Listeners ---")
    listeners = run_command(["ss", "-tulnp"])
    append_log(listeners.strip())

    append_log("")  # blank line

    print(f"Scan complete. Results logged to {LOGFILE}")

if __name__ == "__main__":
    main()
