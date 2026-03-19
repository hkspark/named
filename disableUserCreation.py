#!/usr/bin/env python3
import os
import stat
import subprocess
import sys

TOOLS = [
    "/usr/sbin/useradd",
    "/usr/sbin/adduser",
    "/usr/sbin/usermod",
    "/usr/sbin/groupadd",
    "/usr/sbin/groupmod"
]

def check_root():
    if os.geteuid() != 0:
        print("This script must be run as sudo/root.")
        sys.exit(1)

def disable_tools():
    print("Disabling user creation tools...")

    for tool in TOOLS:
        if os.path.isfile(tool):
            try:
                os.chmod(tool, 0)
                print(f"Disabled {tool}")
            except Exception as e:
                print(f"Failed to disable {tool}: {e}")
        else:
            print(f"{tool} not found, skipping.")

    print("User creation disabled.")

def main():
    check_root()
    disable_tools()

if __name__ == "__main__":
    main()
