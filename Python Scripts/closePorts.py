#!/usr/bin/env python3
import subprocess
import sys

def run_command(cmd):
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running {' '.join(cmd)}: {e}")
        sys.exit(1)

def main():
    print("Applying firewall rules...")

    # Reset UFW (flush rules)
    run_command(["ufw", "reset"])

    # Set default policies
    run_command(["ufw", "default", "deny", "incoming"])
    run_command(["ufw", "default", "deny", "outgoing"])

    # Allow localhost HTTP
    run_command(["ufw", "allow", "from", "127.0.0.1", "to", "127.0.0.1", "port", "80", "proto", "tcp"])

    # Allow SSH + FTP + HTTPS
    run_command(["ufw", "allow", "22/tcp"])
    run_command(["ufw", "allow", "20/tcp"])
    run_command(["ufw", "allow", "21/tcp"])
    run_command(["ufw", "allow", "443/tcp"])

    # Reload rules
    run_command(["ufw", "reload"])

    print("All non-FTP ports blocked.")

if __name__ == "__main__":
    # Ensure running as root
    if subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() != "0":
        print("This script must be run as sudo/root.")
        sys.exit(1)

    main()
