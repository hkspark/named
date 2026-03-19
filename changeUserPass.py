#!/usr/bin/env python3
import subprocess
import secrets
import base64
import re

# Users to exclude (regex pattern like your bash script)
EXCLUDE_PATTERN = r"cyberrange|greyteam"

def get_users():
    users = []
    with open("/etc/passwd", "r") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) < 3:
                continue
            username = parts[0]
            uid = int(parts[2])

            # Match UID range and exclude pattern
            if 1000 <= uid < 65534 and not re.search(EXCLUDE_PATTERN, username):
                users.append(username)
    return users

def generate_password():
    # Equivalent to openssl rand -base64 12
    random_bytes = secrets.token_bytes(12)
    return base64.b64encode(random_bytes).decode("utf-8")

def change_password(user, password):
    try:
        proc = subprocess.Popen(
            ["chpasswd"],
            stdin=subprocess.PIPE,
            text=True
        )
        proc.communicate(f"{user}:{password}")
    except Exception as e:
        print(f"Error updating {user}: {e}")

def main():
    users = get_users()

    for user in users:
        newpass = generate_password()
        print(f"User: {user} | New Password: {newpass}")
        change_password(user, newpass)

if __name__ == "__main__":
    main()
