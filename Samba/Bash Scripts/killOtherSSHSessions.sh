#!/bin/bash
set -euo pipefail

# Important/off-limits accounts (per your rule)
ALLOW_USERS=("root" "GREYTEAM" "ANSIBLE" "SCORING")

# Optional: if set, also lock disallowed users to prevent future logins
LOCK_FUTURE="${LOCK_FUTURE:-0}"   # 0/1

current_user="${SUDO_USER:-$(whoami)}"
ALLOW_USERS+=("$current_user")

is_allowed() {
  local u="$1"
  for a in "${ALLOW_USERS[@]}"; do
    if [[ "$a" == "$u" ]]; then
      return 0
    fi
  done
  return 1
}

# Kill sshd session processes for disallowed users
# This mimics your existing killSSH.sh approach (ps + "sshd:" + "@").
ps -eo pid,args | grep "sshd:" | grep "@" | grep -v grep | while read -r pid rest; do
  # Try to extract username from "sshd: user@..."
  sess_user="$(echo "$rest" | sed -E 's/.*sshd: ([^@ ]+).*/\1/')"

  if is_allowed "$sess_user"; then
    continue
  fi

  echo "[+] Killing sshd session pid=$pid user=$sess_user"
  kill -TERM "$pid" 2>/dev/null || true
  sleep 0.2
  kill -KILL "$pid" 2>/dev/null || true
done

# Optional future login prevention (only for non-important accounts)
if [[ "$LOCK_FUTURE" == "1" ]]; then
  for u in $(awk -F: '($3>=1000 && $3<65534){print $1}' /etc/passwd); do
    if is_allowed "$u"; then
      continue
    fi
    echo "[+] Locking future access for user=$u"
    usermod -L -s /usr/sbin/nologin "$u" 2>/dev/null || usermod -L -s /sbin/nologin "$u" 2>/dev/null || true
  done
fi