#!/bin/bash
set -euo pipefail

# Run with sudo/root:
#   sudo /opt/cdt-blue-team/bash_scripts/afterSSH.sh
#
# Behavior:
# 1) Ensure deliveryDriver exists
# 2) Lock/disable all non-allowed human users
# 3) Kill current processes for disabled users
# 4) Optionally switch this session to deliveryDriver

DELIVERY_USER="deliveryDriver"
SWITCH_TO_DELIVERY="${SWITCH_TO_DELIVERY:-1}"
NEWUSER="${NEWUSER:-}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

# Off-limits / must-keep accounts
ALLOW_USERS=("root" "GREYTEAM" "ANSIBLE" "SCORING" "greyteam" "ansible" "scoring" "cyberrange")

# Keep whoever launched sudo alive
CURRENT_USER="${SUDO_USER:-$(whoami)}"
ALLOW_USERS+=("${CURRENT_USER}")

# Ensure delivery user exists (idempotent)
if ! id "${DELIVERY_USER}" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "${DELIVERY_USER}"
  echo "${DELIVERY_USER}:$(openssl rand -base64 12)" | chpasswd
fi
ALLOW_USERS+=("${DELIVERY_USER}")

is_allowed() {
  local u="$1"
  for a in "${ALLOW_USERS[@]}"; do
    [[ "$a" == "$u" ]] && return 0
  done
  [[ -n "${NEWUSER}" && "$u" == "${NEWUSER}" ]] && return 0
  return 1
}

# Only touch "human" users (UID range)
for u in $(awk -F: '($3>=1000 && $3<65534){print $1}' /etc/passwd); do
  if is_allowed "${u}"; then
    continue
  fi

  echo "[+] Disabling user: ${u}"

  # Prevent new logins + interactive command execution
  usermod -L -s /usr/sbin/nologin "${u}" 2>/dev/null || \
    usermod -L -s /sbin/nologin "${u}" 2>/dev/null || true

  # Stop anything they currently have running (includes SSH sessions)
  pkill -KILL -u "${u}" 2>/dev/null || true

  # Best-effort: remove per-user cron persistence
  crontab -u "${u}" -r 2>/dev/null || true
done

if [[ "${SWITCH_TO_DELIVERY}" == "1" && "${CURRENT_USER}" != "${DELIVERY_USER}" ]]; then
  exec su - "${DELIVERY_USER}"
fi