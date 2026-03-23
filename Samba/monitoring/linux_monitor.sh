#!/bin/bash
# Author: Andrew Xie
# Date: 03/15/2026
# linux_monitor.sh — Run as: bash linux_monitor.sh | tee /var/log/blueteam.log
# This script scans for new SUID binaries, listening ports on the server, new/modified users, new cronjobs, and records failed login attempts.
# Run this script as a loop: watch -n 60 bash linux_monitor.sh
# Check /var/log/blueteam_monitor.log consistently to view new events.

LOG="/var/log/blueteam_monitor.log"
ALERT_EMAIL="blueteam@corp.local"

echo "[$(date)] === Blue Team Monitor Started ===" | tee -a $LOG

# --- Watch for new SUID binaries ---
monitor_suid() {
  echo "[*] Scanning for SUID binaries..."
  find / -perm -4000 -type f 2>/dev/null | sort > /tmp/suid_current.txt
  if [ -f /tmp/suid_baseline.txt ]; then
    NEW=$(diff /tmp/suid_baseline.txt /tmp/suid_current.txt | grep "^>" )
    if [ -n "$NEW" ]; then
      echo "[ALERT] New SUID binaries detected: $NEW" | tee -a $LOG
    fi
  else
    cp /tmp/suid_current.txt /tmp/suid_baseline.txt
    echo "[*] SUID baseline created"
  fi
}

# --- Check for new listening ports ---
monitor_ports() {
  ss -tlnp | awk 'NR>1{print $4}' | sort > /tmp/ports_current.txt
  if [ -f /tmp/ports_baseline.txt ]; then
    NEW=$(diff /tmp/ports_baseline.txt /tmp/ports_current.txt | grep "^>")
    if [ -n "$NEW" ]; then
      echo "[ALERT] New listening ports: $NEW" | tee -a $LOG
    fi
  else
    cp /tmp/ports_current.txt /tmp/ports_baseline.txt
    echo "[*] Port baseline created"
  fi
}

# --- Check for new/modified users ---
monitor_users() {
  cut -d: -f1 /etc/passwd | sort > /tmp/users_current.txt
  if [ -f /tmp/users_baseline.txt ]; then
    NEW=$(diff /tmp/users_baseline.txt /tmp/users_current.txt | grep "^>")
    if [ -n "$NEW" ]; then
      echo "[ALERT] New users detected: $NEW" | tee -a $LOG
    fi
  else
    cp /tmp/users_current.txt /tmp/users_baseline.txt
  fi
}

# --- Check crontabs for new entries ---
monitor_cron() {
  (crontab -l 2>/dev/null; cat /etc/cron* /var/spool/cron/crontabs/* 2>/dev/null) \
    | sort > /tmp/cron_current.txt
  if [ -f /tmp/cron_baseline.txt ]; then
    NEW=$(diff /tmp/cron_baseline.txt /tmp/cron_current.txt | grep "^>")
    if [ -n "$NEW" ]; then
      echo "[ALERT] Cron change detected: $NEW" | tee -a $LOG
    fi
  else
    cp /tmp/cron_current.txt /tmp/cron_baseline.txt
  fi
}

# --- Watch auth log for brute force ---
monitor_auth() {
  FAILS=$(grep "Failed password" /var/log/auth.log 2>/dev/null | \
    awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -5)
  if [ -n "$FAILS" ]; then
    echo "[INFO] Top SSH fail sources:" | tee -a $LOG
    echo "$FAILS" | tee -a $LOG
  fi
}

# Run all checks
monitor_suid
monitor_ports
monitor_users
monitor_cron
monitor_auth

echo "[$(date)] === Check Complete ===" | tee -a $LOG
