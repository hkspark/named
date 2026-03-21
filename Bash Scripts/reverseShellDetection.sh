#!/bin/bash
#returns all connections and ports
#logs it in /var/log/reverse_shell_deection.log

LOGFILE="/var/log/reverse_shell_detection.log"

echo "==== Reverse Shell Scan $(date) ====" >> $LOGFILE

echo "--- Suspicious Processes ---" >> $LOGFILE
ps aux | grep -E "nc|netcat|ncat|socat|bash -i|python -c|perl -e|php -r" | grep -v grep >> $LOGFILE

echo "--- Suspicious Network Connections ---" >> $LOGFILE
ss -tunap | grep ESTAB >> $LOGFILE

echo "--- Connections to External IPs ---" >> $LOGFILE
ss -tunap | grep -E "ESTAB" | grep -v "127.0.0.1" >> $LOGFILE

echo "--- Active Listeners ---" >> $LOGFILE
ss -tulnp >> $LOGFILE

echo "" >> $LOGFILE

echo "Scan complete. Results logged to $LOGFILE"
