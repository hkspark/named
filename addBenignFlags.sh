#!/bin/bash

# Blue team messages
messages=(
"blue_team_detected_intrusion"
"security_monitoring_active"
"incident_response_engaged"
"network_defense_operational"
"log_analysis_in_progress"
"threat_hunters_watching"
"malware_analysis_pipeline_active"
"siem_alert_triggered"
)

# Pick random message
rand_msg=${messages[$RANDOM % ${#messages[@]}]}

flag="flag{${rand_msg}}"

echo "Using flag: $flag"

# Find config files
find / -type f \( \
-name "*.conf" -o \
-name "*.config" -o \
-name "*.cfg" -o \
-name "*.yaml" -o \
-name "*.yml" -o \
-name "*.ini" \
\) 2>/dev/null | while read file
do

    # Determine comment style
    case "$file" in
        *.yaml|*.yml)
            comment="# $flag"
            ;;
        *.conf|*.config|*.cfg|*.ini)
            comment="# $flag"
            ;;
    esac

    echo "$comment" >> "$file"

    echo "Appended flag to $file"

done
