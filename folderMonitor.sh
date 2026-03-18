#!/bin/bash
#Run ./folderMonitor.sh <directory>
#Run first to get baseline, run again to look for changes, will give hash and name of added/modified

# Folder to monitor
DIR="$1"

# Baseline file
BASELINE="baseline_hashes.txt"

if [ -z "$DIR" ]; then
    echo "Usage: $0 <directory_to_monitor>"
    exit 1
fi

# If baseline doesn't exist, create it
if [ ! -f "$BASELINE" ]; then
    echo "Creating baseline..."
    find "$DIR" -type f -exec sha256sum {} \; > "$BASELINE"
    echo "Baseline created. Run the script again to check for changes."
    exit 0
fi

# Create current snapshot
TEMPFILE=$(mktemp)
find "$DIR" -type f -exec sha256sum {} \; > "$TEMPFILE"

echo "Checking for changes..."

# Compare snapshots
diff "$BASELINE" "$TEMPFILE"

echo ""
echo "Summary:"
echo "Lines starting with '<' = removed or modified files"
echo "Lines starting with '>' = new or modified files"

rm "$TEMPFILE"
