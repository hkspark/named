#!/usr/bin/env python3
import os
import sys
import hashlib
import tempfile

BASELINE_FILE = "baseline_hashes.txt"

def sha256_file(filepath):
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None  # skip unreadable files

def build_snapshot(directory):
    snapshot = {}
    for root, _, files in os.walk(directory):
        for name in files:
            path = os.path.join(root, name)
            file_hash = sha256_file(path)
            if file_hash:
                snapshot[path] = file_hash
    return snapshot

def save_baseline(snapshot):
    with open(BASELINE_FILE, "w") as f:
        for path, h in snapshot.items():
            f.write(f"{h}  {path}\n")

def load_baseline():
    baseline = {}
    with open(BASELINE_FILE, "r") as f:
        for line in f:
            parts = line.strip().split("  ", 1)
            if len(parts) == 2:
                baseline[parts[1]] = parts[0]
    return baseline

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <directory_to_monitor>")
        sys.exit(1)

    directory = sys.argv[1]

    if not os.path.isdir(directory):
        print("Invalid directory.")
        sys.exit(1)

    # First run: create baseline
    if not os.path.isfile(BASELINE_FILE):
        print("Creating baseline...")
        snapshot = build_snapshot(directory)
        save_baseline(snapshot)
        print("Baseline created. Run the script again to check for changes.")
        sys.exit(0)

    # Subsequent runs: compare
    print("Checking for changes...")
    baseline = load_baseline()
    current = build_snapshot(directory)

    print("\nChanges:\n")

    # Check removed or modified
    for path, old_hash in baseline.items():
        if path not in current:
            print(f"< REMOVED: {path}")
        elif current[path] != old_hash:
            print(f"< MODIFIED: {path}")

    # Check new or modified
    for path, new_hash in current.items():
        if path not in baseline:
            print(f"> NEW: {path}")
        elif baseline[path] != new_hash:
            print(f"> MODIFIED: {path}")

    print("\nSummary:")
    print("'<': removed or modified files")
    print("'>': new or modified files")

if __name__ == "__main__":
    main()
