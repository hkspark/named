#!/usr/bin/env python3

"""
Directory Snapshot Comparison Tool (Blue Team)

This script:
- Loads a previous snapshot (JSON)
- Extracts the original scanned directory
- Re-hashes that directory automatically
- Compares differences
- Prints results to console
- Saves a new clean snapshot

Usage:
python3 compare.py <snapshot.json>

⚠️ Safety:
- READ-ONLY: Does NOT modify any files
"""

import os
import hashlib
import json
import sys
from datetime import datetime


def compute_sha256(file_path, chunk_size=8192):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError):
        return None


def snapshot_directory(root_path):
    snapshot = {}

    for dirpath, dirnames, filenames in os.walk(root_path):
        for filename in filenames:
            full_path = os.path.abspath(os.path.join(dirpath, filename))
            file_hash = compute_sha256(full_path)

            if file_hash:
                snapshot[full_path] = file_hash

    return snapshot


# -----------------------------
# Load Snapshot + Extract Directory
# -----------------------------
def load_snapshot(file_path):
    try:
        with open(file_path, "r") as f:
            data = json.load(f)

        # New format
        if "snapshot" in data and "scanned_directory" in data:
            return data["snapshot"], data["scanned_directory"]

        # Old format fallback
        print("[!] Warning: Old snapshot format detected. No directory stored.")
        print("[!] You must manually modify this script or re-create snapshot.")
        sys.exit(1)

    except Exception as e:
        print(f"[!] Failed to load snapshot: {e}")
        sys.exit(1)


def compare_snapshots(old, new):
    old_files = set(old.keys())
    new_files = set(new.keys())

    added = sorted(new_files - old_files)
    removed = sorted(old_files - new_files)

    changed = []
    unchanged = []

    for file in old_files & new_files:
        if old[file] != new[file]:
            changed.append(file)
        else:
            unchanged.append(file)

    return sorted(added), sorted(removed), sorted(changed), sorted(unchanged)


def generate_output_filename(directory):
    folder_name = os.path.basename(os.path.normpath(directory))
    if folder_name == "":
        folder_name = "root"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{folder_name}_{timestamp}_Snapshot.json"


def print_results(added, removed, changed, unchanged):
    print("\n====== COMPARISON RESULTS ======\n")

    print(f"[+] New Files: {len(added)}")
    for f in added:
        print(f"    + {f}")

    print(f"\n[-] Missing Files: {len(removed)}")
    for f in removed:
        print(f"    - {f}")

    print(f"\n[*] Changed Files: {len(changed)}")
    for f in changed:
        print(f"    * {f}")

    print(f"\n[=] Unchanged Files: {len(unchanged)}")
    for f in unchanged:
        print(f"    = {f}")


def save_snapshot(snapshot, directory, output_file):
    try:
        output = {
            "scanned_directory": os.path.abspath(directory),
            "snapshot": snapshot
        }

        with open(output_file, "w") as f:
            json.dump(output, f, indent=4)

        print(f"\n[+] New snapshot saved to: {output_file}")

    except Exception as e:
        print(f"[!] Failed to save snapshot: {e}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 compare.py <snapshot.json>")
        sys.exit(1)

    snapshot_file = sys.argv[1]

    old_snapshot, directory = load_snapshot(snapshot_file)

    if not os.path.isdir(directory):
        print(f"[!] Stored directory no longer exists: {directory}")
        sys.exit(1)

    print(f"[+] Using stored directory: {directory}")

    new_snapshot = snapshot_directory(directory)

    added, removed, changed, unchanged = compare_snapshots(old_snapshot, new_snapshot)

    print_results(added, removed, changed, unchanged)

    output_file = generate_output_filename(directory)
    save_snapshot(new_snapshot, directory, output_file)


if __name__ == "__main__":
    main()
