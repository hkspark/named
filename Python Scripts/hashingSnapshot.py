#!/usr/bin/env python3

"""
Directory Snapshot Generator (Blue Team Tool)

This script:
- Recursively walks through a directory
- Computes SHA-256 hashes for every file
- Saves results to an automatically named JSON file
- Stores the scanned directory path inside the JSON

Output format:
<FolderName>_<YYYYMMDD_HHMMSS>_Snapshot.json

Usage:
"Usage: python3 snapshot.py <directory_path>")
or in binary
./HashSnapshot <dir_path>

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

    except (PermissionError, FileNotFoundError) as e:
        print(f"[!] Skipping {file_path}: {e}")
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


def generate_output_filename(directory):
    folder_name = os.path.basename(os.path.normpath(directory))
    if folder_name == "":
        folder_name = "root"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{folder_name}_{timestamp}_Snapshot.json"


def save_snapshot(snapshot_data, directory, output_file):
    try:
        output = {
            "scanned_directory": os.path.abspath(directory),
            "snapshot": snapshot_data
        }

        with open(output_file, "w") as f:
            json.dump(output, f, indent=4)

        print(f"[+] Snapshot saved to: {output_file}")

    except Exception as e:
        print(f"[!] Failed to save snapshot: {e}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 snapshot.py <directory_path>")
        sys.exit(1)

    directory = sys.argv[1]

    if not os.path.isdir(directory):
        print(f"[!] Error: {directory} is not a valid directory.")
        sys.exit(1)

    print(f"[+] Scanning directory: {directory}")

    snapshot = snapshot_directory(directory)
    print(f"[+] Hashed {len(snapshot)} files.")

    output_file = generate_output_filename(directory)
    save_snapshot(snapshot, directory, output_file)


if __name__ == "__main__":
    main()
