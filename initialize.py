import os
import json
import time
import hashlib
from utils.file_utils import get_file_metadata
from utils.config_loader import load_config

config = load_config()

MONITOR_PATH = config["monitor_path"]
BASELINE_PATH = config["baseline_file"]
exclude = config["exclude"]

def is_excluded(path):
    return any(excluded in path for excluded in exclude)

def build_baseline(directory):
    baseline_data = {}

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root, d))]  # filter dirs
        for fname in files:
            file_path = os.path.join(root, fname)
            if is_excluded(file_path):
                continue
            metadata = get_file_metadata(file_path)

            if metadata:
                relative_path = os.path.relpath(file_path, directory)
                baseline_data[relative_path] = metadata

    return baseline_data

def save_baseline(data):
    with open(BASELINE_PATH, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Baseline saved to {BASELINE_PATH}")

def main():
    #target_directory = input("Enter the directory to monitor: ").strip()

    if not os.path.isdir(MONITOR_PATH):
        print("Invalid directory path.")
        return

    baseline = build_baseline(MONITOR_PATH)
    save_baseline(baseline)

if __name__ == "__main__":
    main()
