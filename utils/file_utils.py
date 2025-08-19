import os
import hashlib
import time

def hash_file(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def get_file_metadata(file_path):
    try:
        stat = os.stat(file_path)

        return {
            "hash": hash_file(file_path),
            "size": stat.st_size,
            "last_modified": time.ctime(stat.st_mtime),
            "created_time": time.ctime(stat.st_ctime),
            "permissions": oct(stat.st_mode)[-3:]
        }
    except (FileNotFoundError, PermissionError) as e:
        print(f"Skipping {file_path}: {e}")
        return None
