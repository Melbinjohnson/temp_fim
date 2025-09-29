import os
import hashlib
import time
import pwd
from utils.audit_utils import get_file_audit_info

def hash_file(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def get_file_metadata(file_path):
    try:
        stat = os.stat(file_path)
        owner = pwd.getpwuid(stat.st_uid).pw_name

        # Get audit information
        audit_info = get_file_audit_info(file_path, "accessed")

        return {
            "hash": hash_file(file_path),
            "size": stat.st_size,
            "last_modified": time.ctime(stat.st_mtime),
            "created_time": time.ctime(stat.st_ctime),
            "permissions": oct(stat.st_mode)[-3:],
            "owner": owner,
            # NEW: Audit information
            "audit": {
                "last_modified_by": audit_info.get('user', 'Unknown'),
                "modification_time": audit_info.get('timestamp'),
                "process": audit_info.get('process', 'Unknown'),
                "command": audit_info.get('command', 'Unknown')
            }
        }
    except (FileNotFoundError, PermissionError) as e:
        print(f"Skipping {file_path}: {e}")
        return None


# import os
# import hashlib
# import time

# def hash_file(file_path):
#     sha256_hash = hashlib.sha256()
#     with open(file_path, "rb") as f:
#         for chunk in iter(lambda: f.read(4096), b""):
#             sha256_hash.update(chunk)
#     return sha256_hash.hexdigest()

# def get_file_metadata(file_path):
#     try:
#         stat = os.stat(file_path)

#         return {
#             "hash": hash_file(file_path),
#             "size": stat.st_size,
#             "last_modified": time.ctime(stat.st_mtime),
#             "created_time": time.ctime(stat.st_ctime),
#             "permissions": oct(stat.st_mode)[-3:]
#         }
#     except (FileNotFoundError, PermissionError) as e:
#         print(f"Skipping {file_path}: {e}")
#         return None
