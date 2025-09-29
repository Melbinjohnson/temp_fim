import subprocess
import re
import pwd
import os
import json
import time
from datetime import datetime

def get_username_from_uid(uid):
    """Convert UID to username"""
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except:
        return f"UID:{uid}"

def get_last_modifier(file_path):
    """Get the username who last modified a file using audit logs"""
    try:
        # Step 1: Try ausearch for the specific file
        cmd = ["ausearch", "-f", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            uid_match = re.search(r'uid=(\d+)', result.stdout)
            if uid_match:
                return get_username_from_uid(uid_match.group(1))

        # Step 2: Try with track_mods key
        cmd = ["ausearch", "-k", "track_mods"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            uid_match = re.search(r'uid=(\d+)', result.stdout)
            if uid_match:
                return get_username_from_uid(uid_match.group(1))

        # Step 3: Fallback to grep audit log
        cmd = ["grep", "track_mods", "/var/log/audit/audit.log"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            lines = result.stdout.strip().split('\n')
            if lines:
                last_line = lines[-1]
                uid_match = re.search(r'uid=(\d+)', last_line)
                if uid_match:
                    return get_username_from_uid(uid_match.group(1))

        return "Unknown"

    except Exception as e:
        return f"Error: {e}"

def get_file_audit_info(file_path, change_type="modified"):
    """Get comprehensive audit information for a file"""
    try:
        audit_info = {
            'user': 'Unknown',
            'timestamp': None,
            'action': change_type,
            'process': 'Unknown',
            'command': 'Unknown'
        }

        # Try multiple audit search methods
        search_methods = [
            ["ausearch", "-f", file_path, "-ts", "today"],
            ["ausearch", "-k", "track_mods", "-f", file_path],
            ["ausearch", "-sc", "open,openat,write,unlink", "-f", file_path]
        ]

        for cmd in search_methods:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.stdout and result.returncode == 0:
                    # Parse the most recent audit entry
                    lines = result.stdout.strip().split('\n')
                    for line in reversed(lines):  # Start from most recent
                        if 'uid=' in line:
                            # Extract UID
                            uid_match = re.search(r'uid=(\d+)', line)
                            if uid_match:
                                audit_info['user'] = get_username_from_uid(uid_match.group(1))
                            
                            # Extract timestamp
                            time_match = re.search(r'msg=audit\((\d+)\.\d+:', line)
                            if time_match:
                                timestamp = int(time_match.group(1))
                                audit_info['timestamp'] = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                            
                            # Extract process info
                            exe_match = re.search(r'exe="([^"]+)"', line)
                            if exe_match:
                                audit_info['process'] = os.path.basename(exe_match.group(1))
                            
                            # Extract command
                            comm_match = re.search(r'comm="([^"]+)"', line)
                            if comm_match:
                                audit_info['command'] = comm_match.group(1)
                            
                            break
                    
                    if audit_info['user'] != 'Unknown':
                        break
            except subprocess.TimeoutExpired:
                continue
            except Exception:
                continue

        return audit_info

    except Exception as e:
        return {
            'user': f"Error: {str(e)}",
            'timestamp': None,
            'action': change_type,
            'process': 'Unknown',
            'command': 'Unknown'
        }

def setup_audit_rules():
    """Setup audit rules for file monitoring"""
    try:
        # Check if auditd is running
        result = subprocess.run(["systemctl", "is-active", "auditd"], 
                               capture_output=True, text=True)
        if result.stdout.strip() != "active":
            print("⚠️  auditd service is not running. Starting it...")
            subprocess.run(["sudo", "systemctl", "start", "auditd"], check=True)

        # Add audit rules for file modifications
        audit_rules = [
            # Monitor file writes/modifications
            "-w /etc -p wa -k track_mods",
            "-w /usr/bin -p wa -k track_mods", 
            "-w /usr/sbin -p wa -k track_mods",
            "-w /var/log -p wa -k track_mods",
            # Monitor file attribute changes
            "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -k track_mods",
            "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -k track_mods",
            # Monitor file creation/deletion
            "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -k track_mods",
            "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -k track_mods"
        ]

        for rule in audit_rules:
            try:
                subprocess.run(["sudo", "auditctl"] + rule.split()[1:], 
                              check=False, capture_output=True)
            except Exception:
                pass  # Ignore rule addition errors

        print("✅ Audit rules configured for file monitoring")
        return True

    except Exception as e:
        print(f"❌ Failed to setup audit rules: {e}")
        return False

def check_audit_system():
    """Check if audit system is properly configured"""
    try:
        # Check if auditd is installed
        result = subprocess.run(["which", "auditctl"], capture_output=True, text=True)
        if result.returncode != 0:
            return {"status": "not_installed", "message": "auditd not installed"}

        # Check if auditd service is running
        result = subprocess.run(["systemctl", "is-active", "auditd"], 
                               capture_output=True, text=True)
        if result.stdout.strip() != "active":
            return {"status": "not_running", "message": "auditd service not running"}

        # Check if audit rules are loaded
        result = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
        if "track_mods" not in result.stdout:
            return {"status": "no_rules", "message": "audit rules not configured"}

        return {"status": "active", "message": "audit system ready"}

    except Exception as e:
        return {"status": "error", "message": f"audit check failed: {e}"}
