import subprocess
import re
import pwd
import os
import json
import time
import stat
from datetime import datetime

def get_username_from_uid(uid):
    """Convert UID to username"""
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except:
        return f"UID:{uid}"

def get_current_user():
    """Get current logged in user as fallback"""
    try:
        # Method 1: Check who is currently logged in
        result = subprocess.run(["who"], capture_output=True, text=True, timeout=5)
        if result.stdout:
            lines = result.stdout.strip().split('\n')
            if lines and lines[0]:
                username = lines[0].split()[0]
                return username
        
        # Method 2: Check environment variables
        for env_var in ['SUDO_USER', 'USER', 'USERNAME', 'LOGNAME']:
            user = os.environ.get(env_var)
            if user and user != 'root':
                return user
        
        # Method 3: Get from process owner
        import getpass
        return getpass.getuser()
        
    except:
        return "system"

def get_file_stat_user(file_path):
    """Get file owner from file system stats"""
    try:
        if os.path.exists(file_path):
            stat_info = os.stat(file_path)
            return pwd.getpwuid(stat_info.st_uid).pw_name
        return None
    except:
        return None

def get_last_modifier_advanced(file_path):
    """Advanced method to detect who modified a file"""
    methods = []
    
    # Method 1: Try audit logs with multiple approaches
    audit_user = get_audit_user(file_path)
    if audit_user and audit_user != "Unknown":
        return audit_user
    methods.append(f"audit: {audit_user}")
    
    # Method 2: Check recent file system events via lsof
    lsof_user = get_lsof_user(file_path)
    if lsof_user:
        return lsof_user
    methods.append(f"lsof: {lsof_user}")
    
    # Method 3: Check process that might have accessed the file
    process_user = get_process_user(file_path)
    if process_user:
        return process_user
    methods.append(f"process: {process_user}")
    
    # Method 4: Check file owner (last resort)
    owner_user = get_file_stat_user(file_path)
    if owner_user:
        return f"{owner_user}*"  # * indicates it's file owner, not necessarily modifier
    methods.append(f"owner: {owner_user}")
    
    # Method 5: Current user fallback
    current_user = get_current_user()
    methods.append(f"current: {current_user}")
    
    # If all methods fail, return current user with indication
    return f"{current_user}?"  # ? indicates uncertainty

def get_audit_user(file_path):
    """Get user from audit logs"""
    try:
        # Multiple audit search methods
        commands = [
            ["ausearch", "-f", file_path, "-ts", "today"],
            ["ausearch", "-k", "track_mods", "-ts", "today"],
            ["ausearch", "-sc", "write,open,openat", "-f", file_path],
        ]
        
        for cmd in commands:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if result.stdout and result.returncode == 0:
                    # Look for the most recent entry
                    lines = result.stdout.strip().split('\n')
                    for line in reversed(lines):
                        uid_match = re.search(r'uid=(\d+)', line)
                        if uid_match:
                            return get_username_from_uid(uid_match.group(1))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
                
        # Fallback to grep audit log
        try:
            result = subprocess.run(
                ["grep", os.path.basename(file_path), "/var/log/audit/audit.log"], 
                capture_output=True, text=True, timeout=10
            )
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in reversed(lines[-10:]):  # Check last 10 matches
                    uid_match = re.search(r'uid=(\d+)', line)
                    if uid_match:
                        return get_username_from_uid(uid_match.group(1))
        except:
            pass
            
    except Exception as e:
        pass
    
    return "Unknown"

def get_lsof_user(file_path):
    """Get user who has file open via lsof"""
    try:
        result = subprocess.run(["lsof", file_path], capture_output=True, text=True, timeout=5)
        if result.stdout:
            lines = result.stdout.strip().split('\n')
            for line in lines[1:]:  # Skip header
                if line:
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]  # User column
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None

def get_process_user(file_path):
    """Get user from processes that might have accessed the file"""
    try:
        # Look for recent processes that accessed files in the same directory
        dir_path = os.path.dirname(file_path)
        result = subprocess.run(["fuser", "-v", dir_path], capture_output=True, text=True, timeout=5)
        if result.stderr:  # fuser outputs to stderr
            lines = result.stderr.strip().split('\n')
            for line in lines:
                if 'USER' not in line and line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]  # User column
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None

def get_file_audit_info(file_path, change_type="modified"):
    """Get comprehensive audit information with multiple fallback methods"""
    try:
        # Enhanced user detection
        user = get_last_modifier_advanced(file_path)
        
        audit_info = {
            'user': user,
            'timestamp': None,
            'action': change_type,
            'process': 'Unknown',
            'command': 'Unknown'
        }

        # Try to get additional context from audit logs
        try:
            result = subprocess.run(
                ["ausearch", "-f", file_path, "-ts", "today"], 
                capture_output=True, text=True, timeout=5
            )
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in reversed(lines):
                    if 'msg=audit' in line:
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
        except:
            pass

        # If no timestamp from audit, use file modification time
        if not audit_info['timestamp']:
            try:
                if os.path.exists(file_path):
                    mtime = os.path.getmtime(file_path)
                    audit_info['timestamp'] = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    audit_info['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            except:
                audit_info['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        return audit_info

    except Exception as e:
        current_user = get_current_user()
        return {
            'user': f"{current_user}?",
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'action': change_type,
            'process': 'Unknown',
            'command': 'Unknown'
        }

def setup_audit_rules():
    """Setup audit rules for file monitoring"""
    try:
        # Check if running with sudo
        if os.geteuid() != 0:
            print("⚠️  Audit setup requires root privileges. Run with sudo.")
            return False

        # Check if auditd is installed
        result = subprocess.run(["which", "auditd"], capture_output=True, text=True)
        if result.returncode != 0:
            print("📦 Installing auditd...")
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "auditd", "audispd-plugins"], check=True)

        # Start auditd service
        subprocess.run(["systemctl", "start", "auditd"], check=False)
        subprocess.run(["systemctl", "enable", "auditd"], check=False)

        # Add comprehensive audit rules
        audit_rules = [
            # File system monitoring
            "-w /etc -p wa -k track_mods",
            "-w /usr/bin -p wa -k track_mods", 
            "-w /usr/sbin -p wa -k track_mods",
            "-w /var -p wa -k track_mods",
            "-w /home -p wa -k track_mods",
            # System calls
            "-a always,exit -F arch=b64 -S open,openat,write,close -k track_mods",
            "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -k track_mods",
            "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -k track_mods",
            "-a always,exit -F arch=b32 -S open,openat,write,close -k track_mods",
            "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -k track_mods",
        ]

        success_count = 0
        for rule in audit_rules:
            try:
                result = subprocess.run(
                    ["auditctl"] + rule.split()[1:], 
                    check=False, capture_output=True, text=True
                )
                if result.returncode == 0:
                    success_count += 1
            except Exception:
                pass

        if success_count > 0:
            print(f"✅ {success_count}/{len(audit_rules)} audit rules configured")
            return True
        else:
            print("❌ Failed to configure audit rules")
            return False

    except Exception as e:
        print(f"❌ Audit setup failed: {e}")
        return False

def check_audit_system():
    """Check if audit system is working"""
    try:
        # Test multiple detection methods
        detection_methods = {
            'audit_logs': False,
            'lsof': False,
            'fuser': False,
            'who': False
        }
        
        # Check auditd
        try:
            result = subprocess.run(["systemctl", "is-active", "auditd"], 
                                   capture_output=True, text=True, timeout=5)
            if result.stdout.strip() == "active":
                detection_methods['audit_logs'] = True
        except:
            pass
        
        # Check lsof
        try:
            result = subprocess.run(["which", "lsof"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                detection_methods['lsof'] = True
        except:
            pass
            
        # Check fuser
        try:
            result = subprocess.run(["which", "fuser"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                detection_methods['fuser'] = True
        except:
            pass
            
        # Check who command
        try:
            result = subprocess.run(["who"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                detection_methods['who'] = True
        except:
            pass

        active_methods = sum(detection_methods.values())
        
        if active_methods >= 2:
            return {"status": "good", "message": f"{active_methods}/4 detection methods available"}
        elif active_methods >= 1:
            return {"status": "limited", "message": f"{active_methods}/4 detection methods available"}
        else:
            return {"status": "poor", "message": "No reliable user detection methods available"}

    except Exception as e:
        return {"status": "error", "message": f"Detection check failed: {e}"}
