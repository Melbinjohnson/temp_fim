import subprocess
import re
import pwd
import os
import json
import time
import stat
from datetime import datetime
import grp

def get_username_from_uid(uid):
    """Convert UID to username"""
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except:
        return f"UID:{uid}"

def get_real_user():
    """Get the real user who is running the session (not effective user)"""
    try:
        # Method 1: Check SUDO_USER (most reliable when using sudo)
        sudo_user = os.environ.get('SUDO_USER')
        if sudo_user and sudo_user != 'root':
            return sudo_user
        
        # Method 2: Check who is actually logged in to the terminal
        result = subprocess.run(["who", "am", "i"], capture_output=True, text=True, timeout=5)
        if result.stdout and result.returncode == 0:
            # Parse "username pts/0 ..."
            parts = result.stdout.split()
            if parts:
                return parts[0]
        
        # Method 3: Check the login sessions
        result = subprocess.run(["w", "-h"], capture_output=True, text=True, timeout=5)
        if result.stdout:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                parts = line.split()
                if len(parts) >= 1:
                    user = parts[0]
                    if user != 'root':
                        return user
        
        # Method 4: Environment variables
        for env_var in ['USER', 'LOGNAME', 'USERNAME']:
            user = os.environ.get(env_var)
            if user and user != 'root':
                return user
        
        # Method 5: Current effective user
        import getpass
        return getpass.getuser()
        
    except Exception as e:
        print(f"Error getting real user: {e}")
        return "unknown"

def get_current_user():
    """Get current logged in user with better detection"""
    return get_real_user()

def get_file_owner_info(file_path):
    """Get detailed file ownership information"""
    try:
        if not os.path.exists(file_path):
            return None
        
        stat_info = os.stat(file_path)
        owner_uid = stat_info.st_uid
        owner_gid = stat_info.st_gid
        
        try:
            owner_name = pwd.getpwuid(owner_uid).pw_name
        except:
            owner_name = f"UID:{owner_uid}"
        
        try:
            group_name = grp.getgrgid(owner_gid).gr_name
        except:
            group_name = f"GID:{owner_gid}"
        
        return {
            'owner': owner_name,
            'group': group_name,
            'uid': owner_uid,
            'gid': owner_gid,
            'mtime': stat_info.st_mtime
        }
    except Exception as e:
        print(f"Error getting file owner info for {file_path}: {e}")
        return None

def get_process_creator(file_path):
    """Try to identify who created/modified a file by checking running processes"""
    try:
        # Check if any current process has this file open
        result = subprocess.run(["lsof", "+c", "15", file_path], 
                               capture_output=True, text=True, timeout=5)
        
        if result.stdout and result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 3:
                    command = parts[0]
                    pid = parts[1]
                    user = parts[2]
                    
                    # Get more details about this process
                    try:
                        proc_result = subprocess.run(["ps", "-p", pid, "-o", "user,ruser,comm"], 
                                                   capture_output=True, text=True, timeout=2)
                        if proc_result.stdout:
                            proc_lines = proc_result.stdout.strip().split('\n')
                            if len(proc_lines) > 1:
                                proc_parts = proc_lines[1].split()
                                if len(proc_parts) >= 2:
                                    real_user = proc_parts[1]  # RUSER (real user)
                                    if real_user != user and real_user != 'root':
                                        return real_user
                                    return user
                    except:
                        pass
                    
                    return user
    except Exception:
        pass
    
    return None

def get_recent_user_activity(file_path):
    """Check recent user activity around the file creation/modification time"""
    try:
        if not os.path.exists(file_path):
            return None
        
        file_mtime = os.path.getmtime(file_path)
        file_time = datetime.fromtimestamp(file_mtime)
        
        # Check who was active around that time
        result = subprocess.run(["last", "-n", "20"], capture_output=True, text=True, timeout=5)
        if result.stdout:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                # Parse last output: username tty date time - date time
                parts = line.split()
                if len(parts) >= 4:
                    username = parts[0]
                    if username in ['reboot', 'wtmp']:
                        continue
                    
                    # Try to parse the login time
                    try:
                        login_info = ' '.join(parts[3:])
                        # This is a simplified check - you might want to improve date parsing
                        if 'still logged in' in login_info or username != 'root':
                            return username
                    except:
                        continue
    except Exception:
        pass
    
    return None

def get_last_modifier_advanced(file_path):
    """Enhanced method to detect who modified a file with multiple techniques"""
    detection_methods = []
    
    print(f"🔍 Advanced user detection for: {file_path}")
    
    # Method 1: Audit logs
    audit_user = get_audit_user(file_path)
    detection_methods.append(f"audit: {audit_user}")
    if audit_user and audit_user != "Unknown":
        print(f"  ✅ Audit logs found: {audit_user}")
        return audit_user
    
    # Method 2: Process check (who currently has the file open)
    process_user = get_process_creator(file_path)
    detection_methods.append(f"process: {process_user}")
    if process_user:
        print(f"  ✅ Process found: {process_user}")
        return process_user
    
    # Method 3: Check recent user activity
    activity_user = get_recent_user_activity(file_path)
    detection_methods.append(f"activity: {activity_user}")
    if activity_user:
        print(f"  ✅ Recent activity: {activity_user}")
        return activity_user
    
    # Method 4: File owner (but check if it's different from current user)
    file_info = get_file_owner_info(file_path)
    if file_info:
        owner = file_info['owner']
        current = get_real_user()
        detection_methods.append(f"owner: {owner}, current: {current}")
        
        # If owner is different from current user, it might be the creator
        if owner != current and owner != 'root':
            print(f"  ⚠️  File owner differs from current user: {owner}")
            return f"{owner}*"
    
    # Method 5: Check environment and session info
    real_user = get_real_user()
    detection_methods.append(f"real_user: {real_user}")
    
    # Method 6: Check if we're in a su/sudo session
    try:
        # Check if we switched users
        effective_user = pwd.getpwuid(os.geteuid()).pw_name
        real_uid = os.getuid()
        real_user_name = pwd.getpwuid(real_uid).pw_name
        
        if effective_user != real_user_name:
            print(f"  ⚠️  User switch detected: {real_user_name} -> {effective_user}")
            return f"{real_user_name}→{effective_user}"
        
    except:
        pass
    
    print(f"  ❓ All methods tried: {', '.join(detection_methods)}")
    return f"{real_user}?"

def get_audit_user(file_path):
    """Enhanced audit user detection"""
    try:
        file_basename = os.path.basename(file_path)
        file_dirname = os.path.dirname(file_path)
        
        # Multiple audit search strategies
        search_strategies = [
            # Strategy 1: Search by full path
            ["ausearch", "-f", file_path, "-ts", "today", "-i"],
            # Strategy 2: Search by filename in directory
            ["ausearch", "-f", file_basename, "-ts", "today", "-i"],
            # Strategy 3: Search for write operations
            ["ausearch", "-sc", "openat,write,close", "-f", file_path, "-ts", "today"],
            # Strategy 4: Search for file creation
            ["ausearch", "-sc", "creat,open", "-f", file_path, "-ts", "recent"],
        ]
        
        for strategy in search_strategies:
            try:
                print(f"    Trying audit strategy: {' '.join(strategy[:3])}")
                result = subprocess.run(strategy, capture_output=True, text=True, timeout=10)
                
                if result.stdout and result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    
                    # Look for the most recent entry with user info
                    for line in reversed(lines):
                        # Look for different user field formats
                        user_patterns = [
                            r'auid=(\w+)',  # Audit user ID (name format)
                            r'uid=(\w+)',   # User ID (name format)
                            r'auid=(\d+)',  # Audit user ID (numeric)
                            r'uid=(\d+)',   # User ID (numeric)
                        ]
                        
                        for pattern in user_patterns:
                            match = re.search(pattern, line)
                            if match:
                                user_id = match.group(1)
                                if user_id.isdigit():
                                    user_name = get_username_from_uid(user_id)
                                else:
                                    user_name = user_id
                                
                                if user_name and user_name != 'root':
                                    print(f"    ✅ Found in audit: {user_name}")
                                    return user_name
                        
                        # Also look for comm= (command) to get context
                        comm_match = re.search(r'comm="([^"]+)"', line)
                        if comm_match:
                            command = comm_match.group(1)
                            print(f"    📝 Command context: {command}")
                
            except subprocess.TimeoutExpired:
                print(f"    ⏰ Audit search timed out")
                continue
            except FileNotFoundError:
                print(f"    ❌ ausearch not available")
                break
            except Exception as e:
                print(f"    ⚠️  Audit search error: {e}")
                continue
        
        # Fallback: check audit log file directly
        try:
            print("    📋 Checking audit log file directly...")
            with open('/var/log/audit/audit.log', 'r') as f:
                # Read last 1000 lines
                lines = f.readlines()[-1000:]
                
                for line in reversed(lines):
                    if file_basename in line or file_path in line:
                        uid_match = re.search(r'uid=(\d+)', line)
                        if uid_match:
                            user_name = get_username_from_uid(uid_match.group(1))
                            if user_name != 'root':
                                print(f"    ✅ Found in log file: {user_name}")
                                return user_name
        except Exception as e:
            print(f"    ⚠️  Direct log check failed: {e}")
        
    except Exception as e:
        print(f"    ❌ Audit user detection failed: {e}")
    
    return "Unknown"

def get_file_audit_info(file_path, change_type="modified"):
    """Get comprehensive audit information with enhanced user detection"""
    try:
        print(f"🔍 Getting audit info for: {file_path} ({change_type})")
        
        # Enhanced user detection
        user = get_last_modifier_advanced(file_path)
        
        audit_info = {
            'user': user,
            'timestamp': None,
            'action': change_type,
            'process': 'Unknown',
            'command': 'Unknown'
        }

        # Try to get timestamp from file system if audit fails
        try:
            if os.path.exists(file_path):
                if change_type == "new":
                    # For new files, use creation time (birth time) if available
                    try:
                        stat_result = os.stat(file_path)
                        # On Linux, st_ctime is the last metadata change time
                        timestamp = stat_result.st_ctime
                        audit_info['timestamp'] = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        mtime = os.path.getmtime(file_path)
                        audit_info['timestamp'] = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    mtime = os.path.getmtime(file_path)
                    audit_info['timestamp'] = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
            else:
                audit_info['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        except:
            audit_info['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        print(f"✅ Audit info: user={user}, time={audit_info['timestamp']}")
        return audit_info

    except Exception as e:
        print(f"❌ Audit info failed: {e}")
        current_user = get_real_user()
        return {
            'user': f"{current_user}?",
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'action': change_type,
            'process': 'Unknown',
            'command': 'Unknown'
        }

# ... (rest of the functions remain the same: setup_audit_rules, check_audit_system, etc.)

def setup_audit_rules():
    """Setup audit rules for file monitoring"""
    try:
        # Check if running with sudo
        if os.geteuid() != 0:
            print("⚠️  Audit setup requires root privileges. Run with sudo for best results.")
            return False

        # Check if auditd is installed
        result = subprocess.run(["which", "auditd"], capture_output=True, text=True)
        if result.returncode != 0:
            print("📦 Installing auditd...")
            try:
                subprocess.run(["apt-get", "update"], check=True)
                subprocess.run(["apt-get", "install", "-y", "auditd", "audispd-plugins"], check=True)
            except subprocess.CalledProcessError:
                print("❌ Failed to install auditd. Manual installation may be required.")
                return False

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
            'user_session': False,
            'who_command': False
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
            
        # Check user session detection
        try:
            real_user = get_real_user()
            if real_user and real_user != 'unknown':
                detection_methods['user_session'] = True
        except:
            pass
            
        # Check who command
        try:
            result = subprocess.run(["who"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                detection_methods['who_command'] = True
        except:
            pass

        active_methods = sum(detection_methods.values())
        
        if active_methods >= 3:
            return {"status": "excellent", "message": f"{active_methods}/4 detection methods available"}
        elif active_methods >= 2:
            return {"status": "good", "message": f"{active_methods}/4 detection methods available"}
        elif active_methods >= 1:
            return {"status": "limited", "message": f"{active_methods}/4 detection methods available"}
        else:
            return {"status": "poor", "message": "No reliable user detection methods available"}

    except Exception as e:
        return {"status": "error", "message": f"Detection check failed: {e}"}
