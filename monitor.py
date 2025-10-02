import os
import json
import time
from datetime import datetime
from utils.file_utils import get_file_metadata
from utils.config_loader import load_config
from utils.email_alert import send_email_alert, play_beep
from utils.audit_utils import get_file_audit_info, check_audit_system, setup_audit_rules, get_current_user, get_last_modifier_advanced
from ai_modules.risk_scorer import AIRiskScorer
from utils.virus_total import check_file_hash_vt, vt_integration, set_vt_api_key
from utils.audit_utils import get_file_audit_info, check_audit_system, setup_audit_rules
import getpass


config = load_config()

MONITOR_PATH = config["monitor_path"]
BASELINE_PATH = config["baseline_file"]
REPORT_PATH = config["report_file"]
AI_REPORT_PATH = config.get("ai_report_file", "data/ai_risk_report.json")
VT_REPORT_PATH = config.get("vt_report_file", "data/virustotal_report.json")
exclude = config["exclude"]
SCAN_INTERVAL = config.get("scan_interval", 10)
AI_ENABLED = config.get("ai_risk_scoring", True)

def get_current_user():
    """Get current user as fallback"""
    try:
        for env_var in ['SUDO_USER', 'USER', 'USERNAME', 'LOGNAME']:
            user = os.environ.get(env_var)
            if user and user != 'root':
                return user
        return getpass.getuser()
    except:
        return "system"

def get_last_modifier_advanced(file_path):
    """Simple fallback for user detection"""
    try:
        # Try to get file owner
        import pwd
        import stat
        if os.path.exists(file_path):
            stat_info = os.stat(file_path)
            return pwd.getpwuid(stat_info.st_uid).pw_name + "*"
    except:
        pass
    return get_current_user() + "?"

def is_excluded(path):
    return any(excluded in path for excluded in exclude)

def load_baseline():
    if not os.path.exists(BASELINE_PATH):
        print("Baseline not found. Please run initialize.py first.")
        return None

    with open(BASELINE_PATH, "r") as f:
        baseline_data = json.load(f)
        
    # Handle new format with metadata
    if isinstance(baseline_data, dict) and "files" in baseline_data:
        return baseline_data["files"]
    else:
        # Legacy format
        return baseline_data

def scan_current_state(directory):
    current_data = {}
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root, d))]
        for fname in files:
            file_path = os.path.join(root, fname)
            if is_excluded(file_path):
                continue
            metadata = get_file_metadata(file_path)

            if metadata:
                relative_path = os.path.relpath(file_path, directory)
                current_data[relative_path] = metadata

    return current_data

def compare_states(baseline, current):
    modified = []
    deleted = []
    new = []

    # Check for modified and deleted files
    for path in baseline:
        if path not in current:
            deleted.append(path)
        elif baseline[path]['hash'] != current[path]['hash']:
            modified.append(path)

    # Check for new files
    for path in current:
        if path not in baseline:
            new.append(path)

    return modified, deleted, new

def enhance_changes_with_audit_info(modified, deleted, new, current_state):
    """Enhanced version with better user detection and multiple fallbacks"""
    enhanced_changes = []
    
    print("🔍 Enhancing changes with audit information...")
    
    # Process modified files
    for file_path in modified:
        print(f"  📄 Analyzing modified: {file_path}")
        
        # Get comprehensive audit info
        audit_info = get_file_audit_info(file_path, "modified")
        metadata = current_state.get(file_path, {})
        
        # Enhanced user detection with multiple fallbacks
        detected_user = audit_info.get('user', 'Unknown')
        if detected_user == 'Unknown' or not detected_user:
            # Fallback 1: Try advanced detection
            detected_user = get_last_modifier_advanced(file_path)
            if detected_user == 'Unknown':
                # Fallback 2: Use file owner
                detected_user = metadata.get('owner', get_current_user())
        
        enhanced_changes.append({
            'file_path': file_path,
            'change_type': 'modified',
            'audit_user': detected_user,
            'audit_timestamp': audit_info.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            'audit_process': audit_info.get('process', 'Unknown'),
            'audit_command': audit_info.get('command', 'Unknown'),
            'file_owner': metadata.get('owner', 'Unknown'),
            'file_size': metadata.get('size', 0),
            'last_modified': metadata.get('last_modified', 'Unknown')
        })
        print(f"    👤 User detected: {detected_user}")
    
    # Process new files
    for file_path in new:
        print(f"  📄 Analyzing new: {file_path}")
        
        audit_info = get_file_audit_info(file_path, "created")
        metadata = current_state.get(file_path, {})
        
        # Enhanced user detection
        detected_user = audit_info.get('user', 'Unknown')
        if detected_user == 'Unknown' or not detected_user:
            detected_user = get_last_modifier_advanced(file_path)
            if detected_user == 'Unknown':
                detected_user = metadata.get('owner', get_current_user())
        
        enhanced_changes.append({
            'file_path': file_path,
            'change_type': 'new',
            'audit_user': detected_user,
            'audit_timestamp': audit_info.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            'audit_process': audit_info.get('process', 'Unknown'),
            'audit_command': audit_info.get('command', 'Unknown'),
            'file_owner': metadata.get('owner', 'Unknown'),
            'file_size': metadata.get('size', 0),
            'last_modified': metadata.get('last_modified', 'Unknown')
        })
        print(f"    👤 User detected: {detected_user}")
    
    # Process deleted files
    for file_path in deleted:
        print(f"  📄 Analyzing deleted: {file_path}")
        
        audit_info = get_file_audit_info(file_path, "deleted")
        
        # For deleted files, rely more on audit logs and current user
        detected_user = audit_info.get('user', 'Unknown')
        if detected_user == 'Unknown' or not detected_user:
            detected_user = get_current_user()
        
        enhanced_changes.append({
            'file_path': file_path,
            'change_type': 'deleted',
            'audit_user': detected_user,
            'audit_timestamp': audit_info.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            'audit_process': audit_info.get('process', 'Unknown'),
            'audit_command': audit_info.get('command', 'Unknown'),
            'file_owner': 'N/A',
            'file_size': 0,
            'last_modified': 'N/A'
        })
        print(f"    👤 User detected: {detected_user}")
    
    print(f"✅ Enhanced {len(enhanced_changes)} changes with user information")
    return enhanced_changes

def analyze_with_ai(changes_dict, current_data, ai_scorer, enhanced_changes=None, vt_results=None):
    """
    Analyze file changes using AI risk scoring with VirusTotal integration
    """
    ai_results = {
        'high_risk_changes': [],
        'medium_risk_changes': [],
        'low_risk_changes': [],
        'total_risk_score': 0.0,
        'critical_alerts': [],
        'recommendations': []
    }
    
    all_changes = []
    
    for change_type in ['modified', 'deleted', 'new']:
        for file_path in changes_dict[change_type]:
            if change_type == 'deleted':
                metadata = {'size': 0, 'permissions': '000'}
            else:
                full_path = os.path.join(MONITOR_PATH, file_path)
                metadata = get_file_metadata(full_path) or {}
            
            # Find VT results for this specific file
            file_vt_result = None
            if vt_results:
                for category in ['malicious_files', 'suspicious_files', 'clean_files', 'not_found_files']:
                    for vt_file in vt_results.get(category, []):
                        if vt_file.get('file_path') == file_path:
                            file_vt_result = vt_file
                            break
                    if file_vt_result:
                        break
            
            # NEW: Pass VT results to AI analysis
            analysis = ai_scorer.analyze_file_change(file_path, change_type, metadata, file_vt_result)
            
            # Enhance with audit information if available
            if enhanced_changes:
                for enhanced_change in enhanced_changes:
                    if enhanced_change['file_path'] == file_path:
                        analysis.update({
                            'audit_user': enhanced_change.get('audit_user', 'Unknown'),
                            'audit_timestamp': enhanced_change.get('audit_timestamp'),
                            'audit_process': enhanced_change.get('audit_process', 'Unknown'),
                            'audit_command': enhanced_change.get('audit_command', 'Unknown')
                        })
                        break
            
            all_changes.append(analysis)
            
            # Categorize by risk level
            risk_level = analysis['risk_level']
            if risk_level == 'CRITICAL':
                ai_results['high_risk_changes'].append(analysis)
                ai_results['critical_alerts'].extend(analysis['recommendations'])
            elif risk_level == 'HIGH':
                ai_results['high_risk_changes'].append(analysis)
            elif risk_level == 'MEDIUM':
                ai_results['medium_risk_changes'].append(analysis)
            else:
                ai_results['low_risk_changes'].append(analysis)
    
    # Calculate overall risk score
    if all_changes:
        ai_results['total_risk_score'] = sum(change['risk_score'] for change in all_changes) / len(all_changes)
    
    # Enhanced recommendations for malware detection
    malware_detected = any(change.get('features', {}).get('vt_is_malicious', 0) == 1 for change in all_changes)
    if malware_detected:
        ai_results['recommendations'].insert(0, "🚨 MALWARE DETECTED - IMMEDIATE SYSTEM ISOLATION REQUIRED")
        ai_results['critical_alerts'].insert(0, "MALWARE ALERT: Malicious files detected by VirusTotal")
    
    # Generate overall recommendations
    if ai_results['high_risk_changes']:
        ai_results['recommendations'].append("🚨 HIGH RISK ACTIVITY DETECTED - Immediate investigation required")
    if len(ai_results['high_risk_changes']) > 5:
        ai_results['recommendations'].append("⚠️  Multiple high-risk changes detected - Possible systematic attack")
    if ai_results['total_risk_score'] > 0.7:
        ai_results['recommendations'].append("🔍 Overall risk level is elevated - Enhanced monitoring recommended")
    
    return ai_results

def analyze_with_virustotal(modified, new, deleted, current_data):
    """Analyze files with VirusTotal"""
    vt_results = {
        'scanned_files': [],
        'malicious_files': [],
        'suspicious_files': [],
        'clean_files': [],
        'not_found_files': [],
        'scan_errors': []
    }
    
    current_config = load_config()
    if not current_config.get("virustotal_enabled", False):
        print("🦠 VirusTotal scanning is disabled")
        return vt_results
    
    if not current_config.get("virustotal_api_key"):
        print("🦠 VirusTotal API key not configured")
        return vt_results
    
    # Initialize VirusTotal if not already done
    if not vt_integration.vtotal:
        api_key = current_config.get("virustotal_api_key")
        if api_key:
            set_vt_api_key(api_key)
            print("🦠 VirusTotal API initialized")
        else:
            print("🦠 No API key available")
            return vt_results
    
    # Files to scan (only new and modified, not deleted)
    files_to_scan = []
    if current_config.get("virustotal_scan_new_files", True):
        files_to_scan.extend(new)
    if current_config.get("virustotal_scan_modified_files", True):
        files_to_scan.extend(modified)
    
    if not files_to_scan:
        return vt_results
    
    print(f"🦠 VirusTotal: Scanning {len(files_to_scan)} files...")
    
    for file_path in files_to_scan:
        try:
            metadata = current_data.get(file_path, {})
            file_hash = metadata.get('hash')
            
            if not file_hash:
                print(f"🦠 No hash available for {file_path}")
                continue
            
            print(f"🔍 Scanning {file_path} with hash {file_hash[:8]}...")
            result, message = check_file_hash_vt(file_hash)
            
            scan_info = {
                'file_path': file_path,
                'file_hash': file_hash,
                'timestamp': datetime.now().isoformat()
            }
            
            if result:
                scan_info.update(result)
                vt_results['scanned_files'].append(scan_info)
                
                if result.get('status') == 'found':
                    malicious_count = result.get('malicious', 0)
                    suspicious_count = result.get('suspicious', 0)
                    
                    if malicious_count > 0:
                        print(f"🚨 MALWARE DETECTED: {file_path} - {malicious_count} engines")
                        vt_results['malicious_files'].append(scan_info)
                    elif suspicious_count > 0:
                        print(f"⚠️  SUSPICIOUS: {file_path} - {suspicious_count} engines")
                        vt_results['suspicious_files'].append(scan_info)
                    else:
                        print(f"✅ Clean: {file_path}")
                        vt_results['clean_files'].append(scan_info)
                elif result.get('status') == 'not_found':
                    print(f"❓ Unknown: {file_path} not in VirusTotal database")
                    vt_results['not_found_files'].append(scan_info)
            else:
                # Handle errors (like 404) as "not found" instead of error
                if "404" in message or "not found" in message.lower():
                    print(f"❓ Unknown: {file_path} not in VirusTotal database")
                    scan_info['status'] = 'not_found'
                    vt_results['not_found_files'].append(scan_info)
                else:
                    print(f"❌ Error scanning {file_path}: {message}")
                    scan_info['error'] = message
                    vt_results['scan_errors'].append(scan_info)
                    
        except Exception as e:
            print(f"❌ Error scanning {file_path} with VirusTotal: {e}")
            error_info = {
                'file_path': file_path,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            vt_results['scan_errors'].append(error_info)
    
    print(f"🦠 VirusTotal scan complete: {len(vt_results['scanned_files'])} scanned, {len(vt_results['not_found_files'])} unknown")
    return vt_results

def merge_vt_results(existing_vt_results, new_vt_results):
    """
    Merge new VirusTotal results with existing ones, preserving old scans
    """
    if not existing_vt_results:
        return new_vt_results
    
    if not new_vt_results:
        return existing_vt_results
    
    # Create a merged result starting with existing data
    merged = existing_vt_results.copy()
    
    # Track files that have new scans
    new_scanned_files = set()
    for new_file in new_vt_results.get('scanned_files', []):
        new_scanned_files.add(new_file['file_path'])
    
    # Remove old entries for files with new scans
    for category in ['scanned_files', 'malicious_files', 'suspicious_files', 'clean_files', 'not_found_files', 'scan_errors']:
        merged[category] = [
            f for f in merged.get(category, [])
            if f['file_path'] not in new_scanned_files
        ]
    
    # Add all new results
    for category in ['scanned_files', 'malicious_files', 'suspicious_files', 'clean_files', 'not_found_files', 'scan_errors']:
        merged.setdefault(category, []).extend(new_vt_results.get(category, []))
    
    return merged

def merge_ai_results(existing_ai_results, new_ai_results):
    """
    Merge new AI results with existing ones, preserving old analysis
    """
    if not existing_ai_results:
        return new_ai_results
    
    if not new_ai_results:
        return existing_ai_results
    
    merged = existing_ai_results.copy()
    
    # Update overall metrics with new data
    merged['total_risk_score'] = new_ai_results.get('total_risk_score', existing_ai_results.get('total_risk_score', 0.0))
    merged['critical_alerts'] = new_ai_results.get('critical_alerts', [])
    merged['recommendations'] = new_ai_results.get('recommendations', [])
    
    # Track files that have new analysis
    new_analyzed_files = set()
    for category in ['high_risk_changes', 'medium_risk_changes', 'low_risk_changes']:
        for change in new_ai_results.get(category, []):
            new_analyzed_files.add(change['file_path'])
    
    # Remove old entries for files with new analysis
    for category in ['high_risk_changes', 'medium_risk_changes', 'low_risk_changes']:
        merged[category] = [
            change for change in merged.get(category, [])
            if change['file_path'] not in new_analyzed_files
        ]
    
    # Add new analysis results
    for category in ['high_risk_changes', 'medium_risk_changes', 'low_risk_changes']:
        merged.setdefault(category, []).extend(new_ai_results.get(category, []))
    
    return merged

def cleanup_deleted_files_from_reports(deleted_files):
    """
    Remove deleted files from AI and VT reports to keep them clean
    """
    if not deleted_files:
        return
    
    print(f"🧹 Cleaning up {len(deleted_files)} deleted files from reports...")
    
    # Clean AI report
    if os.path.exists(AI_REPORT_PATH):
        try:
            with open(AI_REPORT_PATH, "r") as f:
                ai_results = json.load(f)
            
            cleaned = False
            for category in ['high_risk_changes', 'medium_risk_changes', 'low_risk_changes']:
                original_count = len(ai_results.get(category, []))
                ai_results[category] = [
                    change for change in ai_results.get(category, [])
                    if change['file_path'] not in deleted_files
                ]
                if len(ai_results[category]) < original_count:
                    cleaned = True
            
            if cleaned:
                with open(AI_REPORT_PATH, "w") as f:
                    json.dump(ai_results, f, indent=4)
                print(f"🤖 Cleaned deleted files from AI report")
                    
        except Exception as e:
            print(f"Warning: Could not clean AI report: {e}")
    
    # Clean VT report  
    if os.path.exists(VT_REPORT_PATH):
        try:
            with open(VT_REPORT_PATH, "r") as f:
                vt_results = json.load(f)
            
            cleaned = False
            for category in ['scanned_files', 'malicious_files', 'suspicious_files', 
                           'clean_files', 'not_found_files', 'scan_errors']:
                original_count = len(vt_results.get(category, []))
                vt_results[category] = [
                    result for result in vt_results.get(category, [])
                    if result['file_path'] not in deleted_files
                ]
                if len(vt_results[category]) < original_count:
                    cleaned = True
            
            if cleaned:
                with open(VT_REPORT_PATH, "w") as f:
                    json.dump(vt_results, f, indent=4)
                print(f"🦠 Cleaned deleted files from VT report")
                    
        except Exception as e:
            print(f"Warning: Could not clean VT report: {e}")

def save_report(modified, deleted, new, ai_results=None, vt_results=None):
    """
    Save reports with incremental updates - preserving old scan results
    """
    # Save basic file changes report (always replace - this is current state)
    report = {
        "timestamp": datetime.now().isoformat(),
        "modified": modified,
        "deleted": deleted,
        "new": new
    }
    
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=4)
    
    # Clean up deleted files from historical reports
    if deleted:
        cleanup_deleted_files_from_reports(deleted)
    
    # Handle AI report with merging
    if ai_results:
        existing_ai_results = {}
        if os.path.exists(AI_REPORT_PATH):
            try:
                with open(AI_REPORT_PATH, "r") as f:
                    existing_ai_results = json.load(f)
            except Exception as e:
                print(f"Warning: Could not load existing AI results: {e}")
        
        # Merge AI results
        merged_ai_results = merge_ai_results(existing_ai_results, ai_results)
        
        with open(AI_REPORT_PATH, "w") as f:
            json.dump(merged_ai_results, f, indent=4)
    
    # Handle VirusTotal report with merging
    if vt_results:
        existing_vt_results = {}
        if os.path.exists(VT_REPORT_PATH):
            try:
                with open(VT_REPORT_PATH, "r") as f:
                    existing_vt_results = json.load(f)
            except Exception as e:
                print(f"Warning: Could not load existing VT results: {e}")
        
        # Merge VirusTotal results
        merged_vt_results = merge_vt_results(existing_vt_results, vt_results)
        
        with open(VT_REPORT_PATH, "w") as f:
            json.dump(merged_vt_results, f, indent=4)
    
    print(f"\n📄 Report saved to {REPORT_PATH}")
    if ai_results:
        print(f"🤖 AI Analysis merged and saved to {AI_REPORT_PATH}")
    if vt_results:
        print(f"🦠 VirusTotal Analysis merged and saved to {VT_REPORT_PATH}")

def print_report_with_audit(modified, deleted, new, enhanced_changes, ai_results=None, vt_results=None):
    """Enhanced reporting with audit information and better user display"""
    print("\n📂 Enhanced File Integrity Report with User Tracking:")
    print("=" * 65)

    if not enhanced_changes:
        print("✅ No changes detected. All files are intact.")
        return

    # Group changes by type
    modified_changes = [c for c in enhanced_changes if c['change_type'] == 'modified']
    new_changes = [c for c in enhanced_changes if c['change_type'] == 'new']
    deleted_changes = [c for c in enhanced_changes if c['change_type'] == 'deleted']

    if modified_changes:
        print(f"\n✏️  Modified files ({len(modified_changes)}):")
        for change in modified_changes:
            user_display = change['audit_user']
            # Clean up user display
            if user_display.endswith('*'):
                user_display = f"{user_display[:-1]} (owner)"
            elif user_display.endswith('?'):
                user_display = f"{user_display[:-1]} (detected)"
            
            print(f"   📄 {change['file_path']}")
            print(f"      👤 Modified by: {user_display}")
            print(f"      🕐 When: {change['audit_timestamp']}")
            print(f"      ⚙️  Process: {change['audit_process']}")
            print(f"      📝 Command: {change['audit_command']}")
            print(f"      👑 Owner: {change['file_owner']}")
            print()

    if new_changes:
        print(f"\n➕ New files ({len(new_changes)}):")
        for change in new_changes:
            user_display = change['audit_user']
            if user_display.endswith('*'):
                user_display = f"{user_display[:-1]} (owner)"
            elif user_display.endswith('?'):
                user_display = f"{user_display[:-1]} (detected)"
                
            print(f"   📄 {change['file_path']}")
            print(f"      👤 Created by: {user_display}")
            print(f"      🕐 When: {change['audit_timestamp']}")
            print(f"      ⚙️  Process: {change['audit_process']}")
            print(f"      📝 Command: {change['audit_command']}")
            print(f"      👑 Owner: {change['file_owner']}")
            print()

    if deleted_changes:
        print(f"\n❌ Deleted files ({len(deleted_changes)}):")
        for change in deleted_changes:
            user_display = change['audit_user']
            if user_display.endswith('*'):
                user_display = f"{user_display[:-1]} (owner)"
            elif user_display.endswith('?'):
                user_display = f"{user_display[:-1]} (detected)"
                
            print(f"   📄 {change['file_path']}")
            print(f"      👤 Deleted by: {user_display}")
            print(f"      🕐 When: {change['audit_timestamp']}")
            print(f"      ⚙️  Process: {change['audit_process']}")
            print(f"      📝 Command: {change['audit_command']}")
            print()

    # Print AI analysis if available
    if ai_results:
        print("\n🤖 AI Risk Analysis:")
        print("=" * 25)
        print(f"Overall Risk Score: {ai_results['total_risk_score']:.3f}")
        
        if ai_results['critical_alerts']:
            print("\n🚨 CRITICAL ALERTS:")
            for alert in ai_results['critical_alerts'][:3]:
                print(f"   {alert}")
        
        if ai_results['high_risk_changes']:
            print(f"\n⚠️  High Risk Changes ({len(ai_results['high_risk_changes'])}):")
            for change in ai_results['high_risk_changes'][:5]:
                user_info = change.get('audit_user', 'Unknown')
                vt_info = ""
                if change.get('features', {}).get('vt_is_malicious', 0) == 1:
                    vt_info = " 🦠 MALWARE"
                elif change.get('features', {}).get('vt_is_suspicious', 0) == 1:
                    vt_info = " ⚠️ SUSPICIOUS"
                print(f"   {change['file_path']} - Risk: {change['risk_score']:.3f} ({change['risk_level']}) - User: {user_info}{vt_info}")
        
        if ai_results['recommendations']:
            print("\n💡 Recommendations:")
            for rec in ai_results['recommendations'][:3]:
                print(f"   {rec}")
    
    # Print VirusTotal analysis if available
    if vt_results:
        print("\n🦠 VirusTotal Analysis:")
        print("=" * 25)
        
        total_scanned = len(vt_results['scanned_files'])
        malicious_count = len(vt_results['malicious_files'])
        suspicious_count = len(vt_results['suspicious_files'])
        clean_count = len(vt_results['clean_files'])
        not_found_count = len(vt_results['not_found_files'])
        
        if total_scanned > 0:
            print(f"New files scanned this round: {total_scanned}")
            
            if malicious_count > 0:
                print(f"\n🚨 MALWARE DETECTED ({malicious_count} files):")
                for malware in vt_results['malicious_files'][:3]:
                    print(f"   {malware['file_path']} - {malware.get('malicious', 0)} engines")
            
            if suspicious_count > 0:
                print(f"\n⚠️  SUSPICIOUS FILES ({suspicious_count} files):")
                for suspicious in vt_results['suspicious_files'][:3]:
                    print(f"   {suspicious['file_path']} - {suspicious.get('suspicious', 0)} engines")
            
            if clean_count > 0:
                print(f"\n✅ Clean files this round: {clean_count}")
            
            if not_found_count > 0:
                print(f"\n❓ Unknown files (not in VT database): {not_found_count}")
        else:
            print("No new files were scanned this round")

def send_ai_enhanced_alert(modified, deleted, new, enhanced_changes, ai_results, vt_results, current_config):
    """Send enhanced email alert with AI risk analysis, VirusTotal results, and user audit information"""
    if not current_config.get("email_alert"):
        return
    
    # Determine if alert should be sent based on risk level
    should_alert = False
    if ai_results and (ai_results['high_risk_changes'] or ai_results['total_risk_score'] > 0.6):
        should_alert = True
    elif vt_results and vt_results['malicious_files']:
        should_alert = True
    elif current_config.get("alert_all_changes", False):
        should_alert = True
    
    if not should_alert:
        return
    
    # Compose enhanced email body with audit information
    body = "🕵️ Enhanced File Integrity Monitoring Alert with User Tracking & Malware Detection\n\n"
    
    if ai_results:
        body += f"🤖 AI Risk Assessment: {ai_results['total_risk_score']:.3f}\n\n"
    
    # VirusTotal alerts first (highest priority)
    if vt_results and vt_results['malicious_files']:
        body += "🦠 VIRUSTOTAL MALWARE DETECTED:\n"
        for malicious_file in vt_results['malicious_files'][:3]:
            file_name = malicious_file['file_path'].split("/")[-1]
            detections = malicious_file.get('malicious', 0)
            body += f"  • {file_name} - {detections} engines detected malware\n"
        body += "\n"
    
    if ai_results and ai_results['critical_alerts']:
        body += "🚨 CRITICAL ALERTS:\n"
        for alert in ai_results['critical_alerts']:
            body += f"  • {alert}\n"
        body += "\n"
    
    # Enhanced file change information with user audit data
    if enhanced_changes:
        for change in enhanced_changes:
            change_type = change['change_type'].upper()
            user_display = change['audit_user']
            
            # Clean up user display for email
            if user_display.endswith('*'):
                user_display = f"{user_display[:-1]} (file owner)"
            elif user_display.endswith('?'):
                user_display = f"{user_display[:-1]} (detected user)"
            
            body += f"{change_type}: {change['file_path']}\n"
            body += f"   👤 User: {user_display}\n"
            body += f"   🕐 Time: {change['audit_timestamp']}\n"
            body += f"   ⚙️  Process: {change['audit_process']}\n"
            body += f"   📝 Command: {change['audit_command']}\n"
            if change['change_type'] != 'deleted':
                body += f"   👑 Owner: {change['file_owner']}\n"
            
            # Add AI risk info if available
            if ai_results:
                for category in ['high_risk_changes', 'medium_risk_changes', 'low_risk_changes']:
                    for ai_change in ai_results.get(category, []):
                        if ai_change['file_path'] == change['file_path']:
                            body += f"   🤖 AI Risk: {ai_change['risk_score']:.3f} ({ai_change['risk_level']})\n"
                            # Add VirusTotal info
                            if ai_change.get('features', {}).get('vt_is_malicious', 0) == 1:
                                body += f"   🦠 VirusTotal: MALWARE DETECTED\n"
                            elif ai_change.get('features', {}).get('vt_is_suspicious', 0) == 1:
                                body += f"   ⚠️  VirusTotal: SUSPICIOUS\n"
                            break
            body += "\n"
    
    if ai_results and ai_results['recommendations']:
        body += "💡 AI Recommendations:\n"
        for rec in ai_results['recommendations']:
            body += f"  • {rec}\n"

    send_email_alert(body.strip())

def debug_user_detection(file_path):
    """Debug user detection for a specific file"""
    print(f"\n🔍 DEBUG: User detection for {file_path}")
    print("-" * 50)
    
    from utils.audit_utils import (
        get_real_user, get_last_modifier_advanced, 
        get_file_audit_info, get_file_owner_info
    )
    
    # Check real user
    real_user = get_real_user()
    print(f"Real user: {real_user}")
    
    # Check file owner
    owner_info = get_file_owner_info(file_path)
    print(f"File owner info: {owner_info}")
    
    # Check advanced detection
    advanced_user = get_last_modifier_advanced(file_path)
    print(f"Advanced detection: {advanced_user}")
    
    # Check audit info
    audit_info = get_file_audit_info(file_path, "modified")
    print(f"Audit info: {audit_info}")
    
    print("-" * 50)


def main():
    if not os.path.isdir(MONITOR_PATH):
        print("Invalid directory.")
        return

    # Enhanced audit system check and setup
    print("🔍 Checking user detection and audit system...")
    audit_status = check_audit_system()
    print(f"Audit Status: {audit_status['message']}")
    
    if audit_status['status'] in ['not_running', 'no_rules', 'poor']:
        print("🔧 Setting up enhanced user detection...")
        setup_success = setup_audit_rules()
        if setup_success:
            print("✅ User detection system configured")
        else:
            print("⚠️  Limited user detection available - will use fallback methods")

    baseline = load_baseline()
    if baseline is None:
        return

    # Initialize AI risk scorer if enabled
    ai_scorer = None
    if AI_ENABLED:
        try:
            ai_scorer = AIRiskScorer()
            ai_scorer.load_model()
            print("🤖 AI Risk Scoring enabled with VirusTotal integration")
        except Exception as e:
            print(f"⚠️  AI Risk Scoring initialization failed: {e}")
            print("Continuing with traditional monitoring...")

    last_modified = set()
    last_deleted = set()
    last_new = set()
    audio_last_modified = set()
    audio_last_deleted = set()
    audio_last_new = set()

    print(f"🕵️  Starting enhanced user-tracking FIM with malware detection every {SCAN_INTERVAL} seconds...")
    print("(Press Ctrl+C to stop)\n")
    
    try:
        while True:
            # Reload config each iteration to pick up GUI changes
            current_config = load_config()

            current_state = scan_current_state(MONITOR_PATH)
            modified, deleted, new = compare_states(baseline, current_state)
            
            # Initialize results
            ai_results = None
            vt_results = None
            enhanced_changes = []
            
            # Only process if there are changes
            if modified or deleted or new:
                # NEW: Enhance changes with comprehensive user detection
                enhanced_changes = enhance_changes_with_audit_info(modified, deleted, new, current_state)
                
                # Perform VirusTotal analysis first (needed for AI integration)
                if modified or new:
                    vt_results = analyze_with_virustotal(modified, new, [], current_state)
                
                # Perform AI analysis if enabled (with enhanced audit info and VT results)
                if ai_scorer:
                    changes_dict = {'modified': modified, 'deleted': deleted, 'new': new}
                    ai_results = analyze_with_ai(changes_dict, current_state, ai_scorer, enhanced_changes, vt_results)
            
            # Print enhanced report with comprehensive user information and malware detection
            print_report_with_audit(modified, deleted, new, enhanced_changes, ai_results, vt_results)
            save_report(modified, deleted, new, ai_results, vt_results)

            current_modified = set(modified)
            current_deleted = set(deleted)
            current_new = set(new)

            # Send enhanced alerts with user audit information and malware detection
            if enhanced_changes and (ai_results or vt_results):
                send_ai_enhanced_alert(modified, deleted, new, enhanced_changes, ai_results, vt_results, current_config)
            elif current_config.get("email_alert"):
                # Fallback to traditional alerting with basic user info
                if(current_modified != last_modified or
                   current_deleted != last_deleted or
                   current_new != last_new):
                    
                    body = "File Integrity Monitoring Alert with User Information\n\n"
                    if modified:
                        body += "Modified files:\n"
                        for f in modified:
                            # Try to get user info for email
                            user_info = get_current_user()
                            body += f"  - {f} (by {user_info})\n"
                        body += "\n"
                    if deleted:
                        body += "Deleted files:\n"
                        for f in deleted:
                            user_info = get_current_user()
                            body += f"  - {f} (by {user_info})\n"
                        body += "\n"
                    if new:
                        body += "New files:\n"
                        for f in new:
                            user_info = get_current_user()
                            body += f"  - {f} (by {user_info})\n"

                    send_email_alert(body.strip())
                    last_modified = current_modified
                    last_deleted = current_deleted
                    last_new = current_new

            # Audio alerts
            if current_config.get("beep_on_change", False):
                if(current_modified != audio_last_modified or
                   current_deleted != audio_last_deleted or
                   current_new != audio_last_new):

                    audio_last_modified = current_modified
                    audio_last_deleted = current_deleted
                    audio_last_new = current_new
                    play_beep(current_config)

            time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")

if __name__ == "__main__":
    main()
