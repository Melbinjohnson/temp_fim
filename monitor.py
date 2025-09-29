import os
import json
import time
from datetime import datetime
from utils.file_utils import get_file_metadata
from utils.config_loader import load_config
from utils.email_alert import send_email_alert, play_beep
from ai_modules.risk_scorer import AIRiskScorer
from utils.virus_total import check_file_hash_vt, vt_integration, set_vt_api_key

config = load_config()

MONITOR_PATH = config["monitor_path"]
BASELINE_PATH = config["baseline_file"]
REPORT_PATH = config["report_file"]
AI_REPORT_PATH = config.get("ai_report_file", "data/ai_risk_report.json")
exclude = config["exclude"]
SCAN_INTERVAL = config.get("scan_interval", 10)
AI_ENABLED = config.get("ai_risk_scoring", True)

def is_excluded(path):
    return any(excluded in path for excluded in exclude)

def load_baseline():
    if not os.path.exists(BASELINE_PATH):
        print("Baseline not found. Please run initialize.py first.")
        return None

    with open(BASELINE_PATH, "r") as f:
        return json.load(f)

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

def analyze_with_ai(changes_dict, current_data, ai_scorer):
    """
    Analyze file changes using AI risk scoring
    
    Args:
        changes_dict: Dictionary with 'modified', 'deleted', 'new' lists
        current_data: Current file metadata
        ai_scorer: AIRiskScorer instance
        
    Returns:
        Dictionary with AI analysis results
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
    
    # Process all types of changes
    for change_type in ['modified', 'deleted', 'new']:
        for file_path in changes_dict[change_type]:
            # Get metadata for the file
            if change_type == 'deleted':
                metadata = {'size': 0, 'permissions': '000'}  # Placeholder for deleted files
            else:
                full_path = os.path.join(MONITOR_PATH, file_path)
                metadata = get_file_metadata(full_path) or {}
            
            # Analyze with AI
            analysis = ai_scorer.analyze_file_change(file_path, change_type, metadata)
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
    
    # Files to scan
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


def save_report(modified, deleted, new, ai_results=None, vt_results=None):
    report = {
        "timestamp": datetime.now().isoformat(),
        "modified": modified,
        "deleted": deleted,
        "new": new
    }
    
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=4)
    
    # Save AI report separately if available
    if ai_results:
        with open(AI_REPORT_PATH, "w") as f:
            json.dump(ai_results, f, indent=4)
    
    # Save VirusTotal report
    if vt_results:
        vt_report_path = config.get("vt_report_file", "data/virustotal_report.json")
        with open(vt_report_path, "w") as f:
            json.dump(vt_results, f, indent=4)
    
    print(f"\n📄 Report saved to {REPORT_PATH}")
    if ai_results:
        print(f"🤖 AI Analysis saved to {AI_REPORT_PATH}")
    if vt_results:
        print(f"🦠 VirusTotal Analysis saved to {vt_report_path}")

def print_report(modified, deleted, new, ai_results=None, vt_results=None):
    print("\n📂 Comparison Report:")
    print("----------------------")

    if not modified and not deleted and not new:
        print("✅ No changes detected. All files are intact.")
        return

    if modified:
        print(f"\n✏ Modified files ({len(modified)}):")
        for f in modified:
            print(f" - {f}")

    if deleted:
        print(f"\n❌ Deleted files ({len(deleted)}):")
        for f in deleted:
            print(f" - {f}")

    if new:
        print(f"\n➕ New files ({len(new)}):")
        for f in new:
            print(f" - {f}")
    
    # Print AI analysis if available
    if ai_results:
        print("\n🤖 AI Risk Analysis:")
        print("=====================")
        print(f"Overall Risk Score: {ai_results['total_risk_score']:.3f}")
        
        if ai_results['critical_alerts']:
            print("\n🚨 CRITICAL ALERTS:")
            for alert in ai_results['critical_alerts'][:3]:
                print(f"   {alert}")
        
        if ai_results['high_risk_changes']:
            print(f"\n⚠️  High Risk Changes ({len(ai_results['high_risk_changes'])}):")
            for change in ai_results['high_risk_changes'][:5]:
                print(f"   {change['file_path']} - Risk: {change['risk_score']:.3f} ({change['risk_level']})")
        
        if ai_results['recommendations']:
            print("\n💡 Recommendations:")
            for rec in ai_results['recommendations'][:3]:
                print(f"   {rec}")
    
    # Print VirusTotal analysis if available
    if vt_results:
        print("\n🦠 VirusTotal Analysis:")
        print("=======================")
        
        total_scanned = len(vt_results['scanned_files'])
        malicious_count = len(vt_results['malicious_files'])
        suspicious_count = len(vt_results['suspicious_files'])
        clean_count = len(vt_results['clean_files'])
        not_found_count = len(vt_results['not_found_files'])
        error_count = len(vt_results['scan_errors'])
        
        if total_scanned > 0:
            print(f"Total files scanned: {total_scanned}")
            
            if malicious_count > 0:
                print(f"\n🚨 MALWARE DETECTED ({malicious_count} files):")
                for malware in vt_results['malicious_files'][:3]:
                    print(f"   {malware['file_path']} - {malware.get('malicious', 0)} engines")
            
            if suspicious_count > 0:
                print(f"\n⚠️  SUSPICIOUS FILES ({suspicious_count} files):")
                for suspicious in vt_results['suspicious_files'][:3]:
                    print(f"   {suspicious['file_path']} - {suspicious.get('suspicious', 0)} engines")
            
            if clean_count > 0:
                print(f"\n✅ Clean files: {clean_count}")
            
            if not_found_count > 0:
                print(f"\n❓ Unknown files (not in VT database): {not_found_count}")
                for unknown in vt_results['not_found_files'][:3]:
                    print(f"   {unknown['file_path']}")
            
            if error_count > 0:
                print(f"\n❌ Scan errors: {error_count}")
        else:
            print("No files were scanned")


def send_ai_enhanced_alert(modified, deleted, new, ai_results, vt_results, current_config):
    """Send enhanced email alert with AI risk analysis and VirusTotal results"""
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
    
    # Compose enhanced email body
    body = "🤖 AI-Enhanced File Integrity Monitoring Alert\n\n"
    
    if ai_results:
        body += f"Overall Risk Assessment: {ai_results['total_risk_score']:.3f}\n\n"
    
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
    
    if modified:
        body += "Modified files:\n"
        for f in modified:
            # Find AI analysis for this file
            risk_info = ""
            if ai_results:
                file_analysis = next((c for c in ai_results['high_risk_changes'] + ai_results['medium_risk_changes'] + ai_results['low_risk_changes'] 
                                    if c['file_path'] == f), None)
                risk_info = f" [Risk: {file_analysis['risk_score']:.3f}]" if file_analysis else ""
            body += f"  - {f}{risk_info}\n"
        body += "\n"

    if deleted:
        body += "Deleted files:\n"
        for f in deleted:
            risk_info = ""
            if ai_results:
                file_analysis = next((c for c in ai_results['high_risk_changes'] + ai_results['medium_risk_changes'] + ai_results['low_risk_changes'] 
                                    if c['file_path'] == f), None)
                risk_info = f" [Risk: {file_analysis['risk_score']:.3f}]" if file_analysis else ""
            body += f"  - {f}{risk_info}\n"
        body += "\n"

    if new:
        body += "New files:\n"
        for f in new:
            risk_info = ""
            if ai_results:
                file_analysis = next((c for c in ai_results['high_risk_changes'] + ai_results['medium_risk_changes'] + ai_results['low_risk_changes'] 
                                    if c['file_path'] == f), None)
                risk_info = f" [Risk: {file_analysis['risk_score']:.3f}]" if file_analysis else ""
            body += f"  - {f}{risk_info}\n"
        body += "\n"
    
    if ai_results and ai_results['recommendations']:
        body += "💡 AI Recommendations:\n"
        for rec in ai_results['recommendations']:
            body += f"  • {rec}\n"

    send_email_alert(body.strip())

def main():
    if not os.path.isdir(MONITOR_PATH):
        print("Invalid directory.")
        return

    baseline = load_baseline()
    if baseline is None:
        return

    # Initialize AI risk scorer if enabled
    ai_scorer = None
    if AI_ENABLED:
        try:
            ai_scorer = AIRiskScorer()
            ai_scorer.load_model()  # Try to load existing model
            print("🤖 AI Risk Scoring enabled")
        except Exception as e:
            print(f"⚠️  AI Risk Scoring initialization failed: {e}")
            print("Continuing with traditional monitoring...")

    last_modified = set()
    last_deleted = set()
    last_new = set()
    audio_last_modified = set()
    audio_last_deleted = set()
    audio_last_new = set()

    print(f"🕵 Starting AI-enhanced periodic scan every {SCAN_INTERVAL} seconds...\n(Press Ctrl+C to stop)\n")
    
    try:
        while True:
            # Reload config each iteration to pick up GUI changes
            current_config = load_config()
            current_state = scan_current_state(MONITOR_PATH)
            modified, deleted, new = compare_states(baseline, current_state)
            
            # Initialize results
            ai_results = None
            vt_results = None
            
            # Process changes if any exist
            if modified or deleted or new:
                
                # 1. FIRST - Perform AI analysis if enabled
                if ai_scorer:
                    changes_dict = {'modified': modified, 'deleted': deleted, 'new': new}
                    ai_results = analyze_with_ai(changes_dict, current_state, ai_scorer)
                
                # 2. SECOND - Perform VirusTotal analysis (independent of AI)
                print("🦠 Starting VirusTotal analysis...")  # Debug line
                vt_results = analyze_with_virustotal(modified, new, deleted, current_state)
                print("🦠 VirusTotal analysis completed")  # Debug line
            
            # 3. THIRD - Print the complete report with all results
            print_report(modified, deleted, new, ai_results, vt_results)
            save_report(modified, deleted, new, ai_results, vt_results)

            current_modified = set(modified)
            current_deleted = set(deleted)
            current_new = set(new)

            # Send enhanced alerts with AI analysis and VirusTotal results
            if ai_results or vt_results:
                send_ai_enhanced_alert(modified, deleted, new, ai_results, vt_results, current_config)
            elif current_config.get("email_alert"):
                # Fallback to traditional alerting
                if(current_modified != last_modified or
                   current_deleted != last_deleted or
                   current_new != last_new):
                    body=""
                    if modified:
                        body += "Modified files:\n" + "\n".join(f" -{f}" for f in modified) + "\n\n"
                    if deleted:
                        body += "Deleted files:\n" + "\n".join(f" -{f}" for f in deleted) + "\n\n"
                    if new:
                        body += "New files:\n" + "\n".join(f" -{f}" for f in new) + "\n\n"

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
