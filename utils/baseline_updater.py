import os
import json
from datetime import datetime
from utils.file_utils import get_file_metadata
from utils.config_loader import load_config

def update_baseline_for_files(file_paths, monitor_path, baseline_path):
    """
    Update baseline for specific files
    
    Args:
        file_paths: List of relative file paths to update
        monitor_path: Root monitoring directory
        baseline_path: Path to baseline file
    
    Returns:
        dict: Results of the update operation
    """
    results = {
        'updated': [],
        'errors': [],
        'total': len(file_paths)
    }
    
    # Load existing baseline
    try:
        if os.path.exists(baseline_path):
            with open(baseline_path, "r") as f:
                baseline = json.load(f)
        else:
            baseline = {}
    except Exception as e:
        results['errors'].append(f"Failed to load baseline: {e}")
        return results
    
    # Update specific files
    for file_path in file_paths:
        try:
            full_path = os.path.join(monitor_path, file_path)
            
            if os.path.exists(full_path):
                # Get current file metadata
                metadata = get_file_metadata(full_path)
                if metadata:
                    # Update baseline entry
                    baseline[file_path] = metadata
                    results['updated'].append(file_path)
                else:
                    results['errors'].append(f"Failed to get metadata for {file_path}")
            else:
                # File was deleted - remove from baseline
                if file_path in baseline:
                    del baseline[file_path]
                    results['updated'].append(f"{file_path} (removed)")
                else:
                    results['errors'].append(f"File not found: {file_path}")
                    
        except Exception as e:
            results['errors'].append(f"Error updating {file_path}: {e}")
    
    # Save updated baseline
    try:
        # Create backup first
        backup_path = f"{baseline_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if os.path.exists(baseline_path):
            import shutil
            shutil.copy2(baseline_path, backup_path)
        
        # Save updated baseline
        with open(baseline_path, "w") as f:
            json.dump(baseline, f, indent=4)
            
        results['backup_created'] = backup_path
        
        # Also clean up the reports when baseline is updated
        cleanup_reports_for_updated_files(file_paths)
        
    except Exception as e:
        results['errors'].append(f"Failed to save baseline: {e}")
    
    return results

def cleanup_reports_for_updated_files(file_paths):
    """
    Remove updated files from AI and VT reports since they're now accepted in baseline
    """
    config = load_config()
    ai_report_path = config.get("ai_report_file", "data/ai_risk_report.json")
    vt_report_path = config.get("vt_report_file", "data/virustotal_report.json")
    
    # Clean AI report
    if os.path.exists(ai_report_path):
        try:
            with open(ai_report_path, "r") as f:
                ai_results = json.load(f)
            
            cleaned = False
            for category in ['high_risk_changes', 'medium_risk_changes', 'low_risk_changes']:
                original_count = len(ai_results.get(category, []))
                ai_results[category] = [
                    change for change in ai_results.get(category, [])
                    if change['file_path'] not in file_paths
                ]
                if len(ai_results[category]) < original_count:
                    cleaned = True
            
            if cleaned:
                with open(ai_report_path, "w") as f:
                    json.dump(ai_results, f, indent=4)
                    
        except Exception as e:
            print(f"Warning: Could not clean AI report: {e}")
    
    # Clean VT report  
    if os.path.exists(vt_report_path):
        try:
            with open(vt_report_path, "r") as f:
                vt_results = json.load(f)
            
            cleaned = False
            for category in ['scanned_files', 'malicious_files', 'suspicious_files', 
                           'clean_files', 'not_found_files', 'scan_errors']:
                original_count = len(vt_results.get(category, []))
                vt_results[category] = [
                    result for result in vt_results.get(category, [])
                    if result['file_path'] not in file_paths
                ]
                if len(vt_results[category]) < original_count:
                    cleaned = True
            
            if cleaned:
                with open(vt_report_path, "w") as f:
                    json.dump(vt_results, f, indent=4)
                    
        except Exception as e:
            print(f"Warning: Could not clean VT report: {e}")

def update_single_file(file_path, monitor_path, baseline_path):
    """Update baseline for a single file"""
    return update_baseline_for_files([file_path], monitor_path, baseline_path)

def get_baseline_diff():
    """Get current differences from baseline"""
    try:
        from monitor import load_baseline, scan_current_state, compare_states
        config = load_config()
        
        baseline = load_baseline()
        if not baseline:
            return None
            
        current_state = scan_current_state(config["monitor_path"])
        modified, deleted, new = compare_states(baseline, current_state)
        
        return {
            'modified': modified,
            'deleted': deleted,
            'new': new,
            'current_state': current_state
        }
    except Exception as e:
        print(f"Error getting baseline diff: {e}")
        return None
