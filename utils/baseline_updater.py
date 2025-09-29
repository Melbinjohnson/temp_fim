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
        
    except Exception as e:
        results['errors'].append(f"Failed to save baseline: {e}")
    
    return results

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
