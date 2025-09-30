import os
import json
import time
import hashlib
from datetime import datetime
from utils.file_utils import get_file_metadata
from utils.config_loader import load_config
from utils.audit_utils import check_audit_system, setup_audit_rules

config = load_config()

MONITOR_PATH = config["monitor_path"]
BASELINE_PATH = config["baseline_file"]
exclude = config["exclude"]

def is_excluded(path):
    """Check if a path should be excluded from monitoring"""
    return any(excluded in path for excluded in exclude)

def build_baseline(directory):
    """
    Build comprehensive baseline with file metadata including audit information
    """
    print("🔍 Building baseline with enhanced file metadata...")
    baseline_data = {}
    file_count = 0
    error_count = 0
    
    for root, dirs, files in os.walk(directory):
        # Filter directories based on exclusion rules
        dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root, d))]
        
        for fname in files:
            file_path = os.path.join(root, fname)
            if is_excluded(file_path):
                continue
                
            try:
                metadata = get_file_metadata(file_path)
                
                if metadata:
                    relative_path = os.path.relpath(file_path, directory)
                    baseline_data[relative_path] = metadata
                    file_count += 1
                    
                    # Progress indicator for large directories
                    if file_count % 100 == 0:
                        print(f"   📄 Processed {file_count} files...")
                        
            except Exception as e:
                error_count += 1
                print(f"⚠️  Error processing {file_path}: {e}")
                continue

    print(f"✅ Baseline built successfully:")
    print(f"   📄 Total files processed: {file_count}")
    print(f"   ⚠️  Files with errors: {error_count}")
    
    return baseline_data

def save_baseline(data):
    """Save baseline data with metadata and timestamp"""
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(BASELINE_PATH), exist_ok=True)
        
        # Add metadata to the baseline
        baseline_with_meta = {
            "metadata": {
                "created_at": datetime.now().isoformat(),
                "monitor_path": MONITOR_PATH,
                "total_files": len(data),
                "version": "2.0",
                "audit_enabled": config.get("audit_enabled", False)
            },
            "files": data
        }
        
        with open(BASELINE_PATH, "w") as f:
            json.dump(baseline_with_meta, f, indent=4)
            
        print(f"📄 Baseline saved to {BASELINE_PATH}")
        print(f"   📊 Total files in baseline: {len(data)}")
        
    except Exception as e:
        print(f"❌ Failed to save baseline: {e}")
        return False
        
    return True

def validate_baseline():
    """Validate the created baseline"""
    try:
        if not os.path.exists(BASELINE_PATH):
            print("❌ Baseline file was not created")
            return False
            
        with open(BASELINE_PATH, "r") as f:
            baseline = json.load(f)
            
        # Check if it's the new format with metadata
        if "files" in baseline and "metadata" in baseline:
            file_count = len(baseline["files"])
            created_at = baseline["metadata"]["created_at"]
            print(f"✅ Baseline validation successful:")
            print(f"   📄 Files: {file_count}")
            print(f"   🕐 Created: {created_at}")
            return True
        # Handle old format
        elif isinstance(baseline, dict):
            print(f"✅ Baseline validation successful (legacy format):")
            print(f"   📄 Files: {len(baseline)}")
            return True
        else:
            print("❌ Baseline format is invalid")
            return False
            
    except Exception as e:
        print(f"❌ Baseline validation failed: {e}")
        return False

def setup_system():
    """Setup and check system requirements"""
    print("🔧 Setting up system for File Integrity Monitoring...")
    
    # Create necessary directories
    directories = ['data', 'logs', 'models']
    for dir_name in directories:
        os.makedirs(dir_name, exist_ok=True)
        print(f"   📁 Directory '{dir_name}' ready")
    
    # Check audit system
    print("🔍 Checking audit system...")
    audit_status = check_audit_system()
    print(f"   Audit Status: {audit_status['message']}")
    
    if audit_status['status'] in ['not_running', 'no_rules', 'poor']:
        print("🔧 Setting up audit system...")
        setup_success = setup_audit_rules()
        if setup_success:
            print("   ✅ Audit system configured")
        else:
            print("   ⚠️  Limited audit capability - will use fallback methods")
    else:
        print("   ✅ Audit system ready")

def display_summary():
    """Display initialization summary"""
    print("\n" + "="*60)
    print("🛡️  FILE INTEGRITY MONITORING - INITIALIZATION COMPLETE")
    print("="*60)
    print(f"📂 Monitor Path: {MONITOR_PATH}")
    print(f"📄 Baseline File: {BASELINE_PATH}")
    print(f"🚫 Excluded Patterns: {len(exclude)} patterns")
    print("\n🚀 System is ready for monitoring!")
    print("   Run: python3 monitor.py (CLI)")
    print("   Run: python3 gui_main.py (GUI)")
    print("="*60)

def main():
    """Main initialization function"""
    print("🛡️  File Integrity Monitoring - System Initialization")
    print("="*60)
    
    # Validate monitor path
    if not os.path.isdir(MONITOR_PATH):
        print(f"❌ Invalid monitor directory: {MONITOR_PATH}")
        print("   Please check your config/settings.json file")
        return
    
    print(f"📂 Monitor Path: {MONITOR_PATH}")
    print(f"📄 Baseline File: {BASELINE_PATH}")
    print(f"🚫 Excluded Patterns: {exclude}")
    
    # Setup system requirements
    setup_system()
    
    # Build baseline
    print("\n🔨 Building comprehensive baseline...")
    start_time = time.time()
    
    baseline = build_baseline(MONITOR_PATH)
    
    if not baseline:
        print("❌ No files found to monitor. Check your monitor path and exclusions.")
        return
    
    # Save baseline
    if not save_baseline(baseline):
        print("❌ Failed to save baseline. Initialization aborted.")
        return
    
    # Validate baseline
    if not validate_baseline():
        print("❌ Baseline validation failed. Please check the file.")
        return
    
    elapsed_time = time.time() - start_time
    print(f"⏱️  Initialization completed in {elapsed_time:.2f} seconds")
    
    # Display summary
    display_summary()

if __name__ == "__main__":
    main()
