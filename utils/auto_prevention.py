#!/usr/bin/env python3
"""
Automatic malware prevention system with file removal and quarantine
"""

import os
import shutil
import json
import time
import hashlib
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import subprocess
import threading
import zipfile
import tempfile

class AutoPreventionEngine:
    """Automatic prevention and response system for malicious files"""
    
    def __init__(self, config_path='config/settings.json'):
        self.config = self.load_config(config_path)
        self.prevention_log_path = 'data/auto_prevention_log.json'
        self.quarantine_dir = 'quarantine/'
        self.backup_dir = 'backup/auto_prevention/'
        
        # Prevention settings
        self.auto_removal_enabled = self.config.get('auto_removal_enabled', True)
        self.quarantine_enabled = self.config.get('quarantine_enabled', True)
        self.backup_before_removal = self.config.get('backup_before_removal', True)
        self.min_malicious_engines = self.config.get('min_malicious_engines', 3)
        
        # Initialize directories
        self.setup_directories()
        
        # Prevention statistics
        self.prevention_stats = {
            'total_prevented': 0,
            'files_removed': 0,
            'files_quarantined': 0,
            'false_positives': 0,
            'last_reset': datetime.now().isoformat()
        }
        
        self.load_prevention_stats()
    
    def load_config(self, path: str) -> Dict:
        """Load configuration"""
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def setup_directories(self):
        """Setup required directories"""
        directories = [
            self.quarantine_dir,
            self.backup_dir,
            'data/',
            'logs/prevention/'
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
        
        print(f"📁 Prevention directories initialized")
    
    def load_prevention_stats(self):
        """Load prevention statistics"""
        stats_path = 'data/prevention_stats.json'
        try:
            if os.path.exists(stats_path):
                with open(stats_path, 'r') as f:
                    self.prevention_stats.update(json.load(f))
        except Exception as e:
            print(f"Warning: Could not load prevention stats: {e}")
    
    def save_prevention_stats(self):
        """Save prevention statistics"""
        stats_path = 'data/prevention_stats.json'
        try:
            with open(stats_path, 'w') as f:
                json.dump(self.prevention_stats, f, indent=4)
        except Exception as e:
            print(f"Warning: Could not save prevention stats: {e}")
    
    def is_malicious_file(self, file_path: str, vt_results: Dict = None, ai_results: Dict = None) -> Tuple[bool, str, Dict]:
        """
        Determine if a file is malicious based on multiple criteria
        
        Args:
            file_path: Path to the file
            vt_results: VirusTotal scan results
            ai_results: AI analysis results
            
        Returns:
            Tuple of (is_malicious, reason, details)
        """
        reasons = []
        details = {
            'vt_malicious_count': 0,
            'vt_suspicious_count': 0,
            'ai_risk_score': 0.0,
            'ai_risk_level': 'UNKNOWN',
            'malware_indicators': []
        }
        
        # Check VirusTotal results
        if vt_results:
            malicious_count = vt_results.get('malicious', 0)
            suspicious_count = vt_results.get('suspicious', 0)
            total_engines = vt_results.get('total', 70)
            
            details['vt_malicious_count'] = malicious_count
            details['vt_suspicious_count'] = suspicious_count
            
            if malicious_count >= self.min_malicious_engines:
                reasons.append(f"VirusTotal: {malicious_count}/{total_engines} engines detected malware")
                details['malware_indicators'].append('virustotal_malware')
            elif malicious_count >= 1:
                reasons.append(f"VirusTotal: {malicious_count} engines flagged as malicious")
                details['malware_indicators'].append('virustotal_suspicious')
        
        # Check AI analysis results
        if ai_results:
            risk_score = ai_results.get('risk_score', 0.0)
            risk_level = ai_results.get('risk_level', 'UNKNOWN')
            
            details['ai_risk_score'] = risk_score
            details['ai_risk_level'] = risk_level
            
            if risk_level == 'CRITICAL' and risk_score >= 0.9:
                reasons.append(f"AI Analysis: CRITICAL risk ({risk_score:.3f})")
                details['malware_indicators'].append('ai_critical')
            
            # Check for specific malware features
            features = ai_results.get('features', {})
            if features.get('vt_is_malicious', 0) == 1:
                reasons.append("AI detected VirusTotal malware flag")
                details['malware_indicators'].append('ai_vt_malware')
            
            if features.get('has_suspicious_name', 0) == 1:
                reasons.append("Suspicious filename pattern detected")
                details['malware_indicators'].append('suspicious_name')
        
        # Check filename patterns for obvious malware
        filename = os.path.basename(file_path).lower()
        malware_patterns = [
            'malware', 'virus', 'trojan', 'backdoor', 'rootkit', 'keylogger',
            'spyware', 'ransomware', 'adware', 'worm', 'botnet'
        ]
        
        for pattern in malware_patterns:
            if pattern in filename:
                reasons.append(f"Malware pattern in filename: '{pattern}'")
                details['malware_indicators'].append('filename_pattern')
                break
        
        # Determine if malicious
        is_malicious = len(reasons) > 0 and (
            details['vt_malicious_count'] >= self.min_malicious_engines or
            details['ai_risk_level'] == 'CRITICAL' or
            'virustotal_malware' in details['malware_indicators']
        )
        
        reason = "; ".join(reasons) if reasons else "No malware indicators"
        
        return is_malicious, reason, details
    
    def backup_file(self, file_path: str) -> Optional[str]:
        """
        Create a backup of the file before removal
        
        Args:
            file_path: Path to file to backup
            
        Returns:
            Path to backup file or None if failed
        """
        if not self.backup_before_removal:
            return None
        
        try:
            # Create backup filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = os.path.basename(file_path)
            backup_filename = f"{timestamp}_{filename}.backup"
            backup_path = os.path.join(self.backup_dir, backup_filename)
            
            # Copy file to backup
            shutil.copy2(file_path, backup_path)
            
            print(f"💾 Backup created: {backup_path}")
            return backup_path
            
        except Exception as e:
            print(f"⚠️  Backup failed for {file_path}: {e}")
            return None
    
    def quarantine_file(self, file_path: str) -> Optional[str]:
        """
        Move file to quarantine instead of deleting
        
        Args:
            file_path: Path to file to quarantine
            
        Returns:
            Path to quarantined file or None if failed
        """
        if not self.quarantine_enabled:
            return None
        
        try:
            # Create quarantine filename with metadata
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = os.path.basename(file_path)
            safe_filename = "".join(c for c in filename if c.isalnum() or c in '.-_')[:50]
            quarantine_filename = f"{timestamp}_{safe_filename}.quarantine"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            
            # Create quarantine package (zip with metadata)
            with zipfile.ZipFile(quarantine_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                # Add the malicious file
                zf.write(file_path, filename)
                
                # Add metadata
                metadata = {
                    'original_path': file_path,
                    'quarantine_time': datetime.now().isoformat(),
                    'file_hash': self.calculate_file_hash(file_path),
                    'file_size': os.path.getsize(file_path) if os.path.exists(file_path) else 0
                }
                
                zf.writestr('quarantine_metadata.json', json.dumps(metadata, indent=2))
            
            print(f"🔒 File quarantined: {quarantine_path}")
            return quarantine_path
            
        except Exception as e:
            print(f"⚠️  Quarantine failed for {file_path}: {e}")
            return None
    
    def remove_file_safely(self, file_path: str) -> bool:
        """
        Safely remove a malicious file
        
        Args:
            file_path: Path to file to remove
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not os.path.exists(file_path):
                print(f"⚠️  File already removed: {file_path}")
                return True
            
            # Multiple removal attempts for stubborn files
            removal_methods = [
                # Standard removal
                lambda: os.remove(file_path),
                # Force removal with attributes
                lambda: self.force_remove_file(file_path),
                # System command removal
                lambda: subprocess.run(['rm', '-f', file_path], check=True)
            ]
            
            for i, method in enumerate(removal_methods):
                try:
                    method()
                    if not os.path.exists(file_path):
                        print(f"🗑️  File removed successfully: {file_path} (method {i+1})")
                        return True
                except Exception as e:
                    print(f"   Removal method {i+1} failed: {e}")
                    continue
            
            print(f"❌ All removal methods failed for: {file_path}")
            return False
            
        except Exception as e:
            print(f"❌ File removal error: {e}")
            return False
    
    def force_remove_file(self, file_path: str):
        """Force remove file by changing attributes first"""
        try:
            # Try to remove read-only attributes
            os.chmod(file_path, 0o777)
            os.remove(file_path)
        except:
            # Try with system command
            subprocess.run(['chmod', '777', file_path], check=False)
            subprocess.run(['rm', '-rf', file_path], check=True)
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except:
            return "unknown"
    
    def process_malicious_file(self, file_path: str, vt_results: Dict = None, ai_results: Dict = None) -> Dict:
        """
        Main processing function for malicious files
        
        Args:
            file_path: Path to potentially malicious file
            vt_results: VirusTotal results
            ai_results: AI analysis results
            
        Returns:
            Dictionary with prevention action results
        """
        print(f"🚨 Processing potentially malicious file: {file_path}")
        
        # Check if file is actually malicious
        is_malicious, reason, details = self.is_malicious_file(file_path, vt_results, ai_results)
        
        prevention_result = {
            'timestamp': datetime.now().isoformat(),
            'file_path': file_path,
            'is_malicious': is_malicious,
            'reason': reason,
            'details': details,
            'actions_taken': [],
            'success': False,
            'backup_path': None,
            'quarantine_path': None,
            'removal_success': False
        }
        
        if not is_malicious:
            prevention_result['success'] = True
            prevention_result['actions_taken'].append('No action needed - file not malicious')
            return prevention_result
        
        print(f"🚨 MALWARE CONFIRMED: {reason}")
        
        # Step 1: Create backup if enabled
        if self.backup_before_removal:
            backup_path = self.backup_file(file_path)
            if backup_path:
                prevention_result['backup_path'] = backup_path
                prevention_result['actions_taken'].append(f'Backup created: {backup_path}')
        
        # Step 2: Quarantine if enabled
        if self.quarantine_enabled:
            quarantine_path = self.quarantine_file(file_path)
            if quarantine_path:
                prevention_result['quarantine_path'] = quarantine_path
                prevention_result['actions_taken'].append(f'File quarantined: {quarantine_path}')
        
        # Step 3: Remove the malicious file
        if self.auto_removal_enabled:
            removal_success = self.remove_file_safely(file_path)
            prevention_result['removal_success'] = removal_success
            
            if removal_success:
                prevention_result['actions_taken'].append('Malicious file removed')
                prevention_result['success'] = True
                self.prevention_stats['files_removed'] += 1
                print(f"✅ Malicious file successfully removed: {file_path}")
            else:
                prevention_result['actions_taken'].append('File removal failed - manual intervention required')
                print(f"❌ Failed to remove malicious file: {file_path}")
        else:
            prevention_result['actions_taken'].append('Auto-removal disabled - file quarantined only')
            prevention_result['success'] = True
        
        # Update statistics
        self.prevention_stats['total_prevented'] += 1
        if prevention_result['quarantine_path']:
            self.prevention_stats['files_quarantined'] += 1
        
        # Log the prevention action
        self.log_prevention_action(prevention_result)
        self.save_prevention_stats()
        
        return prevention_result
    
    def log_prevention_action(self, prevention_result: Dict):
        """Log prevention action to file"""
        try:
            # Load existing log
            prevention_log = []
            if os.path.exists(self.prevention_log_path):
                with open(self.prevention_log_path, 'r') as f:
                    prevention_log = json.load(f)
            
            # Add new entry
            prevention_log.append(prevention_result)
            
            # Keep only last 1000 entries
            if len(prevention_log) > 1000:
                prevention_log = prevention_log[-1000:]
            
            # Save updated log
            with open(self.prevention_log_path, 'w') as f:
                json.dump(prevention_log, f, indent=4)
            
            print(f"📝 Prevention action logged")
            
        except Exception as e:
            print(f"⚠️  Failed to log prevention action: {e}")
    
    def get_prevention_log(self) -> List[Dict]:
        """Get prevention log entries"""
        try:
            if os.path.exists(self.prevention_log_path):
                with open(self.prevention_log_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading prevention log: {e}")
        
        return []
    
    def get_prevention_stats(self) -> Dict:
        """Get prevention statistics"""
        return self.prevention_stats.copy()

# Global instance
auto_prevention = AutoPreventionEngine()
