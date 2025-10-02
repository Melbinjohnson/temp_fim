import os
import json
import time
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import logging
from typing import Dict, List, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')


class AIRiskScorer:
    """
    AI-powered risk scoring system for File Integrity Monitoring
    Enhanced with VirusTotal malware detection integration
    """
    
    def __init__(self, config_path='config/settings.json'):
        self.config = self.load_config(config_path)
        self.model = None
        self.scaler = StandardScaler()
        self.risk_threshold = 0.7
        self.model_path = 'models/fim_risk_model.pkl'
        self.scaler_path = 'models/fim_scaler.pkl'
        self.feature_history = []
        self.logger = self.setup_logging()
        
        # Risk scoring weights
        self.risk_weights = {
            'file_type_risk': 0.20,
            'location_risk': 0.15,
            'time_risk': 0.10,
            'change_magnitude': 0.15,
            'user_behavior': 0.15,
            'virustotal_risk': 0.25  # NEW: VirusTotal gets highest weight
        }
        
        # Critical file patterns and risk levels
        self.critical_patterns = {
            'system_files': {
                'patterns': ['/etc/', '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/'],
                'risk_score': 0.9
            },
            'config_files': {
                'patterns': ['.conf', '.cfg', '.ini', 'config'],
                'risk_score': 0.8
            },
            'executable_files': {
                'patterns': ['.exe', '.bat', '.sh', '.ps1', '.py'],
                'risk_score': 0.7
            },
            'data_files': {
                'patterns': ['.db', '.sql', '.csv', '.json'],
                'risk_score': 0.6
            },
            'log_files': {
                'patterns': ['.log', '.txt'],
                'risk_score': 0.3
            }
        }
        
    def load_config(self, path: str) -> Dict:
        """Load configuration from JSON file"""
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def setup_logging(self) -> logging.Logger:
        """Setup logging for the AI risk scorer"""
        logger = logging.getLogger('AIRiskScorer')
        logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
        
        # Avoid adding multiple handlers
        if not logger.handlers:
            handler = logging.FileHandler('logs/ai_risk_scorer.log')
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def get_virustotal_risk(self, file_path: str, vt_results: Dict = None) -> Tuple[float, str]:
        """
        Calculate risk based on VirusTotal scan results
        
        Args:
            file_path: Path to the file
            vt_results: VirusTotal scan results dictionary
            
        Returns:
            Tuple of (risk_score, status_description)
        """
        if not vt_results:
            # Try to load VT results from file
            vt_report_path = self.config.get("vt_report_file", "data/virustotal_report.json")
            try:
                if os.path.exists(vt_report_path):
                    with open(vt_report_path, "r") as f:
                        vt_data = json.load(f)
                        
                    # Search for this file in VT results
                    for category in ['malicious_files', 'suspicious_files', 'clean_files', 'not_found_files']:
                        for vt_file in vt_data.get(category, []):
                            if vt_file.get('file_path') == file_path:
                                return self._calculate_vt_risk(vt_file, category)
            except Exception as e:
                self.logger.error(f"Error loading VT results: {e}")
        else:
            # Use provided VT results
            return self._calculate_vt_risk(vt_results, 'provided')
        
        # No VT data available
        return 0.0, "not_scanned"
    
    def _calculate_vt_risk(self, vt_file: Dict, category: str) -> Tuple[float, str]:
        """Calculate risk score from VirusTotal file data"""
        malicious_count = vt_file.get('malicious', 0)
        suspicious_count = vt_file.get('suspicious', 0)
        total_engines = vt_file.get('total', 70)  # Typical VT engine count
        
        if malicious_count > 0:
            # CRITICAL: Any malware detection = maximum risk
            malware_ratio = malicious_count / max(total_engines, 1)
            if malicious_count >= 10:  # Many engines detect malware
                return 1.0, f"malicious_high_{malicious_count}"
            elif malicious_count >= 5:  # Several engines detect malware
                return 0.95, f"malicious_medium_{malicious_count}"
            else:  # Few engines detect malware
                return 0.85, f"malicious_low_{malicious_count}"
        
        elif suspicious_count > 0:
            # HIGH: Suspicious behavior detected
            suspicious_ratio = suspicious_count / max(total_engines, 1)
            if suspicious_count >= 10:
                return 0.75, f"suspicious_high_{suspicious_count}"
            elif suspicious_count >= 5:
                return 0.65, f"suspicious_medium_{suspicious_count}"
            else:
                return 0.55, f"suspicious_low_{suspicious_count}"
        
        elif category == 'clean_files' or (malicious_count == 0 and suspicious_count == 0):
            # LOW: File is clean
            return 0.1, "clean"
        
        else:
            # UNKNOWN: File not in VT database
            return 0.3, "not_found"

    def extract_features(self, file_path: str, change_type: str, metadata: Dict, vt_results: Dict = None) -> Dict:
        """
        Extract features for AI risk scoring including VirusTotal data
        
        Args:
            file_path: Path to the file
            change_type: Type of change (modified, new, deleted)
            metadata: File metadata including hash, size, timestamps
            vt_results: VirusTotal scan results (optional)
            
        Returns:
            Dictionary of extracted features
        """
        now = datetime.now()
        
        # Get VirusTotal risk
        vt_risk, vt_status = self.get_virustotal_risk(file_path, vt_results)
        
        features = {
            # File type and location features
            'file_extension_risk': self.get_file_extension_risk(file_path),
            'location_risk': self.get_location_risk(file_path),
            'is_hidden_file': 1 if os.path.basename(file_path).startswith('.') else 0,
            'is_system_path': self.is_system_path(file_path),
            
            # Time-based features
            'hour_of_change': now.hour,
            'day_of_week': now.weekday(),
            'is_weekend': 1 if now.weekday() >= 5 else 0,
            'is_business_hours': 1 if 9 <= now.hour <= 17 else 0,
            
            # Change characteristics
            'change_type_modified': 1 if change_type == 'modified' else 0,
            'change_type_new': 1 if change_type == 'new' else 0,
            'change_type_deleted': 1 if change_type == 'deleted' else 0,
            
            # File size features
            'file_size': metadata.get('size', 0),
            'size_category': self.categorize_file_size(metadata.get('size', 0)),
            
            # Historical features
            'change_frequency': self.get_change_frequency(file_path),
            'time_since_last_change': self.get_time_since_last_change(file_path),
            
            # Permission features
            'permission_risk': self.get_permission_risk(metadata.get('permissions', '644')),
            
            # NEW: VirusTotal features
            'virustotal_risk': vt_risk,
            'vt_is_malicious': 1 if vt_risk >= 0.85 else 0,
            'vt_is_suspicious': 1 if 0.55 <= vt_risk < 0.85 else 0,
            'vt_is_clean': 1 if vt_risk <= 0.3 and vt_status == "clean" else 0,
            'vt_status': vt_status  # For logging/analysis
        }
        
        return features
    
    def get_file_extension_risk(self, file_path: str) -> float:
        """Calculate risk based on file extension"""
        ext = os.path.splitext(file_path)[1].lower()
        
        high_risk_extensions = ['.exe', '.bat', '.sh', '.ps1', '.dll', '.so']
        medium_risk_extensions = ['.py', '.js', '.php', '.pl', '.rb']
        config_extensions = ['.conf', '.cfg', '.ini', '.yml', '.yaml', '.json']
        
        if ext in high_risk_extensions:
            return 0.9
        elif ext in medium_risk_extensions:
            return 0.7
        elif ext in config_extensions:
            return 0.6
        else:
            return 0.3
    
    def get_location_risk(self, file_path: str) -> float:
        """Calculate risk based on file location"""
        path_lower = file_path.lower()
        
        for category, info in self.critical_patterns.items():
            for pattern in info['patterns']:
                if pattern in path_lower:
                    return info['risk_score']
        
        return 0.3  # Default low risk
    
    def is_system_path(self, file_path: str) -> int:
        """Check if file is in a system path"""
        system_paths = ['/etc/', '/bin/', '/sbin/', '/usr/', '/var/', '/sys/', '/proc/']
        return 1 if any(path in file_path for path in system_paths) else 0
    
    def categorize_file_size(self, size: int) -> int:
        """Categorize file size for risk assessment"""
        if size > 100 * 1024 * 1024:  # > 100MB
            return 4
        elif size > 10 * 1024 * 1024:  # > 10MB
            return 3
        elif size > 1024 * 1024:  # > 1MB
            return 2
        elif size > 1024:  # > 1KB
            return 1
        else:
            return 0
    
    def get_change_frequency(self, file_path: str) -> float:
        """Calculate how frequently this file changes"""
        count = sum(1 for entry in self.feature_history if entry['file_path'] == file_path)
        return min(count / 100.0, 1.0)
    
    def get_time_since_last_change(self, file_path: str) -> float:
        """Calculate time since last change in hours"""
        recent_changes = [entry for entry in self.feature_history 
                         if entry['file_path'] == file_path]
        
        if recent_changes:
            last_change = max(recent_changes, key=lambda x: x['timestamp'])
            last_time = datetime.fromisoformat(last_change['timestamp'])
            time_diff = (datetime.now() - last_time).total_seconds() / 3600
            return time_diff
        else:
            return 168.0
    
    def get_permission_risk(self, permissions: str) -> float:
        """Calculate risk based on file permissions"""
        if permissions.endswith('777') or permissions.endswith('666'):
            return 0.9
        elif permissions.endswith('755') or permissions.endswith('644'):
            return 0.3
        else:
            return 0.5
    
    def calculate_rule_based_risk(self, features: Dict) -> float:
        """
        Calculate risk score using rule-based approach with VirusTotal integration
        
        Args:
            features: Extracted features dictionary
            
        Returns:
            Risk score between 0 and 1
        """
        risk_score = 0.0
        
        # VirusTotal risk (HIGHEST PRIORITY)
        vt_risk = features.get('virustotal_risk', 0.0)
        risk_score += vt_risk * self.risk_weights['virustotal_risk']
        
        # CRITICAL: If malware is detected, automatically boost to high risk
        if features.get('vt_is_malicious', 0) == 1:
            risk_score = max(risk_score, 0.9)  # Ensure at least HIGH risk
            self.logger.warning(f"MALWARE DETECTED: Boosting risk score to {risk_score:.3f}")
        
        # File type and location risk
        risk_score += features['file_extension_risk'] * self.risk_weights['file_type_risk']
        risk_score += features['location_risk'] * self.risk_weights['location_risk']
        
        # Time-based risk
        time_risk = 0.3
        if not features['is_business_hours']:
            time_risk += 0.4
        if features['is_weekend']:
            time_risk += 0.3
        risk_score += min(time_risk, 1.0) * self.risk_weights['time_risk']
        
        # Change magnitude risk
        change_risk = 0.5
        if features['change_type_deleted']:
            change_risk = 0.8
        elif features['change_type_new'] and features['is_system_path']:
            change_risk = 0.9
        
        # BOOST: New malicious files are CRITICAL
        if features['change_type_new'] == 1 and features.get('vt_is_malicious', 0) == 1:
            change_risk = 1.0
            self.logger.critical(f"NEW MALWARE FILE DETECTED: Maximum risk applied")
        
        risk_score += change_risk * self.risk_weights['change_magnitude']
        
        # User behavior risk
        behavior_risk = 0.4
        if features['change_frequency'] > 0.5:
            behavior_risk = 0.2
        elif features['change_frequency'] == 0:
            behavior_risk = 0.6
        risk_score += behavior_risk * self.risk_weights['user_behavior']
        
        return min(risk_score, 1.0)
    
    def predict_risk(self, features: Dict) -> Tuple[float, str]:
        """
        Predict risk score with VirusTotal malware detection priority
        
        Args:
            features: Feature dictionary
            
        Returns:
            Tuple of (risk_score, risk_level)
        """
        # Rule-based risk score
        rule_risk = self.calculate_rule_based_risk(features)
        
        # ML-based risk score (if model is available)
        ml_risk = None
        if self.model is not None:
            try:
                feature_keys = sorted([k for k in features.keys() if isinstance(features[k], (int, float))])
                feature_array = np.array([[features[key] for key in feature_keys]])
                
                if len(feature_array[0]) > 0:
                    feature_array_scaled = self.scaler.transform(feature_array)
                    ml_prob = self.model.predict_proba(feature_array_scaled)[0]
                    ml_risk = ml_prob[1] if len(ml_prob) > 1 else ml_prob[0]
            except Exception as e:
                self.logger.error(f"ML prediction failed: {e}")
                ml_risk = None
        
        # Combine scores
        if ml_risk is not None:
            final_risk = (rule_risk * 0.4) + (ml_risk * 0.6)
        else:
            final_risk = rule_risk
        
        # OVERRIDE: Malware detection always results in CRITICAL risk
        if features.get('vt_is_malicious', 0) == 1:
            final_risk = max(final_risk, 0.90)  # Force CRITICAL level
        elif features.get('vt_is_suspicious', 0) == 1:
            final_risk = max(final_risk, 0.65)  # Force HIGH level
        
        # Determine risk level
        if final_risk >= 0.8:
            risk_level = "CRITICAL"
        elif final_risk >= 0.6:
            risk_level = "HIGH"
        elif final_risk >= 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return final_risk, risk_level
    
    def analyze_file_change(self, file_path: str, change_type: str, metadata: Dict, vt_results: Dict = None) -> Dict:
        """
        Enhanced analysis with VirusTotal integration
        
        Args:
            file_path: Path to the changed file
            change_type: Type of change (modified, new, deleted)
            metadata: File metadata
            vt_results: VirusTotal scan results (optional)
            
        Returns:
            Dictionary containing enhanced risk analysis results
        """
        # Extract features including VirusTotal data
        features = self.extract_features(file_path, change_type, metadata, vt_results)
        
        # Get audit information
        audit_info = {'user': 'Unknown', 'timestamp': None, 'process': 'Unknown', 'command': 'Unknown'}
        try:
            from utils.audit_utils import get_file_audit_info
            audit_info = get_file_audit_info(file_path, change_type)
        except ImportError:
            self.logger.warning("Audit utils not available. Using default audit info.")
        except Exception as e:
            self.logger.error(f"Failed to get audit info: {e}")
        
        # Predict risk with VirusTotal priority
        risk_score, risk_level = self.predict_risk(features)
        
        # Update history
        self.update_feature_history(file_path, features, risk_score)
        
        # Create enhanced analysis result
        result = {
            'file_path': file_path,
            'change_type': change_type,
            'risk_score': round(risk_score, 3),
            'risk_level': risk_level,
            'timestamp': datetime.now().isoformat(),
            'features': {
                'file_extension_risk': features['file_extension_risk'],
                'location_risk': features['location_risk'],
                'time_risk': 1 if not features['is_business_hours'] else 0,
                'is_system_file': features['is_system_path'],
                # NEW: VirusTotal features in result
                'virustotal_risk': features['virustotal_risk'],
                'vt_is_malicious': features.get('vt_is_malicious', 0),
                'vt_status': features.get('vt_status', 'unknown')
            },
            'recommendations': self.get_recommendations(risk_score, risk_level, change_type, features),
            # Enhanced: Add audit information
            'audit_user': audit_info.get('user', 'Unknown'),
            'audit_timestamp': audit_info.get('timestamp'),
            'audit_process': audit_info.get('process', 'Unknown'),
            'audit_command': audit_info.get('command', 'Unknown')
        }
        
        return result
    
    def get_recommendations(self, risk_score: float, risk_level: str, change_type: str, features: Dict = None) -> List[str]:
        """Generate recommendations with VirusTotal-aware suggestions"""
        recommendations = []
        
        # CRITICAL: Malware-specific recommendations
        if features and features.get('vt_is_malicious', 0) == 1:
            recommendations.extend([
                "🚨 MALWARE DETECTED - IMMEDIATE ISOLATION REQUIRED",
                "🛑 STOP all system processes accessing this file",
                "🔒 QUARANTINE the infected file immediately",
                "🧹 SCAN entire system for additional malware",
                "📱 NOTIFY security team and management",
                "🔄 RESTORE from clean backup if available",
                "🕵️ INVESTIGATE how malware entered the system"
            ])
        elif features and features.get('vt_is_suspicious', 0) == 1:
            recommendations.extend([
                "⚠️  SUSPICIOUS FILE - HIGH PRIORITY INVESTIGATION",
                "🔍 DEEP SCAN with additional antivirus engines",
                "🛡️ MONITOR file behavior in sandboxed environment",
                "👨‍💻 VERIFY with security team before allowing execution"
            ])
        elif risk_level == "CRITICAL":
            recommendations.extend([
                "🚨 IMMEDIATE ACTION REQUIRED",
                "Verify the legitimacy of this change",
                "Check for signs of compromise",
                "Consider isolating the affected system",
                "Review user access permissions"
            ])
        elif risk_level == "HIGH":
            recommendations.extend([
                "⚠️  HIGH PRIORITY REVIEW",
                "Verify change authorization",
                "Review system logs for context",
                "Monitor for additional suspicious activity",
                "Check user authentication logs"
            ])
        elif risk_level == "MEDIUM":
            recommendations.extend([
                "📋 REVIEW RECOMMENDED",
                "Check change management records",
                "Verify with system administrator",
                "Monitor file for additional changes"
            ])
        else:
            recommendations.extend([
                "✅ Low risk - routine monitoring sufficient",
                "Log change for audit trail"
            ])
        
        # Additional context-aware recommendations
        if change_type == "deleted" and risk_score > 0.5:
            recommendations.append("🗑️  Critical file deletion detected - verify backup status")
        elif change_type == "new" and features and features.get('vt_is_malicious', 0) == 1:
            recommendations.append("💀 NEW MALWARE FILE - Immediate containment protocol")
        elif change_type == "modified" and risk_score > 0.8:
            recommendations.append("✏️  Critical file modification - check for unauthorized access")
        
        return recommendations
    
    # Include all other existing methods (load_model, save_model, etc.)
    # ... [rest of the methods remain the same as in previous version]
    
    def load_model(self) -> bool:
        """Load saved model and scaler"""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                self.logger.info("AI model loaded successfully")
                return True
            else:
                self.logger.info("No saved model found. Using rule-based scoring only.")
                return False
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            return False
    
    def save_model(self) -> None:
        """Save trained model and scaler"""
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            self.logger.info("Model saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
    
    def update_feature_history(self, file_path: str, features: Dict, risk_score: float) -> None:
        """Update feature history for continuous learning"""
        history_entry = {
            'timestamp': datetime.now().isoformat(),
            'file_path': file_path,
            'features': features,
            'risk_score': risk_score
        }
        
        self.feature_history.append(history_entry)
        
        if len(self.feature_history) > 1000:
            self.feature_history = self.feature_history[-1000:]
    
    def train_ml_model(self, training_data: List[Dict], labels: List[int]) -> None:
        """Train machine learning model for risk prediction"""
        if not training_data or len(training_data) < 10:
            self.logger.warning("Insufficient training data. Using rule-based scoring only.")
            return
        
        try:
            df = pd.DataFrame(training_data)
            X = df.select_dtypes(include=[np.number])
            y = np.array(labels)
            
            if len(X) < 10:
                self.logger.warning("Insufficient training data after filtering. Using rule-based scoring only.")
                return
            
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                class_weight='balanced'
            )
            
            self.model.fit(X_train_scaled, y_train)
            
            y_pred = self.model.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)
            
            self.logger.info(f"Model trained with accuracy: {accuracy:.3f}")
            self.save_model()
            
        except Exception as e:
            self.logger.error(f"Model training failed: {e}")
