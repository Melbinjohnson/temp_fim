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
    \"\"\"
    AI-powered risk scoring system for File Integrity Monitoring
    Uses machine learning algorithms to assess risk levels of file changes
    \"\"\"
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
            'file_type_risk': 0.25,
            'location_risk': 0.20,
            'time_risk': 0.15,
            'change_magnitude': 0.20,
            'user_behavior': 0.20
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
        #\"\"\"Load configuration from JSON file\"\"\"
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def setup_logging(self) -> logging.Logger:
        #\"\"\"Setup logging for the AI risk scorer\"\"\"
        logger = logging.getLogger('AIRiskScorer')
        logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler('logs/ai_risk_scorer.log')
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def extract_features(self, file_path: str, change_type: str, metadata: Dict) -> Dict:
        """
        \"\"\"
        Extract features for AI risk scoring
        
        Args:
            file_path: Path to the file
            change_type: Type of change (modified, new, deleted)
            metadata: File metadata including hash, size, timestamps
            
        Returns:
            Dictionary of extracted features
        \"\"\"
        """
        now = datetime.now()
        
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
            'permission_risk': self.get_permission_risk(metadata.get('permissions', '644'))
        }
        
        return features
    
    def get_file_extension_risk(self, file_path: str) -> float:
        #\"\"\"Calculate risk based on file extension\"\"\"
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
        #\"\"\"Calculate risk based on file location\"\"\"
        path_lower = file_path.lower()
        
        for category, info in self.critical_patterns.items():
            for pattern in info['patterns']:
                if pattern in path_lower:
                    return info['risk_score']
        
        return 0.3  # Default low risk
    
    def is_system_path(self, file_path: str) -> int:
        #\"\"\"Check if file is in a system path\"\"\"
        system_paths = ['/etc/', '/bin/', '/sbin/', '/usr/', '/var/', '/sys/', '/proc/']
        return 1 if any(path in file_path for path in system_paths) else 0
    
    def categorize_file_size(self, size: int) -> int:
        #\"\"\"Categorize file size for risk assessment\"\"\"
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
        #\"\"\"Calculate how frequently this file changes\"\"\"
        # This would typically query historical data
        # For now, return a default value
        return 0.1
    
    def get_time_since_last_change(self, file_path: str) -> float:
        #\"\"\"Calculate time since last change in hours\"\"\"
        # This would typically query historical data
        # For now, return a default value
        return 24.0
    
    def get_permission_risk(self, permissions: str) -> float:
        #\"\"\"Calculate risk based on file permissions\"\"\"
        if permissions.endswith('777') or permissions.endswith('666'):
            return 0.9  # World writable is high risk
        elif permissions.endswith('755') or permissions.endswith('644'):
            return 0.3  # Standard permissions
        else:
            return 0.5  # Medium risk for other permissions
    
    def calculate_rule_based_risk(self, features: Dict) -> float:
        """
        \"\"\"
        Calculate risk score using rule-based approach
        
        Args:
            features: Extracted features dictionary
            
        Returns:
            Risk score between 0 and 1
        \"\"\"
        """
        risk_score = 0.0
        
        # File type and location risk
        risk_score += features['file_extension_risk'] * self.risk_weights['file_type_risk']
        risk_score += features['location_risk'] * self.risk_weights['location_risk']
        
        # Time-based risk
        time_risk = 0.3  # Default
        if not features['is_business_hours']:
            time_risk += 0.4
        if features['is_weekend']:
            time_risk += 0.3
        risk_score += min(time_risk, 1.0) * self.risk_weights['time_risk']
        
        # Change magnitude risk
        change_risk = 0.5  # Default
        if features['change_type_deleted']:
            change_risk = 0.8
        elif features['change_type_new'] and features['is_system_path']:
            change_risk = 0.9
        risk_score += change_risk * self.risk_weights['change_magnitude']
        
        # User behavior risk (simplified)
        behavior_risk = 0.4
        if features['change_frequency'] > 0.5:
            behavior_risk = 0.2  # Frequent changes are less suspicious
        risk_score += behavior_risk * self.risk_weights['user_behavior']
        
        return min(risk_score, 1.0)
    
    def train_ml_model(self, training_data: List[Dict], labels: List[int]) -> None:
        """
        \"\"\"
        Train machine learning model for risk prediction
        
        Args:
            training_data: List of feature dictionaries
            labels: List of risk labels (0: low risk, 1: high risk)
        \"\"\"
        """
        if not training_data:
            self.logger.warning("No training data provided. Using rule-based scoring only.")
            return
        
        # Convert to DataFrame
        df = pd.DataFrame(training_data)
        
        # Prepare features
        X = df.select_dtypes(include=[np.number])
        y = np.array(labels)
        
        if len(X) < 10:
            self.logger.warning("Insufficient training data. Using rule-based scoring only.")
            return
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Random Forest model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        self.logger.info(f"Model trained with accuracy: {accuracy:.3f}")
        
        # Save model and scaler
        self.save_model()
    
    def predict_risk(self, features: Dict) -> Tuple[float, str]:
        """
        \"\"\"
        Predict risk score for a file change
        
        Args:
            features: Feature dictionary
            
        Returns:
            Tuple of (risk_score, risk_level)
        \"\"\"
        """
        # Rule-based risk score
        rule_risk = self.calculate_rule_based_risk(features)
        
        # ML-based risk score (if model is available)
        ml_risk = None
        if self.model is not None:
            try:
                feature_array = np.array([list(features.values())]).reshape(1, -1)
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
    
    def load_model(self) -> bool:
        #\"\"\"Load saved model and scaler\"\"\"
        try:
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            self.logger.info("AI model loaded successfully")
            return True
        except FileNotFoundError:
            self.logger.info("No saved model found. Using rule-based scoring only.")
            return False
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            return False
    
    def save_model(self) -> None:
        #\"\"\"Save trained model and scaler\"\"\"
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            self.logger.info("Model saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
    
    def update_feature_history(self, file_path: str, features: Dict, risk_score: float) -> None:
        #\"\"\"Update feature history for continuous learning\"\"\"
        history_entry = {
            'timestamp': datetime.now().isoformat(),
            'file_path': file_path,
            'features': features,
            'risk_score': risk_score
        }
        
        self.feature_history.append(history_entry)
        
        # Keep only last 1000 entries
        if len(self.feature_history) > 1000:
            self.feature_history = self.feature_history[-1000:]
    
    def analyze_file_change(self, file_path: str, change_type: str, metadata: Dict) -> Dict:
        """
        \"\"\"
        Main method to analyze a file change and return risk assessment
        
        Args:
            file_path: Path to the changed file
            change_type: Type of change (modified, new, deleted)
            metadata: File metadata
            
        Returns:
            Dictionary containing risk analysis results
        \"\"\"
        """
        # Extract features
        features = self.extract_features(file_path, change_type, metadata)
        
        # Predict risk
        risk_score, risk_level = self.predict_risk(features)
        
        # Update history
        self.update_feature_history(file_path, features, risk_score)
        
        # Create analysis result
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
                'is_system_file': features['is_system_path']
            },
            'recommendations': self.get_recommendations(risk_score, risk_level, change_type)
        }
        
        return result
    
    def get_recommendations(self, risk_score: float, risk_level: str, change_type: str) -> List[str]:
        #\"\"\"Generate recommendations based on risk assessment\"\"\"
        recommendations = []
        
        if risk_level == "CRITICAL":
            recommendations.extend([
                "🚨 IMMEDIATE ACTION REQUIRED",
                "Verify the legitimacy of this change",
                "Check for signs of compromise",
                "Consider isolating the affected system"
            ])
        elif risk_level == "HIGH":
            recommendations.extend([
                "⚠️  HIGH PRIORITY REVIEW",
                "Verify change authorization",
                "Review system logs for context",
                "Monitor for additional suspicious activity"
            ])
        elif risk_level == "MEDIUM":
            recommendations.extend([
                "📋 REVIEW RECOMMENDED",
                "Check change management records",
                "Verify with system administrator"
            ])
        else:
            recommendations.append("✅ Low risk - routine monitoring sufficient")
        
        if change_type == "deleted" and risk_score > 0.5:
            recommendations.append("🗑️  Critical file deletion detected - verify backup status")
        
        return recommendations
