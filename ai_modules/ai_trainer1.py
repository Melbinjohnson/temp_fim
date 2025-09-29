import os
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from ai_modules.risk_scorer import AIRiskScorer
from utils.config_loader import load_config
import random

class AIModelTrainer:
    """\"\"\"
    AI Model Training module for FIM system
    Generates synthetic training data and trains risk assessment models
    \"\"\""""
    
    def __init__(self):
        self.config = load_config()
        self.risk_scorer = AIRiskScorer()
        
    def generate_synthetic_training_data(self, num_samples=1000):
        """\"\"\"
        Generate synthetic training data for AI model training
        
        Args:
            num_samples: Number of training samples to generate
            
        Returns:
            Tuple of (features_list, labels_list)
        \"\"\""""
        features_list = []
        labels_list = []
        
        # Define file types and their base risk levels
        file_scenarios = [
            # High risk scenarios
            {
                'file_paths': ['/etc/passwd', '/bin/bash', '/usr/bin/sudo', '/etc/shadow'],
                'change_types': ['modified', 'deleted'],
                'base_risk': 0.9,
                'label': 1
            },
            # Medium risk scenarios  
            {
                'file_paths': ['/home/user/config.json', '/opt/app/settings.conf', '/var/log/app.log'],
                'change_types': ['modified', 'new'],
                'base_risk': 0.6,
                'label': 1 if random.random() > 0.3 else 0  # 70% high risk
            },
            # Low risk scenarios
            {
                'file_paths': ['/tmp/tempfile.txt', '/home/user/document.pdf', '/var/cache/file.cache'],
                'change_types': ['new', 'modified'],
                'base_risk': 0.2,
                'label': 0
            }
        ]
        
        for _ in range(num_samples):
            # Select a random scenario
            scenario = random.choice(file_scenarios)
            file_path = random.choice(scenario['file_paths'])
            change_type = random.choice(scenario['change_types'])
            
            # Generate realistic metadata
            metadata = {
                'size': random.randint(100, 10000000),  # 100B to 10MB
                'permissions': random.choice(['644', '755', '777', '600', '700']),
                'last_modified': datetime.now().isoformat(),
                'created_time': datetime.now().isoformat()
            }
            
            # Add time-based variations
            hour = random.randint(0, 23)
            is_weekend = random.choice([True, False])
            
            # Modify risk based on time factors
            time_risk_modifier = 0
            if hour < 6 or hour > 22:  # Night time changes
                time_risk_modifier += 0.2
            if is_weekend:  # Weekend changes
                time_risk_modifier += 0.1
            
            # Extract features using the risk scorer
            features = self.risk_scorer.extract_features(file_path, change_type, metadata)
            
            # Override time features for synthetic data
            features['hour_of_change'] = hour
            features['is_weekend'] = 1 if is_weekend else 0
            features['is_business_hours'] = 1 if 9 <= hour <= 17 and not is_weekend else 0
            
            features_list.append(features)
            
            # Determine label based on scenario and time factors
            final_risk = scenario['base_risk'] + time_risk_modifier
            label = 1 if final_risk > 0.5 else 0
            
            # Add some noise to make it more realistic
            if random.random() < 0.05:  # 5% noise
                label = 1 - label
                
            labels_list.append(label)
        
        return features_list, labels_list
    
    def train_model(self, features_list=None, labels_list=None):
        """\"\"\"
        Train the AI risk assessment model
        
        Args:
            features_list: List of feature dictionaries (optional)
            labels_list: List of risk labels (optional)
        \"\"\""""
        print("🤖 Starting AI Model Training...")
        
        # Generate synthetic data if not provided
        if features_list is None or labels_list is None:
            print("📊 Generating synthetic training data...")
            features_list, labels_list = self.generate_synthetic_training_data(1000)
        
        print(f"📈 Training with {len(features_list)} samples...")
        
        # Train the model
        self.risk_scorer.train_ml_model(features_list, labels_list)
        
        print("✅ AI Model training completed!")
        print("🎯 Model is now ready for real-time risk assessment")
        
        return True
    
    def evaluate_model(self):
        #\"\"\"Evaluate the trained model with test data\"\"\"
        print("🔍 Evaluating model performance...")
        
        # Generate test data
        test_features, test_labels = self.generate_synthetic_training_data(200)
        
        if self.risk_scorer.model is None:
            print("❌ No trained model found")
            return False
        
        # Test predictions
        correct_predictions = 0
        total_predictions = len(test_features)
        
        for features, true_label in zip(test_features, test_labels):
            risk_score, risk_level = self.risk_scorer.predict_risk(features)
            predicted_label = 1 if risk_score > 0.5 else 0
            
            if predicted_label == true_label:
                correct_predictions += 1
        
        accuracy = correct_predictions / total_predictions
        print(f"📊 Model Accuracy: {accuracy:.3f}")
        print(f"✅ Correct Predictions: {correct_predictions}/{total_predictions}")
        
        return accuracy

def main():
    #\"\"\"Main training function\"\"\"
    trainer = AIModelTrainer()
    
    print("🚀 FIM AI Model Training System")
    print("================================")
    
    # Train the model
    success = trainer.train_model()
    
    if success:
        # Evaluate the model
        trainer.evaluate_model()
        
        print("\\n🎉 Training completed successfully!")
        print("🔧 The AI-enhanced FIM system is now ready to use")
    else:
        print("❌ Training failed")

if __name__ == "__main__":
    main()
"""

# Create updated configuration file
updated_config = """
{
    "monitor_path": "/home/kali/nsal",
    "hash_algorithm": "sha256",
    "exclude": [
        ".git",
        "venv",
        "__pycache__",
        "config/",
        "data/",
        "models/",
        "logs/"
    ],
    "baseline_file": "data/baseline.json",
    "report_file": "data/report.json",
    "ai_report_file": "data/ai_risk_report.json",
    "scan_interval": 10,
    "beep_on_change": true,
    "beep_sound_file": "audio/alert.wav",
    "email_alert": false,
    
    "_comment_ai_settings": "AI Risk Scoring Configuration",
    "ai_risk_scoring": true,
    "ai_model_path": "models/fim_risk_model.pkl",
    "ai_scaler_path": "models/fim_scaler.pkl",
    "risk_threshold": 0.7,
    "smart_alerts": true,
    "auto_training": false,
    "training_data_retention_days": 30,
    
    "_comment_risk_weights": "Risk Assessment Weights",
    "risk_weights": {
        "file_type_risk": 0.25,
        "location_risk": 0.20,
        "time_risk": 0.15,
        "change_magnitude": 0.20,
        "user_behavior": 0.20
    },
    
    "_comment_alerting": "Enhanced Alerting Configuration", 
    "alert_critical_only": false,
    "alert_high_risk_threshold": 0.8,
    "alert_medium_risk_threshold": 0.6,
    "max_alerts_per_hour": 10,
    
    "_comment_ml_settings": "Machine Learning Settings",
    "ml_model_type": "random_forest",
    "ml_retrain_frequency_days": 7,
    "feature_importance_threshold": 0.01,
    "anomaly_detection_enabled": true,
    
    "_comment_logging": "Logging Configuration",
    "log_level": "INFO",
    "log_file": "logs/fim_system.log",
    "ai_log_file": "logs/ai_risk_scorer.log",
    "log_retention_days": 30
}
"""

# Create updated initialize.py with AI training capabilities
updated_initialize_py = """
import os
import json
import time
import hashlib
from utils.file_utils import get_file_metadata
from utils.config_loader import load_config
from ai_modules.risk_scorer import AIRiskScorer

config = load_config()

MONITOR_PATH = config["monitor_path"]
BASELINE_PATH = config["baseline_file"]
exclude = config["exclude"]
AI_ENABLED = config.get("ai_risk_scoring", True)

def is_excluded(path):
    return any(excluded in path for excluded in exclude)

def build_baseline(directory):
    baseline_data = {}
    sample_changes = []  # Collect sample data for AI training

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root, d))]  # filter dirs
        for fname in files:
            file_path = os.path.join(root, fname)
            if is_excluded(file_path):
                continue
            metadata = get_file_metadata(file_path)

            if metadata:
                relative_path = os.path.relpath(file_path, directory)
                baseline_data[relative_path] = metadata
                
                # Collect sample for AI training (simulate as 'new' files during baseline)
                if AI_ENABLED:
                    sample_changes.append({
                        'file_path': relative_path,
                        'change_type': 'new',
                        'metadata': metadata,
                        'risk_level': 'low'  # Baseline files are typically low risk
                    })

    return baseline_data, sample_changes

def save_baseline(data):
    with open(BASELINE_PATH, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Baseline saved to {BASELINE_PATH}")

def initialize_ai_system(sample_changes):
    #\"\"\"Initialize and optionally train the AI risk scoring system\"\"\"
    if not AI_ENABLED:
        print("AI Risk Scoring is disabled in configuration")
        return
    
    print("\\n🤖 Initializing AI Risk Scoring System...")
    
    try:
        risk_scorer = AIRiskScorer()
        
        # Try to load existing model
        model_loaded = risk_scorer.load_model()
        
        if not model_loaded:
            print("📚 No existing AI model found")
            
            # Ask user if they want to train a new model
            response = input("Do you want to train a new AI model? (y/n): ").lower().strip()
            
            if response == 'y':
                print("🎯 Training new AI model with synthetic data...")
                
                # Import and use the trainer
                from ai_modules.ai_trainer import AIModelTrainer
                trainer = AIModelTrainer()
                trainer.train_model()
                
                # Try loading the newly trained model
                risk_scorer.load_model()
                print("✅ AI system initialized with new model")
            else:
                print("ℹ️  AI system will use rule-based scoring only")
        else:
            print("✅ AI system initialized with existing model")
            
        # Test the system with a sample file
        if sample_changes:
            print("\\n🧪 Testing AI system with sample data...")
            test_sample = sample_changes[0]
            
            result = risk_scorer.analyze_file_change(
                test_sample['file_path'],
                test_sample['change_type'], 
                test_sample['metadata']
            )
            
            print(f"📊 Sample analysis result:")
            print(f"   File: {result['file_path']}")
            print(f"   Risk Score: {result['risk_score']}")
            print(f"   Risk Level: {result['risk_level']}")
            
    except Exception as e:
        print(f"❌ AI system initialization failed: {e}")
        print("⚠️  Continuing with traditional FIM only")

def main():
    print("🛠️  Enhanced FIM System Initialization")
    print("=====================================")
    
    if not os.path.isdir(MONITOR_PATH):
        print("Invalid directory path.")
        return

    print(f"🔍 Building baseline for: {MONITOR_PATH}")
    baseline, sample_changes = build_baseline(MONITOR_PATH)
    
    print(f"📁 Processed {len(baseline)} files")
    save_baseline(baseline)
    
    # Initialize AI system if enabled
    if AI_ENABLED:
        initialize_ai_system(sample_changes)
    
    print("\\n🎉 Initialization completed successfully!")
    print("🚀 You can now start monitoring with: python monitor.py")
    print("🖥️  Or use the GUI with: python gui/gui_main.py")

if __name__ == "__main__":
    main()
