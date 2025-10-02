#!/usr/bin/env python3
"""
Script to train the AI Risk Model for File Integrity Monitoring
Run this before using the AI features
"""

import os
import json
import numpy as np
from datetime import datetime
from ai_modules.risk_scorer import AIRiskScorer

def generate_synthetic_training_data():
    """
    Generate synthetic training data for the AI model
    In a real environment, this would come from historical FIM data
    """
    print("🤖 Generating synthetic training data...")
    
    training_data = []
    labels = []
    
    # High-risk scenarios
    high_risk_scenarios = [
        # System files modified outside business hours
        {
            'file_extension_risk': 0.9, 'location_risk': 0.9, 'is_hidden_file': 0,
            'is_system_path': 1, 'hour_of_change': 2, 'day_of_week': 6,
            'is_weekend': 1, 'is_business_hours': 0, 'change_type_modified': 1,
            'change_type_new': 0, 'change_type_deleted': 0, 'file_size': 1024,
            'size_category': 1, 'change_frequency': 0.1, 'time_since_last_change': 168,
            'permission_risk': 0.9
        },
        # New executable files in system directories
        {
            'file_extension_risk': 0.9, 'location_risk': 0.9, 'is_hidden_file': 0,
            'is_system_path': 1, 'hour_of_change': 3, 'day_of_week': 0,
            'is_weekend': 0, 'is_business_hours': 0, 'change_type_modified': 0,
            'change_type_new': 1, 'change_type_deleted': 0, 'file_size': 51200,
            'size_category': 2, 'change_frequency': 0.0, 'time_since_last_change': 0,
            'permission_risk': 0.9
        },
        # Config file deletions
        {
            'file_extension_risk': 0.6, 'location_risk': 0.8, 'is_hidden_file': 0,
            'is_system_path': 1, 'hour_of_change': 23, 'day_of_week': 5,
            'is_weekend': 1, 'is_business_hours': 0, 'change_type_modified': 0,
            'change_type_new': 0, 'change_type_deleted': 1, 'file_size': 0,
            'size_category': 0, 'change_frequency': 0.2, 'time_since_last_change': 24,
            'permission_risk': 0.3
        }
    ]
    
    # Generate multiple variations of high-risk scenarios
    for scenario in high_risk_scenarios:
        for _ in range(20):  # 20 variations each
            variation = scenario.copy()
            # Add some noise
            for key in ['hour_of_change', 'file_size', 'change_frequency']:
                if key in variation:
                    noise = np.random.normal(0, 0.1)
                    variation[key] = max(0, variation[key] + noise)
            
            training_data.append(variation)
            labels.append(1)  # High risk
    
    # Low-risk scenarios
    low_risk_scenarios = [
        # Regular document modifications during business hours
        {
            'file_extension_risk': 0.3, 'location_risk': 0.3, 'is_hidden_file': 0,
            'is_system_path': 0, 'hour_of_change': 10, 'day_of_week': 2,
            'is_weekend': 0, 'is_business_hours': 1, 'change_type_modified': 1,
            'change_type_new': 0, 'change_type_deleted': 0, 'file_size': 2048,
            'size_category': 1, 'change_frequency': 0.5, 'time_since_last_change': 2,
            'permission_risk': 0.3
        },
        # Log file updates
        {
            'file_extension_risk': 0.3, 'location_risk': 0.3, 'is_hidden_file': 0,
            'is_system_path': 0, 'hour_of_change': 14, 'day_of_week': 1,
            'is_weekend': 0, 'is_business_hours': 1, 'change_type_modified': 1,
            'change_type_new': 0, 'change_type_deleted': 0, 'file_size': 10240,
            'size_category': 2, 'change_frequency': 0.8, 'time_since_last_change': 0.5,
            'permission_risk': 0.3
        },
        # New data files during business hours
        {
            'file_extension_risk': 0.6, 'location_risk': 0.3, 'is_hidden_file': 0,
            'is_system_path': 0, 'hour_of_change': 11, 'day_of_week': 3,
            'is_weekend': 0, 'is_business_hours': 1, 'change_type_modified': 0,
            'change_type_new': 1, 'change_type_deleted': 0, 'file_size': 5120,
            'size_category': 2, 'change_frequency': 0.3, 'time_since_last_change': 12,
            'permission_risk': 0.3
        }
    ]
    
    # Generate multiple variations of low-risk scenarios
    for scenario in low_risk_scenarios:
        for _ in range(25):  # 25 variations each (more low-risk examples)
            variation = scenario.copy()
            # Add some noise
            for key in ['hour_of_change', 'file_size', 'change_frequency']:
                if key in variation:
                    noise = np.random.normal(0, 0.1)
                    variation[key] = max(0, variation[key] + noise)
            
            training_data.append(variation)
            labels.append(0)  # Low risk
    
    print(f"✅ Generated {len(training_data)} training samples")
    print(f"   High-risk samples: {sum(labels)}")
    print(f"   Low-risk samples: {len(labels) - sum(labels)}")
    
    return training_data, labels

def main():
    """Train the AI model"""
    print("🤖 AI Risk Model Training")
    print("=" * 50)
    
    # Create directories
    os.makedirs('models', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    # Initialize AI Risk Scorer
    ai_scorer = AIRiskScorer()
    
    # Generate training data
    training_data, labels = generate_synthetic_training_data()
    
    # Train the model
    print("\n🧠 Training AI model...")
    ai_scorer.train_ml_model(training_data, labels)
    
    # Test the trained model
    print("\n🧪 Testing trained model...")
    
    # Test with a high-risk scenario
    test_high_risk = {
        'file_extension_risk': 0.9, 'location_risk': 0.9, 'is_hidden_file': 0,
        'is_system_path': 1, 'hour_of_change': 2, 'day_of_week': 6,
        'is_weekend': 1, 'is_business_hours': 0, 'change_type_modified': 1,
        'change_type_new': 0, 'change_type_deleted': 0, 'file_size': 1024,
        'size_category': 1, 'change_frequency': 0.1, 'time_since_last_change': 168,
        'permission_risk': 0.9
    }
    
    risk_score, risk_level = ai_scorer.predict_risk(test_high_risk)
    print(f"   High-risk test: {risk_score:.3f} ({risk_level})")
    
    # Test with a low-risk scenario
    test_low_risk = {
        'file_extension_risk': 0.3, 'location_risk': 0.3, 'is_hidden_file': 0,
        'is_system_path': 0, 'hour_of_change': 10, 'day_of_week': 2,
        'is_weekend': 0, 'is_business_hours': 1, 'change_type_modified': 1,
        'change_type_new': 0, 'change_type_deleted': 0, 'file_size': 2048,
        'size_category': 1, 'change_frequency': 0.5, 'time_since_last_change': 2,
        'permission_risk': 0.3
    }
    
    risk_score, risk_level = ai_scorer.predict_risk(test_low_risk)
    print(f"   Low-risk test: {risk_score:.3f} ({risk_level})")
    
    print("\n✅ AI model training completed!")
    print(f"   Model saved to: {ai_scorer.model_path}")
    print(f"   Scaler saved to: {ai_scorer.scaler_path}")
    print("\n🚀 You can now use AI risk scoring in your FIM system!")

if __name__ == "__main__":
    main()
