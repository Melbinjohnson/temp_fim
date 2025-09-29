#!/usr/bin/env python3
"""
Train AI Model with Pre-built Dataset from models/ directory
"""
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os

def train_model():
    print("🤖 Training FIM AI Model with Dataset")
    print("=" * 40)
    
    # Load dataset from models directory
    dataset_path = 'models/fim_training_dataset.csv'
    print(f"📊 Loading dataset from: {dataset_path}")
    
    try:
        df = pd.read_csv(dataset_path)
    except FileNotFoundError:
        print(f"❌ Dataset not found at {dataset_path}")
        print("Please save the dataset CSV file to that location first.")
        return
    
    print(f"Dataset shape: {df.shape}")
    print(f"Risk distribution:")
    print(df['risk_label'].value_counts())
    
    # Prepare features and labels
    feature_columns = [col for col in df.columns if col not in ['file_path', 'change_type', 'risk_label']]
    X = df[feature_columns]
    y = df['risk_label']
    
    print(f"\nFeatures: {len(feature_columns)}")
    print(f"Samples: {len(X)}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale features
    print("🔧 Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train model
    print("🎯 Training Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight='balanced'
    )
    
    model.fit(X_train_scaled, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n📈 Model Performance:")
    print(f"Accuracy: {accuracy:.3f}")
    print(f"\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Low Risk', 'High Risk']))
    
    print(f"\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': feature_columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print(f"\n🔍 Top 10 Most Important Features:")
    print(feature_importance.head(10))
    
    # Save model and scaler to models directory
    print(f"\n💾 Saving model to models/ directory...")
    model_path = 'models/fim_risk_model.pkl'
    scaler_path = 'models/fim_scaler.pkl'
    
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    
    print(f"✅ Training completed successfully!")
    print(f"📁 Dataset: {dataset_path}")
    print(f"📁 Model: {model_path}")
    print(f"📁 Scaler: {scaler_path}")
    
    return True

if __name__ == "__main__":
    # Create models directory if it doesn't exist
    os.makedirs('models', exist_ok=True)
    
    success = train_model()
    
    if success:
        print(f"\n🚀 Your FIM AI model is ready to use!")
        print(f"   The model will be automatically loaded by your monitoring system.")
    else:
        print(f"\n❌ Training failed. Check the dataset file location.")
