"""
VNC Security Monitor - Train All Models
Trains Random Forest, SVM, XGBoost, and CNN on the Kaggle Dataset
"""

import pandas as pd
import numpy as np
import joblib
from pathlib import Path
import os
import sys

# Add project root to path
sys.path.append(os.getcwd())

# Import Detectors
from ml_models.random_forest_detector import RandomForestDetector
from ml_models.svm_detector import SVMDetector
try:
    from ml_models.xgboost_detector import XGBoostDetector
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False
    print("XGBoost not available.")

try:
    from ml_models.cnn_detector import CNNDetector
    CNN_AVAILABLE = True
except ImportError:
    CNN_AVAILABLE = False
    print("CNN not available.")

def train_all():
    print("="*60)
    print("VNC Security Monitor - Training Pipeline")
    print("="*60)
    
    # Load Dataset
    data_path = Path('data/kaggle_dataset/cybersecurity_dataset.csv')
    if not data_path.exists():
        print(f"Error: Dataset not found at {data_path}")
        return
        
    print(f"Loading dataset from {data_path}...")
    try:
        df = pd.read_csv(data_path)
    except Exception as e:
        print(f"Failed to read CSV: {e}")
        return

    print(f"Dataset shape: {df.shape}")
    
    # Feature Selection
    target_col = 'AttackLabel'
    if target_col not in df.columns:
        print(f"Error: Target column '{target_col}' not found.")
        return
        
    # Drop target
    X = df.drop(columns=[target_col])
    y = df[target_col]
    
    # Preprocessing
    def ip_to_int(ip):
        try:
            parts = str(ip).split('.')
            if len(parts) == 4:
                return int(parts[0])<<24 | int(parts[1])<<16 | int(parts[2])<<8 | int(parts[3])
            else:
                 return 0
        except:
            return 0
            
    if 'SrcIP' in X.columns:
        X['SrcIP'] = X['SrcIP'].apply(ip_to_int)
    if 'DstIP' in X.columns:
        X['DstIP'] = X['DstIP'].apply(ip_to_int)
        
    # Handle Protocol
    if 'Protocol' in X.columns:
        from sklearn.preprocessing import LabelEncoder
        le = LabelEncoder()
        X['Protocol'] = le.fit_transform(X['Protocol'].astype(str))
        
    # Fill NA
    X = X.fillna(0)
    
    print("Data Preprocessing complete.")
    
    # 1. Random Forest
    try:
        print("\n" + "-"*30)
        print("Training Random Forest...")
        rf = RandomForestDetector()
        rf.train(X, y, optimize=False)
        rf.save_model()
    except Exception as e:
        print(f"Error training Random Forest: {e}")

    # 2. SVM
    try:
        print("\n" + "-"*30)
        print("Training SVM...")
        svm = SVMDetector()
        svm.train(X, y)
        svm.save_model()
    except Exception as e:
        print(f"Error training SVM: {e}")

    # 3. XGBoost
    if XGB_AVAILABLE:
        try:
            print("\n" + "-"*30)
            print("Training XGBoost...")
            xgb = XGBoostDetector()
            xgb.train(X, y)
            xgb.save_model()
        except Exception as e:
            print(f"Error training XGBoost: {e}")
    else:
        print("\nSkipping XGBoost (Not installed)")

    # 4. CNN
    if CNN_AVAILABLE:
        try:
            print("\n" + "-"*30)
            print("Training CNN...")
            cnn = CNNDetector()
            cnn.train(X, y, epochs=3) # Reduced epochs for speed
            cnn.save_model()
        except Exception as e:
            print(f"Error training CNN: {e}")
    else:
        print("\nSkipping CNN (Not installed)")

    print("\n" + "="*60)
    print("Training process completed.")
    print("="*60)

if __name__ == "__main__":
    train_all()
