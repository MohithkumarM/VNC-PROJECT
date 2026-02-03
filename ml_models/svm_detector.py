"""
VNC Security Monitor - SVM Classifier
Detects network attacks using Support Vector Machine (SVM)
"""

import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
import json

from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, f1_score

class SVMDetector:
    def __init__(self, models_dir=None):
        self.model = None
        self.scaler = StandardScaler()
        self.le = LabelEncoder()
        self.is_trained = False
        
        if models_dir:
            self.models_dir = Path(models_dir)
        else:
            self.models_dir = Path(__file__).parent.parent / 'models'
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        self.model_path = self.models_dir / 'svm_model.joblib'
        self.scaler_path = self.models_dir / 'svm_scaler.joblib'
        self.le_path = self.models_dir / 'svm_le.joblib'

    def train(self, X, y):
        print("Training SVM...")
        
        # Encoding labels if they are strings
        if y.dtype == object:
            y = self.le.fit_transform(y)
            joblib.dump(self.le, self.le_path)
            
        # Select only numeric columns for X
        X_numeric = X.select_dtypes(include=[np.number])
        
        # Scale
        X_scaled = self.scaler.fit_transform(X_numeric)
        
        # Split (Internal validation)
        X_train, X_val, y_train, y_val = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
        
        self.model = SVC(kernel='rbf', probability=True, random_state=42)
        self.model.fit(X_train, y_train)
        
        val_preds = self.model.predict(X_val)
        acc = accuracy_score(y_val, val_preds)
        print(f"SVM Validation Accuracy: {acc:.4f}")
        
        self.is_trained = True
        return acc

    def _preprocess_features(self, X):
        """Apply same preprocessing as training: IP to int, Protocol encoding"""
        X = X.copy()
        
        # Convert IP addresses to integers
        def ip_to_int(ip):
            try:
                parts = str(ip).split('.')
                if len(parts) == 4:
                    return int(parts[0])<<24 | int(parts[1])<<16 | int(parts[2])<<8 | int(parts[3])
                return 0
            except:
                return 0
        
        if 'SrcIP' in X.columns and X['SrcIP'].dtype == object:
            X['SrcIP'] = X['SrcIP'].apply(ip_to_int)
        if 'DstIP' in X.columns and X['DstIP'].dtype == object:
            X['DstIP'] = X['DstIP'].apply(ip_to_int)
            
        # Encode Protocol (simple numeric encoding)
        if 'Protocol' in X.columns and X['Protocol'].dtype == object:
            protocol_map = {'ICMP': 0, 'TCP': 1, 'UDP': 2}
            X['Protocol'] = X['Protocol'].map(lambda p: protocol_map.get(str(p).upper(), 1))
        
        return X

    def predict(self, X):
        if not self.is_trained:
            raise Exception("Model not trained")
        
        # Handle dict input - convert to DataFrame
        if isinstance(X, dict):
            X = pd.DataFrame([X])
        
        # Apply preprocessing (IP to int, Protocol encoding)
        X = self._preprocess_features(X)
        
        # Get expected feature names from scaler (if available)
        if hasattr(self.scaler, 'feature_names_in_'):
            expected_features = list(self.scaler.feature_names_in_)
            # Add missing columns with default values
            for col in expected_features:
                if col not in X.columns:
                    X[col] = 0
            # Select only expected features in the right order
            X = X[expected_features]
            
        # All features should now be numeric after preprocessing
        X_scaled = self.scaler.transform(X)
        pred_idx = self.model.predict(X_scaled)[0]
        
        # Decode label if encoder exists
        try:
            pred_label = self.le.inverse_transform([pred_idx])[0]
        except:
            pred_label = pred_idx
            
        probs = self.model.predict_proba(X_scaled)[0]
        confidence = max(probs)
        
        return {
            'prediction': pred_label,
            'confidence': float(confidence)
        }

    def save_model(self):
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)
        print(f"SVM model saved to {self.model_path}")

    def load_model(self):
        if self.model_path.exists():
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            if self.le_path.exists():
                self.le = joblib.load(self.le_path)
            self.is_trained = True
            print("SVM model loaded.")
        else:
            print("SVM model not found.")
