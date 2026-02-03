"""
VNC Security Monitor - CNN Classifier
Detects network attacks using Convolutional Neural Networks
"""

import os
import numpy as np
import pandas as pd
from pathlib import Path
import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split

# Lazy import placeholder
tf = None
layers = None
models = None

class CNNDetector:
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
        
        self.model_path = self.models_dir / 'cnn_model.h5'
        self.scaler_path = self.models_dir / 'cnn_scaler.joblib'
        self.le_path = self.models_dir / 'cnn_le.joblib'
        
        # Check tensorflow availability
        self._check_tf()

    def _check_tf(self):
        global tf, layers, models
        try:
            import tensorflow as _tf
            from tensorflow.keras import layers as _layers
            from tensorflow.keras import models as _models
            tf = _tf
            layers = _layers
            models = _models
            return True
        except ImportError:
            print("Warning: TensorFlow not available for CNNDetector")
            return False

    def train(self, X, y, epochs=10):
        if not tf:
            print("TensorFlow not installed. Skipping CNN training.")
            return 0
            
        print("Training CNN...")
        
        # Encoding labels
        if y.dtype == object:
            y = self.le.fit_transform(y)
            joblib.dump(self.le, self.le_path)
        
        num_classes = len(np.unique(y))
        
        # Select numeric columns
        X_numeric = X.select_dtypes(include=[np.number])
        X_scaled = self.scaler.fit_transform(X_numeric)
        
        # Reshape for CNN (samples, features, 1)
        X_reshaped = X_scaled.reshape((X_scaled.shape[0], X_scaled.shape[1], 1))
        
        # Split
        X_train, X_val, y_train, y_val = train_test_split(X_reshaped, y, test_size=0.2, random_state=42)
        
        # Build Model
        self.model = models.Sequential([
            layers.Input(shape=(X_train.shape[1], 1)),
            layers.Conv1D(32, 3, activation='relu', padding='same'),
            layers.MaxPooling1D(2),
            layers.Conv1D(64, 3, activation='relu', padding='same'),
            layers.MaxPooling1D(2),
            layers.Flatten(),
            layers.Dense(64, activation='relu'),
            layers.Dropout(0.5),
            layers.Dense(num_classes, activation='softmax')
        ])
        
        self.model.compile(optimizer='adam',
                           loss='sparse_categorical_crossentropy',
                           metrics=['accuracy'])
        
        history = self.model.fit(X_train, y_train, epochs=epochs, validation_data=(X_val, y_val), verbose=1)
        
        val_acc = history.history['val_accuracy'][-1]
        print(f"CNN Validation Accuracy: {val_acc:.4f}")
        
        self.is_trained = True
        return val_acc

    def _preprocess_features(self, X):
        """Apply same preprocessing as training: IP to int, Protocol encoding"""
        X = X.copy()

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

        if 'Protocol' in X.columns and X['Protocol'].dtype == object:
            protocol_map = {'ICMP': 0, 'TCP': 1, 'UDP': 2}
            X['Protocol'] = X['Protocol'].map(lambda p: protocol_map.get(str(p).upper(), 1))

        return X

    def predict(self, X):
        if not self.is_trained:
            raise Exception("Model not trained")
        if not tf:
            raise Exception("TensorFlow not available")
        
        # Handle dict input - convert to DataFrame
        if isinstance(X, dict):
            X = pd.DataFrame([X])

        X = self._preprocess_features(X)

        if hasattr(self.scaler, 'feature_names_in_'):
            expected_features = list(self.scaler.feature_names_in_)
            for col in expected_features:
                if col not in X.columns:
                    X[col] = 0
            X = X[expected_features]

        X_scaled = self.scaler.transform(X)
        X_reshaped = X_scaled.reshape((X_scaled.shape[0], X_scaled.shape[1], 1))
        
        preds = self.model.predict(X_reshaped)
        pred_idx = np.argmax(preds, axis=1)[0]
        
        try:
            pred_label = self.le.inverse_transform([pred_idx])[0]
        except:
            pred_label = pred_idx
            
        confidence = float(np.max(preds))
        
        return {
            'prediction': pred_label,
            'confidence': confidence
        }

    def save_model(self):
        if self.model:
            self.model.save(self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            print(f"CNN model saved to {self.model_path}")

    def load_model(self):
        if not tf:
            return
            
        if self.model_path.exists():
            self.model = models.load_model(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            if self.le_path.exists():
                self.le = joblib.load(self.le_path)
            self.is_trained = True
            print("CNN model loaded.")
        else:
            print("CNN model not found.")
