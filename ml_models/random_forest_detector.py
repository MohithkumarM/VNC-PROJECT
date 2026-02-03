"""
VNC Security Monitor - Random Forest Classifier
Detects VNC attacks using supervised machine learning
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score
)
from sklearn.preprocessing import StandardScaler


class RandomForestDetector:
    """
    Random Forest classifier for VNC attack detection.
    Uses 100+ trees with optimized hyperparameters.
    """
    
    def __init__(self, models_dir=None):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = None
        self.is_trained = False
        
        # Model directory
        if models_dir:
            self.models_dir = Path(models_dir)
        else:
            self.models_dir = Path(__file__).parent.parent / 'models'
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Model file paths
        self.model_path = self.models_dir / 'random_forest_model.joblib'
        self.scaler_path = self.models_dir / 'rf_scaler.joblib'
        self.metadata_path = self.models_dir / 'rf_metadata.json'
        
        # Training metrics
        self.metrics = {}
    
    def _log(self, message):
        """Log message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [RF] {message}")
    
    def train(self, X, y, optimize=True):
        """
        Train the Random Forest classifier.
        
        Args:
            X: Training features (DataFrame or array)
            y: Training labels (0=normal, 1=attack)
            optimize: Whether to perform hyperparameter optimization
            
        Returns:
            dict with training metrics
        """
        self._log("Starting Random Forest training...")
        
        # Convert to numpy if DataFrame
        if isinstance(X, pd.DataFrame):
            self.feature_names = X.columns.tolist()
            X = X.values
        
        if isinstance(y, pd.Series):
            y = y.values
        
        # Scale features
        self._log("Scaling features...")
        X_scaled = self.scaler.fit_transform(X)
        
        # Split for validation
        X_train, X_val, y_train, y_val = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        
        if optimize:
            self._log("Performing hyperparameter optimization...")
            self.model = self._optimize_hyperparameters(X_train, y_train)
        else:
            # Default model
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            )
            self.model.fit(X_train, y_train)
        
        # Evaluate
        self._log("Evaluating model...")
        self.metrics = self._evaluate(X_train, y_train, X_val, y_val)
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X_scaled, y, cv=5, scoring='f1_weighted')
        self.metrics['cv_f1_mean'] = cv_scores.mean()
        self.metrics['cv_f1_std'] = cv_scores.std()
        
        self._log(f"Cross-validation F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        
        self.is_trained = True
        
        # Print classification report
        y_pred = self.model.predict(X_val)
        labels = np.unique(np.concatenate([y_val, y_pred]))
        target_names = [str(label) for label in labels]
        print("\n" + "="*50)
        print("Classification Report:")
        print("="*50)
        print(classification_report(y_val, y_pred, labels=labels, target_names=target_names, zero_division=0))
        
        return self.metrics
    
    def _optimize_hyperparameters(self, X_train, y_train):
        """Optimize hyperparameters using GridSearchCV"""
        param_grid = {
            'n_estimators': [100, 200],
            'max_depth': [10, 20, None],
            'min_samples_split': [2, 5],
            'min_samples_leaf': [1, 2]
        }
        
        base_model = RandomForestClassifier(random_state=42, n_jobs=-1)
        
        grid_search = GridSearchCV(
            base_model,
            param_grid,
            cv=3,
            scoring='f1',
            n_jobs=-1,
            verbose=1
        )
        
        grid_search.fit(X_train, y_train)
        
        self._log(f"Best parameters: {grid_search.best_params_}")
        
        return grid_search.best_estimator_
    
    def _evaluate(self, X_train, y_train, X_val, y_val):
        """Evaluate model performance"""
        # Training metrics
        y_train_pred = self.model.predict(X_train)
        train_accuracy = accuracy_score(y_train, y_train_pred)
        
        # Validation metrics
        y_val_pred = self.model.predict(X_val)
        if len(np.unique(y_val)) == 2:
            _ = self.model.predict_proba(X_val)[:, 1]
        
        metrics = {
            'train_accuracy': train_accuracy,
            'val_accuracy': accuracy_score(y_val, y_val_pred),
            'precision': precision_score(y_val, y_val_pred, average='weighted', zero_division=0),
            'recall': recall_score(y_val, y_val_pred, average='weighted', zero_division=0),
            'f1_score': f1_score(y_val, y_val_pred, average='weighted', zero_division=0),
            'roc_auc': 0 # ROC AUC for multiclass is complex, skipping for now
        }
        
        self._log(f"Validation Accuracy: {metrics['val_accuracy']:.4f}")
        self._log(f"Precision: {metrics['precision']:.4f}")
        self._log(f"Recall: {metrics['recall']:.4f}")
        self._log(f"F1 Score: {metrics['f1_score']:.4f}")
        self._log(f"ROC AUC: {metrics['roc_auc']:.4f}")
        
        return metrics
    
    def predict(self, X):
        """
        Make prediction on new data.
        
        Args:
            X: Features (DataFrame, array, or dict)
            
        Returns:
            dict with prediction and confidence score
        """
        # Validate model is trained
        if not self.is_trained and self.model is None:
            raise ValueError("Model not trained. Call train() or load_model() first.")
            
        # Handle different input types
        if isinstance(X, dict):
            X = pd.DataFrame([X])

        X = self._preprocess_features(X)
        
        # Ensure we have the same features as training
        if self.feature_names:
            # Add missing columns with 0
            for col in self.feature_names:
                if col not in X.columns:
                    X[col] = 0
            # Reorder/Select columns
            X = X[self.feature_names]
            
        # Select numeric columns if we haven't filtered yet (and if feature_names wasn't used)
        if not self.feature_names:
             X = X.select_dtypes(include=[np.number])

        # Convert to numpy
        X_val = X.values
        
        # Scale
        X_scaled = self.scaler.transform(X_val)
        
        # Predict
        prediction = self.model.predict(X_scaled)[0]
        probabilities = self.model.predict_proba(X_scaled)[0]
        
        confidence = float(max(probabilities))
        
        result_label = prediction
        # If we had encoded labels, we might want to decode them, 
        # but RF usually handles strings if not encoded, or we handle it outside.
        # For consistency with other models, let's assume y was passed as is to fit.
        
        return {
            'prediction': result_label,
            'confidence': confidence,
            'probabilities': probabilities.tolist()
        }

    def _preprocess_features(self, X):
        """Apply same preprocessing as Kaggle training: IP to int, Protocol encoding"""
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
    
    def predict_batch(self, X):
        """Make predictions on multiple samples"""
        if isinstance(X, dict):
            X = pd.DataFrame([X])

        if isinstance(X, pd.DataFrame):
            X = self._preprocess_features(X)

            if self.feature_names:
                for col in self.feature_names:
                    if col not in X.columns:
                        X[col] = 0
                X = X[self.feature_names]
            else:
                X = X.select_dtypes(include=[np.number])

            X_val = X.values
        else:
            X_val = X

        X_scaled = self.scaler.transform(X_val)
        
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)
        
        results = []
        for i, (pred, proba) in enumerate(zip(predictions, probabilities)):
            results.append({
                'prediction': pred,
                'confidence': float(max(proba)),
                'probabilities': proba.tolist()
            })
        
        return results
    
    def get_feature_importance(self, top_n=10):
        """Get feature importance rankings"""
        if self.model is None:
            return None
        
        importances = self.model.feature_importances_
        
        if self.feature_names:
            importance_df = pd.DataFrame({
                'feature': self.feature_names,
                'importance': importances
            }).sort_values('importance', ascending=False)
        else:
            importance_df = pd.DataFrame({
                'feature': [f'feature_{i}' for i in range(len(importances))],
                'importance': importances
            }).sort_values('importance', ascending=False)
        
        return importance_df.head(top_n)
    
    def save_model(self, path=None):
        """Save model to disk"""
        if self.model is None:
            raise ValueError("No model to save")
        
        model_path = path or self.model_path
        
        # Save model
        joblib.dump(self.model, model_path)
        self._log(f"Model saved to {model_path}")
        
        # Save scaler
        joblib.dump(self.scaler, self.scaler_path)
        
        # Save metadata
        metadata = {
            'feature_names': self.feature_names,
            'metrics': self.metrics,
            'n_estimators': self.model.n_estimators,
            'max_depth': self.model.max_depth,
            'trained_at': datetime.now().isoformat()
        }
        
        with open(self.metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return str(model_path)
    
    def load_model(self, path=None):
        """Load model from disk"""
        model_path = path or self.model_path
        
        if not Path(model_path).exists():
            raise FileNotFoundError(f"Model not found at {model_path}")
        
        # Load model
        self.model = joblib.load(model_path)
        self._log(f"Model loaded from {model_path}")
        
        # Load scaler if exists
        if self.scaler_path.exists():
            self.scaler = joblib.load(self.scaler_path)
        
        # Load metadata if exists
        if self.metadata_path.exists():
            with open(self.metadata_path, 'r') as f:
                metadata = json.load(f)
                self.feature_names = metadata.get('feature_names')
                self.metrics = metadata.get('metrics', {})
        
        self.is_trained = True
        
        return self


# Standalone training function
def train_from_csv(data_dir=None):
    """Train model from CSV files"""
    if data_dir is None:
        data_dir = Path(__file__).parent.parent / 'data' / 'processed'
    else:
        data_dir = Path(data_dir)
    
    # Load data
    X_train = pd.read_csv(data_dir / 'X_train.csv')
    y_train = pd.read_csv(data_dir / 'y_train.csv')['label']
    
    # Create and train model
    detector = RandomForestDetector()
    metrics = detector.train(X_train, y_train, optimize=True)
    
    # Save model
    detector.save_model()
    
    return detector, metrics


if __name__ == "__main__":
    print("="*60)
    print("VNC Security Monitor - Random Forest Training")
    print("="*60)
    
    # Check for training data
    data_dir = Path(__file__).parent.parent / 'data' / 'processed'
    
    if (data_dir / 'X_train.csv').exists():
        print("\nTraining data found. Starting training...")
        detector, metrics = train_from_csv(data_dir)
        
        print("\n" + "="*60)
        print("Training Complete!")
        print("="*60)
        print(f"Accuracy: {metrics['val_accuracy']:.4f}")
        print(f"F1 Score: {metrics['f1_score']:.4f}")
        print(f"ROC AUC: {metrics['roc_auc']:.4f}")
        
        print("\nTop 10 Important Features:")
        print(detector.get_feature_importance(10))
    else:
        print("\nNo training data found.")
        print("Generate training data first using Phase 4 (Attack Simulation).")
        print(f"Expected location: {data_dir}")
