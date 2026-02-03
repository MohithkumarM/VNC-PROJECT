"""
VNC Security Monitor - Ensemble Predictor
Combines Random Forest, SVM, XGBoost, and CNN for robust detection
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Import our models
from .random_forest_detector import RandomForestDetector
from .svm_detector import SVMDetector
from .xgboost_detector import XGBoostDetector
from .cnn_detector import CNNDetector

class EnsemblePredictor:
    """
    Ensemble system combining RF, SVM, XGBoost, and CNN.
    
    Voting Logic:
        - Majority Vote on the predicted label.
        - If Tie: Returns one of the tied labels (implementation dependent/pessimistic if possible).
    """
    
    # Expected features from trained models (from rf_metadata.json)
    TRAINED_FEATURES = [
        'packet_count', 'total_bytes', 'avg_packet_size', 'std_packet_size',
        'min_packet_size', 'max_packet_size', 'bytes_per_second', 'packets_per_second',
        'connection_duration', 'unique_ports', 'protocol_ratio_tcp', 'entropy_bytes',
        'entropy_packets', 'vnc_commands', 'vnc_responses', 'framebuffer_updates',
        'key_events', 'pointer_events', 'mouse_clicks', 'keystroke_count',
        'screenshot_count', 'file_transfer_size', 'compression_ratio', 'encryption_level',
        'anomaly_score', 'protocol_ratio_udp', 'session_length'
    ]
    
    def __init__(self, models_dir=None):
        # Model directory
        if models_dir:
            self.models_dir = Path(models_dir)
        else:
            self.models_dir = Path(__file__).parent.parent / 'models'
        
        # Initialize detectors
        self.detectors = {
            'random_forest': RandomForestDetector(self.models_dir),
            'svm': SVMDetector(self.models_dir),
            'xgboost': XGBoostDetector(self.models_dir),
            'cnn': CNNDetector(self.models_dir)
        }
        
        # Status flags
        self.loaded_status = {name: False for name in self.detectors}
        
        # Load models
        self._load_models()
    
    def _log(self, message):
        """Log message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [ENSEMBLE] {message}")
    
    def _load_models(self):
        """Load all ML models"""
        self._log("Loading ensemble models...")
        
        for name, detector in self.detectors.items():
            try:
                detector.load_model()
                self.loaded_status[name] = True
                self._log(f"{name.replace('_', ' ').title()} loaded")
            except Exception as e:
                self.loaded_status[name] = False
                self._log(f"{name.replace('_', ' ').title()} not loaded: {e}")

    def _transform_features(self, X):
        """
        Transform incoming API features to match the trained model's expected features.
        
        The frontend sends features like PacketSize, ResponseTime, Protocol, etc.
        The models were trained with features like packet_count, total_bytes, etc.
        
        This method creates a synthetic mapping from API features to model features.
        """
        # Convert to DataFrame if dict
        if isinstance(X, dict):
            X = pd.DataFrame([X])
        elif not isinstance(X, pd.DataFrame):
            X = pd.DataFrame([X])
        
        # Create new DataFrame with expected features
        transformed = pd.DataFrame()
        
        # Map API features to model features
        # Use sensible defaults/transformations
        transformed['packet_count'] = X.get('NumPackets', pd.Series([100]))
        transformed['total_bytes'] = X.get('BytesSent', pd.Series([0])) + X.get('BytesReceived', pd.Series([0]))
        transformed['avg_packet_size'] = X.get('PacketSize', pd.Series([500]))
        transformed['std_packet_size'] = transformed['avg_packet_size'] * 0.2  # Estimate
        transformed['min_packet_size'] = transformed['avg_packet_size'] * 0.5
        transformed['max_packet_size'] = transformed['avg_packet_size'] * 1.5
        transformed['bytes_per_second'] = X.get('FlowRate', pd.Series([100]))
        transformed['packets_per_second'] = X.get('PacketRate', pd.Series([50]))
        transformed['connection_duration'] = X.get('FlowDuration', pd.Series([1]))
        transformed['unique_ports'] = 1
        transformed['protocol_ratio_tcp'] = 1.0 if X.get('Protocol', pd.Series(['TCP'])).iloc[0] == 'TCP' else 0.0
        transformed['protocol_ratio_udp'] = 1.0 if X.get('Protocol', pd.Series(['TCP'])).iloc[0] == 'UDP' else 0.0
        transformed['entropy_bytes'] = X.get('Entropy', pd.Series([0.5]))
        transformed['entropy_packets'] = X.get('Entropy', pd.Series([0.5]))
        transformed['vnc_commands'] = 10
        transformed['vnc_responses'] = 10
        transformed['framebuffer_updates'] = 5
        transformed['key_events'] = 0
        transformed['pointer_events'] = 0
        transformed['mouse_clicks'] = 0
        transformed['keystroke_count'] = 0
        transformed['screenshot_count'] = 0
        transformed['file_transfer_size'] = 0
        transformed['compression_ratio'] = 0.8
        transformed['encryption_level'] = 1
        transformed['anomaly_score'] = X.get('AnomalyScore', pd.Series([0]))
        transformed['session_length'] = X.get('ActiveTime', pd.Series([1]))
        
        # Ensure all expected columns exist
        for col in self.TRAINED_FEATURES:
            if col not in transformed.columns:
                transformed[col] = 0
        
        # Reorder to match expected order
        transformed = transformed[self.TRAINED_FEATURES]
        
        return transformed

    def predict(self, X):
        """
        Make ensemble prediction on input data.
        
        Args:
            X: Input features (dict or DataFrame)
        """
        predictions = []
        confidences = []
        details = []
        
        # Convert dict to DataFrame if needed (DON'T transform - models expect original features)
        if isinstance(X, dict):
            X_input = pd.DataFrame([X])
        else:
            X_input = X
        
        # Collect predictions
        for name, detector in self.detectors.items():
            if self.loaded_status[name]:
                try:
                    result = detector.predict(X_input)
                    pred = result['prediction']
                    conf = result['confidence']
                    
                    predictions.append(pred)
                    confidences.append(conf)
                    details.append(f"{name}: {pred} ({conf:.2f})")
                except Exception as e:
                    self._log(f"Error predicting with {name}: {e}")
        
        if not predictions:
            return {
                'prediction': 'Unknown',
                'confidence': 0.0,
                'details': 'No models available',
                'models_used': self.loaded_status
            }
            
        # Majority Vote
        from collections import Counter
        vote_counts = Counter(predictions)
        winner, count = vote_counts.most_common(1)[0]
        
        # Average confidence of the winner
        winner_confs = [c for p, c in zip(predictions, confidences) if p == winner]
        avg_conf = sum(winner_confs) / len(winner_confs) if winner_confs else 0
        
        # Construct response
        # Note: Logic for SAFE/DANGER based on label
        # Assuming 'Normal' is the safe label from the dataset
        threat_level = 'SAFE' if str(winner).lower() == 'normal' else 'DANGER'
        
        detail_str = f"Majority Vote: {winner} ({count}/{len(predictions)}). " + ", ".join(details)
        
        return {
            'prediction': winner,
            'threat_level': threat_level,
            'confidence': avg_conf,
            'details': detail_str,
            'timestamp': datetime.now().isoformat(),
            'models_used': self.loaded_status,
            'votes': dict(vote_counts)
        }
    
    def predict_batch(self, X):
        """Make predictions on multiple samples"""
        if isinstance(X, pd.DataFrame):
            results = []
            for i in range(len(X)):
                row = X.iloc[[i]]
                result = self.predict(row)
                results.append(result)
            return results
        else:
            return [self.predict(X)]
    
    def get_status(self):
        """Get ensemble system status"""
        return {
            'ensemble_ready': any(self.loaded_status.values()),
            'full_ensemble': all(self.loaded_status.values()),
            'models_loaded': self.loaded_status,
            'models_dir': str(self.models_dir)
        }
    
    def reload_models(self):
        """Reload all models"""
        self._load_models()
        return self.get_status()

# Create global instance for easy import
ensemble = None

def get_ensemble(models_dir=None):
    """Get or create ensemble instance"""
    global ensemble
    if ensemble is None:
        ensemble = EnsemblePredictor(models_dir)
    return ensemble

if __name__ == "__main__":
    print("Testing Ensemble...")
    ep = EnsemblePredictor()
    print(ep.get_status())
