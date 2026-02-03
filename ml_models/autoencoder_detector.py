"""
VNC Security Monitor - Autoencoder Anomaly Detector
Detects VNC attacks using unsupervised deep learning
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

# Suppress TensorFlow warnings
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

# Try to import TensorFlow
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, Model
    from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    print("Warning: TensorFlow not available. Install with: pip install tensorflow")


class AutoencoderDetector:
    """
    Autoencoder neural network for anomaly detection.
    Trained on NORMAL traffic only - high reconstruction error indicates anomaly.
    
    Architecture:
        Input (N features) → 64 → 32 → 16 (bottleneck) → 32 → 64 → N (output)
    """
    
    def __init__(self, models_dir=None):
        if not TF_AVAILABLE:
            raise ImportError("TensorFlow is required for AutoencoderDetector")
        
        self.model = None
        self.encoder = None
        self.threshold = None
        self.input_dim = None
        self.is_trained = False
        
        # Normalization parameters
        self.mean = None
        self.std = None
        
        # Model directory
        if models_dir:
            self.models_dir = Path(models_dir)
        else:
            self.models_dir = Path(__file__).parent.parent / 'models'
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Model file paths
        self.model_path = self.models_dir / 'autoencoder_model.h5'
        self.threshold_path = self.models_dir / 'autoencoder_threshold.json'
        self.metadata_path = self.models_dir / 'ae_metadata.json'
        
        # Training history
        self.history = None
        self.training_errors = None
    
    def _log(self, message):
        """Log message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [AE] {message}")
    
    def _build_model(self, input_dim):
        """Build autoencoder architecture"""
        self.input_dim = input_dim
        
        # Encoder
        inputs = keras.Input(shape=(input_dim,))
        x = layers.Dense(64, activation='relu')(inputs)
        x = layers.BatchNormalization()(x)
        x = layers.Dropout(0.2)(x)
        x = layers.Dense(32, activation='relu')(x)
        x = layers.BatchNormalization()(x)
        x = layers.Dropout(0.2)(x)
        encoded = layers.Dense(16, activation='relu', name='bottleneck')(x)
        
        # Decoder
        x = layers.Dense(32, activation='relu')(encoded)
        x = layers.BatchNormalization()(x)
        x = layers.Dense(64, activation='relu')(x)
        x = layers.BatchNormalization()(x)
        decoded = layers.Dense(input_dim, activation='linear')(x)
        
        # Full autoencoder
        self.model = Model(inputs, decoded, name='autoencoder')
        
        # Encoder only (for feature extraction)
        self.encoder = Model(inputs, encoded, name='encoder')
        
        # Compile
        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='mse'
        )
        
        self._log(f"Built autoencoder: {input_dim} → 64 → 32 → 16 → 32 → 64 → {input_dim}")
        
        return self.model
    
    def _normalize(self, X):
        """Normalize data using stored mean/std"""
        if self.mean is None or self.std is None:
            self.mean = np.mean(X, axis=0)
            self.std = np.std(X, axis=0) + 1e-8  # Avoid division by zero
        
        return (X - self.mean) / self.std
    
    def _apply_normalization(self, X):
        """Apply stored normalization to new data"""
        if self.mean is None or self.std is None:
            raise ValueError("Normalization parameters not set. Train model first.")
        return (X - self.mean) / self.std
    
    def train(self, X_normal, epochs=50, batch_size=32, validation_split=0.2):
        """
        Train autoencoder on NORMAL traffic only.
        
        Args:
            X_normal: Normal traffic data (DataFrame or array)
            epochs: Number of training epochs
            batch_size: Training batch size
            validation_split: Fraction for validation
            
        Returns:
            dict with training metrics
        """
        self._log("Starting Autoencoder training on NORMAL data only...")
        
        # Convert to numpy
        if isinstance(X_normal, pd.DataFrame):
            X_normal = X_normal.values
        
        # Normalize
        X_normalized = self._normalize(X_normal)
        
        # Build model
        self._build_model(X_normalized.shape[1])
        
        # Callbacks
        callbacks = [
            EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True,
                verbose=1
            ),
            ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=5,
                min_lr=0.0001,
                verbose=1
            )
        ]
        
        # Train
        self._log(f"Training for {epochs} epochs...")
        self.history = self.model.fit(
            X_normalized, X_normalized,  # Autoencoder: input = output
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            callbacks=callbacks,
            verbose=1
        )
        
        # Calculate reconstruction errors on training data
        self._log("Calculating anomaly threshold...")
        reconstructed = self.model.predict(X_normalized, verbose=0)
        self.training_errors = np.mean(np.square(X_normalized - reconstructed), axis=1)
        
        # Set threshold: Mean + 2*StdDev (catches ~95% of normal traffic)
        mean_error = np.mean(self.training_errors)
        std_error = np.std(self.training_errors)
        self.threshold = mean_error + 2 * std_error
        
        self._log(f"Training MSE: {mean_error:.6f}")
        self._log(f"Threshold set to: {self.threshold:.6f}")
        
        self.is_trained = True
        
        metrics = {
            'final_loss': float(self.history.history['loss'][-1]),
            'final_val_loss': float(self.history.history['val_loss'][-1]),
            'mean_reconstruction_error': float(mean_error),
            'std_reconstruction_error': float(std_error),
            'threshold': float(self.threshold),
            'epochs_trained': len(self.history.history['loss'])
        }
        
        print("\n" + "="*50)
        print("Autoencoder Training Complete!")
        print("="*50)
        print(f"Final Loss: {metrics['final_loss']:.6f}")
        print(f"Final Val Loss: {metrics['final_val_loss']:.6f}")
        print(f"Anomaly Threshold: {metrics['threshold']:.6f}")
        
        return metrics
    
    def detect_anomaly(self, X):
        """
        Calculate anomaly score for input data.
        
        Args:
            X: Input features (DataFrame, array, or dict)
            
        Returns:
            float: Reconstruction error (anomaly score)
        """
        if not self.is_trained and self.model is None:
            raise ValueError("Model not trained. Call train() or load_model() first.")
        
        # Handle different input types
        if isinstance(X, dict):
            X = pd.DataFrame([X])
        
        if isinstance(X, pd.DataFrame):
            X = X.values
        
        # Ensure 2D
        if X.ndim == 1:
            X = X.reshape(1, -1)
        
        # Normalize
        X_normalized = self._apply_normalization(X)
        
        # Reconstruct
        reconstructed = self.model.predict(X_normalized, verbose=0)
        
        # Calculate reconstruction error (MSE)
        error = np.mean(np.square(X_normalized - reconstructed), axis=1)
        
        return float(error[0]) if len(error) == 1 else error.tolist()
    
    def is_anomaly(self, X, threshold=None):
        """
        Check if input is anomaly.
        
        Args:
            X: Input features
            threshold: Custom threshold (optional, uses trained threshold if None)
            
        Returns:
            dict with anomaly detection result
        """
        if threshold is None:
            threshold = self.threshold
        
        if threshold is None:
            raise ValueError("No threshold set. Train model first.")
        
        score = self.detect_anomaly(X)
        is_anomaly = score > threshold
        
        # Calculate confidence (how far from threshold)
        if score > threshold:
            confidence = min(1.0, (score - threshold) / threshold)
        else:
            confidence = min(1.0, (threshold - score) / threshold)
        
        return {
            'is_anomaly': bool(is_anomaly),
            'anomaly_score': float(score),
            'threshold': float(threshold),
            'confidence': float(confidence),
            'status': 'ANOMALY' if is_anomaly else 'NORMAL'
        }
    
    def detect_batch(self, X):
        """Detect anomalies in batch"""
        if isinstance(X, pd.DataFrame):
            X = X.values
        
        X_normalized = self._apply_normalization(X)
        reconstructed = self.model.predict(X_normalized, verbose=0)
        errors = np.mean(np.square(X_normalized - reconstructed), axis=1)
        
        results = []
        for error in errors:
            is_anom = error > self.threshold
            results.append({
                'is_anomaly': bool(is_anom),
                'anomaly_score': float(error),
                'status': 'ANOMALY' if is_anom else 'NORMAL'
            })
        
        return results
    
    def get_encoded_features(self, X):
        """Get encoded (compressed) representation of input"""
        if self.encoder is None:
            raise ValueError("Encoder not available. Train model first.")
        
        if isinstance(X, pd.DataFrame):
            X = X.values
        
        X_normalized = self._apply_normalization(X)
        return self.encoder.predict(X_normalized, verbose=0)
    
    def save_model(self, path=None):
        """Save model and parameters to disk"""
        if self.model is None:
            raise ValueError("No model to save")
        
        model_path = path or self.model_path
        
        # Save model
        self.model.save(model_path)
        self._log(f"Model saved to {model_path}")
        
        # Save threshold
        threshold_data = {
            'threshold': float(self.threshold),
            'mean_error': float(np.mean(self.training_errors)) if self.training_errors is not None else 0,
            'std_error': float(np.std(self.training_errors)) if self.training_errors is not None else 0
        }
        
        with open(self.threshold_path, 'w') as f:
            json.dump(threshold_data, f, indent=2)
        
        # Save metadata
        metadata = {
            'input_dim': self.input_dim,
            'mean': self.mean.tolist() if self.mean is not None else None,
            'std': self.std.tolist() if self.std is not None else None,
            'trained_at': datetime.now().isoformat()
        }
        
        with open(self.metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return str(model_path)
    
    def load_model(self, path=None):
        """Load model and parameters from disk"""
        model_path = path or self.model_path
        
        if not Path(model_path).exists():
            raise FileNotFoundError(f"Model not found at {model_path}")
        
        # Load model
        self.model = keras.models.load_model(model_path)
        self._log(f"Model loaded from {model_path}")
        
        # Extract encoder
        self.encoder = Model(
            self.model.input,
            self.model.get_layer('bottleneck').output
        )
        
        # Load threshold
        if self.threshold_path.exists():
            with open(self.threshold_path, 'r') as f:
                threshold_data = json.load(f)
                self.threshold = threshold_data['threshold']
            self._log(f"Threshold loaded: {self.threshold}")
        
        # Load metadata
        if self.metadata_path.exists():
            with open(self.metadata_path, 'r') as f:
                metadata = json.load(f)
                self.input_dim = metadata.get('input_dim')
                if metadata.get('mean'):
                    self.mean = np.array(metadata['mean'])
                if metadata.get('std'):
                    self.std = np.array(metadata['std'])
        
        self.is_trained = True
        
        return self


# Standalone training function
def train_from_csv(data_dir=None):
    """Train autoencoder on normal traffic from CSV files"""
    if not TF_AVAILABLE:
        print("TensorFlow not available. Cannot train autoencoder.")
        return None, None
    
    if data_dir is None:
        data_dir = Path(__file__).parent.parent / 'data' / 'processed'
    else:
        data_dir = Path(data_dir)
    
    # Load data
    X_train = pd.read_csv(data_dir / 'X_train.csv')
    y_train = pd.read_csv(data_dir / 'y_train.csv')['label']
    
    # Filter only normal traffic (label = 0)
    X_normal = X_train[y_train == 0]
    
    print(f"Training on {len(X_normal)} normal samples (out of {len(X_train)} total)")
    
    # Create and train model
    detector = AutoencoderDetector()
    metrics = detector.train(X_normal, epochs=50)
    
    # Save model
    detector.save_model()
    
    return detector, metrics


if __name__ == "__main__":
    print("="*60)
    print("VNC Security Monitor - Autoencoder Training")
    print("="*60)
    
    if not TF_AVAILABLE:
        print("\nTensorFlow not installed.")
        print("Install with: pip install tensorflow")
        sys.exit(1)
    
    # Check for training data
    data_dir = Path(__file__).parent.parent / 'data' / 'processed'
    
    if (data_dir / 'X_train.csv').exists():
        print("\nTraining data found. Starting training...")
        detector, metrics = train_from_csv(data_dir)
        
        if detector:
            print("\n" + "="*60)
            print("Training Complete!")
            print("="*60)
            print(f"Anomaly Threshold: {metrics['threshold']:.6f}")
            print(f"Mean Reconstruction Error: {metrics['mean_reconstruction_error']:.6f}")
    else:
        print("\nNo training data found.")
        print("Generate training data first using Phase 4 (Attack Simulation).")
        print(f"Expected location: {data_dir}")
