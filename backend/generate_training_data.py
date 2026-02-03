"""
VNC Security Monitor - Training Data Generator
Generates realistic demo training data for ML models
"""

import os
import sys
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from sklearn.model_selection import train_test_split
import warnings
warnings.filterwarnings('ignore')

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TrainingDataGenerator:
    """
    Generates training data for VNC security ML models.
    
    Generates:
    - 10,000 normal traffic samples
    - 2,000 attack samples (mix of all attack types)
    """
    
    # Feature definitions with realistic distributions
    FEATURE_CONFIGS = {
        'normal': {
            'packet_count': {'mean': 200, 'std': 50, 'min': 50, 'max': 500},
            'total_bytes': {'mean': 60000, 'std': 20000, 'min': 10000, 'max': 150000},
            'avg_packet_size': {'mean': 300, 'std': 100, 'min': 64, 'max': 1500},
            'std_packet_size': {'mean': 50, 'std': 15, 'min': 10, 'max': 100},
            'min_packet_size': {'fixed': 64},
            'max_packet_size': {'fixed': 1500},
            'bytes_per_second': {'mean': 1000, 'std': 500, 'min': 100, 'max': 5000},
            'packets_per_second': {'mean': 3, 'std': 1, 'min': 1, 'max': 10},
            'connection_duration': {'mean': 180, 'std': 60, 'min': 30, 'max': 600},
            'unique_ports': {'mean': 3, 'std': 1, 'min': 2, 'max': 6},
            'protocol_ratio_tcp': {'mean': 0.88, 'std': 0.05, 'min': 0.75, 'max': 0.99},
            'entropy_bytes': {'mean': 6.5, 'std': 0.5, 'min': 5.0, 'max': 8.0},
            'entropy_packets': {'mean': 4.2, 'std': 0.4, 'min': 3.0, 'max': 5.5},
            'vnc_commands': {'mean': 35, 'std': 10, 'min': 15, 'max': 70},
            'vnc_responses': {'mean': 38, 'std': 12, 'min': 15, 'max': 80},
            'framebuffer_updates': {'mean': 15, 'std': 5, 'min': 5, 'max': 35},
            'key_events': {'mean': 5, 'std': 5, 'min': 0, 'max': 30},
            'pointer_events': {'mean': 15, 'std': 8, 'min': 0, 'max': 50},
            'mouse_clicks': {'mean': 5, 'std': 3, 'min': 0, 'max': 20},
            'keystroke_count': {'mean': 5, 'std': 5, 'min': 0, 'max': 30},
            'screenshot_count': {'mean': 3, 'std': 2, 'min': 0, 'max': 10},
            'file_transfer_size': {'fixed': 0},
            'compression_ratio': {'mean': 1.2, 'std': 0.3, 'min': 0.5, 'max': 2.0},
            'encryption_level': {'fixed': 1},
            'anomaly_score': {'mean': 0.05, 'std': 0.02, 'min': 0.01, 'max': 0.15}
        },
        'attack': {
            'packet_count': {'mean': 400, 'std': 150, 'min': 100, 'max': 1000},
            'total_bytes': {'mean': 500000, 'std': 300000, 'min': 50000, 'max': 2000000},
            'avg_packet_size': {'mean': 1200, 'std': 800, 'min': 200, 'max': 50000},
            'std_packet_size': {'mean': 200, 'std': 100, 'min': 50, 'max': 500},
            'min_packet_size': {'fixed': 64},
            'max_packet_size': {'mean': 30000, 'std': 20000, 'min': 1500, 'max': 65000},
            'bytes_per_second': {'mean': 50000, 'std': 40000, 'min': 5000, 'max': 500000},
            'packets_per_second': {'mean': 100, 'std': 80, 'min': 20, 'max': 500},
            'connection_duration': {'mean': 120, 'std': 60, 'min': 20, 'max': 300},
            'unique_ports': {'mean': 5, 'std': 2, 'min': 2, 'max': 10},
            'protocol_ratio_tcp': {'mean': 0.85, 'std': 0.10, 'min': 0.60, 'max': 0.99},
            'entropy_bytes': {'mean': 7.2, 'std': 0.6, 'min': 5.5, 'max': 8.0},
            'entropy_packets': {'mean': 4.8, 'std': 0.5, 'min': 3.5, 'max': 6.0},
            'vnc_commands': {'mean': 150, 'std': 80, 'min': 50, 'max': 400},
            'vnc_responses': {'mean': 120, 'std': 60, 'min': 30, 'max': 350},
            'framebuffer_updates': {'mean': 100, 'std': 80, 'min': 10, 'max': 400},
            'key_events': {'mean': 200, 'std': 200, 'min': 0, 'max': 1000},
            'pointer_events': {'mean': 100, 'std': 80, 'min': 10, 'max': 400},
            'mouse_clicks': {'mean': 30, 'std': 25, 'min': 0, 'max': 150},
            'keystroke_count': {'mean': 200, 'std': 200, 'min': 0, 'max': 1000},
            'screenshot_count': {'mean': 50, 'std': 40, 'min': 5, 'max': 200},
            'file_transfer_size': {'mean': 50000000, 'std': 100000000, 'min': 0, 'max': 500000000},
            'compression_ratio': {'mean': 0.8, 'std': 0.3, 'min': 0.3, 'max': 1.5},
            'encryption_level': {'fixed': 0},
            'anomaly_score': {'mean': 0.6, 'std': 0.2, 'min': 0.3, 'max': 0.95}
        }
    }
    
    ATTACK_TYPES = ['file_exfiltration', 'clipboard_hijacking', 'screen_capture', 'keylogging', 'unencrypted']
    
    def __init__(self, output_dir=None):
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = Path(__file__).parent.parent / 'data' / 'processed'
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def _log(self, message):
        """Log message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [DATA] {message}")
    
    def _generate_feature(self, config):
        """Generate a single feature value based on config"""
        if 'fixed' in config:
            return config['fixed']
        
        value = np.random.normal(config['mean'], config['std'])
        value = np.clip(value, config['min'], config['max'])
        return value
    
    def _generate_sample(self, label):
        """Generate a single sample"""
        config_type = 'normal' if label == 0 else 'attack'
        configs = self.FEATURE_CONFIGS[config_type]
        
        sample = {}
        for feature, config in configs.items():
            value = self._generate_feature(config)
            
            # Ensure integer types for count features
            if any(x in feature for x in ['count', 'events', 'updates', 'clicks', 'size', 'ports', 'commands', 'responses']):
                value = int(max(0, value))
            
            sample[feature] = value
        
        # Calculate derived features
        sample['protocol_ratio_udp'] = round(1 - sample['protocol_ratio_tcp'], 4)
        sample['session_length'] = sample['connection_duration']
        
        # Assign attack type for attack samples
        if label == 1:
            sample['attack_type'] = np.random.choice(self.ATTACK_TYPES)
        else:
            sample['attack_type'] = 'normal'
        
        return sample
    
    def generate_training_data(self, n_normal=10000, n_attack=2000, save=True):
        """
        Generate training dataset.
        
        Args:
            n_normal: Number of normal samples
            n_attack: Number of attack samples
            save: Whether to save to CSV files
            
        Returns:
            Tuple of (X_train, X_test, y_train, y_test) DataFrames
        """
        self._log(f"Generating {n_normal} normal + {n_attack} attack samples...")
        
        # Generate normal samples
        normal_samples = []
        for i in range(n_normal):
            sample = self._generate_sample(label=0)
            sample['label'] = 0
            normal_samples.append(sample)
            if (i + 1) % 2000 == 0:
                self._log(f"  Generated {i + 1}/{n_normal} normal samples")
        
        # Generate attack samples
        attack_samples = []
        for i in range(n_attack):
            sample = self._generate_sample(label=1)
            sample['label'] = 1
            attack_samples.append(sample)
            if (i + 1) % 500 == 0:
                self._log(f"  Generated {i + 1}/{n_attack} attack samples")
        
        # Combine and shuffle
        all_samples = normal_samples + attack_samples
        np.random.shuffle(all_samples)
        
        # Create DataFrame
        df = pd.DataFrame(all_samples)
        
        self._log(f"Total samples: {len(df)}")
        self._log(f"Normal: {len(df[df['label']==0])}, Attack: {len(df[df['label']==1])}")
        
        # Prepare features and labels
        feature_columns = [col for col in df.columns if col not in ['label', 'attack_type']]
        
        X = df[feature_columns]
        y = df['label']
        
        # Split into train/test
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        self._log(f"Train set: {len(X_train)} samples")
        self._log(f"Test set: {len(X_test)} samples")
        
        if save:
            self._save_data(X_train, X_test, y_train, y_test, df)
        
        return X_train, X_test, y_train, y_test
    
    def _save_data(self, X_train, X_test, y_train, y_test, full_df):
        """Save data to CSV files"""
        self._log("Saving data to CSV files...")
        
        # Save train/test splits
        X_train.to_csv(self.output_dir / 'X_train.csv', index=False)
        X_test.to_csv(self.output_dir / 'X_test.csv', index=False)
        
        # Save labels as DataFrame
        pd.DataFrame({'label': y_train}).to_csv(self.output_dir / 'y_train.csv', index=False)
        pd.DataFrame({'label': y_test}).to_csv(self.output_dir / 'y_test.csv', index=False)
        
        # Save full dataset
        full_df.to_csv(self.output_dir / 'training_data.csv', index=False)
        
        # Save preprocessing info
        import json
        preprocessing_info = {
            'feature_columns': X_train.columns.tolist(),
            'selected_features': X_train.columns.tolist(),
            'n_features': len(X_train.columns),
            'n_train_samples': len(X_train),
            'n_test_samples': len(X_test),
            'train_attack_ratio': float(y_train.mean()),
            'test_attack_ratio': float(y_test.mean()),
            'created_at': datetime.now().isoformat()
        }
        
        with open(self.output_dir / 'preprocessing_info.json', 'w') as f:
            json.dump(preprocessing_info, f, indent=2)
        
        self._log(f"Data saved to {self.output_dir}")
        self._log("Files created:")
        self._log("  - X_train.csv")
        self._log("  - X_test.csv")
        self._log("  - y_train.csv")
        self._log("  - y_test.csv")
        self._log("  - training_data.csv")
        self._log("  - preprocessing_info.json")
    
    def generate_quick_data(self, n_samples=1000):
        """Generate a smaller dataset for quick testing"""
        n_normal = int(n_samples * 0.8)
        n_attack = n_samples - n_normal
        return self.generate_training_data(n_normal, n_attack)


def generate_training_data(n_normal=10000, n_attack=2000):
    """Convenience function to generate training data"""
    generator = TrainingDataGenerator()
    return generator.generate_training_data(n_normal, n_attack)


if __name__ == "__main__":
    print("="*60)
    print("VNC Security Monitor - Training Data Generator")
    print("="*60)
    
    generator = TrainingDataGenerator()
    
    print("\nGenerating training data...")
    print("  - 10,000 normal traffic samples")
    print("  - 2,000 attack samples (mixed types)")
    print()
    
    X_train, X_test, y_train, y_test = generator.generate_training_data(
        n_normal=10000,
        n_attack=2000,
        save=True
    )
    
    print("\n" + "="*60)
    print("Data Generation Complete!")
    print("="*60)
    print(f"\nTraining set shape: {X_train.shape}")
    print(f"Test set shape: {X_test.shape}")
    print(f"\nFeatures: {len(X_train.columns)}")
    print(f"Feature names: {list(X_train.columns)[:10]}...")
    
    print("\nClass distribution (train):")
    print(f"  Normal: {sum(y_train==0)} ({sum(y_train==0)/len(y_train)*100:.1f}%)")
    print(f"  Attack: {sum(y_train==1)} ({sum(y_train==1)/len(y_train)*100:.1f}%)")
    
    print("\nData is ready for ML training!")
    print(f"  Location: {generator.output_dir}")
