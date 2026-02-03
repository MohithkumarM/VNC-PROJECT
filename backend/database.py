"""
VNC Security Monitor - Database Module
Handles in-memory storage and data persistence
"""

import json
import threading
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd
import numpy as np


def _sanitize_for_json(obj):
    """Recursively convert NumPy types to Python types for JSON serialization"""
    if isinstance(obj, dict):
        return {k: _sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_sanitize_for_json(v) for v in obj]
    elif isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return _sanitize_for_json(obj.tolist())
    elif isinstance(obj, np.bool_):
        return bool(obj)
    return obj


class Database:
    """
    In-memory database for storing alerts, traffic data, and system state.
    Uses deque for efficient fixed-size storage.
    """
    
    def __init__(self, max_alerts=100, max_traffic_records=1000):
        self.max_alerts = max_alerts
        self.max_traffic_records = max_traffic_records
        
        # Thread-safe lock
        self._lock = threading.Lock()
        
        # Data stores
        self.alerts = deque(maxlen=max_alerts)
        self.traffic_records = deque(maxlen=max_traffic_records)
        self.predictions = deque(maxlen=max_traffic_records)
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'total_attacks_detected': 0,
            'total_bytes_analyzed': 0,
            'monitoring_start_time': None,
            'last_update_time': None
        }
        
        # System state
        self.system_state = {
            'monitoring_active': False,
            'ml_models_loaded': False,
            'last_prediction_time': None
        }
    
    # ==================== Alert Methods ====================
    
    def add_alert(self, alert_type, severity, message, details=None):
        """Add a new alert to the database"""
        with self._lock:
            # Sanitize details to ensure JSON serializable
            sanitized_details = _sanitize_for_json(details) if details else {}
            
            alert = {
                'id': len(self.alerts) + 1,
                'timestamp': datetime.now().isoformat(),
                'type': str(alert_type),  # Ensure string
                'severity': severity,  # 'safe', 'suspicious', 'danger'
                'message': str(message),  # Ensure string
                'details': sanitized_details,
                'acknowledged': False
            }
            self.alerts.append(alert)
            
            if severity == 'danger':
                self.stats['total_attacks_detected'] += 1
            
            return alert
    
    def get_alerts(self, limit=None, severity=None, acknowledged=None):
        """Get alerts with optional filtering"""
        with self._lock:
            alerts = list(self.alerts)
            
            # Filter by severity
            if severity:
                alerts = [a for a in alerts if a['severity'] == severity]
            
            # Filter by acknowledged status
            if acknowledged is not None:
                alerts = [a for a in alerts if a['acknowledged'] == acknowledged]
            
            # Sort by timestamp (newest first)
            alerts.sort(key=lambda x: x['timestamp'], reverse=True)
            
            # Limit results
            if limit:
                alerts = alerts[:limit]
            
            return alerts
    
    def acknowledge_alert(self, alert_id):
        """Mark an alert as acknowledged"""
        with self._lock:
            for alert in self.alerts:
                if alert['id'] == alert_id:
                    alert['acknowledged'] = True
                    return True
            return False
    
    def clear_alerts(self):
        """Clear all alerts"""
        with self._lock:
            self.alerts.clear()
    
    # ==================== Traffic Methods ====================
    
    def add_traffic_record(self, record):
        """Add a traffic record"""
        with self._lock:
            # Sanitize record data
            sanitized_record = _sanitize_for_json(record)
            sanitized_record['timestamp'] = datetime.now().isoformat()
            self.traffic_records.append(sanitized_record)
            self.stats['total_connections'] += 1
            # Support both 'bytes' and 'BytesSent'/'BytesReceived' fields
            bytes_count = sanitized_record.get('bytes', 0)
            if bytes_count == 0:
                bytes_count = sanitized_record.get('BytesSent', 0) + sanitized_record.get('BytesReceived', 0)
            self.stats['total_bytes_analyzed'] += bytes_count
            self.stats['last_update_time'] = datetime.now().isoformat()
            return sanitized_record
    
    def get_traffic_records(self, limit=None, since=None):
        """Get traffic records with optional filtering"""
        with self._lock:
            records = list(self.traffic_records)
            
            # Filter by time
            if since:
                records = [r for r in records if r['timestamp'] >= since.isoformat()]
            
            # Sort by timestamp (newest first)
            records.sort(key=lambda x: x['timestamp'], reverse=True)
            
            # Limit results
            if limit:
                records = records[:limit]
            
            return records
    
    # ==================== Prediction Methods ====================
    
    def add_prediction(self, prediction):
        """Add a prediction result"""
        with self._lock:
            # Sanitize prediction data
            sanitized_prediction = _sanitize_for_json(prediction)
            sanitized_prediction['timestamp'] = datetime.now().isoformat()
            self.predictions.append(sanitized_prediction)
            self.system_state['last_prediction_time'] = sanitized_prediction['timestamp']
            return sanitized_prediction
    
    def get_predictions(self, limit=None):
        """Get prediction results"""
        with self._lock:
            predictions = list(self.predictions)
            predictions.sort(key=lambda x: x['timestamp'], reverse=True)
            
            if limit:
                predictions = predictions[:limit]
            
            return predictions
    
    # ==================== Statistics Methods ====================
    
    def get_stats(self):
        """Get current statistics"""
        with self._lock:
            # Calculate derived stats
            total_records = len(self.traffic_records)
            
            # Count attack predictions - anything that's not Normal/Safe/Unknown
            safe_labels = ['NORMAL', 'SAFE', 'UNKNOWN', 'Normal', 'Safe', 'Unknown']
            attack_records = sum(1 for p in self.predictions 
                               if str(p.get('prediction', 'Normal')) not in safe_labels)
            
            normal_percentage = 100.0
            if total_records > 0:
                normal_percentage = ((total_records - attack_records) / total_records) * 100
            
            return {
                **self.stats,
                'active_threats': len([a for a in self.alerts 
                                      if a['severity'] == 'danger' and not a['acknowledged']]),
                'normal_percentage': round(normal_percentage, 1),
                'total_records': total_records
            }
    
    def update_stats(self, key, value):
        """Update a specific statistic"""
        with self._lock:
            self.stats[key] = value
    
    # ==================== System State Methods ====================
    
    def get_system_state(self):
        """Get system state"""
        with self._lock:
            return self.system_state.copy()
    
    def update_system_state(self, key, value):
        """Update system state"""
        with self._lock:
            self.system_state[key] = value
    
    def start_monitoring(self):
        """Set monitoring as active"""
        with self._lock:
            self.system_state['monitoring_active'] = True
            self.stats['monitoring_start_time'] = datetime.now().isoformat()
    
    def stop_monitoring(self):
        """Set monitoring as inactive"""
        with self._lock:
            self.system_state['monitoring_active'] = False
    
    # ==================== Persistence Methods ====================
    
    def save_to_file(self, filepath):
        """Save database state to JSON file"""
        with self._lock:
            data = {
                'alerts': list(self.alerts),
                'traffic_records': list(self.traffic_records),
                'predictions': list(self.predictions),
                'stats': self.stats,
                'system_state': self.system_state
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
    
    def load_from_file(self, filepath):
        """Load database state from JSON file"""
        if not Path(filepath).exists():
            return False
        
        with self._lock:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            self.alerts = deque(data.get('alerts', []), maxlen=self.max_alerts)
            self.traffic_records = deque(data.get('traffic_records', []), 
                                        maxlen=self.max_traffic_records)
            self.predictions = deque(data.get('predictions', []), 
                                    maxlen=self.max_traffic_records)
            self.stats = data.get('stats', self.stats)
            self.system_state = data.get('system_state', self.system_state)
            
            return True
    
    def export_to_csv(self, directory):
        """Export data to CSV files"""
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        
        with self._lock:
            # Export alerts
            if self.alerts:
                pd.DataFrame(list(self.alerts)).to_csv(
                    directory / 'alerts.csv', index=False
                )
            
            # Export traffic records
            if self.traffic_records:
                pd.DataFrame(list(self.traffic_records)).to_csv(
                    directory / 'traffic_records.csv', index=False
                )
            
            # Export predictions
            if self.predictions:
                pd.DataFrame(list(self.predictions)).to_csv(
                    directory / 'predictions.csv', index=False
                )


# Global database instance
db = Database()
