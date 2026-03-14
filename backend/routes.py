"""
VNC Security Monitor - API Routes
Flask Blueprint with all API endpoints
"""

import sys
from pathlib import Path
from flask import Blueprint, jsonify, request, render_template, send_file
from datetime import datetime, timedelta
import json

from .database import db
from .config import Config
from .protection import get_recommendation

# Add ml_models to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Try to import ensemble predictor
try:
    from ml_models.ensemble_predictor import EnsemblePredictor
    ensemble_predictor = EnsemblePredictor()
    ML_AVAILABLE = ensemble_predictor.get_status()['ensemble_ready']
except Exception as e:
    print(f"Warning: ML models not available: {e}")
    ensemble_predictor = None
    ML_AVAILABLE = False

# Create Blueprint
api = Blueprint('api', __name__)

import numpy as np

def sanitize_json(obj):
    """Recursively convert NumPy types to Python types for JSON serialization"""
    if isinstance(obj, dict):
        return {k: sanitize_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_json(v) for v in obj]
    elif isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return sanitize_json(obj.tolist())
    elif isinstance(obj, np.bool_):
        return bool(obj)
    return obj




# ==================== Dashboard Routes ====================

@api.route('/')
def dashboard():
    """Serve main dashboard page"""
    return render_template('dashboard.html')


@api.route('/alerts')
def alerts_page():
    """Serve alerts page"""
    return render_template('alerts.html')


@api.route('/reports')
def reports_page():
    """Serve reports page"""
    return render_template('reports.html')


@api.route('/settings')
def settings_page():
    """Serve settings page"""
    return render_template('settings.html')


# ==================== Traffic API ====================

@api.route('/api/traffic')
def get_traffic():
    """Get current traffic statistics and recent records"""
    try:
        limit = request.args.get('limit', 60, type=int)
        stats = db.get_stats()
        recent_traffic = db.get_traffic_records(limit=limit)
        predictions = db.get_predictions(limit=limit)
        
        # Merge traffic with predictions for timeline
        traffic_timeline = []
        for i, record in enumerate(recent_traffic):
            # Try to find matching prediction
            threat_level = 'safe'
            if i < len(predictions):
                pred_raw = predictions[i].get('prediction', 'SAFE')
                pred = str(pred_raw).upper()
                
                # Map attack types to threat levels
                if pred in ['DANGER', 'DOS', 'DDOS', 'MALWARE', 'PORTSCAN']:
                    threat_level = 'danger'
                elif pred == 'SUSPICIOUS':
                    threat_level = 'suspicious'
                elif pred in ['NORMAL', 'SAFE']:
                    threat_level = 'safe'
                else:
                    # Any non-Normal label is treated as danger
                    threat_level = 'danger' if pred != 'NORMAL' else 'safe'
            
            # Support both 'bytes' and 'BytesSent'/'BytesReceived'
            byte_count = record.get('bytes', 0)
            if byte_count == 0:
                byte_count = record.get('BytesSent', 0) + record.get('BytesReceived', 0)
            if byte_count == 0:
                byte_count = record.get('PacketSize', 0)
            
            traffic_timeline.append({
                'timestamp': record.get('timestamp', ''),
                'bytes': byte_count,
                'prediction': record.get('prediction', threat_level),
                'threat_level': threat_level
            })
        
        return jsonify(sanitize_json({
            'timestamp': datetime.now().isoformat(),
            'total_connections': stats.get('total_connections', 0),
            'active_threats': stats.get('active_threats', 0),
            'normal_percentage': stats.get('normal_percentage', 100),
            'system_status': 'online' if db.get_system_state().get('monitoring_active') else 'offline',
            'traffic': traffic_timeline,
            'total_bytes_analyzed': stats.get('total_bytes_analyzed', 0)
        }))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/api/traffic/history')
def get_traffic_history():
    """Get traffic history for specified time range"""
    try:
        hours = request.args.get('hours', 1, type=int)
        since = datetime.now() - timedelta(hours=hours)
        
        records = db.get_traffic_records(since=since)
        
        return jsonify(sanitize_json({
            'records': records,
            'count': len(records),
            'time_range': f'Last {hours} hour(s)'
        }))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== Alerts API ====================

@api.route('/api/alerts')
def get_alerts():
    """Get security alerts"""
    try:
        limit = request.args.get('limit', 50, type=int)
        severity = request.args.get('severity', None)
        source_ip = request.args.get('source_ip', None)

        if source_ip:
            alerts = db.get_alerts_by_source_ip(source_ip=source_ip, limit=limit)
            if severity:
                alerts = [a for a in alerts if a.get('severity') == severity]
        else:
            alerts = db.get_alerts(limit=limit, severity=severity)
        
        return jsonify({
            'alerts': sanitize_json(alerts),
            'count': len(alerts),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/api/alerts', methods=['POST'])
def create_alert():
    """Create a new alert (for testing)"""
    try:
        data = request.get_json()
        
        alert = db.add_alert(
            alert_type=data.get('type', 'manual'),
            severity=data.get('severity', 'suspicious'),
            message=data.get('message', 'Manual alert'),
            details=data.get('details', {}),
            source_ip=data.get('source_ip', '')
        )

        if alert.get('severity') == 'danger' and alert.get('source_ip'):
            db.block_ip(alert.get('source_ip'))
        
        return jsonify({'success': True, 'alert': alert})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    try:
        success = db.acknowledge_alert(alert_id)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/api/alerts/clear', methods=['POST'])
def clear_alerts():
    """Clear all alerts"""
    try:
        db.clear_alerts()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== Prediction API ====================

@api.route('/api/predict', methods=['POST'])
def predict():
    """Make prediction on traffic data using ML ensemble"""
    try:
        data = request.get_json()
        
        if ensemble_predictor and ML_AVAILABLE:
            # Use actual ML models
            prediction = ensemble_predictor.predict(data)
            
            # Add protection advice based on the predicted label
            # The ensemble returns raw label in 'prediction' (e.g., 'DoS')
            label = prediction.get('prediction', 'Unknown')
            advice = get_recommendation(label)
            prediction['protection_advice'] = advice
            
            # Create alert if dangerous
            # We use threat_level from ensemble if available, or infer from label
            is_danger = prediction.get('threat_level', 'SAFE') == 'DANGER'
            
            if is_danger:
                source_ip = data.get('SrcIP', data.get('src_ip', ''))
                db.add_alert(
                    alert_type=label,
                    severity='danger',
                    message=f"Attack detected! {label} - {prediction.get('details')}",
                    details=sanitize_json(prediction),
                    source_ip=source_ip
                )
                if source_ip:
                    db.block_ip(source_ip)
        else:
            # Fallback - ML models not loaded
            prediction = {
                'prediction': 'UNKNOWN',
                'confidence': 0,
                'details': 'ML models not loaded. Train models first.',
                'timestamp': datetime.now().isoformat()
            }
        
        prediction = sanitize_json(prediction)
        db.add_prediction(prediction)
        
        return jsonify(prediction)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/api/ml/status')
def ml_status():
    """Get ML models status"""
    try:
        if ensemble_predictor:
            status = ensemble_predictor.get_status()
        else:
            status = {
                'random_forest_loaded': False,
                'autoencoder_loaded': False,
                'ensemble_ready': False,
                'full_ensemble': False,
                'error': 'ML models not initialized'
            }
        
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/api/ml/reload', methods=['POST'])
def reload_ml_models():
    """Reload ML models"""
    try:
        global ensemble_predictor, ML_AVAILABLE
        
        ensemble_predictor = EnsemblePredictor()
        ML_AVAILABLE = ensemble_predictor.get_status()['ensemble_ready']
        
        return jsonify({
            'success': True,
            'status': ensemble_predictor.get_status()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/api/predictions')
def get_predictions():
    """Get recent predictions"""
    try:
        limit = request.args.get('limit', 100, type=int)
        predictions = db.get_predictions(limit=limit)
        
        return jsonify(sanitize_json({
            'predictions': predictions,
            'count': len(predictions)
        }))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== Simulation API ====================

@api.route('/api/simulate', methods=['POST'])
def simulate_attack():
    """Simulate attack scenario for demo"""
    try:
        data = request.get_json() or {}
        # Support both 'type' and 'attack_type' keys
        attack_type = data.get('attack_type') or data.get('type', 'Normal')
        count = data.get('count', 5)
        
        # Import attack simulator
        try:
            from backend.attack_simulator import AttackSimulator
            simulator = AttackSimulator()
            
            # Generate simulated traffic
            simulated_data = []
            for _ in range(count):
                traffic = simulator.generate_sample(attack_type)
                simulated_data.append(traffic)
                
                # Add to database
                db.add_traffic_record({
                    **traffic,
                    'simulated': True,
                    'timestamp': datetime.now().isoformat()
                })
                
                # Run ML prediction if available
                if ensemble_predictor and ML_AVAILABLE:
                    prediction = ensemble_predictor.predict(traffic)
                    prediction = sanitize_json(prediction)
                    db.add_prediction(prediction)
                    
                    # Create alert for threats based on threat_level or prediction label
                    threat_level = prediction.get('threat_level', 'SAFE')
                    pred_label = str(prediction.get('prediction', 'Normal')).upper()
                    
                    # Check if this is an attack (not Normal/Safe)
                    is_attack = pred_label not in ['NORMAL', 'SAFE'] or threat_level == 'DANGER'
                    
                    _src_ip = traffic.get('SrcIP', traffic.get('src_ip', ''))
                    if is_attack:
                        db.add_alert(
                            alert_type=prediction.get('prediction', attack_type),
                            severity='danger',
                            message=f"Attack detected: {prediction.get('prediction', attack_type)}",
                            details={'prediction': prediction, 'traffic': sanitize_json(traffic)},
                            source_ip=_src_ip
                        )
                        if _src_ip:
                            db.block_ip(_src_ip)
                    elif threat_level == 'SUSPICIOUS':
                        db.add_alert(
                            alert_type=attack_type,
                            severity='warning',
                            message=f"Suspicious: {attack_type.replace('_', ' ').title()}",
                            details={'prediction': prediction, 'traffic': sanitize_json(traffic)},
                            source_ip=_src_ip
                        )
            
            return jsonify({
                'success': True,
                'message': f'Generated {count} {attack_type} traffic records',
                'generated': count,
                'type': attack_type
            })
        except ImportError as e:
            return jsonify({
                'success': False,
                'error': f'Attack simulator not available: {e}'
            }), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/api/connections/active')
def get_active_connections():
    """Get active network connections"""
    try:
        minutes = request.args.get('minutes', 5, type=int)
        limit = request.args.get('limit', 100, type=int)
        connections = db.get_active_connections(minutes=minutes, limit=limit)
        return jsonify({
            'connections': sanitize_json(connections),
            'count': len(connections),
            'window_minutes': minutes,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/api/alerts/history')
def get_alert_history_by_ip():
    """Get alert history for a specific source IP"""
    try:
        source_ip = request.args.get('source_ip', '', type=str)
        limit = request.args.get('limit', 50, type=int)
        if not source_ip:
            return jsonify({'error': 'source_ip is required'}), 400

        alerts = db.get_alerts_by_source_ip(source_ip=source_ip, limit=limit)
        return jsonify({
            'source_ip': source_ip,
            'alerts': sanitize_json(alerts),
            'count': len(alerts),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/api/blocklist', methods=['GET', 'POST', 'DELETE'])
def blocklist_api():
    """Manage blocked source IP list"""
    try:
        if request.method == 'GET':
            ips = db.get_blocked_ips()
            return jsonify({
                'blocked_ips': ips,
                'count': len(ips),
                'timestamp': datetime.now().isoformat()
            })

        data = request.get_json(silent=True) or {}
        ip_address = data.get('ip', '').strip()
        if not ip_address:
            return jsonify({'error': 'ip is required'}), 400

        if request.method == 'POST':
            result = db.block_ip(ip_address)
            return jsonify(result)

        result = db.unblock_ip(ip_address)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== Reports API ====================

@api.route('/api/reports/generate', methods=['POST'])
def generate_report():
    """Generate PDF report"""
    try:
        data = request.get_json(silent=True) or {}
        report_type = data.get('type', 'summary')
        
        # Get current stats for the report
        stats = db.get_stats()
        alerts = db.get_alerts(limit=50)
        predictions = db.get_predictions(limit=100)
        
        # Create a simple report summary
        report_data = {
            'generated_at': datetime.now().isoformat(),
            'report_type': report_type,
            'summary': {
                'total_connections': stats.get('total_connections', 0),
                'total_attacks_detected': stats.get('total_attacks_detected', 0),
                'normal_percentage': stats.get('normal_percentage', 100),
                'total_alerts': len(alerts),
                'total_predictions': len(predictions)
            },
            'message': 'Report generated successfully. PDF export coming soon!'
        }
        
        return jsonify({
            'success': True,
            'report': report_data
        })
    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500


@api.route('/api/reports/list')
def list_reports():
    """List available reports"""
    try:
        # Placeholder for report listing
        return jsonify({
            'reports': [],
            'count': 0
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== System API ====================

@api.route('/api/system/status')
def system_status():
    """Get system status"""
    try:
        state = db.get_system_state()
        stats = db.get_stats()
        
        return jsonify({
            'monitoring_active': state.get('monitoring_active', False),
            'ml_models_loaded': state.get('ml_models_loaded', False),
            'last_prediction_time': state.get('last_prediction_time'),
            'uptime': stats.get('monitoring_start_time'),
            'total_connections': stats.get('total_connections', 0),
            'total_attacks_detected': stats.get('total_attacks_detected', 0)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/api/system/start', methods=['POST'])
def start_system():
    """Start monitoring system"""
    try:
        db.start_monitoring()
        return jsonify({
            'success': True,
            'message': 'Monitoring started'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/api/system/stop', methods=['POST'])
def stop_system():
    """Stop monitoring system"""
    try:
        db.stop_monitoring()
        return jsonify({
            'success': True,
            'message': 'Monitoring stopped'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.route('/api/system/settings', methods=['GET', 'POST'])
def system_settings():
    """Get or update system settings"""
    try:
        if request.method == 'GET':
            return jsonify({
                'vnc_port_start': Config.VNC_PORT_START,
                'vnc_port_end': Config.VNC_PORT_END,
                'monitoring_interval': Config.MONITORING_INTERVAL,
                'max_alerts': Config.MAX_ALERTS
            })
        else:
            # Update settings (placeholder)
            data = request.get_json()
            return jsonify({
                'success': True,
                'message': 'Settings updated'
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== Statistics API ====================

@api.route('/api/stats')
def get_stats():
    """Get all statistics"""
    try:
        stats = db.get_stats()
        predictions = db.get_predictions(limit=100)
        alerts = db.get_alerts(limit=100)
        
        # Calculate threat levels for distribution chart
        threat_levels = {
            'safe': 0,
            'suspicious': 0,
            'danger': 0
        }
        
        for pred in predictions:
            pred_raw = pred.get('prediction', 'SAFE')
            pred_result = str(pred_raw).upper()
            
            if pred_result in ['SAFE', 'NORMAL']:
                threat_levels['safe'] += 1
            elif pred_result == 'SUSPICIOUS':
                threat_levels['suspicious'] += 1
            elif pred_result in ['DANGER', 'DOS', 'DDOS', 'MALWARE', 'PORTSCAN']:
                threat_levels['danger'] += 1
            else:
                # Any unknown/attack labels count as danger
                threat_levels['danger'] += 1
        
        # Calculate attack type distribution (matching charts.js expected keys)
        attack_types = {
            'DoS': 0,
            'PortScan': 0,
            'Malware': 0,
            'DDoS': 0,
            'Other': 0
        }
        
        for alert in alerts:
            alert_type = alert.get('type', 'Normal')
            if alert_type in attack_types:
                attack_types[alert_type] += 1
            elif alert_type not in ['Normal', 'system', 'normal']:
                attack_types['Other'] += 1
        
        return jsonify({
            **stats,
            'total_alerts': len([a for a in alerts if a.get('severity') in ['danger', 'warning']]),
            'threat_levels': threat_levels,
            'attack_distribution': attack_types
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== Health Check ====================

@api.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })
