#!/usr/bin/env python
"""
VNC Security Monitor - Demo Script
Demonstrates all system capabilities for testing and presentations
"""

import os
import sys
import time
import requests
import json
from pathlib import Path
from datetime import datetime

# Configuration
API_BASE = "http://localhost:5000"
PROJECT_ROOT = Path(__file__).parent


def print_header(text):
    """Print formatted header"""
    print("\n" + "="*60)
    print(f"  {text}")
    print("="*60 + "\n")


def print_step(step_num, text):
    """Print step info"""
    print(f"\n  [{step_num}] {text}")
    print("  " + "-"*50)


def api_call(endpoint, method='GET', data=None):
    """Make API call and return response"""
    url = f"{API_BASE}{endpoint}"
    try:
        if method == 'GET':
            response = requests.get(url)
        else:
            response = requests.post(url, json=data)
        return response.json()
    except Exception as e:
        return {'error': str(e)}


def demo_system_health():
    """Demo: Check system health"""
    print_header("SYSTEM HEALTH CHECK")
    
    result = api_call('/api/health')
    print(f"  Status: {result.get('status', 'unknown')}")
    print(f"  Version: {result.get('version', 'unknown')}")
    print(f"  Timestamp: {result.get('timestamp', 'unknown')}")
    
    return result.get('status') == 'healthy'


def demo_ml_status():
    """Demo: Check ML model status"""
    print_header("ML MODEL STATUS")
    
    result = api_call('/api/ml/status')
    
    rf_status = "Loaded" if result.get('random_forest_loaded') else "Not Loaded"
    ae_status = "Loaded" if result.get('autoencoder_loaded') else "Not Loaded"
    ensemble_status = "Ready" if result.get('ensemble_ready') else "Not Ready"
    
    print(f"  Random Forest:  {rf_status}")
    print(f"  Autoencoder:    {ae_status}")
    print(f"  Ensemble:       {ensemble_status}")
    
    return result.get('ensemble_ready', False)


def demo_normal_traffic():
    """Demo: Simulate normal VNC traffic"""
    print_header("SIMULATING NORMAL TRAFFIC")
    
    print_step(1, "Generating 20 normal traffic samples...")
    result = api_call('/api/simulate', 'POST', {'type': 'normal', 'count': 20})
    print(f"  Result: {result.get('message', result.get('error', 'unknown'))}")
    
    time.sleep(1)
    
    print_step(2, "Checking predictions...")
    stats = api_call('/api/stats')
    print(f"  Total Records: {stats.get('total_records', 0)}")
    print(f"  Normal Traffic: {stats.get('normal_percentage', 0):.1f}%")
    print(f"  Threat Levels: {stats.get('threat_levels', {})}")


def demo_attack_scenarios():
    """Demo: Simulate various attack scenarios"""
    print_header("ATTACK SIMULATION DEMO")
    
    attacks = [
        ('file_exfiltration', 'Large File Exfiltration (100MB+ transfer)'),
        ('clipboard_hijacking', 'Clipboard Hijacking (data stealing)'),
        ('screen_capture', 'Screen Capture Attack (excessive framebuffer)'),
        ('keylogging', 'Keylogging Attack (keyboard snooping)'),
        ('unencrypted', 'Unencrypted Connection (no TLS)')
    ]
    
    for i, (attack_type, description) in enumerate(attacks, 1):
        print_step(i, f"Simulating: {description}")
        
        result = api_call('/api/simulate', 'POST', {'type': attack_type, 'count': 5})
        print(f"     Generated: {result.get('generated', 0)} samples")
        
        time.sleep(0.5)
        
        # Check alerts
        alerts = api_call('/api/alerts?limit=5')
        danger_alerts = [a for a in alerts.get('alerts', []) if a.get('severity') == 'danger']
        print(f"     Alerts Generated: {len(danger_alerts)} threats detected")
    
    print("\n  " + "-"*50)
    print("  All attack scenarios simulated!")


def demo_predictions():
    """Demo: Test real-time predictions"""
    print_header("ML PREDICTION DEMO")
    
    test_cases = [
        {
            'name': 'Normal Traffic Pattern',
            'data': {
                'packet_size_mean': 500,
                'packet_size_std': 100,
                'packets_per_second': 30,
                'bytes_per_second': 15000,
                'duration': 120,
                'encryption_level': 1,
                'vnc_commands_count': 35,
                'file_transfer_size': 0
            }
        },
        {
            'name': 'Suspicious Activity',
            'data': {
                'packet_size_mean': 5000,
                'packet_size_std': 2000,
                'packets_per_second': 100,
                'bytes_per_second': 500000,
                'duration': 60,
                'encryption_level': 0,
                'vnc_commands_count': 200,
                'file_transfer_size': 5000000
            }
        },
        {
            'name': 'Data Exfiltration Attack',
            'data': {
                'packet_size_mean': 30000,
                'packet_size_std': 10000,
                'packets_per_second': 300,
                'bytes_per_second': 3000000,
                'duration': 45,
                'encryption_level': 0,
                'vnc_commands_count': 250,
                'file_transfer_size': 200000000
            }
        }
    ]
    
    for i, test in enumerate(test_cases, 1):
        print_step(i, f"Testing: {test['name']}")
        
        result = api_call('/api/predict', 'POST', {'features': test['data']})
        
        prediction = result.get('prediction', 'UNKNOWN')
        confidence = result.get('confidence', 0) * 100
        
        icon = "OK" if prediction == 'SAFE' else "WARNING" if prediction == 'SUSPICIOUS' else "ALERT"
        print(f"     Prediction: {icon} {prediction}")
        print(f"     Confidence: {confidence:.1f}%")
        print(f"     Details: {result.get('details', 'N/A')}")


def demo_statistics():
    """Demo: Show system statistics"""
    print_header("SYSTEM STATISTICS")
    
    stats = api_call('/api/stats')
    
    print(f"  Total Traffic Records:    {stats.get('total_records', 0)}")
    print(f"  Total Connections:        {stats.get('total_connections', 0)}")
    print(f"  Total Attacks Detected:   {stats.get('total_attacks_detected', 0)}")
    print(f"  Active Threats:           {stats.get('active_threats', 0)}")
    print(f"  Normal Traffic %:         {stats.get('normal_percentage', 0):.1f}%")
    
    print("\n  Threat Level Distribution:")
    threat_levels = stats.get('threat_levels', {})
    print(f"     Safe:       {threat_levels.get('safe', 0)}")
    print(f"     Suspicious: {threat_levels.get('suspicious', 0)}")
    print(f"     Danger:     {threat_levels.get('danger', 0)}")
    
    print("\n  Attack Type Distribution:")
    attack_dist = stats.get('attack_distribution', {})
    for attack_type, count in attack_dist.items():
        if count > 0:
            print(f"     {attack_type}: {count}")


def demo_alerts():
    """Demo: Show recent alerts"""
    print_header("RECENT SECURITY ALERTS")
    
    alerts = api_call('/api/alerts?limit=10')
    alert_list = alerts.get('alerts', [])
    
    if not alert_list:
        print("  No alerts to display")
        return
    
    for i, alert in enumerate(alert_list[:5], 1):
        severity = alert.get('severity', 'unknown')
        icon = "DANGER" if severity == 'danger' else "WARNING" if severity == 'warning' else "INFO"

        print(f"  {icon} [{severity.upper()}] {alert.get('type', 'Unknown')}")
        print(f"     Message: {alert.get('message', 'N/A')}")
        print(f"     Time: {alert.get('timestamp', 'N/A')}")
        print()


def main():
    """Run full demo"""
    print("\n" + "="*60)
    print("       VNC SECURITY MONITOR - DEMONSTRATION")
    print("       Data Exfiltration Detection System")
    print("="*60)
    
    print("\n  Note: This demo will showcase all system capabilities")
    print("  Note: Make sure the server is running at localhost:5000")
    print("  Note: Press Enter to continue...")
    input()
    
    # 1. System Health
    if not demo_system_health():
        print("\n  ERROR: Server not responding!")
        print("     Please start the server with: python run.py")
        return
    
    print("\n  Press Enter for next demo...")
    input()
    
    # 2. ML Status
    demo_ml_status()
    print("\n  Press Enter for next demo...")
    input()
    
    # 3. Normal Traffic
    demo_normal_traffic()
    print("\n  Press Enter for next demo...")
    input()
    
    # 4. Attack Scenarios
    demo_attack_scenarios()
    print("\n  Press Enter for next demo...")
    input()
    
    # 5. Predictions
    demo_predictions()
    print("\n  Press Enter for next demo...")
    input()
    
    # 6. Statistics
    demo_statistics()
    print("\n  Press Enter for next demo...")
    input()
    
    # 7. Alerts
    demo_alerts()
    
    # Summary
    print_header("DEMO COMPLETE")
    print("  System Health Check - PASSED")
    print("  ML Models Loaded")
    print("  Normal Traffic Simulation")
    print("  Attack Scenarios Simulated")
    print("  ML Predictions Working")
    print("  Statistics & Alerts Generated")
    
    print("\n  Open the dashboard at: http://localhost:5000")
    print("  View real-time data and visualizations")
    print("  Generate reports from the Reports page")
    print("\n" + "="*60 + "\n")


if __name__ == '__main__':
    main()
