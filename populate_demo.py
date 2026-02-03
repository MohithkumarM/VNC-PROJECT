#!/usr/bin/env python3
"""
Quick Demo Data Populator
Adds sample traffic and attacks to demonstrate the dashboard
"""

import requests
import time
import sys

BASE_URL = "http://localhost:5000"

def print_status(msg, status="info"):
    symbols = {"info": "INFO", "success": "OK", "error": "ERROR", "attack": "ALERT"}
    print(f"{symbols.get(status, 'INFO')} {msg}")

def check_server():
    """Check if server is running"""
    try:
        r = requests.get(f"{BASE_URL}/api/health", timeout=5)
        return r.status_code == 200
    except:
        return False

def simulate_traffic(traffic_type, count):
    """Simulate traffic via API"""
    try:
        r = requests.post(
            f"{BASE_URL}/api/simulate",
            json={"type": traffic_type, "count": count},
            timeout=30
        )
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def get_stats():
    """Get current stats"""
    try:
        r = requests.get(f"{BASE_URL}/api/stats", timeout=5)
        return r.json()
    except:
        return {}

def main():
    print("\n" + "="*50)
    print("   VNC Security Monitor - Demo Populator")
    print("="*50 + "\n")
    
    # Check server
    print_status("Checking server connection...")
    if not check_server():
        print_status("Server not running! Start it with: python run.py", "error")
        sys.exit(1)
    print_status("Server is online!", "success")
    
    # Step 1: Add normal traffic
    print("\n" + "-"*40)
    print_status("Step 1: Generating normal VNC traffic...")
    result = simulate_traffic("Normal", 40)
    if "error" not in result:
        print_status(f"Added {result.get('generated', 40)} normal connections", "success")
    else:
        print_status(f"Error: {result.get('error')}", "error")
    time.sleep(1)
    
    # Step 2: Add DoS attacks
    print("\n" + "-"*40)
    print_status("Step 2: Simulating DoS attacks...", "attack")
    result = simulate_traffic("DoS", 8)
    if "error" not in result:
        print_status(f"Simulated {result.get('generated', 8)} DoS attack attempts", "success")
    else:
        print_status(f"Error: {result.get('error')}", "error")
    time.sleep(1)
    
    # Step 3: Add PortScan attacks
    print("\n" + "-"*40)
    print_status("Step 3: Simulating PortScan attacks...", "attack")
    result = simulate_traffic("PortScan", 5)
    if "error" not in result:
        print_status(f"Simulated {result.get('generated', 5)} PortScan attempts", "success")
    else:
        print_status(f"Error: {result.get('error')}", "error")
    time.sleep(1)
    
    # Step 4: Add DDoS attacks
    print("\n" + "-"*40)
    print_status("Step 4: Adding DDoS attack traffic...", "attack")
    result = simulate_traffic("DDoS", 10)
    if "error" not in result:
        print_status(f"Added {result.get('generated', 10)} DDoS attack samples", "success")
    else:
        print_status(f"Error: {result.get('error')}", "error")
    
    # Show final stats
    print("\n" + "="*50)
    print("   DASHBOARD SUMMARY")
    print("="*50)
    
    stats = get_stats()
    print(f"""
    Total Connections:   {stats.get('total_connections', 'N/A')}
    Active Threats:      {stats.get('active_threats', 'N/A')}
    Normal Traffic:      {stats.get('normal_percentage', 'N/A'):.1f}%
    Alerts Generated:    {stats.get('total_alerts', 'N/A')}
    """)
    
    print("="*50)
    print_status("Demo data populated! Refresh your browser to see the dashboard.", "success")
    print(f"\nOpen: {BASE_URL}\n")

if __name__ == "__main__":
    main()
