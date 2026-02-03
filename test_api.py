"""Quick test for API endpoints"""
import requests
import json

BASE_URL = "http://localhost:5000"

# Test Prediction
print("=" * 50)
print("Testing /api/predict endpoint...")
print("=" * 50)

test_features = {
    'PacketSize': 500,
    'ResponseTime': 20,
    'Protocol': 'TCP',
    'SrcIP': '192.168.1.50',
    'DstIP': '10.0.0.5',
    'SrcPort': 443,
    'DstPort': 5900,
    'PacketRate': 50,
    'FlowDuration': 5,
    'NumPackets': 20,
    'PayloadSize': 100,
    'FlagCount': 0,
    'AnomalyScore': 0,
    'Entropy': 0.5,
    'BytesSent': 500,
    'BytesReceived': 500,
    'FlowRate': 100,
    'ActiveTime': 1,
    'IdleTime': 0
}

try:
    r = requests.post(f"{BASE_URL}/api/predict", json=test_features, timeout=10)
    print(f"Status: {r.status_code}")
    print(f"Response:\n{json.dumps(r.json(), indent=2)}")
except Exception as e:
    print(f"Error: {e}")

# Test Report Generation
print("\n" + "=" * 50)
print("Testing /api/reports/generate endpoint...")
print("=" * 50)

try:
    r = requests.post(f"{BASE_URL}/api/reports/generate", json={}, timeout=10)
    print(f"Status: {r.status_code}")
    print(f"Response:\n{json.dumps(r.json(), indent=2)}")
except Exception as e:
    print(f"Error: {e}")

print("\nTests completed!")
