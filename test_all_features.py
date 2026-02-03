"""
Comprehensive Feature Test for VNC Security Monitor
Tests all API endpoints and features
"""
import requests
import time

BASE_URL = "http://localhost:5000"


def test_endpoint(name, method, url, data=None, expected_keys=None):
    """Test an endpoint and print results"""
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print(f"{'='*60}")
    print(f"   {method} {url}")

    try:
        if method == "GET":
            r = requests.get(url, timeout=10)
        else:
            r = requests.post(url, json=data or {}, timeout=10)

        print(f"   Status: {r.status_code}")
"""
Comprehensive Feature Test for VNC Security Monitor
Tests all API endpoints and features
"""
import requests
import time

BASE_URL = "http://localhost:5000"


def test_endpoint(name, method, url, data=None, expected_keys=None):
    """Test an endpoint and print results"""
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print(f"{'='*60}")
    print(f"   {method} {url}")

    try:
        if method == "GET":
            r = requests.get(url, timeout=10)
        else:
            r = requests.post(url, json=data or {}, timeout=10)

        print(f"   Status: {r.status_code}")

        if r.status_code == 200:
            result = r.json()
            print("   SUCCESS")

            if expected_keys:
                missing = [k for k in expected_keys if k not in result]
                if missing:
                    print(f"   Warning: Missing keys: {missing}")
                else:
                    print("   All expected keys present")

            if isinstance(result, dict):
                for key, value in list(result.items())[:5]:
                    val_str = str(value)[:80] + "..." if len(str(value)) > 80 else str(value)
                    print(f"      {key}: {val_str}")
            elif isinstance(result, list):
                print(f"      Returned {len(result)} items")
                if result:
                    print(
                        f"      First item keys: {list(result[0].keys()) if isinstance(result[0], dict) else 'N/A'}"
                    )

            return True, result

        print(f"   FAILED - Status {r.status_code}")
        print(f"   Response: {r.text[:200]}")
        return False, None

    except Exception as e:
        print(f"   ERROR: {e}")
        return False, None


def main():
    print("\n" + "-" * 60)
    print("   VNC SECURITY MONITOR - COMPREHENSIVE FEATURE TEST")
    print("-" * 60)

    results = {}

    print("\nWaiting for server to be ready...")
    time.sleep(2)

    results['health'], _ = test_endpoint(
        "Health Check",
        "GET",
        f"{BASE_URL}/api/health",
        expected_keys=['status', 'timestamp']
    )

    results['ml_status'], _ = test_endpoint(
        "ML Models Status",
        "GET",
        f"{BASE_URL}/api/ml/status",
        expected_keys=['ensemble_ready', 'models_loaded']
    )

    results['stats'], _ = test_endpoint(
        "Dashboard Statistics",
        "GET",
        f"{BASE_URL}/api/stats",
        expected_keys=['total_connections', 'threat_level', 'attack_distribution']
    )

    results['traffic'], _ = test_endpoint(
        "Traffic Data",
        "GET",
        f"{BASE_URL}/api/traffic?limit=10"
    )

    results['alerts'], _ = test_endpoint(
        "Alerts List",
        "GET",
        f"{BASE_URL}/api/alerts?limit=10"
    )

    results['simulate_normal'], _ = test_endpoint(
        "Simulate Normal Traffic",
        "POST",
        f"{BASE_URL}/api/simulate",
        data={'attack_type': 'Normal'}
    )

    results['simulate_attack'], _ = test_endpoint(
        "Simulate DoS Attack",
        "POST",
        f"{BASE_URL}/api/simulate",
        data={'attack_type': 'DoS'}
    )

    results['simulate_portscan'], _ = test_endpoint(
        "Simulate Port Scan Attack",
        "POST",
        f"{BASE_URL}/api/simulate",
        data={'attack_type': 'PortScan'}
    )

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

    results['predict'], _ = test_endpoint(
        "ML Prediction (Test Features)",
        "POST",
        f"{BASE_URL}/api/predict",
        data=test_features,
        expected_keys=['prediction', 'confidence']
    )

    attack_features = test_features.copy()
    attack_features['PacketRate'] = 5000
    attack_features['NumPackets'] = 10000
    attack_features['AnomalyScore'] = 0.9

    results['predict_attack'], _ = test_endpoint(
        "ML Prediction (Attack-like Features)",
        "POST",
        f"{BASE_URL}/api/predict",
        data=attack_features,
        expected_keys=['prediction', 'confidence']
    )

    results['report'], _ = test_endpoint(
        "Generate Report",
        "POST",
        f"{BASE_URL}/api/reports/generate",
        data={},
        expected_keys=['success', 'report']
    )

    results['ml_reload'], _ = test_endpoint(
        "Reload ML Models",
        "POST",
        f"{BASE_URL}/api/ml/reload",
        expected_keys=['success', 'status']
    )

    print("\n" + "=" * 60)
    print("VERIFYING DATA AFTER SIMULATIONS")
    print("=" * 60)

    r = requests.get(f"{BASE_URL}/api/stats")
    if r.status_code == 200:
        new_stats = r.json()
        print(f"   Total Connections: {new_stats.get('total_connections', 0)}")
        print(f"   Threat Level: {new_stats.get('threat_level', 'N/A')}")
        print(f"   Safe/Danger: {new_stats.get('safe_count', 0)}/{new_stats.get('danger_count', 0)}")
        print(f"   Attack Distribution: {new_stats.get('attack_distribution', {})}")

    r = requests.get(f"{BASE_URL}/api/alerts?limit=5")
    if r.status_code == 200:
        alerts = r.json()
        print(f"\n   Recent Alerts ({len(alerts)}):")
        for alert in alerts[:3]:
            print(
                f"      - [{alert.get('severity', 'N/A')}] {alert.get('type', 'N/A')}: {alert.get('message', 'N/A')[:50]}..."
            )

    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for name, result in results.items():
        status = "PASS" if result else "FAIL"
        print(f"   {status} - {name}")

    print(f"\n   {'='*40}")
    print(f"   Total: {passed}/{total} tests passed ({100*passed//total}%)")
    print(f"   {'='*40}")

    if passed == total:
        print("\n   ALL TESTS PASSED")
    else:
        print(f"\n   {total - passed} test(s) failed")

    return passed == total


if __name__ == "__main__":
    main()
    print("\n" + "-" * 30 + "\n")
