"""
VNC Security Monitor - Attack Simulator
Simulates VNC attack scenarios matching the Kaggle CyberSecurity Dataset schema.
"""

import random
import pandas as pd
from datetime import datetime
import time
from pathlib import Path

class AttackSimulator:
    """
    Simulates:
    1. Normal
    2. PortScan
    3. DoS
    4. Malware
    5. DDoS
    """
    
    SCENARIOS = {
        'Normal': {
            'label': 'Normal',
            'PacketSize': (60, 1500),
            'ResponseTime': (1, 50),
            'PacketRate': (10, 50),
            'Entropy': (3, 5),
            'AnomalyScore': (0, 20)
        },
        'PortScan': {
            'label': 'PortScan',
            'PacketSize': (40, 60),
            'ResponseTime': (0, 10),
            'PacketRate': (1000, 5000),
            'Entropy': (1, 3),
            'AnomalyScore': (80, 100)
        },
        'DoS': {
            'label': 'DoS',
            'PacketSize': (1000, 1500),
            'ResponseTime': (100, 5000),
            'PacketRate': (5000, 20000),
            'Entropy': (5, 8),
            'AnomalyScore': (90, 100)
        },
        'DDoS': {
            'label': 'DDoS',
            'PacketSize': (60, 1500),
            'ResponseTime': (500, 10000),
            'PacketRate': (20000, 100000),
            'Entropy': (6, 9),
            'AnomalyScore': (95, 100)
        },
        'Malware': {
            'label': 'Malware',
            'PacketSize': (500, 2000),
            'ResponseTime': (20, 100),
            'PacketRate': (50, 200),
            'Entropy': (7, 10), # Encrypted/High entropy
            'AnomalyScore': (70, 95)
        }
    }
    
    def __init__(self, output_dir=None):
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = Path(__file__).parent.parent / 'data' / 'simulations'
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _generate_ip(self):
        return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    def generate_sample(self, scenario_name):
        if scenario_name not in self.SCENARIOS:
            # Fallback for unknown scenarios
            scenario_name = 'Normal'
            
        config = self.SCENARIOS[scenario_name]
        
        # Helper to get random value
        def val(key, default=(0,0)):
            r = config.get(key, default)
            return random.uniform(r[0], r[1])
            
        # Basic Stats
        packet_size = int(val('PacketSize', (60, 1500)))
        num_packets = int(val('PacketRate', (10, 1000)) * random.uniform(1, 10)) # Rough estimate
        
        sample = {
            'PacketSize': packet_size,
            'ResponseTime': val('ResponseTime', (10, 100)),
            'Protocol': random.choice(['TCP', 'UDP', 'ICMP']),
            'SrcIP': self._generate_ip(),
            'DstIP': self._generate_ip(),
            'SrcPort': random.randint(1024, 65535),
            'DstPort': 5900 if random.random() > 0.2 else random.randint(1, 65535), # Mostly VNC
            'PacketRate': val('PacketRate', (10, 100)),
            'FlowDuration': random.uniform(0.1, 600),
            'NumPackets': num_packets,
            'PayloadSize': max(0, packet_size - 40), # Valid payload
            'FlagCount': random.randint(0, 6) if config['label'] != 'PortScan' else random.randint(1, 2),
            'AnomalyScore': val('AnomalyScore', (0, 100)),
            'Entropy': val('Entropy', (0, 8)),
            'BytesSent': int(packet_size * num_packets * 0.6),
            'BytesReceived': int(packet_size * num_packets * 0.4),
            'FlowRate': val('PacketRate') * packet_size,
            'ActiveTime': random.uniform(0, 100),
            'IdleTime': random.uniform(0, 50),
            'AttackLabel': config['label']
        }
        
        return sample
    
    def simulate_scenario(self, scenario_name, count=10):
        samples = []
        for _ in range(count):
            samples.append(self.generate_sample(scenario_name))
        return pd.DataFrame(samples)

if __name__ == "__main__":
    sim = AttackSimulator()
    print("Generating Normal samples...")
    print(sim.simulate_scenario("Normal", 5).head())
