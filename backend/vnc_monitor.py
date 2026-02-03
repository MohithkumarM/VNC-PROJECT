"""
VNC Security Monitor - VNC Traffic Monitor
Monitors VNC network traffic on ports 5900-5910
"""

import os
import sys
import time
import threading
import csv
from datetime import datetime
from pathlib import Path
from collections import deque

# Try to import scapy (optional for basic demo)
try:
    from scapy.all import sniff, IP, TCP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Using simulated traffic capture.")

# Try to import psutil for network stats
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class VNCTrafficMonitor:
    """
    Monitors VNC traffic on specified ports.
    Captures packets and extracts features for ML analysis.
    """
    
    def __init__(self, port_start=5900, port_end=5910, data_dir=None):
        self.port_start = port_start
        self.port_end = port_end
        self.vnc_ports = list(range(port_start, port_end + 1))
        
        # Data storage
        self.data_dir = Path(data_dir) if data_dir else Path(__file__).parent.parent / 'data' / 'raw'
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Monitoring state
        self.is_monitoring = False
        self.monitor_thread = None
        self.packet_buffer = deque(maxlen=1000)
        
        # Statistics
        self.stats = {
            'packets_captured': 0,
            'bytes_captured': 0,
            'connections': {},
            'start_time': None
        }
        
        # Callback for new data
        self.on_packet_callback = None
        
        # Lock for thread safety
        self._lock = threading.Lock()
    
    def start(self, callback=None):
        """Start monitoring VNC traffic"""
        if self.is_monitoring:
            return False
        
        self.is_monitoring = True
        self.on_packet_callback = callback
        self.stats['start_time'] = datetime.now()
        
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True
        )
        self.monitor_thread.start()
        
        print(f"[*] VNC Traffic Monitor started on ports {self.port_start}-{self.port_end}")
        return True
    
    def stop(self):
        """Stop monitoring"""
        self.is_monitoring = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        print("[*] VNC Traffic Monitor stopped")
        return True
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        if SCAPY_AVAILABLE:
            self._scapy_capture()
        else:
            self._simulated_capture()
    
    def _scapy_capture(self):
        """Capture packets using Scapy"""
        # Build filter for VNC ports
        port_filter = " or ".join([f"port {p}" for p in self.vnc_ports])
        bpf_filter = f"tcp and ({port_filter})"
        
        try:
            sniff(
                filter=bpf_filter,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.is_monitoring
            )
        except Exception as e:
            print(f"[!] Scapy capture error: {e}")
            print("[*] Falling back to simulated capture")
            self._simulated_capture()
    
    def _simulated_capture(self):
        """Simulated capture for demo/testing"""
        import random
        
        while self.is_monitoring:
            # Generate simulated packet data
            packet_data = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': f"192.168.1.{random.randint(1, 254)}",
                'dst_ip': f"192.168.1.{random.randint(1, 254)}",
                'src_port': random.choice(self.vnc_ports + list(range(49152, 65535))),
                'dst_port': random.choice(self.vnc_ports),
                'protocol': 'TCP',
                'packet_size': random.randint(64, 1500),
                'flags': random.choice(['SYN', 'ACK', 'PSH', 'FIN', 'PSH-ACK']),
                'payload_size': random.randint(0, 1400)
            }
            
            self._add_packet(packet_data)
            
            # Random delay between packets
            time.sleep(random.uniform(0.1, 0.5))
    
    def _process_packet(self, packet):
        """Process a captured packet"""
        try:
            if IP in packet and TCP in packet:
                packet_data = {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'src_port': packet[TCP].sport,
                    'dst_port': packet[TCP].dport,
                    'protocol': 'TCP',
                    'packet_size': len(packet),
                    'flags': str(packet[TCP].flags),
                    'payload_size': len(packet[Raw].load) if Raw in packet else 0
                }
                
                self._add_packet(packet_data)
                
        except Exception as e:
            pass  # Silently ignore malformed packets
    
    def _add_packet(self, packet_data):
        """Add packet to buffer and update stats"""
        with self._lock:
            self.packet_buffer.append(packet_data)
            self.stats['packets_captured'] += 1
            self.stats['bytes_captured'] += packet_data.get('packet_size', 0)
            
            # Track connection
            conn_key = f"{packet_data['src_ip']}:{packet_data['src_port']}-{packet_data['dst_ip']}:{packet_data['dst_port']}"
            if conn_key not in self.stats['connections']:
                self.stats['connections'][conn_key] = {
                    'packet_count': 0,
                    'bytes': 0,
                    'first_seen': packet_data['timestamp'],
                    'last_seen': packet_data['timestamp']
                }
            
            self.stats['connections'][conn_key]['packet_count'] += 1
            self.stats['connections'][conn_key]['bytes'] += packet_data.get('packet_size', 0)
            self.stats['connections'][conn_key]['last_seen'] = packet_data['timestamp']
        
        # Call callback if set
        if self.on_packet_callback:
            self.on_packet_callback(packet_data)
    
    def get_packets(self, count=None):
        """Get captured packets"""
        with self._lock:
            packets = list(self.packet_buffer)
            if count:
                packets = packets[-count:]
            return packets
    
    def get_stats(self):
        """Get monitoring statistics"""
        with self._lock:
            return {
                'packets_captured': self.stats['packets_captured'],
                'bytes_captured': self.stats['bytes_captured'],
                'active_connections': len(self.stats['connections']),
                'start_time': self.stats['start_time'].isoformat() if self.stats['start_time'] else None,
                'duration': (datetime.now() - self.stats['start_time']).total_seconds() if self.stats['start_time'] else 0
            }
    
    def get_connections(self):
        """Get connection information"""
        with self._lock:
            return self.stats['connections'].copy()
    
    def save_to_csv(self, filename=None):
        """Save captured packets to CSV"""
        if filename is None:
            filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        filepath = self.data_dir / filename
        
        with self._lock:
            packets = list(self.packet_buffer)
        
        if not packets:
            return None
        
        # Write to CSV
        fieldnames = packets[0].keys()
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(packets)
        
        print(f"[*] Saved {len(packets)} packets to {filepath}")
        return str(filepath)
    
    def clear_buffer(self):
        """Clear the packet buffer"""
        with self._lock:
            self.packet_buffer.clear()
            self.stats['connections'].clear()
    
    def get_network_interfaces(self):
        """Get available network interfaces"""
        if PSUTIL_AVAILABLE:
            interfaces = []
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family.name == 'AF_INET':
                        interfaces.append({
                            'name': name,
                            'ip': addr.address
                        })
            return interfaces
        return []


# Global monitor instance
vnc_monitor = VNCTrafficMonitor()


if __name__ == "__main__":
    # Test the monitor
    print("Testing VNC Traffic Monitor...")
    
    def packet_callback(packet):
        print(f"Captured: {packet['src_ip']}:{packet['src_port']} -> {packet['dst_ip']}:{packet['dst_port']}")
    
    vnc_monitor.start(callback=packet_callback)
    
    try:
        time.sleep(10)  # Monitor for 10 seconds
    except KeyboardInterrupt:
        pass
    
    vnc_monitor.stop()
    
    print("\nStatistics:")
    print(vnc_monitor.get_stats())
    
    # Save to CSV
    vnc_monitor.save_to_csv()
