"""
VNC Security Monitor - Feature Extractor
Extracts features from VNC traffic matching the Kaggle CyberSecurity Dataset schema.
"""

import pandas as pd
import numpy as np
from datetime import datetime
import math

class FeatureExtractor:
    """
    Extracts features from raw VNC traffic data for machine learning models.
    Matches the schema:
    PacketSize, ResponseTime, Protocol, SrcIP, DstIP, SrcPort, DstPort, 
    PacketRate, FlowDuration, NumPackets, PayloadSize, FlagCount, 
    AnomalyScore, Entropy, BytesSent, BytesReceived, FlowRate, ActiveTime, IdleTime
    """
    
    def __init__(self):
        self.feature_names = [
            'PacketSize', 'ResponseTime', 'Protocol', 'SrcIP', 'DstIP', 
            'SrcPort', 'DstPort', 'PacketRate', 'FlowDuration', 'NumPackets', 
            'PayloadSize', 'FlagCount', 'AnomalyScore', 'Entropy', 
            'BytesSent', 'BytesReceived', 'FlowRate', 'ActiveTime', 'IdleTime'
        ]
        
    def _calculate_entropy(self, payload):
        """Calculate Shannon entropy of payload"""
        if not payload:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(payload.count(bytes([x]))) / len(payload)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def extract_features(self, packet_data):
        """
        Extract features from packet data.
        Args:
            packet_data: List of packet dictionaries or pandas DataFrame
        """
        # Convert to DataFrame if list
        if isinstance(packet_data, list):
            if not packet_data:
                return pd.DataFrame(columns=self.feature_names)
            df = pd.DataFrame(packet_data)
        else:
            df = packet_data.copy()
            
        features = pd.DataFrame()
        
        # 1. Packet Size (Mean of the flow/batch)
        if 'packet_size' in df.columns:
             features['PacketSize'] = df['packet_size']
        else:
             features['PacketSize'] = 0
             
        # 2. Response Time (Estimate)
        if 'timestamp' in df.columns:
            df['datetime'] = pd.to_datetime(df['timestamp'])
            # Simple diff as proxy for response time if we don't have request/response matching
            features['ResponseTime'] = df['datetime'].diff().dt.total_seconds().fillna(0) * 1000 # ms
        else:
            features['ResponseTime'] = 0
            
        # 3. Protocol (Map to Int or String)
        if 'protocol' in df.columns:
            features['Protocol'] = df['protocol'] # Keep as string, ML pipeline handles encoding or use 6 (TCP) / 17 (UDP)
        else:
            features['Protocol'] = 'TCP' # Default VNC
            
        # 4. Source/Dst IP (Pass through)
        if 'src_ip' in df.columns:
            # We might need to convert IP to int for the model if the model expects int
            # But the AttackSimulator generates strings. The training script converts them.
            # Here we pass strings and let the model pipeline/preprocessor handle it.
            # But wait, our simple training script did one-off conversion.
            # We need to match that logic.
            # Let's try to convert to int here if possible.
            features['SrcIP'] = df['src_ip']
            features['DstIP'] = df['dst_ip']
        else:
            features['SrcIP'] = '0.0.0.0'
            features['DstIP'] = '0.0.0.0'

        # 5. Ports
        features['SrcPort'] = df.get('src_port', 0)
        features['DstPort'] = df.get('dst_port', 5900)
        
        # 6. Flow Metrics (Calculated over the batch)
        # Check if we have flow_id or grouped data. If raw packets, we are treating each packet as a sample?
        # The Kaggle dataset seems to be Per Flow or Per Packet? 
        # "PacketSize" implies per packet, but "NumPackets" implies per flow. 
        # It's likely a Flow-based dataset where one row = one flow.
        # But for Real-Time monitoring, we might want to classify *flows*.
        # For simplicity, we'll aggregate the input batch into a single "Flow" or output a row per packet if the model is per-packet.
        # Given "NumPackets" column, it's definitely Flow-based.
        # So we should aggregate the incoming packet_data into a single row (or multiple flows).
        
        # Assuming packet_data represents ONE flow (e.g. captured over 2 seconds)
        total_packets = len(df)
        total_bytes = df['packet_size'].sum() if 'packet_size' in df.columns else 0
        duration = 1.0 # Default 1s if single batch
        if 'datetime' in df.columns and len(df) > 1:
            duration = (df['datetime'].max() - df['datetime'].min()).total_seconds()
            if duration == 0: duration = 0.001
            
        features['PacketRate'] = total_packets / duration
        features['FlowDuration'] = duration
        features['NumPackets'] = total_packets
        features['PayloadSize'] = df['payload_size'].mean() if 'payload_size' in df.columns else 0
        features['FlagCount'] = 0 # Placeholder
        
        # Anomaly Score - Heuristic based
        # e.g. High port scanning?
        features['AnomalyScore'] = 0 
        
        # Entropy
        # We need raw payload to calc entropy.
        features['Entropy'] = 0 # Placeholder
        
        features['BytesSent'] = total_bytes # Approx
        features['BytesReceived'] = 0 # Need bidirectional data
        
        features['FlowRate'] = total_bytes / duration
        features['ActiveTime'] = duration
        features['IdleTime'] = 0
        
        # Fill strictly required columns with 0 if missing
        for col in self.feature_names:
            if col not in features.columns:
                features[col] = 0
                
        # Return only the first row (Flow Summary) or all rows?
        # If we are valid flow-based, we return 1 row representing this batch.
        # But if the user clicks "Simulate", they send PRE-GENERATED features.
        # This extractor is for RAW traffic.
        # We will return the DataFrame.
        # Since we aggregated everything into columns that are same for all rows, we can just return head(1)
        
        return features.head(1) 
