import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from collections import Counter
import time
import sys
from sklearn.model_selection import train_test_split 

from rf_scratch import DecisionTree,RandomForest,MLfuncs,StandardScaler

# --- CONSTANTS FROM YOUR DATASET GENERATOR ---
FIN_BIT = 0x01
SYN_BIT = 0x02
RST_BIT = 0x04
PSH_BIT = 0x08
ACK_BIT = 0x10
URG_BIT = 0x20
TCP_NUM = 6
UDP_NUM = 17

class LiveDetector:
    def __init__(self, model, scaler, feature_columns):
        self.model = model
        self.scaler = scaler
        self.feature_columns = feature_columns
        self.current_flows = {}

    def process_packet(self, pkt):
        """Extracts and stores packet data in flows (similar to your extract_features logic)."""
        if IP not in pkt:
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        timestamp = float(pkt.time)
        ttl = pkt[IP].ttl
        proto_number = pkt[IP].proto

        key = (src_ip, dst_ip)
        if key not in self.current_flows:
            self.current_flows[key] = {
                'start_time': timestamp,
                'packets': [],
                'ttls': [],
                'protocols': [],
                'dst_ports': set()
            }

        data = self.current_flows[key]
        data['packets'].append(pkt)
        data['ttls'].append(ttl)
        data['protocols'].append(proto_number)

        if proto_number == TCP_NUM and TCP in pkt:
            data['dst_ports'].add(pkt[TCP].dport)
        elif proto_number == UDP_NUM and UDP in pkt:
            data['dst_ports'].add(pkt[UDP].dport)

    def analyze_current_flows(self):
        """Converts collected flows into a DataFrame and predicts anomalies."""
        if not self.current_flows:
            return

        feature_list = []
        for (src_ip, dst_ip), data in self.current_flows.items():
            pkt_count = len(data['packets'])
            duration = data['packets'][-1].time - data['packets'][0].time
            ttls = data['ttls']
            protocols = data['protocols']
            most_common_proto = Counter(protocols).most_common(1)[0][0]

            row = {
                'Packet_Count': pkt_count,
                'Duration_sec': float(duration) if duration > 0 else 0.001,
                'Num_Distinct_Dst_Ports': len(data['dst_ports']),
                'Mean_TTL': np.mean(ttls),
                'StdDev_TTL': np.std(ttls) if len(ttls) > 1 else 0,
                'Initial_TTL': ttls[0],
                'Protocol_Diversity': len(set(protocols)),
                'Primary_Protocol_Code': most_common_proto,
                'SYN_Ratio': 0.0, 'ACK_Ratio': 0.0, 'FIN_Ratio': 0.0, 
                'RST_Ratio': 0.0, 'PSH_Ratio': 0.0, 'URG_Ratio': 0.0, 
                'NULL_Ratio': 0.0, 'SynAck_Ratio': 0.0,
                'UDP_Packet_Count': 0.0, 'UDP_Payload_Avg': 0.0
            }

            # Protocol-specific logic matching your dataset creator
            if most_common_proto == TCP_NUM:
                row['SYN_Ratio'] = sum(1 for p in data['packets'] if TCP in p and int(p[TCP].flags) & SYN_BIT) / pkt_count
                row['ACK_Ratio'] = sum(1 for p in data['packets'] if TCP in p and int(p[TCP].flags) & ACK_BIT) / pkt_count
                # ... [Repeat for other flags as per your logic] ...

            # Convert to DataFrame to handle One-Hot Encoding (Protocols)
            df_row = pd.DataFrame([row])
            
            # Match the One-Hot Encoding format from training
            for col in self.feature_columns:
                if col.startswith("Protocol_") and col not in df_row.columns:
                    # Check if this row matches the specific protocol code column
                    proto_code = col.split('_')[-1]
                    df_row[col] = 1 if str(row['Primary_Protocol_Code']) == proto_code else 0
            
            # Remove the raw code before scaling
            if 'Primary_Protocol_Code' in df_row.columns:
                df_row = df_row.drop(columns=['Primary_Protocol_Code'])

            # Ensure column order matches the model training
            df_row = df_row.reindex(columns=self.feature_columns, fill_value=0)
            
            # Predict
            scaled_data = self.scaler.transform(df_row.values)
            prediction = self.model.predict(scaled_data)

            if prediction[0] == 1:
                print(f"[!] ANOMALY DETECTED: {src_ip} -> {dst_ip} | Type: Port Scan Pattern")
            else:
                #print(f"[+] Normal Traffic: {src_ip} -> {dst_ip}")
                print("")
        # Clear flows after analysis to start fresh for the next window
        self.current_flows = {}

def main():
    # 1. SETUP & TRAIN (Same as your original code)
    df = pd.read_csv("port_scan_dataset.csv")
    X = df.drop('Label', axis=1)
    y = df['Label']
    feature_names = X.columns.tolist() # Keep track of exact column order

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    rf = RandomForest(n_trees=20, max_depth=8)
    rf.fit(X_train_scaled, y_train)
    print("Model trained and ready for live capture.")

    # 2. INITIALIZE DETECTOR
    detector = LiveDetector(rf, scaler, feature_names)

    # 3. SNIFFING LOOP
    print("Starting Sniffer (Capturing in 5-second windows)...")
    try:
        while True:
            # Capture packets for 5 seconds
            sniff(prn=detector.process_packet, timeout=5, store=0)
            # Run prediction on the collected flows
            detector.analyze_current_flows()
    except KeyboardInterrupt:
        print("\nStopping detector...")
        sys.exit()

if __name__ == "__main__":
    main()