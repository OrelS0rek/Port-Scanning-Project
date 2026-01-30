import pandas as pd
import scapy.all as sc
from scapy.all import IP, TCP, UDP
import numpy as np
import os
from collections import Counter

FIN_BIT = 0x01
SYN_BIT = 0x02
RST_BIT = 0x04
PSH_BIT = 0x08
ACK_BIT = 0x10
URG_BIT = 0x20

TCP_NUM = 6
UDP_NUM = 17
ICMP_NUM = 1 

def safe_extract(pkt, layer, field):
    if layer in pkt:
        return pkt[layer].getfieldval(field)
    return None

def extract_features(pcap_file):
    try:
        packets = sc.rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"Error: PCAP file not found at {pcap_file}")
        return pd.DataFrame()
    except Exception as e:
        print(f"Error reading PCAP file {pcap_file}: {e}")
        return pd.DataFrame()

    flows = {}

    for pkt in packets:
        if IP not in pkt:
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        timestamp = float(pkt.time)
        ttl = pkt[IP].ttl
        proto_number = pkt[IP].proto

        key = (src_ip, dst_ip) 
        if key not in flows:
            flows[key] = {
                'start_time': timestamp, 
                'packets': [], 
                'ttls': [],
                'protocols': [],
                'dst_ports': set()
            }
        
        flows[key]['packets'].append(pkt)
        flows[key]['ttls'].append(ttl)
        flows[key]['protocols'].append(proto_number)

        if proto_number == TCP_NUM and TCP in pkt:
            flows[key]['dst_ports'].add(pkt[TCP].dport)
        elif proto_number == UDP_NUM and UDP in pkt:
            flows[key]['dst_ports'].add(pkt[UDP].dport)


    feature_list = []
    
    for (src_ip, dst_ip), data in flows.items():
        pkt_count = len(data['packets'])
        
        duration = data['packets'][-1].time - data['packets'][0].time
        
        ttls = data['ttls']
        protocols = data['protocols']
        most_common_proto = Counter(protocols).most_common(1)[0][0] # 6, 17, 1, etc.

        row = {
            'Source_IP': src_ip,
            'Destination_IP': dst_ip,
            'Packet_Count': pkt_count,
            'Duration_sec': duration if duration > 0 else 0.001,
            'Num_Distinct_Dst_Ports': len(data['dst_ports']),
            
            'Mean_TTL': np.mean(ttls) if ttls else 0,
            'StdDev_TTL': np.std(ttls) if len(ttls) > 1 else 0,
            'Initial_TTL': ttls[0] if ttls else 0,
            
            'Protocol_Diversity': len(set(protocols)),
            
            'Primary_Protocol_Code': most_common_proto, 
            
            'Label': 0 
        }


        tcp_features = ['SYN_Ratio', 'ACK_Ratio', 'FIN_Ratio', 'RST_Ratio', 'PSH_Ratio', 'URG_Ratio', 'NULL_Ratio', 'SynAck_Ratio']
        udp_features = ['UDP_Packet_Count', 'UDP_Payload_Avg']
        
        for feat in tcp_features + udp_features:
            row[feat] = 0.0


        if most_common_proto == TCP_NUM:
            syn_count = sum(1 for pkt in data['packets'] if TCP in pkt and int(pkt[TCP].flags) & SYN_BIT)
            ack_count = sum(1 for pkt in data['packets'] if TCP in pkt and int(pkt[TCP].flags) & ACK_BIT)
            fin_count = sum(1 for pkt in data['packets'] if TCP in pkt and int(pkt[TCP].flags) & FIN_BIT)
            rst_count = sum(1 for pkt in data['packets'] if TCP in pkt and int(pkt[TCP].flags) & RST_BIT)
            psh_count = sum(1 for pkt in data['packets'] if TCP in pkt and int(pkt[TCP].flags) & PSH_BIT)
            urg_count = sum(1 for pkt in data['packets'] if TCP in pkt and int(pkt[TCP].flags) & URG_BIT)
            null_count = sum(1 for pkt in data['packets'] if TCP in pkt and int(pkt[TCP].flags) == 0)

            row['SYN_Ratio'] = syn_count / pkt_count
            row['ACK_Ratio'] = ack_count / pkt_count
            row['FIN_Ratio'] = fin_count / pkt_count
            row['RST_Ratio'] = rst_count / pkt_count
            row['PSH_Ratio'] = psh_count / pkt_count
            row['URG_Ratio'] = urg_count / pkt_count
            row['NULL_Ratio'] = null_count / pkt_count
            
            row['SynAck_Ratio'] = syn_count / ack_count if ack_count > 0 else 0.0

        elif most_common_proto == UDP_NUM:
            udp_pkts = [pkt for pkt in data['packets'] if UDP in pkt]
            udp_count = len(udp_pkts)
            
            if udp_count > 0:
                payload_sizes = [len(pkt[UDP].payload) for pkt in udp_pkts if pkt[UDP].payload]
                row['UDP_Packet_Count'] = udp_count
                row['UDP_Payload_Avg'] = np.mean(payload_sizes) if payload_sizes else 0.0
        
        
        feature_list.append(row)
        
    return pd.DataFrame(feature_list)


all_features = []
pcaps_directory = './dataset' 

print(f"Starting feature extraction from PCAP files in: {pcaps_directory}")

for root, dirs, files in os.walk(pcaps_directory):
    for filename in files:
        if filename.endswith(".pcap"):
            pcap_path = os.path.join(root, filename)

            print(f"Processing {filename}...")
            df_file = extract_features(pcap_path)

            if not df_file.empty:
                if 'scan' in filename.lower() or 'attack' in filename.lower():
                    df_file['Label'] = 1
                
                all_features.append(df_file)

if not all_features:
    print("No features extracted. Check your directory path and file contents.")
else:
    final_df = pd.concat(all_features, ignore_index=True)
    print(f"\n--- Total Flows Extracted: {len(final_df)} ---")
    print(f"Distribution of Labels:\n{final_df['Label'].value_counts()}")
    
    final_df = pd.get_dummies(final_df, columns=['Primary_Protocol_Code'], prefix='Protocol', dtype=int)
    
    final_df = final_df.drop(columns=['Source_IP', 'Destination_IP'], errors='ignore')
    
    output_filename = 'port_scan_dataset.csv'
    final_df.to_csv(output_filename, index=False)
    
    print(f"\nDataset successfully created and saved as {output_filename}")