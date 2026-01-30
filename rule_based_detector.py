import argparse
import time
import scapy.all as sc
import serial
import time


try:
    arduino = serial.Serial(port='/dev/cu.usbserial-14110', baudrate=9600, timeout=.1)
    time.sleep(2) # Vital: Give the Arduino time to reboot after connecting
except Exception as e:
    print(f"Could not connect to Arduino: {e}")


FIN_BIT = 0x01
SYN_BIT = 0x02
RST_BIT = 0x04
PSH_BIT = 0x08
ACK_BIT = 0x10
URG_BIT = 0x20


FLOW_WINDOW = 2.0
flows = {}


def packet_features(pkt):
    if sc.IP not in pkt:
        return None

    f = {}

    ip = pkt[sc.IP]
    f["ip_proto"] = ip.proto
    f["ip_src"] = ip.src
    f["ip_dst"] = ip.dst
    f["ttl"] = int(ip.ttl)
    f["ip_len"] = int(ip.len) if hasattr(ip, "len") else None
    f["is_fragmented"] = bool(int(ip.flags) & 0x1)

    f.update({
        "is_tcp": False,
        "is_udp": False,
        "tcp_flags_int": 0,
        "tcp_data_len": 0,
        "udp_data_len": 0,
        "dst_port": None,
        "src_port": None,
        "tcp_window": None
    })

    if pkt.haslayer(sc.TCP):
        tcp = pkt[sc.TCP]
        f["is_tcp"] = True
        f["tcp_flags_int"] = int(tcp.flags)
        f["dst_port"] = int(tcp.dport)
        f["src_port"] = int(tcp.sport)
        f["tcp_data_len"] = len(bytes(tcp.payload))
        f["tcp_window"] = int(tcp.window)

    elif pkt.haslayer(sc.UDP):
        udp = pkt[sc.UDP]
        f["is_udp"] = True
        f["dst_port"] = int(udp.dport)
        f["src_port"] = int(udp.sport)
        f["udp_data_len"] = len(bytes(udp.payload))

    return f


def create_empty_flow():
    return {
        "ports": set(),
        "timestamps": [],
        "syn_count": 0,
        "no_ack_count": 0,
        "xmas_count": 0,
        "null_count": 0,
        "fin_count": 0,
        "total_tcp_data": 0,
        "total_udp_data": 0,
        "packet_count": 0,
        "fragmented_count": 0
    }


def update_flow(f, pkt_time):
    src = f["ip_src"]

    if src not in flows:
        flows[src] = create_empty_flow()

    flow = flows[src]

    flow["timestamps"].append(pkt_time)
    flow["timestamps"] = [t for t in flow["timestamps"] if pkt_time - t <= FLOW_WINDOW]
    flow["packet_count"] = len(flow["timestamps"])

    if f.get("dst_port"):
        flow["ports"].add(f["dst_port"])

    if f["is_tcp"]:
        flow["total_tcp_data"] += f["tcp_data_len"]
    if f["is_udp"]:
        flow["total_udp_data"] += f["udp_data_len"]

    if f["is_fragmented"]:
        flow["fragmented_count"] += 1

    flags = f["tcp_flags_int"]

    if flags == (FIN_BIT | URG_BIT | PSH_BIT):
        flow["xmas_count"] += 1
    if flags == 0:
        flow["null_count"] += 1
    if flags == FIN_BIT:
        flow["fin_count"] += 1

    if flags & SYN_BIT:
        flow["syn_count"] += 1
        if not (flags & ACK_BIT):
            flow["no_ack_count"] += 1

    return flow


def rule_score(f, pkt_time):
    """
    Multiplicative scoring: suspicious features boost the score exponentially
    """
    score = 1.0

    flags = f.get("tcp_flags_int", 0)
    is_tcp = f.get("is_tcp", False)
    is_udp = f.get("is_udp", False)
    data_len = f.get("tcp_data_len", 0) + f.get("udp_data_len", 0)
    ip_len = f.get("ip_len", 0)

    if is_tcp:
        # Xmas scan
        if flags == (FIN_BIT | URG_BIT | PSH_BIT):
            score *= 5.0
        if flags == 0:
            score *= 4.0
        if flags == FIN_BIT:
            score *= 3.0
        if (flags & SYN_BIT) and not (flags & ACK_BIT):
            score *= 2.5
        if data_len == 0:
            score *= 1.5
        if ip_len <= 60:
            score *= 1.2

    if is_udp:
        if data_len == 0:
            score *= 1.2

    flow = update_flow(f,pkt_time)
    num_ports = len(flow["ports"])
    no_ack_count = flow["no_ack_count"]
    num_packets = flow["packet_count"]

    if num_ports >= 5:
        score *= 2.0
    elif num_ports >= 3:
        score *= 1.5

    if no_ack_count >= 3:
        score *= 2.0
    elif no_ack_count >= 1:
        score *= 1.3

    total_data = flow["total_tcp_data"] + flow["total_udp_data"]
    if num_packets >= 5 and total_data <= (num_packets * 15):
        score *= 1.5

    normalized_score = 1 - 1/(1 + score)  
    return normalized_score




def analyze_pcap_or_live(pcap_path=None):
    if pcap_path:
        print(f" Reading PCAP: {pcap_path}")
        packets = sc.rdpcap(pcap_path)

        for pkt in packets:
            f = packet_features(pkt)
            if f is None:
                continue

            pkt_time = getattr(pkt, "time", time.time())
            score = rule_score(f, pkt_time)
            if score > 0.9 and f["ip_src"] != "10.100.102.26":
                print(f"{f['ip_src']} -> {f['ip_dst']}:{f['dst_port']} | score={score:.2f}")
                alert_text = f"{f['ip_src']}" # Keep it short for the small screen
                arduino.write(bytes(alert_text + '\n', 'utf-8'))

    else:
        interfaces=["en0","lo0"]
        sniff_stream = sc.sniff(iface=interfaces,prn=lambda p: process_live(p), store=False)



def process_live(pkt):
    f = packet_features(pkt)
    if f is None:
        return
    pkt_time = getattr(pkt, "time", time.time())
    score = rule_score(f, pkt_time)
    if score > 0.9 and f["ip_src"] != "10.100.102.26":
        print(f"{f['ip_src']} → {f['ip_dst']}:{f['dst_port']} | score={score:.2f}")
        alert_text = f"{f['ip_src']}" 
        arduino.write(bytes(alert_text + '\n', 'utf-8'))



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rule-Based Port Scan Detector")
    parser.add_argument("pcap", nargs="?", help="Path to a PCAP file")

    args = parser.parse_args()

    analyze_pcap_or_live(pcap_path=args.pcap)
