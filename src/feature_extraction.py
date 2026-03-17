from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time

# Global counters
packet_count = 0
syn_packets = 0
udp_packets = 0
unique_ips = set()

# NEW: track packets per IP
ip_packet_count = defaultdict(int)

start_time = time.time()


def packet_callback(packet):
    global packet_count, syn_packets, udp_packets

    if IP in packet:

        packet_count += 1
        src_ip = packet[IP].src

        unique_ips.add(src_ip)
        ip_packet_count[src_ip] += 1   # 🔥 Track per-IP packets

        # TCP SYN detection
        if TCP in packet:
            flags = packet[TCP].flags
            if flags == "S":
                syn_packets += 1

        # UDP detection
        if UDP in packet:
            udp_packets += 1


def calculate_features():

    duration = time.time() - start_time

    packet_rate = packet_count / duration if duration > 0 else 0
    syn_ratio = syn_packets / packet_count if packet_count > 0 else 0
    udp_ratio = udp_packets / packet_count if packet_count > 0 else 0

    # 🔥 Identify top attacker IP
    top_ip = None
    top_count = 0

    if ip_packet_count:
        top_ip = max(ip_packet_count, key=ip_packet_count.get)
        top_count = ip_packet_count[top_ip]

    features = {
        "packet_rate": packet_rate,
        "syn_ratio": syn_ratio,
        "udp_ratio": udp_ratio,
        "unique_ips": len(unique_ips),
        "top_ip": top_ip,
        "top_ip_packets": top_count
    }

    return features


def reset_counters():
    global packet_count, syn_packets, udp_packets, unique_ips, ip_packet_count, start_time

    packet_count = 0
    syn_packets = 0
    udp_packets = 0
    unique_ips = set()
    ip_packet_count = defaultdict(int)
    start_time = time.time()


def start_feature_extraction():

    reset_counters()  # 🔥 important for fresh calculation

    print("Monitoring traffic...\n")

    sniff(prn=packet_callback, timeout=10)

    features = calculate_features()

    print("===== Extracted Features =====")
    for key, value in features.items():
        print(f"{key}: {value}")

    print("==============================")

    return features


if __name__ == "__main__":
    start_feature_extraction()
