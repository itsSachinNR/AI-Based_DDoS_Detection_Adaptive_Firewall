from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time

packet_count = 0
syn_packets = 0
udp_packets = 0
unique_ips = set()

start_time = time.time()


def packet_callback(packet):
    global packet_count, syn_packets, udp_packets

    if IP in packet:

        packet_count += 1
        src_ip = packet[IP].src
        unique_ips.add(src_ip)

        if TCP in packet:
            flags = packet[TCP].flags
            if flags == "S":
                syn_packets += 1

        if UDP in packet:
            udp_packets += 1


def calculate_features():

    duration = time.time() - start_time

    packet_rate = packet_count / duration if duration > 0 else 0
    syn_ratio = syn_packets / packet_count if packet_count > 0 else 0
    udp_ratio = udp_packets / packet_count if packet_count > 0 else 0

    features = {
        "packet_rate": packet_rate,
        "syn_ratio": syn_ratio,
        "udp_ratio": udp_ratio,
        "unique_ips": len(unique_ips)
    }

    return features


def start_feature_extraction():

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
