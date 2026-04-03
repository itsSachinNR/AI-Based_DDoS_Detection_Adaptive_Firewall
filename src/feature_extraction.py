from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from statistics import mean, pstdev
import math
import time

# =========================
# GLOBAL COUNTERS / STATE
# =========================
packet_count = 0
syn_packets = 0
udp_packets = 0
tcp_packets = 0
icmp_packets = 0
other_packets = 0

unique_ips = set()

# Track packets per source IP
ip_packet_count = defaultdict(int)

# Track destination ports (TCP / UDP)
port_packet_count = defaultdict(int)

# Packet timing / size stats
packet_sizes = []
inter_arrival_times = []
total_bytes = 0

start_time = time.time()
last_packet_time = None


# =========================
# HELPERS
# =========================
def shannon_entropy(counter_dict):
    """
    Calculate Shannon entropy of a count dictionary.
    Higher entropy means traffic is more spread out.
    """
    total = sum(counter_dict.values())
    if total <= 0:
        return 0.0

    entropy = 0.0
    for count in counter_dict.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def safe_pstdev(values):
    """
    Population standard deviation with safe fallback.
    """
    if len(values) > 1:
        return pstdev(values)
    return 0.0


# =========================
# PACKET CALLBACK
# =========================
def packet_callback(packet):
    global packet_count, syn_packets, udp_packets, tcp_packets, icmp_packets
    global other_packets, total_bytes, last_packet_time

    if IP not in packet:
        return

    current_time = float(getattr(packet, "time", time.time()))

    # Inter-arrival time
    if last_packet_time is not None:
        delta = max(0.0, current_time - last_packet_time)
        inter_arrival_times.append(delta)
    last_packet_time = current_time

    packet_count += 1

    src_ip = packet[IP].src
    unique_ips.add(src_ip)
    ip_packet_count[src_ip] += 1

    # Packet size
    pkt_len = len(packet)
    packet_sizes.append(pkt_len)
    total_bytes += pkt_len

    # Protocol detection
    if TCP in packet:
        tcp_packets += 1

        flags = str(packet[TCP].flags)
        if flags == "S":
            syn_packets += 1

        # Track TCP destination port
        port_packet_count[("tcp", packet[TCP].dport)] += 1

    elif UDP in packet:
        udp_packets += 1
        port_packet_count[("udp", packet[UDP].dport)] += 1

    elif ICMP in packet:
        icmp_packets += 1

    else:
        other_packets += 1


# =========================
# FEATURE CALCULATION
# =========================
def calculate_features():
    duration = time.time() - start_time
    duration = duration if duration > 0 else 1e-9

    # Core features
    packet_rate = packet_count / duration
    syn_ratio = syn_packets / packet_count if packet_count > 0 else 0
    udp_ratio = udp_packets / packet_count if packet_count > 0 else 0
    tcp_ratio = tcp_packets / packet_count if packet_count > 0 else 0
    icmp_ratio = icmp_packets / packet_count if packet_count > 0 else 0
    other_ratio = other_packets / packet_count if packet_count > 0 else 0

    unique_ip_count = len(unique_ips)
    avg_packets_per_ip = packet_count / unique_ip_count if unique_ip_count > 0 else 0

    # Top attacker IP
    top_ip = None
    top_count = 0
    top_ip_share = 0

    if ip_packet_count:
        top_ip = max(ip_packet_count, key=ip_packet_count.get)
        top_count = ip_packet_count[top_ip]
        top_ip_share = top_count / packet_count if packet_count > 0 else 0

    # Port concentration
    top_dst_port = None
    top_dst_port_packets = 0
    unique_dst_ports = len(port_packet_count)

    if port_packet_count:
        top_proto, top_port = max(port_packet_count, key=port_packet_count.get)
        top_dst_port = f"{top_proto}/{top_port}"
        top_dst_port_packets = port_packet_count[(top_proto, top_port)]

    # Entropy / concentration
    source_ip_entropy = shannon_entropy(ip_packet_count)
    port_entropy = shannon_entropy(port_packet_count)
    ip_concentration = top_ip_share

    # Size stats
    packet_size_mean = mean(packet_sizes) if packet_sizes else 0
    packet_size_std = safe_pstdev(packet_sizes)
    packet_size_min = min(packet_sizes) if packet_sizes else 0
    packet_size_max = max(packet_sizes) if packet_sizes else 0

    # Timing stats
    avg_inter_arrival = mean(inter_arrival_times) if inter_arrival_times else 0
    inter_arrival_std = safe_pstdev(inter_arrival_times)
    burstiness = (inter_arrival_std / avg_inter_arrival) if avg_inter_arrival > 0 else 0

    # Bytes / throughput
    byte_rate = total_bytes / duration
    avg_bytes_per_packet = total_bytes / packet_count if packet_count > 0 else 0

    features = {
        # existing core features
        "packet_rate": packet_rate,
        "syn_ratio": syn_ratio,
        "udp_ratio": udp_ratio,
        "unique_ips": unique_ip_count,
        "top_ip": top_ip,
        "top_ip_packets": top_count,

        # stronger ML features
        "tcp_ratio": tcp_ratio,
        "icmp_ratio": icmp_ratio,
        "other_ratio": other_ratio,
        "avg_packets_per_ip": avg_packets_per_ip,
        "ip_concentration": ip_concentration,
        "source_ip_entropy": source_ip_entropy,
        "port_entropy": port_entropy,
        "unique_dst_ports": unique_dst_ports,
        "top_dst_port": top_dst_port,
        "top_dst_port_packets": top_dst_port_packets,
        "packet_size_mean": packet_size_mean,
        "packet_size_std": packet_size_std,
        "packet_size_min": packet_size_min,
        "packet_size_max": packet_size_max,
        "avg_inter_arrival": avg_inter_arrival,
        "inter_arrival_std": inter_arrival_std,
        "burstiness": burstiness,
        "byte_rate": byte_rate,
        "avg_bytes_per_packet": avg_bytes_per_packet,
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "duration_seconds": duration,
    }

    return features


# =========================
# RESET FOR EACH NEW RUN
# =========================
def reset_counters():
    global packet_count, syn_packets, udp_packets, tcp_packets, icmp_packets
    global other_packets, unique_ips, ip_packet_count, port_packet_count
    global packet_sizes, inter_arrival_times, total_bytes, start_time, last_packet_time

    packet_count = 0
    syn_packets = 0
    udp_packets = 0
    tcp_packets = 0
    icmp_packets = 0
    other_packets = 0

    unique_ips = set()
    ip_packet_count = defaultdict(int)
    port_packet_count = defaultdict(int)

    packet_sizes = []
    inter_arrival_times = []
    total_bytes = 0

    start_time = time.time()
    last_packet_time = None


# =========================
# MAIN FEATURE EXTRACTION
# =========================
def start_feature_extraction(duration=10, iface=None, bpf_filter=None, verbose=True):
    """
    Capture live traffic for a fixed window and return extracted features.
    """
    reset_counters()

    if verbose:
        print(f"Monitoring traffic for {duration} seconds...\n")

    sniff(
        prn=packet_callback,
        timeout=duration,
        iface=iface,
        filter=bpf_filter,
        store=False
    )

    features = calculate_features()

    if verbose:
        print("===== Extracted Features =====")
        for key, value in features.items():
            print(f"{key}: {value}")
        print("==============================")

    return features


if __name__ == "__main__":
    start_feature_extraction()
