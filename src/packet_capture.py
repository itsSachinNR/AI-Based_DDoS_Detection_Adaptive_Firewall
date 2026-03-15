from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time

# store packet statistics
packet_count = defaultdict(int)
syn_count = defaultdict(int)
udp_count = defaultdict(int)

start_time = time.time()


def packet_callback(packet):
    """
    This function runs every time a packet is captured
    """

    if IP in packet:

        src_ip = packet[IP].src
        packet_count[src_ip] += 1

        # detect TCP packets
        if TCP in packet:
            flags = packet[TCP].flags

            if flags == "S":
                syn_count[src_ip] += 1

        # detect UDP packets
        if UDP in packet:
            udp_count[src_ip] += 1

        print(f"[+] Packet captured from {src_ip}")


def print_statistics():

    print("\n====== TRAFFIC REPORT ======")

    for ip in packet_count:

        print(f"\nSource IP: {ip}")
        print(f"Total Packets: {packet_count[ip]}")
        print(f"SYN Packets: {syn_count[ip]}")
        print(f"UDP Packets: {udp_count[ip]}")

        if packet_count[ip] > 100:
            print("⚠️ Possible DDoS Attack!")

    print("=============================\n")


def start_sniffing():

    print("Starting packet capture...\n")

    while True:

        sniff(prn=packet_callback, timeout=10)

        print_statistics()


if __name__ == "__main__":
    start_sniffing()
