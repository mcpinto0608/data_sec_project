import random
import time
from scapy.all import IP, TCP, wrpcap

# Configuration
TOTAL_PACKETS_TARGET = 1_000_000
OUTPUT_PCAP = "synthetic_nmap_attack.pcap"

packets = []
current_packet_count = 0
progress = 0

# Helper functions
def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def generate_syn_probe():
    src_ip = random_ip()
    dst_ip = random_ip()
    src_port = random.randint(1024, 65535)
    dst_port = random.randint(1, 65535)

    # SYN packet
    syn_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S")
    response_type = random.random()

    if response_type < 0.5:
        # SYN-ACK response (open port)
        resp_pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="SA")
    else:
        # RST response (closed port)
        resp_pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="R")

    return [syn_pkt, resp_pkt]

def generate_fin_scan():
    src_ip = random_ip()
    dst_ip = random_ip()
    src_port = random.randint(1024, 65535)
    dst_port = random.randint(1, 65535)

    fin_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="F")

    response_type = random.random()
    if response_type < 0.5:
        # RST (closed port)
        resp_pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="R")
        return [fin_pkt, resp_pkt]
    else:
        # No reply (open|filtered port)
        return [fin_pkt]

def generate_ack_scan():
    src_ip = random_ip()
    dst_ip = random_ip()
    src_port = random.randint(1024, 65535)
    dst_port = random.randint(1, 65535)

    ack_pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A")
    return [ack_pkt]  # ACK scans usually get RST or timeout (simulate timeout here)

# Main low-and-slow generator
print("🚀 Generating synthetic Nmap low-and-slow traffic...")

while current_packet_count < TOTAL_PACKETS_TARGET:
    scan_type = random.choices(["syn", "fin", "ack"], weights=[0.7, 0.2, 0.1])[0]

    if scan_type == "syn":
        flow = generate_syn_probe()
    elif scan_type == "fin":
        flow = generate_fin_scan()
    else:
        flow = generate_ack_scan()

    packets.extend(flow)
    current_packet_count += len(flow)

    # Artificial delay to simulate low rate (every ~500 packets)
    if current_packet_count % 500 == 0:
        time.sleep(0.01)  # very slight

    if current_packet_count // 10000 > progress:
        progress = current_packet_count // 10000
        print(f"Progress: {current_packet_count:,} packets generated...")

# Save
print(f"💾 Saving {len(packets):,} packets to {OUTPUT_PCAP}...")
wrpcap(OUTPUT_PCAP, packets)
print(f"✅ Done! Synthetic Nmap low-and-slow traffic saved: {OUTPUT_PCAP}")
