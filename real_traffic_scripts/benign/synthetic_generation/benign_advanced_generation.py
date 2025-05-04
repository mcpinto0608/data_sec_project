import random
from scapy.all import IP, TCP, UDP, Raw, wrpcap

# Config
TOTAL_PACKETS_TARGET = 2_000_000
OUTPUT_PCAP = "synthetic_benign_traffic_v2.pcap"

packets = []
current_packet_count = 0
progress = 0

# Helpers
def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def random_payload(min_size=50, max_size=1200):
    size = random.randint(min_size, max_size)
    return Raw(load=bytes(random.getrandbits(8) for _ in range(size)))

# Different types of flows
def generate_web_browsing_flow():
    src_ip = random_ip()
    dst_ip = random_ip()
    sport = random.randint(1024, 65535)
    dport = 80

    packets = []
    packets.append(IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S"))
    packets.append(IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="SA"))
    packets.append(IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="A"))
    for _ in range(random.randint(2, 6)):
        packets.append(IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA")/random_payload())
        packets.append(IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="A"))
    if random.random() > 0.2:
        packets.append(IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="FA"))
        packets.append(IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="FA"))
        packets.append(IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="A"))
    return packets

def generate_api_polling_flow():
    src_ip = random_ip()
    dst_ip = random_ip()
    sport = random.randint(1024, 65535)
    dport = 443

    packets = []
    packets.append(IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S"))
    packets.append(IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="SA"))
    packets.append(IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="A"))
    for _ in range(random.randint(5, 15)):
        packets.append(IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA")/random_payload(50, 300))
        if random.random() < 0.4:
            packets.append(IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="PA")/random_payload(50, 300))
    if random.random() > 0.3:
        packets.append(IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="FA"))
        packets.append(IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="FA"))
        packets.append(IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="A"))
    return packets

def generate_partial_handshake():
    src_ip = random_ip()
    dst_ip = random_ip()
    sport = random.randint(1024, 65535)
    dport = random.choice([80, 443, 22, 21, 8080])

    packets = []
    packets.append(IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S"))
    # Randomly drop after SYN
    if random.random() > 0.5:
        packets.append(IP(src=dst_ip, dst=src_ip)/TCP(sport=dport, dport=sport, flags="SA"))
    return packets

def generate_udp_chatter():
    src_ip = random_ip()
    dst_ip = random_ip()
    sport = random.randint(1024, 65535)
    dport = random.choice([53, 161, 500, 69])

    return [
        IP(src=src_ip, dst=dst_ip)/UDP(sport=sport, dport=dport)/random_payload(50, 200),
        IP(src=dst_ip, dst=src_ip)/UDP(sport=dport, dport=sport)/random_payload(50, 200)
    ]

# Main traffic generation loop
print("🚀 Generating next-level synthetic benign traffic...")

while current_packet_count < TOTAL_PACKETS_TARGET:
    traffic_type = random.choices(
        ["web", "api", "partial", "udp"],
        weights=[0.5, 0.3, 0.1, 0.1],
        k=1
    )[0]

    if traffic_type == "web":
        flow = generate_web_browsing_flow()
    elif traffic_type == "api":
        flow = generate_api_polling_flow()
    elif traffic_type == "partial":
        flow = generate_partial_handshake()
    else:
        flow = generate_udp_chatter()

    packets.extend(flow)
    current_packet_count += len(flow)

    if current_packet_count // 10000 > progress:
        progress = current_packet_count // 10000
        print(f"Progress: {current_packet_count:,} packets generated...")

# Save final PCAP
print(f"💾 Saving {len(packets):,} packets to {OUTPUT_PCAP}...")
wrpcap(OUTPUT_PCAP, packets)
print(f"✅ Done! Realistic synthetic benign traffic saved: {OUTPUT_PCAP}")
