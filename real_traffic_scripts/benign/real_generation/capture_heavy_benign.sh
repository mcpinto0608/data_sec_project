#!/bin/bash

# === Configuration ===
CAPTURE_TIME=1200  # 20 minutes
PCAP_NAME="benign_heavy_traffic_$(date +%Y%m%d_%H%M%S).pcap"
SAVE_DIR="./captures"
CHECK_INTERVAL=60

# === Create output directory if needed ===
mkdir -p "$SAVE_DIR"

echo "📡 Capturing bi-directional traffic on ALL interfaces using tshark"
echo "📁 Saving to: $SAVE_DIR/$PCAP_NAME"
echo "⏳ Runtime: $((CAPTURE_TIME/60)) minutes"
echo ""

# === Start tshark capture ===
sudo timeout "$CAPTURE_TIME" tshark -i any -w "$SAVE_DIR/$PCAP_NAME" -q > /dev/null 2>&1 &
PID=$!

# === Traffic generator ===
{
  echo "🌐 Generating aggressive benign traffic..."

  for round in {1..100}; do
    # Multiple parallel benign commands
    curl -s https://speed.hetzner.de/100MB.bin > /dev/null &
    curl -s https://example.com > /dev/null &
    wget -q --no-check-certificate https://speed.hetzner.de/100MB.bin -O /dev/null &
    ping -c 30 1.1.1.1 > /dev/null &
    dig google.com @8.8.8.8 > /dev/null &
    dig amazon.com @1.1.1.1 > /dev/null &

    # Generate synthetic traffic if iperf3 is available
    if command -v iperf3 &> /dev/null; then
      iperf3 -c speedtest.serverius.net -t 10 > /dev/null 2>&1 &
    fi

    # Netcat DNS/HTTP-style random port noise
    for port in 53 80 443 123; do
      nc -zv google.com $port > /dev/null 2>&1 &
    done

    sleep 5
  done
} &

# === Status display ===
for (( i=1; i<=CAPTURE_TIME; i+=CHECK_INTERVAL )); do
  sleep "$CHECK_INTERVAL"
  PACKET_COUNT=$(sudo tshark -r "$SAVE_DIR/$PCAP_NAME" 2>/dev/null | wc -l)
  SIZE=$(du -h "$SAVE_DIR/$PCAP_NAME" | cut -f1)
  echo "🕒 [$i s] Packets captured: $PACKET_COUNT | Size: $SIZE"
done

# === Finish ===
wait $PID
sudo chown "$USER":"$USER" "$SAVE_DIR/$PCAP_NAME"

echo -e "\n✅ HEAVY benign traffic capture complete!"
ls -lh "$SAVE_DIR/$PCAP_NAME"
