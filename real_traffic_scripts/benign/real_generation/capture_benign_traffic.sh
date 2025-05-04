#!/bin/bash

# === Configuration ===
CAPTURE_TIME=1200  # 20 minutes (in seconds)
PCAP_NAME="benign_traffic_$(date +%Y%m%d_%H%M%S).pcap"
SAVE_DIR="./captures"
INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | paste -sd, -)
CHECK_INTERVAL=60

# === Create output folder if needed ===
mkdir -p "$SAVE_DIR"

echo "📡 Capturing traffic on ALL interfaces: $INTERFACES"
echo "📁 Output file: $SAVE_DIR/$PCAP_NAME"
echo "⏳ Duration: $((CAPTURE_TIME/60)) minutes"
echo ""

# === Start capture in background ===
sudo timeout "$CAPTURE_TIME" tcpdump -i any -w "$SAVE_DIR/$PCAP_NAME" -U -nn > /dev/null 2>&1 &
PID=$!

# === Generate Realistic Benign Traffic (background) ===
{
  echo "💻 Generating high-volume benign traffic in background..."

  for i in $(seq 1 20); do
    curl -s https://speed.hetzner.de/100MB.bin > /dev/null &
    wget -q --no-check-certificate https://speed.hetzner.de/100MB.bin -O /dev/null &
    curl -s https://example.com > /dev/null &
    ping -c 30 8.8.8.8 > /dev/null &
    sleep 10
  done
} &

# === Progress Checkpoints ===
for (( i=1; i<=CAPTURE_TIME; i+=CHECK_INTERVAL )); do
  sleep "$CHECK_INTERVAL"
  PACKET_COUNT=$(sudo tcpdump -r "$SAVE_DIR/$PCAP_NAME" -n -q 2>/dev/null | wc -l)
  SIZE=$(du -h "$SAVE_DIR/$PCAP_NAME" | cut -f1)
  echo "🕒 [$i s] Packets captured: $PACKET_COUNT | Size: $SIZE"
done

# === Wait for tcpdump to finish ===
wait $PID

# === Fix ownership (in case root wrote it) ===
sudo chown "$USER":"$USER" "$SAVE_DIR/$PCAP_NAME"

echo -e "\n✅ Capture complete: $SAVE_DIR/$PCAP_NAME"
ls -lh "$SAVE_DIR/$PCAP_NAME"
