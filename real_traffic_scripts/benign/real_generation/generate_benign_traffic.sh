#!/bin/bash

# === Configuration ===
CAPTURE_DURATION=3600  # 1 hour
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_DIR="./captures"
LOG_DIR="./wget_logs"
PCAP_FILE="$PCAP_DIR/benign_traffic_${TIMESTAMP}.pcap"
PARALLEL_TASKS=5

# === Create required directories ===
mkdir -p "$PCAP_DIR"
mkdir -p "$LOG_DIR"

# === Start tshark capture ===
echo "🌐 Starting bi-directional traffic capture for $CAPTURE_DURATION seconds..."
echo "📁 Saving .pcap to: $PCAP_FILE"
sudo tshark -a duration:$CAPTURE_DURATION -i any -w "$PCAP_FILE" > /dev/null 2>&1 &
TSHARK_PID=$!

# === Lightweight traffic generator ===
generate_light_traffic() {
  END=$((SECONDS + CAPTURE_DURATION))
  while [ $SECONDS -lt $END ]; do
    curl -s http://example.com > /dev/null &
    ping -c 1 1.1.1.1 > /dev/null &
    dig +short duckduckgo.com > /dev/null &
    wget -qO "$LOG_DIR/wget_${RANDOM}.html" http://neverssl.com &
    sleep 0.5
  done
}

# === Launch parallel tasks ===
echo "🚀 Launching $PARALLEL_TASKS concurrent traffic generators..."
for i in $(seq 1 $PARALLEL_TASKS); do
  generate_light_traffic &
done

# === Timer display ===
for ((i = 1; i <= CAPTURE_DURATION; i++)); do
  sleep 1
  echo -ne "\r⏱️ Elapsed: ${i}s / ${CAPTURE_DURATION}s"
done
echo ""

# === Finalization ===
wait $TSHARK_PID
sudo chmod 644 "$PCAP_FILE"

echo "✅ Capture complete!"
echo "📂 PCAP saved to: $PCAP_FILE"
echo "📄 Wget logs (if any) saved in: $LOG_DIR"
