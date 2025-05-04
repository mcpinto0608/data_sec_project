#!/bin/bash

# === Settings ===
OUTPUT_DIR="./captures"
DURATION_MINUTES=30
DURATION_SECONDS=$((DURATION_MINUTES * 60) + 5)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILENAME="nmap_attack_traffic_${TIMESTAMP}.pcap"
FULL_PATH="$OUTPUT_DIR/$FILENAME"

# === Create output directory if needed ===
mkdir -p "$OUTPUT_DIR"

echo "🐚 Capturing bi-directional attack traffic on all interfaces using tshark..."
echo "📂 Saving to: $FULL_PATH"
echo "⏳ Duration: $DURATION_MINUTES minutes"

# === Start Capture in Background ===
sudo tshark -i any -w "$FULL_PATH" > /dev/null 2>&1 &
TSHARK_PID=$!

# === Countdown Loop with Progress ===
for (( i=1; i<=DURATION_MINUTES; i++ )); do
    sleep 60
    PACKETS=$(ls -lh "$FULL_PATH" 2>/dev/null | awk '{print $5}')
    echo "🟢 [$((i * 60))s] Capturing... Current file size: ${PACKETS:-not yet created}"
done

# === Stop tshark ===
sudo kill "$TSHARK_PID"
sleep 2

# === Fix Permissions ===
sudo chown "$USER":"$USER" "$FULL_PATH"

echo "✅ Capture complete. File saved: $FULL_PATH"
