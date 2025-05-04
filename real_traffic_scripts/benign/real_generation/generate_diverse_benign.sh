#!/usr/bin/env bash
set -euo pipefail

# ─── CONFIGURATION ─────────────────────────────────────────────────────────────
DURATION=1205             # total capture time in seconds (20m)
UPDATE_INTERVAL=30       # progress every 5 minutes
HTTP_PORT=8080
INTERFACE="any"
FILTER="tcp or udp"
SAVE_DIR="./captures"
SUPPORT_DIR="./support"
# ────────────────────────────────────────────────────────────────────────────────

mkdir -p "$SAVE_DIR" "$SUPPORT_DIR"
PCAP="$SAVE_DIR/capture_$(date +%Y%m%d_%H%M%S).pcap"
LOG="$SUPPORT_DIR/capture_$(date +%Y%m%d_%H%M%S).log"

# Tee all output to log
exec > >(tee -a "$LOG") 2>&1

echo "🗒️  Log: $LOG"
echo "▶️  Capture will run for $((DURATION/60)) minutes"
echo "🌐  HTTP server on port $HTTP_PORT for bidirectional traffic"
echo "📡  tshark filter: $FILTER (iface: $INTERFACE)"
echo "💾  Output PCAP: $PCAP"
echo

# 1) Start HTTP server
pushd "$SUPPORT_DIR" >/dev/null
nohup python3 -m http.server "$HTTP_PORT" >/dev/null 2>&1 &
HTTP_PID=$!
popd >/dev/null
echo "🔸 HTTP server PID: $HTTP_PID"

# 2) Start tshark capture (no -c limit, time only)
tshark -P -i "$INTERFACE" -f "$FILTER" -a duration:"$DURATION" -w "$PCAP" &
CAP_PID=$!
echo "🔸 tshark PID: $CAP_PID"
START_TIME=$SECONDS

# 3) Local traffic generation (background)
(
  echo "🔄 Generating local benign traffic..."
  END=$((START_TIME + DURATION))
  while [ $SECONDS -lt $END ]; do
    #— HTTP GETs (bidir)
    curl -s "http://127.0.0.1:$HTTP_PORT/" > /dev/null &
    curl -I "http://127.0.0.1:$HTTP_PORT/" > /dev/null &

    #— DNS lookups
    dig +short example.com @8.8.8.8 > /dev/null &
    nslookup google.com 1.1.1.1 > /dev/null &

    #— ICMP ping
    ping -c 10 -i 0.1 127.0.0.1 > /dev/null &

    #— UDP echo (port 7)
    echo ping | nc -u -w1 127.0.0.1 7 > /dev/null &

    #— traceroute (UDP/ICMP)
    traceroute -n -q 1 -w 1 127.0.0.1 > /dev/null &

    sleep 5
  done
  echo "🔻 Local traffic generator done."
)&

# 4) Progress updates
NEXT_UPDATE=$UPDATE_INTERVAL
while kill -0 "$CAP_PID" 2>/dev/null; do
  sleep 1
  if [ $((SECONDS - START_TIME)) -ge $NEXT_UPDATE ]; then
    ELAPSED_MIN=$(( NEXT_UPDATE/60 ))
    PKTS=$(tshark -r "$PCAP" -q 2>&1 | awk '/^Packet Count:/ {print $3}')
    SIZE=$(du -h "$PCAP" | cut -f1)
    echo "⏱️  ${ELAPSED_MIN}m elapsed — Packets: ${PKTS:-0}, Size: $SIZE"
    NEXT_UPDATE=$(( NEXT_UPDATE + UPDATE_INTERVAL ))
  fi
done

# 5) Teardown
wait "$CAP_PID" || true
echo "🛑 tshark finished."
kill "$HTTP_PID" 2>/dev/null || true

# 6) Fix permissions
chmod 644 "$PCAP"
chown "$SUDO_USER":"$SUDO_USER" "$PCAP"
echo "✅ Capture complete: $PCAP"
ls -lh "$PCAP"
echo "📂 Support dir: $SUPPORT_DIR"
