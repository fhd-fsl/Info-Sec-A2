#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SMARTLOCK_DIR="$LAB_DIR/smartlock"
EVIDENCE_DIR="$LAB_DIR/../23i-0614-G/evidence/baseline"

mkdir -p "$EVIDENCE_DIR"

# 1. Reset and ensure isolated network is ready
bash "$SCRIPT_DIR/net_setup.sh"

# 2. Extract port from instance.txt
PORT=$(grep -E "^port\s*=" "$SMARTLOCK_DIR/instance.txt" | awk '{print $3}' | tr -d '\r')
echo "[+] Detected Lock Port: $PORT"

# 3. Start lock_server in vm1_lock
echo "[+] Starting lock_server on VM1 (10.10.10.11)..."
killall lock_server 2>/dev/null || true
killall tcpdump 2>/dev/null || true

ip netns exec vm1_lock bash -c "cd '$SMARTLOCK_DIR' && exec ./lock_server instance.txt" > /tmp/lock_normal.log 2>&1 &
sleep 0.8

# 4. Start tcpdump on VM2 interface
PCAP_FILE="$EVIDENCE_DIR/normal_session.pcap"
rm -f "$PCAP_FILE"
echo "[+] Starting packet capture to $PCAP_FILE..."
ip netns exec vm2_kali tcpdump -U -i veth_kali -w "$PCAP_FILE" "tcp port $PORT" > /dev/null 2>&1 &
sleep 0.8

# 5. Run hub_client on VM2 (10.10.10.12) connecting to 10.10.10.11
echo "[+] Running hub_client from VM2 (10.10.10.12) to 10.10.10.11:$PORT..."
ip netns exec vm2_kali bash -c "cd '$SMARTLOCK_DIR' && exec ./hub_client instance.txt 10.10.10.11 $PORT"

# 6. Stop capture and server gracefully
sleep 1
killall -INT tcpdump 2>/dev/null || true
killall lock_server 2>/dev/null || true
sleep 0.5

echo "[+] Capture finished. PCAP file details:"
ls -lh "$PCAP_FILE"

echo "[+] Exporting TCP stream transcript..."
tshark -r "$PCAP_FILE" -z "follow,tcp,ascii,0" -q > "$EVIDENCE_DIR/normal_session_stream.txt" 2>&1 || true

echo "[+] Done. Evidence saved to:"
echo "    - $PCAP_FILE"
echo "    - $EVIDENCE_DIR/normal_session_stream.txt"
