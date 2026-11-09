#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SMARTLOCK_DIR="$LAB_DIR/smartlock"
EVIDENCE_DIR="$LAB_DIR/../23i-0614-G/evidence/taska1_downgrade"
EXPLOIT_SRC="$LAB_DIR/../23i-0614-G/exploits/23i-0614-G-TASKA1-V1.cpp"
EXPLOIT_BIN="/tmp/exploit_taska1"

mkdir -p "$EVIDENCE_DIR"

# 0. Build the exploit from deliverables directory
echo "[+] Compiling TASKA1 exploit from $EXPLOIT_SRC..."
g++ -std=c++17 -O2 -Wall "$EXPLOIT_SRC" -o "$EXPLOIT_BIN"

# 1. Reset network
bash "$SCRIPT_DIR/net_setup.sh"

PORT=$(grep -E "^port\s*=" "$SMARTLOCK_DIR/instance.txt" | awk '{print $3}' | tr -d '\r')
PROXY_PORT=8000

echo "[+] Target Lock Port: $PORT"
echo "[+] Proxy Listen Port: $PROXY_PORT"

killall lock_server 2>/dev/null || true
killall exploit_taska1 2>/dev/null || true
killall tcpdump 2>/dev/null || true

# 2. Start lock_server on VM1 (10.10.10.11)
echo "[+] Starting Lock Server on VM1 (10.10.10.11)..."
ip netns exec vm1_lock bash -c "cd '$SMARTLOCK_DIR' && exec ./lock_server instance.txt" > /tmp/lock_taska1.log 2>&1 &
sleep 0.8

# 3. Start packet capture on VM2
PCAP_FILE="$EVIDENCE_DIR/taska1_downgrade.pcap"
rm -f "$PCAP_FILE"
echo "[+] Starting packet capture to $PCAP_FILE..."
ip netns exec vm2_kali tcpdump -U -i any -w "$PCAP_FILE" "tcp port $PORT or tcp port $PROXY_PORT" > /dev/null 2>&1 &
sleep 0.8

# 4. Start TASKA1 C++ relay exploit on VM2 (10.10.10.12)
OUTPUT_FILE="$EVIDENCE_DIR/taska1_output.txt"
echo "[+] Starting TASKA1 Downgrade Exploit on VM2..."
ip netns exec vm2_kali bash -c "exec '$EXPLOIT_BIN' $PROXY_PORT 10.10.10.11 $PORT" > "$OUTPUT_FILE" 2>&1 &
sleep 0.8

# 5. Run Hub pointing at the Exploit Proxy
echo "[+] Running hub_client connecting to Exploit Proxy (127.0.0.1:$PROXY_PORT)..."
set +e
ip netns exec vm2_kali bash -c "cd '$SMARTLOCK_DIR' && ./hub_client instance.txt 127.0.0.1 $PROXY_PORT" >> "$OUTPUT_FILE" 2>&1
set -e

sleep 1
killall -INT tcpdump 2>/dev/null || true
killall exploit_taska1 2>/dev/null || true
killall lock_server 2>/dev/null || true
sleep 0.5

echo "[+] Exploit run complete. Summary of captured output:"
cat "$OUTPUT_FILE"

echo "[+] PCAP file size:"
ls -lh "$PCAP_FILE"

echo "[+] Exporting TCP stream transcripts..."
tshark -r "$PCAP_FILE" -z "follow,tcp,ascii,0" -q > "$EVIDENCE_DIR/taska1_stream0.txt" 2>&1 || true
tshark -r "$PCAP_FILE" -z "follow,tcp,ascii,1" -q > "$EVIDENCE_DIR/taska1_stream1.txt" 2>&1 || true

echo "[+] TASKA1 execution finished successfully."

