#!/usr/bin/env bash
# Task 4 evidence capture: demonstrate AES-GCM nonce reuse in SmartLock v1.
# A normal session is captured, the greeting and STATUS reply are XORed after
# stripping their GCM tags, and the known greeting prefix recovers the STATUS
# reply without the session key.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SMARTLOCK_DIR="$LAB_DIR/smartlock"
EVIDENCE_DIR="$LAB_DIR/../23i-0614-G/evidence/taska4_nonce"
EXPLOIT_SRC="$LAB_DIR/../23i-0614-G/exploits/23i-0614-G-TASKA4-V1.cpp"
EXPLOIT_BIN="/tmp/exploit_taska4"

mkdir -p "$EVIDENCE_DIR"

# 0. Build the exploit from the deliverables directory
echo "[+] Compiling TASKA4 exploit from $EXPLOIT_SRC..."
g++ -std=c++17 -O2 -Wall "$EXPLOIT_SRC" -o "$EXPLOIT_BIN"

# 1. Reset network
bash "$SCRIPT_DIR/net_setup.sh"

PORT=$(grep -E "^port\s*=" "$SMARTLOCK_DIR/instance.txt" | awk '{print $3}' | tr -d '\r')
echo "[+] Detected Lock Port: $PORT"

killall lock_server 2>/dev/null || true
killall tcpdump 2>/dev/null || true

# 2. Start a fresh lock_server so the first STATUS reply is "unlocks=0"
echo "[+] Starting lock_server on VM1 (10.10.10.11)..."
ip netns exec vm1_lock bash -c "cd '$SMARTLOCK_DIR' && exec ./lock_server instance.txt" \
    > /tmp/lock_taska4.log 2>&1 &
sleep 0.8

# 3. Capture one normal AES256-GCM session
PCAP_FILE="$EVIDENCE_DIR/taska4_nonce.pcap"
rm -f "$PCAP_FILE"
echo "[+] Starting packet capture to $PCAP_FILE..."
ip netns exec vm2_kali tcpdump -U -i veth_kali -w "$PCAP_FILE" \
    "tcp port $PORT" > /dev/null 2>&1 &
sleep 0.8

# 4. Run the legitimate hub
echo "[+] Running hub_client from VM2 (10.10.10.12) to 10.10.10.11:$PORT..."
set +e
ip netns exec vm2_kali bash -c "cd '$SMARTLOCK_DIR' && ./hub_client instance.txt 10.10.10.11 $PORT" \
    > /tmp/hub_taska4.log 2>&1
set -e

sleep 1
killall -INT tcpdump 2>/dev/null || true
killall lock_server 2>/dev/null || true
sleep 0.5

echo "[+] Normal session output:"
cat /tmp/hub_taska4.log

echo "[+] PCAP file size:"
ls -lh "$PCAP_FILE"

# 5. Export the stream and run the nonce-reuse analysis
STREAM_FILE="$EVIDENCE_DIR/taska4_stream.txt"
echo "[+] Exporting TCP stream transcript..."
tshark -r "$PCAP_FILE" -z "follow,tcp,ascii,0" -q > "$STREAM_FILE" 2>&1 || true

OUTPUT_FILE="$EVIDENCE_DIR/taska4_output.txt"
PROOF_FILE="$EVIDENCE_DIR/nonce_xor.txt"
echo "[+] Running nonce-reuse solver..."
"$EXPLOIT_BIN" --stream "$STREAM_FILE" --fileout "$PROOF_FILE" > "$OUTPUT_FILE" 2>&1 || true

# 6. Demonstrate the standalone --xor mode on the two captured ct values
CT1=$(grep '^ciphertext_a_hex = ' "$PROOF_FILE" | awk '{print $3}' || true)
CT2=$(grep '^ciphertext_b_hex = ' "$PROOF_FILE" | awk '{print $3}' || true)
if [ -n "$CT1" ] && [ -n "$CT2" ]; then
    {
        echo ""
        echo "============ STANDALONE --xor MODE ============"
        "$EXPLOIT_BIN" --xor "$CT1" "$CT2" "Paired with SmartLock. Pairing secret: "
    } >> "$OUTPUT_FILE" 2>&1 || true
fi

echo "[+] Solver output:"
cat "$OUTPUT_FILE"

echo "[+] Proof artifact:"
cat "$PROOF_FILE"

echo "[+] TASKA4 execution finished successfully."
