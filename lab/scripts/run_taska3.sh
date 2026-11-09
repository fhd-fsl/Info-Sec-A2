#!/usr/bin/env bash
# Task 3 evidence capture: passive recovery of the SmartLock v1 Diffie-Hellman
# exponent with BSGS, reconstruction of the session key, and decryption of the
# captured greeting record. No packets are modified.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SMARTLOCK_DIR="$LAB_DIR/smartlock"
EVIDENCE_DIR="$LAB_DIR/../23i-0614-G/evidence/taska3_keying"
EXPLOIT_SRC="$LAB_DIR/../23i-0614-G/exploits/23i-0614-G-TASKA3-V1.cpp"
EXPLOIT_BIN="/tmp/exploit_taska3"

mkdir -p "$EVIDENCE_DIR"

# 0. Build the exploit from the deliverables directory
echo "[+] Compiling TASKA3 exploit from $EXPLOIT_SRC..."
g++ -std=c++17 -O2 -Wall "$EXPLOIT_SRC" -o "$EXPLOIT_BIN" -lcrypto

# 1. Reset network
bash "$SCRIPT_DIR/net_setup.sh"

PORT=$(grep -E "^port\s*=" "$SMARTLOCK_DIR/instance.txt" | awk '{print $3}' | tr -d '\r')
echo "[+] Detected Lock Port: $PORT"

killall lock_server 2>/dev/null || true
killall tcpdump 2>/dev/null || true

# 2. Start lock_server on VM1 (10.10.10.11)
echo "[+] Starting lock_server on VM1 (10.10.10.11)..."
ip netns exec vm1_lock bash -c "cd '$SMARTLOCK_DIR' && exec ./lock_server instance.txt" \
    > /tmp/lock_taska3.log 2>&1 &
sleep 0.8

# 3. Capture one normal session on VM2 ('any' also records the loopback-free
#    veth traffic; only this one TCP flow is present)
PCAP_FILE="$EVIDENCE_DIR/taska3_keying.pcap"
rm -f "$PCAP_FILE"
echo "[+] Starting packet capture to $PCAP_FILE..."
ip netns exec vm2_kali tcpdump -U -i veth_kali -w "$PCAP_FILE" \
    "tcp port $PORT" > /dev/null 2>&1 &
sleep 0.8

# 4. Run a legitimate hub session (no interception)
echo "[+] Running hub_client from VM2 (10.10.10.12) to 10.10.10.11:$PORT..."
set +e
ip netns exec vm2_kali bash -c "cd '$SMARTLOCK_DIR' && ./hub_client instance.txt 10.10.10.11 $PORT" \
    > /tmp/hub_taska3.log 2>&1
set -e

sleep 1
killall -INT tcpdump 2>/dev/null || true
killall lock_server 2>/dev/null || true
sleep 0.5

echo "[+] Normal session output:"
cat /tmp/hub_taska3.log

echo "[+] PCAP file size:"
ls -lh "$PCAP_FILE"

# 5. Export the captured TCP stream and run the passive solver
STREAM_FILE="$EVIDENCE_DIR/taska3_stream.txt"
echo "[+] Exporting TCP stream transcript..."
tshark -r "$PCAP_FILE" -z "follow,tcp,ascii,0" -q > "$STREAM_FILE" 2>&1 || true

OUTPUT_FILE="$EVIDENCE_DIR/taska3_output.txt"
KEY_FILE="$EVIDENCE_DIR/recovered_key.txt"
echo "[+] Running BSGS keying-recovery solver..."
"$EXPLOIT_BIN" --stream "$STREAM_FILE" --keyout "$KEY_FILE" > "$OUTPUT_FILE" 2>&1 || true

# 6. Also demonstrate the direct-parameter mode used at the viva on unseen data.
#    Parse only the DH line: a loose grep for "g:" would also match "sig:" in CERT.
DH_LINE=$(grep -m1 'B:.*type:DH' "$STREAM_FILE" || true)
P=$(printf '%s\n' "$DH_LINE" | awk -F'[.\t]' '{for(i=1;i<=NF;i++) if($i ~ /^p:[0-9]+$/){sub(/^p:/,"",$i); print $i}}')
G=$(printf '%s\n' "$DH_LINE" | awk -F'[.\t]' '{for(i=1;i<=NF;i++) if($i ~ /^g:[0-9]+$/){sub(/^g:/,"",$i); print $i}}')
B=$(printf '%s\n' "$DH_LINE" | awk -F'[.\t]' '{for(i=1;i<=NF;i++) if($i ~ /^B:[0-9]+$/){sub(/^B:/,"",$i); print $i}}')
if [ -n "$P" ] && [ -n "$G" ] && [ -n "$B" ]; then
    {
        echo ""
        echo "============ DIRECT-PARAMETER MODE (--solve) ============"
        "$EXPLOIT_BIN" --solve "$P" "$G" "$B"
    } >> "$OUTPUT_FILE" 2>&1 || true
fi

echo "[+] Solver output:"
cat "$OUTPUT_FILE"

echo "[+] Recovered key material:"
cat "$KEY_FILE"

echo "[+] TASKA3 execution finished successfully."
