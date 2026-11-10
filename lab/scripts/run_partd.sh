#!/usr/bin/env bash
# SmartLock Part D Performance Study Automation Script:
#   1. Builds 23i-0614-G-TASKD-V1.cpp.
#   2. Spawns SmartLock v1 (port 9030) and SmartLock v2 (port 9031) in vm1_lock.
#   3. Runs benchmark suite from vm2_kali (handshake >= 30 runs, per-record overhead, throughput 10k records >= 5 runs).
#   4. Emits benchmark_results.txt and benchmark_data.json.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SMARTLOCK_DIR="$LAB_DIR/smartlock"
V2_DIR="$LAB_DIR/v2_skeleton"
PERF_DIR="$LAB_DIR/../23i-0614-G/performance"
SECURELINK_SRC="$LAB_DIR/../23i-0614-G/securelink2.cpp"
BENCH_SRC="$PERF_DIR/23i-0614-G-TASKD-V1.cpp"
BENCH_BIN="/tmp/taskd_bench"
RESULTS_TXT="$PERF_DIR/benchmark_results.txt"
RESULTS_JSON="$PERF_DIR/benchmark_data.json"

mkdir -p "$PERF_DIR"

echo "=========================================================="
echo "[+] Part D: Building Performance Study Harness..."
echo "=========================================================="

g++ -std=c++17 -O2 -Wall -I"$V2_DIR" -I"$SMARTLOCK_DIR" \
    "$BENCH_SRC" "$SECURELINK_SRC" -o "$BENCH_BIN" -lcrypto

echo "[+] Binary built: $BENCH_BIN"

# Ensure v2 lock_server2 is built
(cd "$V2_DIR" && make -s lock_server2)

# Prepare port configs
PORT_V1=$(grep -E "^port\s*=" "$SMARTLOCK_DIR/instance.txt" | awk '{print $3}' | tr -d '\r')
PORT_V2=9031
sed "s/^port\s*=.*/port = $PORT_V2/" "$SMARTLOCK_DIR/instance.txt" > /tmp/instance_v2.txt

echo "[+] Target Ports: v1 = $PORT_V1, v2 = $PORT_V2"

# Setup network
bash "$SCRIPT_DIR/net_setup.sh"
killall lock_server lock_server2 2>/dev/null || true
sleep 0.5

# Start lock_server v1 in vm1_lock
echo "[+] Starting SmartLock v1 on 10.10.10.11:$PORT_V1..."
ip netns exec vm1_lock bash -c "cd '$SMARTLOCK_DIR' && exec ./lock_server instance.txt" > /tmp/lock1.log 2>&1 &
sleep 0.8

# Start lock_server2 v2 in vm1_lock
echo "[+] Starting SmartLock v2 on 10.10.10.11:$PORT_V2..."
ip netns exec vm1_lock bash -c "cd '$V2_DIR' && exec ./lock_server2 /tmp/instance_v2.txt" > /tmp/lock2.log 2>&1 &
sleep 0.8

# Run benchmark harness in vm2_kali
echo "[+] Running TASKD Benchmark from vm2_kali (10.10.10.12)..."
set +e
ip netns exec vm2_kali "$BENCH_BIN" "$SMARTLOCK_DIR/instance.txt" 10.10.10.11 "$PORT_V1" "$PORT_V2" "$RESULTS_JSON" | tee "$RESULTS_TXT"
BENCH_RC=$?
set -e

# Cleanup servers
killall lock_server lock_server2 2>/dev/null || true

if [ $BENCH_RC -eq 0 ]; then
    echo ""
    echo "[+] Benchmark succeeded! Output saved to:"
    echo "    - $RESULTS_TXT"
    echo "    - $RESULTS_JSON"
else
    echo "[!] Benchmark failed with exit code $BENCH_RC"
    exit $BENCH_RC
fi

