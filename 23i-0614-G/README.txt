CS3002 Information Security - Assignment 2: SmartLock
Student: Fahad Bin Faisal (Roll: 23i-0614, Section: G)
Target:  smartlock-23i-0614.local (Port: 9030)
Flag:    FLAG{c3603ab534897940}

--------------------------------------------------------------------------------
1. Directory Structure
--------------------------------------------------------------------------------
23i-0614-G/
├── 23i-0614-G-REPORT.pdf          # Full LaTeX report covering Parts A to D
├── answers.txt                    # Recovered parameters, keys, and flag
├── README.txt                     # Build and execution guide
├── securelink2.cpp                # Hardened SmartLock v2 cryptographic core
├── exploits/                      # Working C++17 exploits for SmartLock v1
│   ├── 23i-0614-G-TASKA1-V1.cpp   # Cipher suite downgrade (forced NULL cipher)
│   ├── 23i-0614-G-TASKA2-V1.cpp   # MITM relay & PIN cracking
│   ├── 23i-0614-G-TASKA3-V1.cpp   # Discrete log key recovery (BSGS)
│   ├── 23i-0614-G-TASKA4-V1.cpp   # Nonce reuse keystream XOR recovery
│   └── 23i-0614-G-TASKA5-V1.cpp   # Replay attack (door unlock replication)
├── performance/                   # Part D benchmark harness, data, and charts
│   ├── 23i-0614-G-TASKD-V1.cpp    # Comparative benchmark harness
│   ├── benchmark_data.json        # Benchmark summary statistics
│   ├── benchmark_results.txt      # Raw benchmark stdout output
│   ├── performance_comparison.png # 3-panel benchmark chart
│   └── tradeoff_defense.md        # Engineering trade-off analysis
└── evidence/                      # Network pcaps, logs, and git history
    ├── git_log.txt                # Git commit history (--stat)
    ├── baseline/                  # v1 normal session capture
    ├── taska1_downgrade/          # A1 downgrade output & pcap
    ├── taska2_mitm/               # A2 MITM relay output & pcap
    ├── taska3_keying/             # A3 discrete log cracking output & pcap
    ├── taska4_nonce/              # A4 keystream extraction output & pcap
    ├── taska5_replay/             # A5 replay execution output & pcap
    └── partc_v2/                  # v2 self-checks, normal pcap, regression logs, AI audit

--------------------------------------------------------------------------------
2. Prerequisites
--------------------------------------------------------------------------------
- Linux / WSL2 (Ubuntu 22.04+ or Kali)
- g++ with C++17 support
- OpenSSL 3.0+ libcrypto (libssl-dev)
- iproute2, tcpdump, bash

Dependencies:
  sudo apt update && sudo apt install -y build-essential libssl-dev tcpdump

Compilation flags:
  g++ -std=c++17 -O2 -Wall <source.cpp> -lcrypto

--------------------------------------------------------------------------------
3. Running Part A Exploits
--------------------------------------------------------------------------------
Make sure the lab namespaces are up:
  sudo bash lab/scripts/net_setup.sh

Start SmartLock v1 inside VM1:
  sudo ip netns exec vm1_lock bash -c "cd lab/smartlock && ./lock_server instance.txt"

Run exploits from VM2:

Task A.1 (Cipher suite downgrade to NULL):
  g++ -std=c++17 -O2 -Wall 23i-0614-G/exploits/23i-0614-G-TASKA1-V1.cpp -o /tmp/taska1 -lcrypto
  sudo ip netns exec vm2_kali /tmp/taska1 lab/smartlock/instance.txt 10.10.10.11 9030

Task A.2 (MITM relay and PIN cracking):
  g++ -std=c++17 -O2 -Wall 23i-0614-G/exploits/23i-0614-G-TASKA2-V1.cpp -o /tmp/taska2 -lcrypto
  # Terminal 1: MITM proxy on Kali (10.10.10.12:8000 -> 10.10.10.11:9030)
  sudo ip netns exec vm2_kali /tmp/taska2 lab/smartlock/instance.txt 10.10.10.11 9030 8000 lab/smartlock/pin_wordlist.txt
  # Terminal 2: Connect hub client through relay
  sudo ip netns exec vm2_kali bash -c "cd lab/smartlock && ./hub_client instance.txt 127.0.0.1 8000"

Task A.3 (40-bit DH discrete log recovery via BSGS):
  g++ -std=c++17 -O2 -Wall 23i-0614-G/exploits/23i-0614-G-TASKA3-V1.cpp -o /tmp/taska3 -lcrypto
  sudo ip netns exec vm2_kali /tmp/taska3 lab/smartlock/instance.txt 10.10.10.11 9030

Task A.4 (Static nonce reuse keystream extraction):
  g++ -std=c++17 -O2 -Wall 23i-0614-G/exploits/23i-0614-G-TASKA4-V1.cpp -o /tmp/taska4 -lcrypto
  sudo ip netns exec vm2_kali /tmp/taska4 lab/smartlock/instance.txt 10.10.10.11 9030

Task A.5 (Command replay - unauthorized unlock):
  g++ -std=c++17 -O2 -Wall 23i-0614-G/exploits/23i-0614-G-TASKA5-V1.cpp -o /tmp/taska5 -lcrypto
  sudo ip netns exec vm2_kali /tmp/taska5 lab/smartlock/instance.txt 10.10.10.11 9030

--------------------------------------------------------------------------------
4. Testing SmartLock v2 (Part C)
--------------------------------------------------------------------------------
Automated test suite (self-checks, normal session, all 5 attack regressions):
  sudo bash lab/scripts/run_partc.sh

Manual v2 build and test:
  cp 23i-0614-G/securelink2.cpp lab/v2_skeleton/
  make -C lab/v2_skeleton

  # Start v2 lock in VM1
  sudo ip netns exec vm1_lock bash -c "cd lab/v2_skeleton && ./lock_server2 ../smartlock/instance.txt"

  # Run v2 hub in VM2
  sudo ip netns exec vm2_kali bash -c "cd lab/v2_skeleton && ./hub_client2 ../smartlock/instance.txt 10.10.10.11 9030"

--------------------------------------------------------------------------------
5. Performance Study (Part D)
--------------------------------------------------------------------------------
Run benchmarks (>= 30 handshakes, per-record overhead, throughput):
  sudo bash lab/scripts/run_partd.sh

Generate comparison plot:
  python lab/scripts/generate_charts.py
