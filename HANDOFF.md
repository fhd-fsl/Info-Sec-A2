# SmartLock Engagement — Comprehensive Agent Handoff

This document provides complete architectural, cryptographic, and practical context for another agent or developer continuing this engagement on Assignment 2: **"Break It, Then Build It: A SmartLock Cryptographic System Engagement"**.

---

## 1. Student & Submission Metadata

- **Student Name**: Fahad Bin Faisal
- **Student Roll Number**: `23i-0614`
- **Section**: `G`
- **Course**: CS3002 Information Security — Assignment 2
- **Deliverable Folder / Prefix**: `23i-0614-G`
- **Submission Archive**: `23i-0614-G.zip` (must contain only the `23i-0614-G/` folder, no binaries, no `.o`, no `.exe`)
- **Key Rules**:
  - All submitted code must be **C++17** and compile cleanly with `g++` and OpenSSL (`-lcrypto`).
  - Every source file must have a comment at the top containing the student's name, roll number, and assignment number.
  - No build binaries or object files may exist in the submission folder.

---

## 2. Directory Layout & Separation of Concerns

```text
Info Sec A2/
├── HANDOFF.md                      # This handoff documentation
├── material/                       # Original read-only assignment materials
│   ├── Assignment2_Statement.pdf   # Complete requirements, marks distribution, rules
│   ├── Lab_Setup_Guide.pdf         # Networking and isolated VM lab guide
│   └── SmartLock/                  # Upstream reference source code and docs
├── lab/                            # Active working and testing environment
│   ├── smartlock/                  # v1 source code, compiled binaries, instance.txt
│   ├── v2_skeleton/                # v2 skeleton for Parts B & C
│   └── scripts/                    # Fully automated bash scripts for network and tests
│       ├── net_setup.sh            # Sets up isolated Linux network namespaces
│       ├── net_teardown.sh         # Tears down isolated network namespaces
│       ├── capture_normal.sh       # Captures baseline normal session traffic
│       └── run_taska1.sh           # Compiles and runs Task 1 downgrade exploit
└── 23i-0614-G/                     # THE SUBMISSION DIRECTORY (Strict Deliverable Layout)
    ├── answers.txt                 # Part A.1 key-value recovered secrets
    ├── exploits/                   # Dedicated C++ exploit tools (TASKA1 .. TASKA5)
    │   └── 23i-0614-G-TASKA1-V1.cpp # Task 1 Negotiation Downgrade exploit
    ├── evidence/                   # Task-compartmentalized captures and logs
    │   ├── baseline/               # Normal session capture
    │   │   ├── normal_session.pcap
    │   │   └── normal_session_stream.txt
    │   └── taska1_downgrade/       # Task 1 downgrade evidence
    │       ├── taska1_downgrade.pcap
    │       ├── taska1_output.txt
    │       ├── taska1_stream0.txt  # Hub <-> Proxy stream
    │       └── taska1_stream1.txt  # Proxy <-> Lock stream
    └── performance/                # Reserved for Part D benchmark tools
```

---

## 3. Network Architecture & Execution Environment

The project runs in **Ubuntu under WSL2** on a Windows 11 host. Instead of multiple heavy VMs, the two-VM architecture from `Lab_Setup_Guide.pdf` is modeled using **Linux Network Namespaces (`ip netns`)**:

- **VM 1 (SmartLock Device / Server)**:
  - Namespace: `vm1_lock`
  - IP Address: `10.10.10.11/24` on interface `veth_lock`
  - Runs: `./lock_server instance.txt` listening on port `9030`
- **VM 2 (Home Hub / Attacker / Kali)**:
  - Namespace: `vm2_kali`
  - IP Address: `10.10.10.12/24` on interface `veth_kali`
  - Runs: `hub_client`, `tcpdump`, and exploit proxies
- **Isolation Properties**:
  - The veth pair links `10.10.10.11` $\leftrightarrow$ `10.10.10.12`. Ping between them takes $\approx 0.03$ ms.
  - There is no gateway to the internet (`ping 8.8.8.8` fails with `Network is unreachable`), strictly complying with isolated lab ethics.
- **Execution Convention**:
  Commands are invoked via WSL2 root:
  ```bash
  wsl -d Ubuntu -u root -- bash -c "<command>"
  ```
  Exploit binaries are compiled to `/tmp/` during test runs so that the repository remains clean of build artifacts.

---

## 4. Deterministic Instance Configuration (`instance.txt`)

Generated once from roll `23i-0614` via `./instance_generator 23i-0614` inside `lab/smartlock/`:

```ini
roll = 23i-0614
device_name = smartlock-23i-0614.local
device_suites = AES256-GCM,AES128-GCM,NULL
hub_id = home-hub
dh_p = 1036603071667
dh_g = 2
dh_b = 426299379703
dh_B = 561189784987
pin = summer283
pin_md5 = 8ce6450b7ffe96f90a954d690c4fc17f
static_nonce = 223b7032c9d5f666cd0974eb
flag = FLAG{c3603ab534897940}
port = 9030
rsa_priv_b64 = ... (2048-bit RSA private PEM base64)
rsa_pub_b64 = ... (2048-bit RSA public PEM base64)
```

---

## 5. Completed Work

### Commit History
- Baseline commit `0997586`: Network namespaces configured, instance generated, baseline normal session captured.
- Task 1 commit `baa566b`: Task 1 Negotiation Downgrade exploit implemented, evidence compartmentalized, flag recovered.
- The working tree is currently **clean**.

### Task 1 (Negotiation Downgrade — `TASKA1`) — Completed
- **Vulnerability**: Negotiation (`HELLO` / `SUITE`) is unauthenticated (no MAC/signature), and `NULL` cipher is supported.
- **Exploit**: [`23i-0614-G-TASKA1-V1.cpp`](file:///c:/Users/fahad/Desktop/Projects/Info%20Sec%20A2/23i-0614-G/exploits/23i-0614-G-TASKA1-V1.cpp) intercepts `HELLO`, rewrites `suites` to `NULL`.
- **Result**: Lock adopts `NULL` suite; record crypto is bypassed; greeting leaks `FLAG{c3603ab534897940}` in hex-encoded ASCII.
- **Evidence**: Stored in `23i-0614-G/evidence/taska1_downgrade/` (`.pcap`, terminal output, stream transcripts).
- **Answers**: `answers.txt` updated with `flag = FLAG{c3603ab534897940}`.

---

## 6. What To Do Next: Task 2 (Authentication & Pairing)

Stage 2 has two distinct deliverables:

### Part 2A: MITM Impersonation Exploit (`TASKA2`) — 4 Marks
- **File to Create**: `23i-0614-G/exploits/23i-0614-G-TASKA2-V1.cpp`
- **Vulnerabilities**:
  1. `hub_client.cpp` receives the lock's RSA certificate but **does not validate it against any trust anchor** (`/* certificate not checked */`).
  2. The Diffie-Hellman parameters ($p, g, B$) sent by the lock in `DH` are **completely unsigned**.
- **Exploit Architecture**:
  - Run an on-path proxy listening on port `8000`, forwarding to `10.10.10.11:9030`.
  - Maintain **two separate cryptographic sessions** under the full `AES256-GCM` cipher suite (unlike Task 1 which downgraded to NULL):
    - **Hub $\leftrightarrow$ Proxy**: Proxy presents its own DH public share $B_{proxy} = g^{b_{proxy}} \pmod p$. Proxy derives $k_{hub} = \text{session\_key}(A_{hub}^{b_{proxy}} \pmod p)$.
    - **Proxy $\leftrightarrow$ Lock**: Proxy acts as hub, generates its own DH client share $A_{proxy} = g^{a_{proxy}} \pmod p$. Proxy derives $k_{lock} = \text{session\_key}(B_{lock}^{a_{proxy}} \pmod p)$.
  - **Payload Interception & Re-encryption**:
    - When Lock sends greeting `MSG`, proxy decrypts using $k_{lock}$ and `static_nonce`, extracts `FLAG{c3603ab534897940}`, logs it, re-encrypts using $k_{hub}$ and `static_nonce`, and forwards to Hub.
    - Commands from Hub (`STATUS`, `UNLOCK`, `LOCK`, `QUIT`) are decrypted with $k_{hub}$, logged, re-encrypted with $k_{lock}$, and forwarded to Lock.
- **Automation & Evidence**:
  - Create `lab/scripts/run_taska2.sh`.
  - Save evidence into `23i-0614-G/evidence/taska2_mitm/`:
    - `taska2_mitm.pcap`
    - `taska2_output.txt`
    - `taska2_stream0.txt` (Hub $\leftrightarrow$ Proxy stream)
    - `taska2_stream1.txt` (Proxy $\leftrightarrow$ Lock stream)

### Part 2B: PIN Recovery (`cracked_pin`) — 2 Marks
- **Vulnerability**:
  - In `PAIR`, the hub sends `pinhash:8ce6450b7ffe96f90a954d690c4fc17f`.
  - This is an unsalted MD5 digest of a word from `pin_wordlist.txt` plus 3 decimal digits (`?d?d?d`).
  - Total search space is only $12 \times 1,000 = 12,000$ hashes.
- **Cracking Tool**:
  - Run `hashcat`:
    ```bash
    hashcat -m 0 -a 6 captured_pin.md5 ../smartlock/pin_wordlist.txt ?d?d?d
    ```
    Or write a fast standalone C++ offline cracker that reads `pin_wordlist.txt`, computes `MD5(word + ddd)`, and compares with the captured hash.
  - Recovered PIN is `summer283`.
- **Answers**: Update `cracked_pin = summer283` in `23i-0614-G/answers.txt`.

---

## 7. Remaining Tasks Roadmap

| Task | Title | Description | Key Deliverable |
| :--- | :--- | :--- | :--- |
| **Task 3** | Keying Recovery (`TASKA3`) | Solve discrete log $b$ from captured $B$ on 40-bit prime $p$ using Baby-Step Giant-Step (BSGS). Derive key $s = A^b \pmod p$ and decrypt greeting flag. | `23i-0614-G-TASKA3-V1.cpp`<br>`recovered_dh_b = 426299379703` |
| **Task 4** | Nonce Reuse (`TASKA4`) | Exploit GCM two-time pad across records reusing `static_nonce`. Compute $C_1 \oplus C_2 = P_1 \oplus P_2$ using known greeting prefix. | `23i-0614-G-TASKA4-V1.cpp`<br>`nonce_xor_hex` in `answers.txt` |
| **Task 5** | Replay Attack (`TASKA5`) | Replay captured `UNLOCK` record over a new TCP connection; verify the unlock counter increments. | `23i-0614-G-TASKA5-V1.cpp`<br>`evidence/taska5_replay/` |
| **Part B** | Design v2 | Write Threat Model, per-stage defenses, PIN protection at rest/in-flight, and Handshake Sequence Diagram. | Section in report PDF |
| **Part C** | Implement v2 | Complete `securelink2.cpp` implementing `strong_suites`, `choose_suite`, `derive_key` (HKDF), `make_nonce`, `seal`, `open_record`. Pass all 6 auto-checks. | `23i-0614-G/securelink2.cpp` |
| **Part D** | Performance Study | Benchmark v1 vs v2 handshake latency, record overhead, and throughput (10,000 records). | `23i-0614-G/performance/`<br>`23i-0614-G-TASKD-V1.cpp` |
| **Report** | Final PDF | Compile `23i-0614-G-REPORT.pdf` adhering to the required 20-page structure and inline evidence. | `23i-0614-G-REPORT.pdf` |

