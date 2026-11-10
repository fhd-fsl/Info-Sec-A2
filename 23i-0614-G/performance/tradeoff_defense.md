# Part D: Performance Study and Trade-Off Analysis
**Student:** Fahad Bin Faisal (23i-0614, Section G)  
**Assignment:** CS3002 Information Security — Assignment 2  

---

### 1. Benchmark Measurements

The benchmark tool (`23i-0614-G-TASKD-V1.cpp`) ran 35 handshakes against both servers across the isolated network namespaces, measured 10,000 seal/open operations, and evaluated bulk throughput over 5 runs of 10,000 records (1 KiB each).

| Metric | SmartLock v1 | SmartLock v2 | Difference ($\Delta$) | Analysis |
| :--- | :---: | :---: | :---: | :--- |
| **Handshake Latency (Mean $\pm$ StdDev)** | $1.64 \pm 0.57\text{ ms}$ | $3.38 \pm 1.33\text{ ms}$ | $+1.74\text{ ms}$ ($+106\%$) | 2048-bit DHE + RSA signature + HKDF derivation |
| **Per-Record Wire Overhead** | $16\text{ bytes}$ | $24\text{ bytes}$ | $+8\text{ bytes}$ | 8-byte big-endian sequence counter + 16B GCM tag |
| **Record Protect Latency (Seal)** | $0.5166\text{ }\mu\text{s}$ | $0.5239\text{ }\mu\text{s}$ | $+0.0073\text{ }\mu\text{s}$ | Sub-microsecond AES-NI operation; no bottleneck |
| **Record Open Latency (Decrypt)** | $0.5166\text{ }\mu\text{s}$ | $0.5453\text{ }\mu\text{s}$ | $+0.0287\text{ }\mu\text{s}$ | Sequence parsing and AAD verification |
| **Protect Throughput (10k $\times$ 1 KiB)** | $913.26\text{ MB/s}$ | $1444.29\text{ MB/s}$ | $+531.03\text{ MB/s}$ | Pre-allocated contiguous buffer in v2 vs dynamic resizing in v1 |
| **Open Throughput (10k $\times$ 1 KiB)** | $1000.13\text{ MB/s}$ | $1090.64\text{ MB/s}$ | $+90.51\text{ MB/s}$ | Wireline line-rate decryption |

---

### 2. Engineering Trade-Off Defense

#### A. Handshake Latency (+1.74 ms)
SmartLock v1 handshakes took $1.64\text{ ms}$ only because the lock used an insecure 40-bit Diffie-Hellman exchange with zero certificate checking and zero transcript signatures. While fast, this allowed an attacker to recover private keys in 0.38 seconds via Baby-Step Giant-Step (BSGS) and mount active MITM parameter substitution.

SmartLock v2 increases mean handshake latency to $3.38\text{ ms}$ ($+1.74\text{ ms}$). This overhead covers:
1. Safe prime modular exponentiation (`dh2048`, RFC 3526 Group 14) providing $\approx 112$ bits of symmetric security and forward secrecy.
2. Device certificate validation and RSA-SHA256 signature verification over the transcript (`offer || suite || B`).
3. RFC 5869 HKDF-SHA256 key derivation separating client-to-server (`c2s`) and server-to-client (`s2c`) traffic.

In an IoT door lock, handshakes occur once per session when a user arrives or pairs. The human perception threshold for interactive latency is approximately $100\text{ ms}$. An added latency of $1.74\text{ ms}$ consumes less than $1.8\%$ of this threshold, meaning the security improvement is completely imperceptible to users.

#### B. Per-Record Wire Overhead (+8 Bytes)
SmartLock v1 added 16 bytes per record (the AES-GCM tag). However, because it relied on a static hardcoded nonce (`static_nonce`), repeated messages leaked plaintext via keystream reuse ($C_1 \oplus C_2 = P_1 \oplus P_2$), and the absence of sequence numbers allowed replay attacks.

SmartLock v2 prepends an 8-byte big-endian sequence counter on the wire (`record = seqno || ciphertext || tag`), totaling 24 bytes of wire overhead.
- On standard Wi-Fi or Ethernet networks with a 1500-byte MTU, 8 bytes is less than $0.53\%$ of frame capacity.
- Binding this 8-byte counter to the AES-GCM Additional Authenticated Data (AAD) ensures that any replayed, dropped, or out-of-order packet fails authentication immediately, stopping replay attacks.

#### C. Throughput and Memory Efficiency
Throughput here measures the raw in-memory cryptographic processing rate of the CPU (in MB/s) using AES-256-GCM hardware instructions (AES-NI and CLMUL).

Interestingly, v2 achieved higher protect throughput ($1,444\text{ MB/s}$ vs. $913\text{ MB/s}$). This difference stems from memory allocation efficiency:
- In v1 (`record_encrypt`), the scaffold allocated a separate `std::vector<uint8_t> tag(16)` on the heap for every record and then called `out.insert()`, forcing dynamic buffer reallocations and memory copies ($20,000$ heap operations per run).
- In v2 (`seal`), the entire record buffer (`kSeqLen + plaintext.size() + kTagLen`) is allocated once up front, and the sequence bytes, ciphertext, and tag are written directly to their destination offsets. This avoids heap reallocation overhead and optimizes CPU cache utilization.

Since a physical door lock transmits small commands (`STATUS`, `UNLOCK`, `LOCK`, all $< 64\text{ bytes}$) at roughly one message per second, real-world bandwidth is below $0.1\text{ KB/s}$. Utilizing less than $0.0001\%$ of available cryptographic throughput, SmartLock v2 guarantees robust security without affecting responsiveness or battery life.
