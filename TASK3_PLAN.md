# Task 3 (Stage 3: Keying Recovery) Architecture & Implementation Plan

## 1. Overview & Context

- **Course:** CS3002 Information Security — Assignment 2
- **Topic:** Stage 3: Keying Vulnerability Analysis & Discrete Logarithm Recovery
- **Target Component:** SmartLock v1 Protocol Key Agreement (`hub_client.cpp` / `lock_server.cpp`)
- **Deliverables Referenced:**
  - `23i-0614-G/answers.txt` (`recovered_dh_b` field)
  - `23i-0614-G/exploits/23i-0614-G-TASKA3-V1.cpp` (BSGS solver & passive decryption tool)
  - `23i-0614-G/evidence/taska3_keying/` (Compartmentalized test capture and logs)

---

## 2. Cryptographic Weakness Analysis

Stage 3 in SmartLock v1 contains three primary cryptographic shortcomings:

### Weakness 3.1: Small Diffie-Hellman Group Modulus ($\approx 40$ bits)
In `lock_server.cpp`, the Diffie-Hellman prime $p$ derived for instance `23i-0614` is:
$$p = 1036603071667 \approx 2^{39.9}$$
Diffie-Hellman's security fundamentally relies on the intractability of the Discrete Logarithm Problem (DLP). In standard deployments, $p \ge 2048$ bits is mandatory. A 40-bit modulus is vulnerable to meet-in-the-middle algorithms such as Baby-Step Giant-Step (BSGS) in $\mathcal{O}(\sqrt{p})$ time and space.
$$\sqrt{p} \approx \sqrt{1036603071667} \approx 1,018,138 \text{ operations}$$
A search space of $\approx 10^6$ operations can be evaluated in under $100\text{ ms}$ on modern commodity hardware using fewer than $20\text{ MB}$ of memory.

### Weakness 3.2: Direct Secret Mapping (Lack of Key Derivation Function)
In `slink.hpp`, `session_key()` turns the raw 40-bit shared secret $s = A^b \pmod p$ directly into the 256-bit AES key:
```cpp
inline std::vector<uint8_t> session_key(uint64_t shared, const std::string& suite) {
    int kl = suite_keylen(suite);
    std::vector<uint8_t> k(kl, 0);
    for (int i = kl - 1; i >= 0 && shared; --i) { k[i] = shared & 0xff; shared >>= 8; }
    return k;
}
```
Using the raw group element directly as a symmetric key violates cryptographic design principles. A secure protocol must use a Key Derivation Function (such as HKDF-SHA256) to extract uniform entropy and bind the key to context parameters (identities, session nonces, handshake transcripts).

### Weakness 3.3: Static Exponent $b$ (Loss of Forward Secrecy)
The lock retains the same private exponent $b$ across all sessions. Forward secrecy requires that compromising long-term private keys does not expose past session keys. Because $b$ is static:
- Recovering $b$ once from any single capture allows an attacker to retroactively decrypt all past sessions and predict all future sessions.

---

## 3. Mathematical Strategy: Baby-Step Giant-Step (BSGS)

Given captured public parameters:
- Prime $p = 1036603071667$, Generator $g = 2$
- Lock Public Share $B = g^b \pmod p = 561189784987$
- Hub Public Share $A = g^a \pmod p$

We solve for $b$ where $g^b \equiv B \pmod p$:
1. Let $m = \lceil\sqrt{p}\rceil = 1,018,138$.
2. Decompose $b$ as $b = i \cdot m - j$, where $0 \le j < m$ and $1 \le i \le m$.
3. Substitute into the congruence:
   $$g^{i \cdot m - j} \equiv B \pmod p \iff (g^m)^i \equiv B \cdot g^j \pmod p$$
4. **Baby Steps Phase:**
   - Compute and store in a hash map or sorted vector:
     $$\text{Table}[B \cdot g^j \bmod p] = j \quad \text{for } j \in [0, m-1]$$
5. **Giant Steps Phase:**
   - Precompute step factor $F = g^m \bmod p$.
   - For $i = 1, 2, \dots, m$:
     - Compute $\gamma = F^i \bmod p$.
     - If $\gamma \in \text{Table}$, retrieve $j$.
     - The private exponent is:
       $$b = i \cdot m - j$$
6. **Key Derivation & Decryption:**
   - Compute shared secret $s = A^b \bmod p$.
   - Format symmetric key: `key = session_key(s, "AES256-GCM")`.
   - Decrypt intercepted greeting `ct` using `nonce` with AES-256-GCM, verifying the 16-byte authentication tag.
   - Extract `FLAG{c3603ab534897940}`.

---

## 4. Architecture of the Exploit Tool (`23i-0614-G-TASKA3-V1.cpp`)

Unlike Tasks 1 and 2, Task 3 is a **purely passive eavesdropping attack**:
- No packets are modified on the wire.
- The tool parses captured protocol transcripts (`--stream <transcript_path>`) or direct parameters (`--solve <p> <g> <B>`), satisfying the oral viva requirement where an unseen capture must be analyzed dynamically.

```
       [ Eavesdropped Normal Session (PCAP / Stream) ]
                              │
             ┌────────────────┴────────────────┐
             ▼                                 ▼
   Extract DH: (p, g, B)             Extract DHCLIENT: (A)
   Extract MSG: (nonce, ct)
             │
             ▼
   [ BSGS Solver (O(√p)) ] ────────> Recovered b = 426299379703
             │
             ▼
   Compute Shared Secret s = A^b mod p
             │
             ▼
   Derive AES-256 Key (session_key)
             │
             ▼
   AES-256-GCM Decrypt (ct, nonce)
             │
             ▼
   [ FLAG RECOVERED: FLAG{c3603ab534897940} ]
```

---

## 5. Implementation Milestones

1. **Source Implementation:**
   - Write [`23i-0614-G/exploits/23i-0614-G-TASKA3-V1.cpp`](file:///c:/Users/fahad/Desktop/Projects/Info%20Sec%20A2/23i-0614-G/exploits/23i-0614-G-TASKA3-V1.cpp) with 64-bit modular arithmetic (`__uint128_t`), BSGS solver, wire format parser, and OpenSSL AES-256-GCM decryption.
2. **Automation Script:**
   - Create `lab/scripts/run_taska3.sh` to capture a clean normal session under network namespaces, export the transcript via `tshark`, run the solver, and save logs.
3. **Evidence Packaging:**
   - Collect artifacts in `23i-0614-G/evidence/taska3_keying/`:
     - `taska3_keying.pcap`
     - `taska3_output.txt`
     - `taska3_stream.txt`
     - `recovered_key.txt`
4. **Answers Update:**
   - Update `23i-0614-G/answers.txt` with `recovered_dh_b = 426299379703`.

---

## 6. Remediation in v2 (Parts B & C)

| v1 Weakness | v2 Defense Implementation |
| :--- | :--- |
| 40-bit Small DH Prime | RFC 3526 2048-bit MODP Group (MODP-2048) in `dh2048.hpp` ($\mathcal{O}(\sqrt{p}) \approx 2^{1024}$, computationally infeasible). |
| Raw Secret Key Mapping | HKDF-SHA256 (`sl2::derive_key`) extracting uniform pseudo-random keys bound to session context (`c2s` and `s2c`). |
| Static Device Exponent | Ephemeral Diffie-Hellman (DHE): fresh keypair generated on every connection, providing Perfect Forward Secrecy (PFS). |

