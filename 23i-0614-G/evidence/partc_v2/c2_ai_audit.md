# Part C.2: AI-Audit Component (Record Layer)

- **Student**: Fahad Bin Faisal (23i-0614, Section G)
- **Course**: CS3002 Information Security — Assignment 2
- **Deliverable**: `evidence/partc_v2/c2_ai_audit.md`

---

### 1. The AI-Generated Draft Snippet

I prompted an AI tool to write `seal()` for `securelink2.cpp`. It produced this concise implementation:

```cpp
std::vector<uint8_t> seal(const std::vector<uint8_t>& key, uint64_t seqno, const std::string& pt) {
    std::vector<uint8_t> out(8 + pt.size() + 16);
    for (int i = 0; i < 8; ++i) out[7 - i] = (seqno >> (8 * i)) & 0xff; // Prepend seqno
    
    std::vector<uint8_t> nonce(12, 0); // Static zero nonce
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), nonce.data());
    int len = 0;
    EVP_EncryptUpdate(ctx, out.data() + 8, &len, (const unsigned char*)pt.data(), pt.size());
    int clen = len;
    EVP_EncryptFinal_ex(ctx, out.data() + 8 + clen, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + 8 + clen);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}
```

---

### 2. Cryptographic Flaws Pinpointed

Although the code compiles and decrypts normally, it contains two critical security defects:

1. **Missing Additional Authenticated Data (AAD) Binding**:
   - The AI placed `seqno` at the beginning of the wire packet (`out[0..7]`), but **never passed it into AES-GCM as AAD** (`EVP_EncryptUpdate` with a null output buffer).
   - **Vulnerability**: The 16-byte GCM authentication tag only seals the ciphertext body, leaving the 8-byte sequence number completely unauthenticated on the wire. An attacker can intercept a captured `UNLOCK` command sent at `seqno = 1`, overwrite the first 8 header bytes from `1` to `2`, and replay it when the lock expects message `2`. The GCM tag check would still pass, completely defeating replay protection.

2. **Static Nonce Reuse**:
   - The AI initialized a fixed zero nonce (`vector<uint8_t>(12, 0)`) for every record rather than deriving a unique IV per sequence number.
   - **Vulnerability**: Reusing the same `(key, nonce)` across records causes the AES-GCM keystream to repeat, recreating the Task 4 two-time pad vulnerability.

---

### 3. How I Corrected It

In my submitted [`securelink2.cpp`](file:///c:/Users/fahad/Desktop/Projects/Info%20Sec%20A2/23i-0614-G/securelink2.cpp):
1. **Dynamic Counter Nonce**: Derived a unique 12-byte IV for every message using `make_nonce(seqno)` (4 zero bytes + 8-byte big-endian sequence counter).
2. **Cryptographic AAD Binding**: Fed the 8-byte sequence number into AES-GCM as AAD:
   ```cpp
   EVP_EncryptUpdate(ctx, nullptr, &len, seqno_bytes, 8);
   ```
   Now, any on-the-wire modification to `seqno` immediately causes the 16-byte GCM tag verification to fail in `open_record()`.
