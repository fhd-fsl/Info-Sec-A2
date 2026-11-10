# Part C.2: Cryptographic AI-Audit Component

- **Student Name**: Fahad Bin Faisal
- **Student Roll Number**: 23i-0614
- **Section**: G
- **Course**: CS3002 Information Security — Assignment 2
- **Deliverable**: `evidence/partc_v2/c2_ai_audit.md`

---

## 1. Objective & Scenario

As mandated in the Assignment 2 specification (§C.2):
> *"Include the AI-audit component: ask an AI tool to write one piece (for example the record layer), then state in your own words what was weak or wrong in the cryptography it produced and how you corrected it."*

We prompted a generic AI coding assistant to implement the record layer (`seal` and `open_record`) and the key derivation module (`derive_key`) for `securelink2.cpp`.

---

## 2. The AI-Generated Draft Code

```cpp
// --- AI Generated Draft Snippet ---
namespace sl2_ai_draft {

// Flaw 1: Naive Key Derivation
std::vector<uint8_t> derive_key(const std::vector<uint8_t>& shared_secret,
                                const std::string& suite, const std::string& context) {
    // AI concatenated secret and context and hashed with a single SHA-256 pass
    std::string data(shared_secret.begin(), shared_secret.end());
    data += suite + context;
    unsigned char md[32];
    unsigned int len = 0;
    EVP_Digest(data.data(), data.size(), md, &len, EVP_sha256(), nullptr);
    int kl = (suite == "AES256-GCM") ? 32 : 16;
    return std::vector<uint8_t>(md, md + kl);
}

// Flaw 2: Record Layer missing AAD binding
std::vector<uint8_t> seal(const std::vector<uint8_t>& key, uint64_t seqno, const std::string& pt) {
    // AI prepended seqno to record, but only encrypted plaintext and never passed seqno as AAD!
    std::vector<uint8_t> out(8 + pt.size() + 16);
    for (int i = 0; i < 8; ++i) out[7 - i] = (seqno >> (8 * i)) & 0xff;
    
    // AI used a static zero nonce instead of calling make_nonce(seqno)
    std::vector<uint8_t> nonce(12, 0); 
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), nonce.data());
    int len = 0;
    // OMITTED: EVP_EncryptUpdate for AAD!
    EVP_EncryptUpdate(ctx, out.data() + 8, &len, (const unsigned char*)pt.data(), pt.size());
    int clen = len;
    EVP_EncryptFinal_ex(ctx, out.data() + 8 + clen, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + 8 + clen);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

std::string open_record(const std::vector<uint8_t>& key, const std::vector<uint8_t>& record, uint64_t expected_seqno) {
    uint64_t rec_seq = 0;
    for (int i = 0; i < 8; ++i) rec_seq = (rec_seq << 8) | record[i];
    if (rec_seq != expected_seqno) throw std::runtime_error("seqno mismatch");
    // Decrypts ciphertext, but never validated seqno integrity in AEAD!
    ...
}
}
```

---

## 3. Cryptographic Audit & Critique (In My Own Words)

Upon reviewing the AI-generated implementation, I identified **two critical cryptographic vulnerabilities** that would compromise the security of SmartLock v2:

### Critique 1: Missing Additional Authenticated Data (AAD) Binding in the Record Layer
- **The Weakness**: While the AI draft parsed and checked `seqno` in plaintext at the beginning of the buffer, it **failed to feed the 8-byte sequence number into AES-GCM as Additional Authenticated Data (AAD)** (`EVP_EncryptUpdate`/`EVP_DecryptUpdate` with `out = nullptr`). Furthermore, it encrypted records using a static zero nonce rather than deriving a unique IV from `seqno`.
- **The Exploit Impact**:
  Because `seqno` was not authenticated by the 16-byte GHASH tag, the sequence number was completely mutable on the wire!
  An on-path network adversary could intercept an authentic, encrypted `UNLOCK` record sent at `seqno = 1`, alter the first 8 cleartext header bytes from `1` to `2`, and replay the record when the lock is expecting message `seqno = 2`. Because the 16-byte tag only covered the ciphertext body, the GCM tag verification would pass, completely defeating the anti-replay mechanism!
- **How I Corrected It**:
  1. Mandated that the 12-byte nonce is derived dynamically via `make_nonce(seqno)` (4 zero bytes + 8-byte big-endian sequence counter), guaranteeing that no two records under the same directional key ever share an IV.
  2. Fed the 8-byte sequence number directly into `EVP_EncryptUpdate(ctx, nullptr, &len, seqno_bytes, 8)` during `seal()` and `EVP_DecryptUpdate(ctx, nullptr, &len, record.data(), 8)` during `open_record()`.
  3. Consequently, any tampering with the wire sequence number causes the 16-byte GHASH tag check to fail instantly, preventing splicing, reordering, and replay.

---

### Critique 2: Raw Hash Function Misuse Instead of an Extract-and-Expand KDF
- **The Weakness**: The AI generated `derive_key()` by running a single pass of `SHA256(shared_secret || suite || context)` using `EVP_Digest`.
- **The Exploit Impact**:
  1. *Non-Uniform Entropy Distribution*: Diffie-Hellman group elements $g^{ab} \bmod p$ are mathematically structured and not uniformly distributed bitstrings. Standard hash functions are not designed as cryptographic randomness extractors. Without an RFC 5869 extract step (`HKDF-Extract`), the resulting key material retains statistical bias.
  2. *Lack of Domain Separation*: Concatenating `suite` and `context` without delimiters or length-prefixing creates ambiguity (`"AES256-GCM" + "c2s"` vs potential overlapping namespaces).
  3. *Failure of Automated Checks*: Check #6 of the assignment specification explicitly scans the submission source code to ensure `hkdf` or `evp_kdf` is utilized, which the raw `EVP_Digest` implementation fails.
- **How I Corrected It**:
  1. Replaced the ad-hoc digest with standard **RFC 5869 HKDF-SHA256** using OpenSSL's `EVP_KDF_fetch(nullptr, "HKDF", nullptr)` and `EVP_KDF_CTX`.
  2. Provided an explicit domain-separation salt (`"SmartLock-v2-HKDF-Salt"`).
  3. Built a structured info parameter string (`suite + "|" + context`), cleanly separating keys between directions (`"c2s"` and `"s2c"`) and across negotiated cipher suites.

