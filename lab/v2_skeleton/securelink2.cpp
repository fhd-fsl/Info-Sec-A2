// Name: Fahad Bin Faisal
// Student ID: 23i-0614
// Section: G
// Assignment: CS3002 Information Security - Assignment 2
// Module: securelink2.cpp - SmartLock v2 Record and Policy Implementation
//
// Implements:
//   - strong_suites(): Accept only strong AEAD suites (never NULL).
//   - choose_suite(): Negotiate strongest common suite or abort.
//   - derive_key(): RFC 5869 HKDF-SHA256 via OpenSSL EVP_KDF for directional keys.
//   - make_nonce(): 96-bit deterministic counter nonce per sequence number.
//   - seal(): AES-GCM AEAD record encryption binding sequence number as AAD.
//   - open_record(): AEAD record decryption verifying strict sequence number and auth tag.

#include "securelink2.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace sl2 {

namespace {

constexpr size_t kSeqLen = 8;
constexpr size_t kNonceLen = 12;
constexpr size_t kTagLen = 16;
constexpr size_t kMinRecordLen = kSeqLen + kTagLen;

}  // namespace

std::vector<std::string> strong_suites() {
    return {"AES256-GCM", "AES128-GCM"};
}

std::string choose_suite(const std::vector<std::string>& hub_offer) {
    const auto accepted = strong_suites();
    for (const auto& preferred : accepted) {
        for (const auto& offered : hub_offer) {
            if (offered == preferred) {
                return preferred;
            }
        }
    }
    return "";
}

std::vector<uint8_t> derive_key(const std::vector<uint8_t>& shared_secret,
                                const std::string& suite, const std::string& context) {
    if (shared_secret.empty()) {
        throw std::runtime_error("derive_key: shared_secret cannot be empty");
    }

    const int target_len = keylen(suite);
    if (target_len <= 0) {
        throw std::runtime_error("derive_key: unsupported cipher suite");
    }

    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) {
        throw std::runtime_error("derive_key: failed to fetch HKDF implementation");
    }

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) {
        throw std::runtime_error("derive_key: failed to create EVP_KDF_CTX");
    }

    char digest_name[] = "SHA256";
    const std::string salt = "SmartLock-v2-HKDF-Salt";
    const std::string info = suite + "|" + context;

    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", digest_name, 0);
    params[1] = OSSL_PARAM_construct_octet_string(
        "key", const_cast<uint8_t*>(shared_secret.data()), shared_secret.size());
    params[2] = OSSL_PARAM_construct_octet_string(
        "salt", const_cast<char*>(salt.data()), salt.size());
    params[3] = OSSL_PARAM_construct_octet_string(
        "info", const_cast<char*>(info.data()), info.size());
    params[4] = OSSL_PARAM_construct_end();

    std::vector<uint8_t> derived(static_cast<size_t>(target_len), 0);
    const int ret = EVP_KDF_derive(kctx, derived.data(), derived.size(), params);
    EVP_KDF_CTX_free(kctx);

    if (ret <= 0) {
        throw std::runtime_error("derive_key: EVP_KDF_derive failed");
    }

    return derived;
}

std::vector<uint8_t> make_nonce(uint64_t seqno) {
    std::vector<uint8_t> nonce(kNonceLen, 0);
    for (size_t i = 0; i < kSeqLen; ++i) {
        nonce[kNonceLen - 1 - i] = static_cast<uint8_t>((seqno >> (8 * i)) & 0xff);
    }
    return nonce;
}

std::vector<uint8_t> seal(const std::vector<uint8_t>& key, uint64_t seqno,
                          const std::string& plaintext) {
    if (key.size() != 16 && key.size() != 32) {
        throw std::runtime_error("seal: invalid key size");
    }

    const EVP_CIPHER* cipher = (key.size() == 32) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    const auto nonce = make_nonce(seqno);

    uint8_t seqno_bytes[kSeqLen];
    for (size_t i = 0; i < kSeqLen; ++i) {
        seqno_bytes[kSeqLen - 1 - i] = static_cast<uint8_t>((seqno >> (8 * i)) & 0xff);
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("seal: EVP_CIPHER_CTX_new failed");
    }

    bool ok = true;
    ok = ok && (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1);
    ok = ok && (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1);

    int len = 0;
    ok = ok && (EVP_EncryptUpdate(ctx, nullptr, &len, seqno_bytes, static_cast<int>(kSeqLen)) == 1);

    std::vector<uint8_t> record(kSeqLen + plaintext.size() + kTagLen);
    std::memcpy(record.data(), seqno_bytes, kSeqLen);

    int total_cipher_len = 0;
    if (!plaintext.empty()) {
        ok = ok && (EVP_EncryptUpdate(
            ctx, record.data() + kSeqLen, &len,
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            static_cast<int>(plaintext.size())) == 1);
        total_cipher_len = len;
    }

    ok = ok && (EVP_EncryptFinal_ex(ctx, record.data() + kSeqLen + total_cipher_len, &len) == 1);
    total_cipher_len += len;

    record.resize(kSeqLen + static_cast<size_t>(total_cipher_len) + kTagLen);
    ok = ok && (EVP_CIPHER_CTX_ctrl(
        ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagLen),
        record.data() + kSeqLen + total_cipher_len) == 1);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        throw std::runtime_error("seal: AES-GCM encryption failed");
    }

    return record;
}

std::string open_record(const std::vector<uint8_t>& key, const std::vector<uint8_t>& record,
                        uint64_t expected_seqno) {
    if (key.size() != 16 && key.size() != 32) {
        throw std::runtime_error("open_record: invalid key size");
    }
    if (record.size() < kMinRecordLen) {
        throw std::runtime_error("open_record: record shorter than minimum framing header + tag");
    }

    uint64_t record_seqno = 0;
    for (size_t i = 0; i < kSeqLen; ++i) {
        record_seqno = (record_seqno << 8) | record[i];
    }

    if (record_seqno != expected_seqno) {
        throw std::runtime_error("open_record: sequence number mismatch (replay or reorder detected)");
    }

    const size_t ciphertext_len = record.size() - kMinRecordLen;
    const uint8_t* ciphertext_ptr = record.data() + kSeqLen;
    const uint8_t* tag_ptr = record.data() + kSeqLen + ciphertext_len;

    const auto nonce = make_nonce(expected_seqno);
    const EVP_CIPHER* cipher = (key.size() == 32) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("open_record: EVP_CIPHER_CTX_new failed");
    }

    bool ok = true;
    ok = ok && (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1);
    ok = ok && (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1);

    int len = 0;
    ok = ok && (EVP_DecryptUpdate(ctx, nullptr, &len, record.data(), static_cast<int>(kSeqLen)) == 1);

    std::vector<uint8_t> plaintext(ciphertext_len);
    int total_pt_len = 0;
    if (ciphertext_len > 0) {
        ok = ok && (EVP_DecryptUpdate(
            ctx, plaintext.data(), &len, ciphertext_ptr, static_cast<int>(ciphertext_len)) == 1);
        total_pt_len = len;
    }

    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagLen),
                                    const_cast<uint8_t*>(tag_ptr)) == 1);

    const int final_ok = ok ? EVP_DecryptFinal_ex(ctx, plaintext.data() + total_pt_len, &len) : 0;
    EVP_CIPHER_CTX_free(ctx);

    if (!ok || final_ok <= 0) {
        throw std::runtime_error("open_record: AEAD authentication tag verification failed");
    }

    total_pt_len += len;
    plaintext.resize(static_cast<size_t>(total_pt_len));

    return std::string(plaintext.begin(), plaintext.end());
}

}  // namespace sl2
