// Self-check test harness for SmartLock v2 securelink2.cpp (Part C.1 checks)
#include "securelink2.hpp"
#include <iostream>
#include <cassert>
#include <cstring>
#include <fstream>
#include <algorithm>

using namespace sl2;

void check1() {
    std::cout << "[Check 1] Cipher Suite Policy (No NULL / No Downgrade)... ";
    auto suites = strong_suites();
    for (const auto& s : suites) {
        if (s == "NULL") {
            std::cerr << "FAIL: strong_suites contains NULL\n";
            exit(1);
        }
    }
    if (choose_suite({"NULL"}) != "") {
        std::cerr << "FAIL: choose_suite accepted NULL\n";
        exit(1);
    }
    if (choose_suite({"UNKNOWN", "TRASH"}) != "") {
        std::cerr << "FAIL: choose_suite accepted unknown\n";
        exit(1);
    }
    if (choose_suite({"NULL", "AES128-GCM", "AES256-GCM"}) != "AES256-GCM") {
        std::cerr << "FAIL: choose_suite did not pick strongest available suite\n";
        exit(1);
    }
    if (choose_suite({"AES128-GCM"}) != "AES128-GCM") {
        std::cerr << "FAIL: choose_suite failed to negotiate AES128-GCM\n";
        exit(1);
    }
    std::cout << "PASS\n";
}

void check2() {
    std::cout << "[Check 2] Key Derivation via KDF (Not raw secret)... ";
    std::vector<uint8_t> secret(256, 0x5a);
    auto k_256_c2s = derive_key(secret, "AES256-GCM", "c2s");
    auto k_256_s2c = derive_key(secret, "AES256-GCM", "s2c");
    auto k_128_c2s = derive_key(secret, "AES128-GCM", "c2s");

    if (k_256_c2s.size() != 32) { std::cerr << "FAIL: 256 keylen != 32\n"; exit(1); }
    if (k_256_s2c.size() != 32) { std::cerr << "FAIL: s2c keylen != 32\n"; exit(1); }
    if (k_128_c2s.size() != 16) { std::cerr << "FAIL: 128 keylen != 16\n"; exit(1); }

    // Must not be raw secret slice
    if (std::memcmp(k_256_c2s.data(), secret.data(), 32) == 0) {
        std::cerr << "FAIL: derived key equals raw secret slice\n";
        exit(1);
    }
    // Directional keys must differ
    if (k_256_c2s == k_256_s2c) {
        std::cerr << "FAIL: k_c2s == k_s2c (no direction separation)\n";
        exit(1);
    }
    // Suite keys must differ
    if (std::memcmp(k_256_c2s.data(), k_128_c2s.data(), 16) == 0) {
        std::cerr << "FAIL: suite separation missing\n";
        exit(1);
    }
    std::cout << "PASS\n";
}

void check3() {
    std::cout << "[Check 3] Unique Nonce per Record under Key... ";
    auto n0 = make_nonce(0);
    auto n1 = make_nonce(1);
    auto n2 = make_nonce(2);
    auto n_large = make_nonce(0x0102030405060708ULL);

    if (n0.size() != 12 || n1.size() != 12 || n_large.size() != 12) {
        std::cerr << "FAIL: nonce size != 12\n";
        exit(1);
    }
    if (n0 == n1 || n1 == n2 || n0 == n2) {
        std::cerr << "FAIL: consecutive nonces are identical\n";
        exit(1);
    }
    std::cout << "PASS\n";
}

void check4() {
    std::cout << "[Check 4] AEAD Seal and Open Correctness... ";
    std::vector<uint8_t> secret(256, 0x77);
    auto k256 = derive_key(secret, "AES256-GCM", "c2s");
    auto k128 = derive_key(secret, "AES128-GCM", "c2s");
    std::string msg = "Paired with SmartLock. Pairing secret: FLAG{test_flag_1234}";

    // Test AES-256-GCM
    auto rec256 = seal(k256, 0, msg);
    if (rec256.size() != 8 + msg.size() + 16) {
        std::cerr << "FAIL: record overhead != 24 bytes\n";
        exit(1);
    }
    std::string opened256 = open_record(k256, rec256, 0);
    if (opened256 != msg) {
        std::cerr << "FAIL: opened plaintext mismatch in AES-256\n";
        exit(1);
    }

    // Test AES-128-GCM
    auto rec128 = seal(k128, 5, msg);
    std::string opened128 = open_record(k128, rec128, 5);
    if (opened128 != msg) {
        std::cerr << "FAIL: opened plaintext mismatch in AES-128\n";
        exit(1);
    }

    // Test Tampering rejection
    auto tampered = rec256;
    tampered.back() ^= 0x01; // flip tag bit
    bool caught_tag_tamper = false;
    try {
        open_record(k256, tampered, 0);
    } catch (...) {
        caught_tag_tamper = true;
    }
    if (!caught_tag_tamper) {
        std::cerr << "FAIL: tampered auth tag was not rejected!\n";
        exit(1);
    }
    std::cout << "PASS\n";
}

void check5() {
    std::cout << "[Check 5] Replay & Out-of-Order Record Rejection... ";
    std::vector<uint8_t> secret(256, 0x88);
    auto key = derive_key(secret, "AES256-GCM", "c2s");
    std::string msg = "UNLOCK";

    auto rec_seq0 = seal(key, 0, msg);
    auto rec_seq1 = seal(key, 1, msg);

    // Opening seq0 when expecting seq1 must throw
    bool caught_replay = false;
    try {
        open_record(key, rec_seq0, 1);
    } catch (...) {
        caught_replay = true;
    }
    if (!caught_replay) {
        std::cerr << "FAIL: replayed record was accepted!\n";
        exit(1);
    }

    // Opening seq2 when expecting seq1 must throw
    bool caught_out_of_order = false;
    try {
        open_record(key, rec_seq1, 0);
    } catch (...) {
        caught_out_of_order = true;
    }
    if (!caught_out_of_order) {
        std::cerr << "FAIL: out-of-order record was accepted!\n";
        exit(1);
    }
    std::cout << "PASS\n";
}

void check6(const std::string& filepath) {
    std::cout << "[Check 6] Source Scan (KDF keyword present, no md5, no todo)... ";
    std::ifstream file(filepath);
    if (!file) {
        std::cerr << "FAIL: cannot open " << filepath << "\n";
        exit(1);
    }
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    std::string lower_content = content;
    std::transform(lower_content.begin(), lower_content.end(), lower_content.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    bool has_kdf = (lower_content.find("hkdf") != std::string::npos) ||
                   (lower_content.find("evp_kdf") != std::string::npos) ||
                   (lower_content.find("pbkdf2") != std::string::npos) ||
                   (lower_content.find("scrypt") != std::string::npos);
    if (!has_kdf) {
        std::cerr << "FAIL: source does not contain required KDF keyword (hkdf/evp_kdf/pbkdf2/scrypt)\n";
        exit(1);
    }

    if (lower_content.find("md5") != std::string::npos) {
        std::cerr << "FAIL: source contains forbidden keyword 'md5'\n";
        exit(1);
    }

    if (lower_content.find("todo") != std::string::npos) {
        std::cerr << "FAIL: source contains forbidden keyword 'todo'\n";
        exit(1);
    }
    std::cout << "PASS\n";
}

int main(int argc, char** argv) {
    std::string src_path = (argc > 1) ? argv[1] : "securelink2.cpp";
    std::cout << "====================================================\n";
    std::cout << "SmartLock v2 (securelink2.cpp) Automated Self-Check\n";
    std::cout << "Testing: " << src_path << "\n";
    std::cout << "====================================================\n";
    check1();
    check2();
    check3();
    check4();
    check5();
    check6(src_path);
    std::cout << "====================================================\n";
    std::cout << "ALL 6 SELF-CHECKS PASSED (18 / 18 Marks)!\n";
    std::cout << "====================================================\n";
    return 0;
}

