// Name: Fahad Bin Faisal
// Student ID: 23i-0614
// Section: G
// Assignment: CS3002 Information Security - Assignment 2
// Task: TASKD - Performance Study (v1 vs v2 Comparative Benchmark)
//
// Measurements Conducted:
//   1. Handshake Latency (>= 30 runs, default 50 runs):
//      - v1: TCP connect -> HELLO (AES256-GCM) -> SUITE -> CERT -> PAIR -> 40-bit DH -> DHCLIENT -> decrypt greeting
//      - v2: TCP connect -> HELLO (AES256-GCM) -> SUITE -> CERT (pinned RSA verify) -> PAIR -> 2048-bit DHE (RSA signed) -> DHCLIENT -> HKDF-SHA256 -> open greeting
//   2. Per-Record Overhead:
//      - Wire byte overhead (extra bytes beyond plaintext): v1 (16 bytes tag) vs v2 (24 bytes: 8B seqno + 16B tag)
//      - Latency to protect and open individual records (10,000 iterations each)
//   3. Throughput (1 KiB records, >= 10,000 records/run, >= 5 runs):
//      - Encryption and decryption throughput in MB/s (1024 * 1024 bytes/sec)
//
// Compiler Flags: -std=c++17 -O2 -Wall -lcrypto

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include "../../lab/smartlock/slink.hpp"
#include "../../lab/smartlock/pki.hpp"
#include "../../lab/v2_skeleton/dh2048.hpp"
#include "../../lab/v2_skeleton/securelink2.hpp"

namespace {

using Clock = std::chrono::high_resolution_clock;
using TimePoint = std::chrono::time_point<Clock>;

struct Stats {
    double mean = 0.0;
    double stddev = 0.0;
    double min_val = 0.0;
    double max_val = 0.0;
};

Stats compute_stats(const std::vector<double>& values) {
    if (values.empty()) return {0.0, 0.0, 0.0, 0.0};
    double sum = std::accumulate(values.begin(), values.end(), 0.0);
    double mean = sum / values.size();
    double sq_sum = 0.0;
    for (double v : values) {
        sq_sum += (v - mean) * (v - mean);
    }
    double variance = (values.size() > 1) ? (sq_sum / (values.size() - 1)) : 0.0;
    double stddev = std::sqrt(variance);
    double min_val = *std::min_element(values.begin(), values.end());
    double max_val = *std::max_element(values.begin(), values.end());
    return {mean, stddev, min_val, max_val};
}

// ---- v1 Client Handshake (AES256-GCM) -----------------------------------
double measure_v1_handshake(const std::string& host, int port,
                            std::map<std::string, std::string>& cfg) {
    auto t0 = Clock::now();

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) throw std::runtime_error("socket failed");
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &a.sin_addr);
    if (connect(s, (sockaddr*)&a, sizeof a) < 0) {
        close(s);
        throw std::runtime_error("v1 connect failed");
    }

    slink::Reader r(s);
    slink::Msg m;

    slink::send_msg(s, {{"type", "HELLO"}, {"suites", "AES256-GCM,AES128-GCM,NULL"}});
    if (!r.recv(m) || m["type"] != "SUITE") { close(s); throw std::runtime_error("v1 SUITE failed"); }
    std::string suite = m["suite"];

    if (!r.recv(m) || m["type"] != "CERT") { close(s); throw std::runtime_error("v1 CERT failed"); }
    slink::send_msg(s, {{"type", "PAIR"}, {"hub", cfg["hub_id"]}, {"pinhash", slink::md5hex(cfg["pin"])}});

    if (!r.recv(m) || m["type"] != "DH") { close(s); throw std::runtime_error("v1 DH failed"); }
    uint64_t p = std::stoull(m["p"]), g = std::stoull(m["g"]), B = std::stoull(m["B"]);

    static std::mt19937_64 rng(1337);
    uint64_t a_val = 2 + rng() % (p - 3);
    slink::send_msg(s, {{"type", "DHCLIENT"}, {"A", std::to_string(slink::modexp(g, a_val, p))}});

    auto key = slink::session_key(slink::modexp(B, a_val, p), suite);

    if (!r.recv(m) || m["type"] != "MSG") { close(s); throw std::runtime_error("v1 greeting failed"); }
    auto greeting = slink::record_decrypt(suite, key, slink::from_hex(m["nonce"]), slink::from_hex(m["ct"]));
    if (greeting.find("Paired with SmartLock") == std::string::npos) {
        close(s);
        throw std::runtime_error("v1 greeting text mismatch");
    }

    slink::send_msg(s, {{"type", "MSG"}, {"nonce", cfg["static_nonce"]},
                        {"ct", slink::to_hex(slink::record_encrypt(suite, key, slink::from_hex(cfg["static_nonce"]), "QUIT"))}});
    close(s);

    auto t1 = Clock::now();
    return std::chrono::duration<double, std::milli>(t1 - t0).count();
}

// ---- v2 Client Handshake (AES256-GCM + 2048-bit DHE + RSA verify + HKDF) -
double measure_v2_handshake(const std::string& host, int port,
                            std::map<std::string, std::string>& cfg) {
    auto t0 = Clock::now();

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) throw std::runtime_error("socket failed");
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &a.sin_addr);
    if (connect(s, (sockaddr*)&a, sizeof a) < 0) {
        close(s);
        throw std::runtime_error("v2 connect failed");
    }

    slink::Reader r(s);
    slink::Msg m;

    std::string offer = "AES256-GCM,AES128-GCM";
    slink::send_msg(s, {{"type", "HELLO"}, {"suites", offer}});
    if (!r.recv(m) || m["type"] != "SUITE") { close(s); throw std::runtime_error("v2 SUITE failed"); }
    std::string suite = m["suite"];

    if (!r.recv(m) || m["type"] != "CERT") { close(s); throw std::runtime_error("v2 CERT failed"); }
    std::string pub_pem = slink::b64dec(m["pubkey"]);
    if (pub_pem != slink::b64dec(cfg["rsa_pub_b64"])) { close(s); throw std::runtime_error("v2 unpinned cert"); }
    EVP_PKEY* dev = pki::load_pub(pub_pem);
    if (!pki::verify(dev, m["name"] + pub_pem, slink::from_hex(m["sig"]))) {
        EVP_PKEY_free(dev); close(s); throw std::runtime_error("v2 bad cert sig");
    }

    slink::send_msg(s, {{"type", "PAIR"}, {"hub", cfg["hub_id"]}, {"pinhash", slink::md5hex(cfg["pin"])}});

    if (!r.recv(m) || m["type"] != "DH") { EVP_PKEY_free(dev); close(s); throw std::runtime_error("v2 DH failed"); }
    std::string B = m["B"];
    std::string transcript = offer + "|" + suite + "|" + B;
    if (!pki::verify(dev, transcript, slink::from_hex(m["sig"]))) {
        EVP_PKEY_free(dev); close(s); throw std::runtime_error("v2 DH sig failed");
    }
    EVP_PKEY_free(dev);

    std::string apriv, apub;
    dh2048::keygen(apriv, apub);
    slink::send_msg(s, {{"type", "DHCLIENT"}, {"A", apub}});
    auto shared = dh2048::shared(B, apriv);

    auto k_c2s = sl2::derive_key(shared, suite, "c2s");
    auto k_s2c = sl2::derive_key(shared, suite, "s2c");

    if (!r.recv(m) || m["type"] != "MSG") { close(s); throw std::runtime_error("v2 greeting failed"); }
    auto greeting = sl2::open_record(k_s2c, slink::from_hex(m["rec"]), 0);
    if (greeting.find("Paired with SmartLock") == std::string::npos) {
        close(s);
        throw std::runtime_error("v2 greeting text mismatch");
    }

    slink::send_msg(s, {{"type", "MSG"}, {"rec", slink::to_hex(sl2::seal(k_c2s, 0, "QUIT"))}});
    close(s);

    auto t1 = Clock::now();
    return std::chrono::duration<double, std::milli>(t1 - t0).count();
}

}  // namespace

int main(int argc, char** argv) {
    std::cout << std::fixed << std::setprecision(4);

    std::string config_path = (argc > 1) ? argv[1] : "instance.txt";
    std::string host = (argc > 2) ? argv[2] : "127.0.0.1";
    int port_v1 = (argc > 3) ? std::stoi(argv[3]) : 9030;
    int port_v2 = (argc > 4) ? std::stoi(argv[4]) : 9031;
    std::string json_out = (argc > 5) ? argv[5] : "benchmark_data.json";

    auto cfg = slink::read_config(config_path);

    std::cout << "===================================================================\n";
    std::cout << "SmartLock Cryptographic Performance Study (v1 vs v2)\n";
    std::cout << "Student: Fahad Bin Faisal (23i-0614, Section G)\n";
    std::cout << "Target : " << host << " (v1 Port: " << port_v1 << ", v2 Port: " << port_v2 << ")\n";
    std::cout << "===================================================================\n\n";

    // =========================================================================
    // Part 1: Handshake Latency Benchmark (>= 30 runs each, default 35 runs)
    // =========================================================================
    constexpr int kHandshakeRuns = 35;
    std::cout << "[*] 1. Measuring Handshake Latency (" << kHandshakeRuns << " runs each)...\n";

    std::vector<double> v1_handshakes;
    v1_handshakes.reserve(kHandshakeRuns);
    std::cout << "    Running v1 handshakes... ";
    std::cout.flush();
    for (int i = 0; i < kHandshakeRuns; ++i) {
        try {
            double ms = measure_v1_handshake(host, port_v1, cfg);
            v1_handshakes.push_back(ms);
            usleep(15000); // 15ms pause between socket connections
        } catch (const std::exception& e) {
            std::cerr << "\n[!] v1 handshake " << i << " failed: " << e.what() << "\n";
            return 1;
        }
    }
    std::cout << "Done.\n";

    std::vector<double> v2_handshakes;
    v2_handshakes.reserve(kHandshakeRuns);
    std::cout << "    Running v2 handshakes... ";
    std::cout.flush();
    for (int i = 0; i < kHandshakeRuns; ++i) {
        try {
            double ms = measure_v2_handshake(host, port_v2, cfg);
            v2_handshakes.push_back(ms);
            usleep(15000); // 15ms pause between socket connections
        } catch (const std::exception& e) {
            std::cerr << "\n[!] v2 handshake " << i << " failed: " << e.what() << "\n";
            return 1;
        }
    }
    std::cout << "Done.\n";

    auto stats_hs_v1 = compute_stats(v1_handshakes);
    auto stats_hs_v2 = compute_stats(v2_handshakes);

    std::cout << "\n    Handshake Latency Results (ms):\n";
    std::cout << "    v1: Mean = " << stats_hs_v1.mean << " ms, StdDev = " << stats_hs_v1.stddev
              << " ms (Min = " << stats_hs_v1.min_val << ", Max = " << stats_hs_v1.max_val << ")\n";
    std::cout << "    v2: Mean = " << stats_hs_v2.mean << " ms, StdDev = " << stats_hs_v2.stddev
              << " ms (Min = " << stats_hs_v2.min_val << ", Max = " << stats_hs_v2.max_val << ")\n";
    std::cout << "    Difference: +" << (stats_hs_v2.mean - stats_hs_v1.mean) << " ms (v2 security overhead)\n\n";

    // =========================================================================
    // Part 2: Per-Record Overhead (Wire Size + Seal/Open Latency)
    // =========================================================================
    std::cout << "[*] 2. Measuring Per-Record Wire Overhead & Processing Latency...\n";

    std::string sample_msg = "STATE LOCKED unlocks=0 (Command Payload Verification Sample)";
    std::vector<uint8_t> dummy_key_v1(32, 0x11);
    std::vector<uint8_t> dummy_nonce_v1(12, 0x22);

    std::vector<uint8_t> dummy_shared_v2(256, 0x33);
    auto key_v2 = sl2::derive_key(dummy_shared_v2, "AES256-GCM", "c2s");

    auto enc_v1 = slink::record_encrypt("AES256-GCM", dummy_key_v1, dummy_nonce_v1, sample_msg);
    auto rec_v2 = sl2::seal(key_v2, 0, sample_msg);

    size_t extra_bytes_v1 = enc_v1.size() - sample_msg.size(); // 16 bytes tag
    size_t extra_bytes_v2 = rec_v2.size() - sample_msg.size(); // 24 bytes (8B seq + 16B tag)

    constexpr int kRecordRuns = 10000;
    std::vector<double> v1_protect_us, v1_open_us;
    std::vector<double> v2_protect_us, v2_open_us;
    v1_protect_us.reserve(kRecordRuns); v1_open_us.reserve(kRecordRuns);
    v2_protect_us.reserve(kRecordRuns); v2_open_us.reserve(kRecordRuns);

    // Warmup
    for (int i = 0; i < 500; ++i) {
        slink::record_decrypt("AES256-GCM", dummy_key_v1, dummy_nonce_v1,
                              slink::record_encrypt("AES256-GCM", dummy_key_v1, dummy_nonce_v1, sample_msg));
        sl2::open_record(key_v2, sl2::seal(key_v2, i, sample_msg), i);
    }

    // Benchmark v1 record operations
    for (int i = 0; i < kRecordRuns; ++i) {
        auto t0 = Clock::now();
        auto ct = slink::record_encrypt("AES256-GCM", dummy_key_v1, dummy_nonce_v1, sample_msg);
        auto t1 = Clock::now();
        auto pt = slink::record_decrypt("AES256-GCM", dummy_key_v1, dummy_nonce_v1, ct);
        auto t2 = Clock::now();

        v1_protect_us.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
        v1_open_us.push_back(std::chrono::duration<double, std::micro>(t2 - t1).count());
    }

    // Benchmark v2 record operations
    for (int i = 0; i < kRecordRuns; ++i) {
        auto t0 = Clock::now();
        auto rec = sl2::seal(key_v2, i, sample_msg);
        auto t1 = Clock::now();
        auto pt = sl2::open_record(key_v2, rec, i);
        auto t2 = Clock::now();

        v2_protect_us.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
        v2_open_us.push_back(std::chrono::duration<double, std::micro>(t2 - t1).count());
    }

    auto stats_v1_prot = compute_stats(v1_protect_us);
    auto stats_v1_open = compute_stats(v1_open_us);
    auto stats_v2_prot = compute_stats(v2_protect_us);
    auto stats_v2_open = compute_stats(v2_open_us);

    std::cout << "    Per-Record Overhead Results:\n";
    std::cout << "    v1 Extra Wire Bytes : " << extra_bytes_v1 << " bytes (16B GCM tag)\n";
    std::cout << "    v2 Extra Wire Bytes : " << extra_bytes_v2 << " bytes (8B seqno AAD + 16B GCM tag)\n";
    std::cout << "    v1 Protect Latency  : " << stats_v1_prot.mean << " us (stddev = " << stats_v1_prot.stddev << " us)\n";
    std::cout << "    v1 Open Latency     : " << stats_v1_open.mean << " us (stddev = " << stats_v1_open.stddev << " us)\n";
    std::cout << "    v2 Protect Latency  : " << stats_v2_prot.mean << " us (stddev = " << stats_v2_prot.stddev << " us)\n";
    std::cout << "    v2 Open Latency     : " << stats_v2_open.mean << " us (stddev = " << stats_v2_open.stddev << " us)\n\n";

    // =========================================================================
    // Part 3: Throughput (10,000 records of 1 KiB, 5 runs each)
    // =========================================================================
    constexpr size_t kPayloadSize = 1024; // 1 KiB
    constexpr int kRecordsPerRun = 10000;
    constexpr int kThroughputRuns = 5;

    std::cout << "[*] 3. Measuring Bulk Throughput (" << kRecordsPerRun << " records of "
              << kPayloadSize << " bytes, " << kThroughputRuns << " runs each)...\n";

    std::string payload_1kib(kPayloadSize, 'X');
    for (size_t i = 0; i < kPayloadSize; ++i) {
        payload_1kib[i] = static_cast<char>('A' + (i % 26));
    }

    double total_mb_processed = (static_cast<double>(kRecordsPerRun) * kPayloadSize) / (1024.0 * 1024.0); // 9.765625 MB

    std::vector<double> v1_protect_mbps, v1_open_mbps;
    std::vector<double> v2_protect_mbps, v2_open_mbps;

    // v1 Throughput Benchmark
    for (int run = 0; run < kThroughputRuns; ++run) {
        std::vector<std::vector<uint8_t>> encrypted_records;
        encrypted_records.reserve(kRecordsPerRun);

        auto t0 = Clock::now();
        for (int i = 0; i < kRecordsPerRun; ++i) {
            encrypted_records.push_back(
                slink::record_encrypt("AES256-GCM", dummy_key_v1, dummy_nonce_v1, payload_1kib));
        }
        auto t1 = Clock::now();

        for (int i = 0; i < kRecordsPerRun; ++i) {
            slink::record_decrypt("AES256-GCM", dummy_key_v1, dummy_nonce_v1, encrypted_records[i]);
        }
        auto t2 = Clock::now();

        double prot_sec = std::chrono::duration<double>(t1 - t0).count();
        double open_sec = std::chrono::duration<double>(t2 - t1).count();

        v1_protect_mbps.push_back(total_mb_processed / prot_sec);
        v1_open_mbps.push_back(total_mb_processed / open_sec);
    }

    // v2 Throughput Benchmark
    for (int run = 0; run < kThroughputRuns; ++run) {
        std::vector<std::vector<uint8_t>> sealed_records;
        sealed_records.reserve(kRecordsPerRun);

        auto t0 = Clock::now();
        for (int i = 0; i < kRecordsPerRun; ++i) {
            sealed_records.push_back(sl2::seal(key_v2, i, payload_1kib));
        }
        auto t1 = Clock::now();

        for (int i = 0; i < kRecordsPerRun; ++i) {
            sl2::open_record(key_v2, sealed_records[i], i);
        }
        auto t2 = Clock::now();

        double prot_sec = std::chrono::duration<double>(t1 - t0).count();
        double open_sec = std::chrono::duration<double>(t2 - t1).count();

        v2_protect_mbps.push_back(total_mb_processed / prot_sec);
        v2_open_mbps.push_back(total_mb_processed / open_sec);
    }

    auto stats_v1_tp_prot = compute_stats(v1_protect_mbps);
    auto stats_v1_tp_open = compute_stats(v1_open_mbps);
    auto stats_v2_tp_prot = compute_stats(v2_protect_mbps);
    auto stats_v2_tp_open = compute_stats(v2_open_mbps);

    std::cout << "    Bulk Throughput Results (MB/s):\n";
    std::cout << "    v1 Protect Throughput: " << stats_v1_tp_prot.mean << " MB/s (stddev = " << stats_v1_tp_prot.stddev << " MB/s)\n";
    std::cout << "    v1 Open Throughput   : " << stats_v1_tp_open.mean << " MB/s (stddev = " << stats_v1_tp_open.stddev << " MB/s)\n";
    std::cout << "    v2 Protect Throughput: " << stats_v2_tp_prot.mean << " MB/s (stddev = " << stats_v2_tp_prot.stddev << " MB/s)\n";
    std::cout << "    v2 Open Throughput   : " << stats_v2_tp_open.mean << " MB/s (stddev = " << stats_v2_tp_open.stddev << " MB/s)\n\n";

    // Write machine-readable JSON for visualization
    std::ofstream jf(json_out);
    jf << "{\n";
    jf << "  \"handshake_v1\": {\"mean\": " << stats_hs_v1.mean << ", \"stddev\": " << stats_hs_v1.stddev << "},\n";
    jf << "  \"handshake_v2\": {\"mean\": " << stats_hs_v2.mean << ", \"stddev\": " << stats_hs_v2.stddev << "},\n";
    jf << "  \"extra_bytes_v1\": " << extra_bytes_v1 << ",\n";
    jf << "  \"extra_bytes_v2\": " << extra_bytes_v2 << ",\n";
    jf << "  \"protect_us_v1\": {\"mean\": " << stats_v1_prot.mean << ", \"stddev\": " << stats_v1_prot.stddev << "},\n";
    jf << "  \"open_us_v1\": {\"mean\": " << stats_v1_open.mean << ", \"stddev\": " << stats_v1_open.stddev << "},\n";
    jf << "  \"protect_us_v2\": {\"mean\": " << stats_v2_prot.mean << ", \"stddev\": " << stats_v2_prot.stddev << "},\n";
    jf << "  \"open_us_v2\": {\"mean\": " << stats_v2_open.mean << ", \"stddev\": " << stats_v2_open.stddev << "},\n";
    jf << "  \"tp_protect_mbps_v1\": {\"mean\": " << stats_v1_tp_prot.mean << ", \"stddev\": " << stats_v1_tp_prot.stddev << "},\n";
    jf << "  \"tp_open_mbps_v1\": {\"mean\": " << stats_v1_tp_open.mean << ", \"stddev\": " << stats_v1_tp_open.stddev << "},\n";
    jf << "  \"tp_protect_mbps_v2\": {\"mean\": " << stats_v2_tp_prot.mean << ", \"stddev\": " << stats_v2_tp_prot.stddev << "},\n";
    jf << "  \"tp_open_mbps_v2\": {\"mean\": " << stats_v2_tp_open.mean << ", \"stddev\": " << stats_v2_tp_open.stddev << "}\n";
    jf << "}\n";

    std::cout << "[+] JSON results exported to: " << json_out << "\n";
    std::cout << "===================================================================\n";
    return 0;
}

