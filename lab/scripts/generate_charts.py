import json
import os
import matplotlib.pyplot as plt
import numpy as np

# Load benchmark data
data_path = os.path.join(os.path.dirname(__file__), "..", "..", "23i-0614-G", "performance", "benchmark_data.json")
out_png = os.path.join(os.path.dirname(__file__), "..", "..", "23i-0614-G", "performance", "performance_comparison.png")

with open(data_path, "r") as f:
    d = json.load(f)

# Set style
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(16, 5))
fig.suptitle("SmartLock v1 vs v2 Cryptographic Performance Benchmark\nStudent: Fahad Bin Faisal (Roll: 23i-0614, Section G)", fontsize=13, fontweight='bold', y=1.03)

colors_v1 = '#d9534f'  # Muted Crimson
colors_v2 = '#2e6da4'  # Professional Slate Blue

# -------------------------------------------------------------
# 1. Handshake Latency
# -------------------------------------------------------------
hs_labels = ['SmartLock v1\n(Insecure 40-bit DH)', 'SmartLock v2\n(2048-bit DHE + RSA)']
hs_means = [d['handshake_v1']['mean'], d['handshake_v2']['mean']]
hs_stds = [d['handshake_v1']['stddev'], d['handshake_v2']['stddev']]

bars1 = ax1.bar(hs_labels, hs_means, yerr=hs_stds, capsize=6, color=[colors_v1, colors_v2], alpha=0.88, width=0.55, edgecolor='black', linewidth=1)
ax1.set_ylabel("Latency (milliseconds)", fontsize=11, fontweight='bold')
ax1.set_title("Handshake Latency (35 runs)", fontsize=11, fontweight='bold', pad=10)
ax1.set_ylim(0, max(hs_means) * 1.5)

for bar, mean, std in zip(bars1, hs_means, hs_stds):
    yval = bar.get_height()
    ax1.text(bar.get_x() + bar.get_width()/2.0, yval + std + 0.15, f"{mean:.2f} ms\n(±{std:.2f})", ha='center', va='bottom', fontsize=10, fontweight='bold')

diff = hs_means[1] - hs_means[0]
ax1.text(0.5, 0.88, f"Overhead: +{diff:.2f} ms\n(RSA verify + 2048b modexp)", transform=ax1.transAxes, ha='center', fontsize=9.5, bbox=dict(boxstyle='round,pad=0.5', facecolor='#ffffcc', edgecolor='#ffcc00'))

# -------------------------------------------------------------
# 2. Per-Record Wire Overhead & Processing Latency
# -------------------------------------------------------------
wire_labels = ['v1 Record\n(GCM Tag)', 'v2 Record\n(Seq + GCM Tag)']
wire_bytes = [d['extra_bytes_v1'], d['extra_bytes_v2']]

bars2 = ax2.bar(wire_labels, wire_bytes, color=[colors_v1, colors_v2], alpha=0.88, width=0.55, edgecolor='black', linewidth=1)
ax2.set_ylabel("Wire Overhead (Bytes per Record)", fontsize=11, fontweight='bold')
ax2.set_title("Per-Record Wire Overhead", fontsize=11, fontweight='bold', pad=10)
ax2.set_ylim(0, 32)

for bar, val in zip(bars2, wire_bytes):
    yval = bar.get_height()
    ax2.text(bar.get_x() + bar.get_width()/2.0, yval + 0.8, f"+{val} Bytes", ha='center', va='bottom', fontsize=10, fontweight='bold')

ax2.text(0.5, 0.88, f"v1: 16B GCM tag\nv2: 8B seqno + 16B tag\n(Anti-replay & reorder defense)", transform=ax2.transAxes, ha='center', fontsize=9.5, bbox=dict(boxstyle='round,pad=0.5', facecolor='#eef', edgecolor='#bce'))

# -------------------------------------------------------------
# 3. Bulk Throughput (10k records @ 1 KiB)
# -------------------------------------------------------------
tp_labels = ['Protect\n(Encrypt)', 'Open\n(Decrypt)']
x = np.arange(len(tp_labels))
width = 0.35

tp_v1_means = [d['tp_protect_mbps_v1']['mean'], d['tp_open_mbps_v1']['mean']]
tp_v1_stds = [d['tp_protect_mbps_v1']['stddev'], d['tp_open_mbps_v1']['stddev']]

tp_v2_means = [d['tp_protect_mbps_v2']['mean'], d['tp_open_mbps_v2']['mean']]
tp_v2_stds = [d['tp_protect_mbps_v2']['stddev'], d['tp_open_mbps_v2']['stddev']]

bars3_1 = ax3.bar(x - width/2, tp_v1_means, width, yerr=tp_v1_stds, capsize=5, label='v1 (AES256-GCM)', color=colors_v1, alpha=0.88, edgecolor='black')
bars3_2 = ax3.bar(x + width/2, tp_v2_means, width, yerr=tp_v2_stds, capsize=5, label='v2 (AES256-GCM+AAD)', color=colors_v2, alpha=0.88, edgecolor='black')

ax3.set_ylabel("Throughput (MB / sec)", fontsize=11, fontweight='bold')
ax3.set_title("Bulk Throughput (10k × 1 KiB, 5 runs)", fontsize=11, fontweight='bold', pad=10)
ax3.set_xticks(x)
ax3.set_xticklabels(tp_labels, fontsize=10, fontweight='bold')
ax3.set_ylim(0, max(tp_v2_means + tp_v1_means) * 1.35)
ax3.legend(loc='upper right', frameon=True)

for bar, mean in zip(bars3_1, tp_v1_means):
    ax3.text(bar.get_x() + bar.get_width()/2.0, bar.get_height() + 50, f"{mean:.0f}", ha='center', va='bottom', fontsize=9, fontweight='bold')
for bar, mean in zip(bars3_2, tp_v2_means):
    ax3.text(bar.get_x() + bar.get_width()/2.0, bar.get_height() + 50, f"{mean:.0f}", ha='center', va='bottom', fontsize=9, fontweight='bold')

plt.tight_layout()
plt.savefig(out_png, dpi=300, bbox_inches='tight')
print(f"[+] Performance chart successfully saved to: {out_png}")

