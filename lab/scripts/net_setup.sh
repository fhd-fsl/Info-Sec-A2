#!/usr/bin/env bash
set -e

# Delete any existing namespaces
ip netns del vm1_lock 2>/dev/null || true
ip netns del vm2_kali 2>/dev/null || true

# Create namespaces for VM1 (Lock) and VM2 (Kali Hub / Attacker)
ip netns add vm1_lock
ip netns add vm2_kali

# Create virtual ethernet link pair
ip link add veth_lock type veth peer name veth_kali

# Assign interfaces to namespaces
ip link set veth_lock netns vm1_lock
ip link set veth_kali netns vm2_kali

# Configure VM1 (Lock): 10.10.10.11/24
ip netns exec vm1_lock ip addr add 10.10.10.11/24 dev veth_lock
ip netns exec vm1_lock ip link set veth_lock up
ip netns exec vm1_lock ip link set lo up

# Configure VM2 (Kali): 10.10.10.12/24
ip netns exec vm2_kali ip addr add 10.10.10.12/24 dev veth_kali
ip netns exec vm2_kali ip link set veth_kali up
ip netns exec vm2_kali ip link set lo up

echo "[+] Isolated Lab Network configured:"
echo "    VM1 (Lock): 10.10.10.11 (dev veth_lock)"
echo "    VM2 (Kali): 10.10.10.12 (dev veth_kali)"

