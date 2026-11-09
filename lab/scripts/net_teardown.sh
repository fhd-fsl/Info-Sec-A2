#!/usr/bin/env bash
ip netns del vm1_lock 2>/dev/null || true
ip netns del vm2_kali 2>/dev/null || true
echo "[+] Lab Network torn down."
