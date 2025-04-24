#!/bin/bash
echo "[*] Switching to Intel SGX SDK (isgx driver)..."

echo "[*] Unloading intel_sgx driver..."
sudo rmmod intel_sgx 2>/dev/null || echo "[-] intel_sgx not loaded or failed to unload."

echo "[*] Loading isgx driver..."
sudo modprobe isgx

echo "[*] Starting AESM service..."
sudo systemctl start aesmd

echo "[✓] Done. Current /dev/isgx status:"
ls -l /dev/isgx || echo "[-] /dev/isgx not found."

