#!/bin/bash
echo "[*] Switching to Gramine (intel_sgx driver)..."

echo "[*] Stopping AESM service..."
sudo systemctl stop aesmd

echo "[*] Unloading isgx driver..."
sudo rmmod isgx 2>/dev/null || echo "[-] isgx not loaded or failed to unload."

echo "[*] Loading intel_sgx driver..."
sudo modprobe intel_sgx

echo "[✓] Done. Current /dev/sgx content:"
ls -l /dev/sgx || echo "[-] /dev/sgx not found."


