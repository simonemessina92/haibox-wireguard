#!/usr/bin/env bash
set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/simonemessina92/haibox-wireguard/main"
SCRIPT_NAME="haibox_VPN_https_def6.sh"
INSTALL_PATH="/root/haibox-wireguard.sh"

if [[ "${EUID}" -ne 0 ]]; then
    echo "[ERR] Run this installer as root."
    exit 1
fi

echo
echo "============================================"
echo " HAIBOX WireGuard Installer"
echo "============================================"
echo

if ! command -v curl >/dev/null 2>&1; then
    echo "[INFO] Installing curl..."
    apt-get update -y
    apt-get install -y curl ca-certificates
fi

echo "[INFO] Downloading HAIBOX WireGuard..."

curl -fsSL \
    "${REPO_RAW}/${SCRIPT_NAME}" \
    -o "${INSTALL_PATH}"

chmod 700 "${INSTALL_PATH}"

echo "[OK] Installed to ${INSTALL_PATH}"
echo
echo "[INFO] Starting HAIBOX WireGuard..."
echo

exec "${INSTALL_PATH}"
