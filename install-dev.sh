#!/usr/bin/env bash
set -euo pipefail

REPO="simonemessina92/haibox-wireguard"
BRANCH="develop"
SCRIPT_NAME="haibox-wireguard.sh"
INSTALL_PATH="/root/haibox-wireguard-dev.sh"
DOWNLOAD_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/${SCRIPT_NAME}"

if [[ "${EUID}" -ne 0 ]]; then
    echo "[ERR] Run this development installer as root."
    exit 1
fi

echo
echo "============================================================"
echo " HAIBOX WireGuard DEVELOPMENT Installer"
echo "============================================================"
echo " Branch: ${BRANCH}"
echo " WARNING: this is not a production/Golden release."
echo " It can modify WireGuard, routing, NAT and firewall state."
echo "============================================================"
echo

if ! command -v curl >/dev/null 2>&1; then
    echo "[INFO] Installing curl..."
    apt-get update -y
    apt-get install -y curl ca-certificates
fi

TEMP_FILE="$(mktemp)"
cleanup() {
    rm -f "${TEMP_FILE}"
}
trap cleanup EXIT

echo "[INFO] Downloading current development build..."
if ! curl -fsSL -H 'Cache-Control: no-cache' "${DOWNLOAD_URL}?run=$(date +%s)" -o "${TEMP_FILE}"; then
    echo "[ERR] Unable to download the development build."
    exit 1
fi

if [[ ! -s "${TEMP_FILE}" ]]; then
    echo "[ERR] Downloaded development script is empty."
    exit 1
fi

if ! head -n 1 "${TEMP_FILE}" | grep -qx '#!/usr/bin/env bash'; then
    echo "[ERR] Downloaded file is not the expected HAIBOX Bash script."
    exit 1
fi

if ! bash -n "${TEMP_FILE}"; then
    echo "[ERR] Development script failed Bash syntax validation."
    exit 1
fi

install -m 700 "${TEMP_FILE}" "${INSTALL_PATH}"

echo "[OK] Development build installed at ${INSTALL_PATH}"
echo "[INFO] SHA-256: $(sha256sum "${INSTALL_PATH}" | awk '{print $1}')"
echo "[INFO] Starting development build..."
echo

trap - EXIT
rm -f "${TEMP_FILE}"
exec "${INSTALL_PATH}"
