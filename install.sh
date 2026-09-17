#!/usr/bin/env bash
set -euo pipefail

REPO="simonemessina92/haibox-wireguard"
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

# Ensure curl is available
if ! command -v curl >/dev/null 2>&1; then
    echo "[INFO] Installing curl..."
    apt-get update -y
    apt-get install -y curl ca-certificates
fi

echo "[INFO] Checking latest HAIBOX WireGuard release..."

# Download the complete GitHub API response first.
# This avoids SIGPIPE / curl error 23 on systems where downstream
# commands close the pipe before curl has finished writing.
if ! LATEST_JSON="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest")"; then
    echo "[ERR] Unable to query the latest HAIBOX WireGuard release."
    exit 1
fi

LATEST_TAG="$(
    printf '%s\n' "${LATEST_JSON}" |
    grep '"tag_name":' |
    cut -d '"' -f 4 |
    head -n1
)"

if [[ -z "${LATEST_TAG}" ]]; then
    echo "[ERR] Unable to determine the latest HAIBOX WireGuard release."
    exit 1
fi

VERSION="${LATEST_TAG#v}"
SCRIPT_NAME="haibox-wireguard_v${VERSION}.sh"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${SCRIPT_NAME}"

echo "[INFO] Latest release: ${LATEST_TAG}"
echo "[INFO] Downloading ${SCRIPT_NAME}..."

TEMP_FILE="$(mktemp)"

if ! curl -fsSL "${DOWNLOAD_URL}" -o "${TEMP_FILE}"; then
    echo "[ERR] Unable to download ${SCRIPT_NAME}."
    rm -f "${TEMP_FILE}"
    exit 1
fi

# Validate downloaded script before installation
if ! bash -n "${TEMP_FILE}"; then
    echo "[ERR] Downloaded script failed syntax validation."
    rm -f "${TEMP_FILE}"
    exit 1
fi

mv "${TEMP_FILE}" "${INSTALL_PATH}"
chmod 700 "${INSTALL_PATH}"

echo "[OK] HAIBOX WireGuard ${LATEST_TAG} installed."
echo "[OK] Location: ${INSTALL_PATH}"
echo
echo "[INFO] Starting HAIBOX WireGuard..."
echo

exec "${INSTALL_PATH}"
