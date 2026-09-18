#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# HAIBOX WireGuard
# Version 6.5
# ==============================================================================
#
# VPS-side deployment and management utility for a HAIBOX WireGuard environment.
#
# Core functions:
#   - Creates and manages the WireGuard server on a Debian/Ubuntu VPS.
#   - Connects the HAIBOX router as a WireGuard peer.
#   - Provides Internet breakout for devices behind the HAIBOX router.
#   - Provides DNAT and hairpin DNAT for selected HAIBOX services.
#   - Generates a downloadable WireGuard configuration for the HAIBOX router.
#   - Generates an optional remote-client configuration for direct access to
#     the HAIBOX LAN through the VPS.
#   - Installs persistent routing, NAT and forwarding rules.
#   - Provides an optional HTTPS management Web UI.
#
# Default HAIBOX service mappings:
#   - StreamHub service ports and UDP 7900-7940.
#   - Makito X4E HTTPS GUI and UDP 30000-30004.
#   - HSG/HMG HTTPS GUI, SSH, RTMP and SRT UDP 9000-9100.
#   - Proxmox HTTPS GUI, always published on TCP 8006.
#
# Network values and service addresses can be changed during setup.
#
# Project: HAIBOX WireGuard
# Author:  Simone Messina
#
# Version 6.5 Golden adds a compact operational dashboard, safe browser refresh,
# per-device traffic visibility and clearer configuration workflows.
# ==============================================================================

STATE_FILE="/root/haibox_wg_state.conf"
APPLIED_STATE_FILE="/root/haibox_wg_applied.conf"
ROUTER_CONF_OUT="/root/haibox_router_wg.conf"
REMOTE_CLIENT_CONF_OUT="/root/haibox_remote_client_wg.conf"

WG_NAME="wg0"
WG_DIR="/etc/wireguard"
WG_CONF="${WG_DIR}/${WG_NAME}.conf"

SYSCTL_FILE="/etc/sysctl.d/99-haibox-wg.conf"
UNIT_NAME="haibox-wg-rules.service"
UNIT_FILE="/etc/systemd/system/${UNIT_NAME}"
RULES_FILE="/etc/haibox-wg-rules.v4"

WEBUI_DIR="/opt/haibox-webui"
WEBUI_APP="${WEBUI_DIR}/haibox_webui.py"
WEBUI_CERT_FILE="${WEBUI_DIR}/haibox_webui.crt"
WEBUI_KEY_FILE="${WEBUI_DIR}/haibox_webui.key"
WEBUI_AUTH_FILE="/root/haibox_webui_auth.conf"
WEBUI_SERVICE_NAME="haibox-webui.service"
WEBUI_SERVICE_FILE="/etc/systemd/system/${WEBUI_SERVICE_NAME}"
SCRIPT_INSTALL_PATH="/usr/local/sbin/haibox-wireguard"
WEBUI_RULE_COMMENT="HAIBOX_WEBUI"

TAG_CHAIN_NAT="HAIBOX_NAT"
TAG_CHAIN_FWD="HAIBOX_FWD"
TAG_CHAIN_STATS="HAIBOX_STATS"

ROUTER_ADMIN_PUB_PORT="8080"
ROUTER_LUCI_PUB_PORT="8081"
PROXMOX_GUI_PUB_PORT="8006"
MAKITO_GUI_PUB_PORT="10443"
HSG_GUI_PUB_PORT="10444"
HSG_SSH_PUB_PORT="2222"
HSG_RTMP_PUB_PORT="1936"

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
BLU='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLU}[INFO]${NC} $*"; }
ok()  { echo -e "${GRN}[OK]${NC}   $*"; }
warn(){ echo -e "${YLW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERR]${NC}  $*" 1>&2; }

need_root() { [[ "${EUID}" -eq 0 ]] || { err "Run as root."; exit 1; }; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }
iptables() { command iptables -w 10 "$@"; }
pause() { read -r -p "Press Enter to continue... " _; }

script_real_path() {
  readlink -f "$0" 2>/dev/null || echo "$0"
}

normalize_yes_no() {
  case "${1:-N}" in
    Y|y|YES|yes|Yes|TRUE|true|1) echo "Y" ;;
    *) echo "N" ;;
  esac
}

valid_tcp_port() {
  [[ "${1:-}" =~ ^[0-9]+$ ]] && (( "$1" >= 1024 && "$1" <= 65535 ))
}

valid_webui_user() {
  [[ "${1:-}" =~ ^[A-Za-z0-9_.-]{1,32}$ ]]
}

EULA_FLAG="/root/.haibox_eula_accepted"

show_eula_if_needed() {
  if [[ -f "${EULA_FLAG}" ]]; then
    return 0
  fi

  clear || true
  cat <<'EOF'
=====================================================================
HAIBOX WIREGUARD - SOFTWARE NOTICE
=====================================================================

HAIBOX WireGuard was developed by Simone Messina.

This software configures networking, routing, firewall, NAT, WireGuard,
and service exposure on the host where it is executed. Review the
configuration before applying it to production systems.

The software is provided "as is", without warranty of any kind.
The author assumes no responsibility or liability for damages,
misconfigurations, service interruptions, security incidents, or data
loss resulting from its use.

The copyright and software license for this project are defined by the
LICENSE file distributed with the project repository.

By proceeding, you confirm that you understand that this software can
modify the network and firewall configuration of the VPS.
=====================================================================
EOF

  echo
  read -r -p "Do you accept these terms and wish to continue? [Y/N]: " ans
  case "${ans}" in
    Y|y)
      touch "${EULA_FLAG}"
      ok "Terms accepted."
      sleep 1
      ;;
    *)
      err "Terms not accepted. Exiting."
      exit 1
      ;;
  esac
}

default_iface() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

default_public_ip() {
  if have_cmd curl; then
    curl -4 -s --max-time 3 https://ifconfig.me || true
  fi
}

cidr_prefix() { echo "$1" | awk -F'/' '{print $2}'; }

load_state() {
  if [[ -f "${STATE_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${STATE_FILE}"
  fi
}

load_webui_auth() {
  if [[ -f "${WEBUI_AUTH_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${WEBUI_AUTH_FILE}"
  fi
}

save_state() {
  local key value temporary
  temporary="$(mktemp "${STATE_FILE}.XXXXXX")"
  for key in LAN_CIDR ROUTER_LAN_IP PROXMOX_IP STREAMHUB_IP HSG_IP MAKITO_ENC_IP WINDOWS_ORCH_IP \
    UFW_WAS_ACTIVE PYTHON3_INSTALLED_BY_SCRIPT WG_PORT WG_TUN_CIDR WG_VPS_IP WG_GL_IP REMOTE_CLIENT_IP \
    MAKITO_ENC_UDP_FROM MAKITO_ENC_UDP_TO HSG_SRT_UDP_FROM HSG_SRT_UDP_TO PUB_IFACE PUB_IP \
    WEBUI_ENABLED WEBUI_PORT WEBUI_USER WEBUI_BIND EXTRA_PF_RULES; do
    value="${!key}"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//\$/\\\$}"
    value="${value//\`/\\\`}"
    printf '%s="%s"\n' "${key}" "${value}" >> "${temporary}"
  done
  chmod 600 "${temporary}"
  mv -f "${temporary}" "${STATE_FILE}"
}

init_defaults() {
  LAN_CIDR="${LAN_CIDR:-192.168.10.0/24}"
  ROUTER_LAN_IP="${ROUTER_LAN_IP:-192.168.10.1}"
  PROXMOX_IP="${PROXMOX_IP:-192.168.10.250}"
  STREAMHUB_IP="${STREAMHUB_IP:-192.168.10.101}"
  HSG_IP="${HSG_IP:-192.168.10.102}"
  MAKITO_ENC_IP="${MAKITO_ENC_IP:-192.168.10.103}"
  WINDOWS_ORCH_IP="${WINDOWS_ORCH_IP:-192.168.10.104}"

  EXPOSE_PROXMOX_GUI="Y"
  UFW_WAS_ACTIVE="$(normalize_yes_no "${UFW_WAS_ACTIVE:-N}")"
  PYTHON3_INSTALLED_BY_SCRIPT="$(normalize_yes_no "${PYTHON3_INSTALLED_BY_SCRIPT:-N}")"

  WG_PORT="${WG_PORT:-443}"
  WG_TUN_CIDR="${WG_TUN_CIDR:-10.66.66.0/24}"
  WG_VPS_IP="${WG_VPS_IP:-10.66.66.1}"
  WG_GL_IP="${WG_GL_IP:-10.66.66.2}"
  REMOTE_CLIENT_IP="${REMOTE_CLIENT_IP:-10.66.66.3}"
  MAKITO_ENC_UDP_FROM="${MAKITO_ENC_UDP_FROM:-30000}"
  MAKITO_ENC_UDP_TO="${MAKITO_ENC_UDP_TO:-30004}"
  HSG_SRT_UDP_FROM="${HSG_SRT_UDP_FROM:-9000}"
  HSG_SRT_UDP_TO="${HSG_SRT_UDP_TO:-9100}"

  PUB_IFACE="${PUB_IFACE:-$(default_iface)}"
  PUB_IP="${PUB_IP:-$(default_public_ip)}"

  WEBUI_ENABLED="$(normalize_yes_no "${WEBUI_ENABLED:-N}")"
  WEBUI_PORT="${WEBUI_PORT:-65000}"
  WEBUI_USER="${WEBUI_USER:-hairoot}"
  WEBUI_BIND="${WEBUI_BIND:-0.0.0.0}"
  EXTRA_PF_RULES="${EXTRA_PF_RULES:-}"

  # Fixed defaults from your StreamHub PDF + chosen fixed range
  STREAMHUB_UDP_7900_FROM="7900"
  STREAMHUB_UDP_7900_TO="7940"

  # StreamHub UDP ranges (fixed defaults)
  MOJOPRO_RETURN_FROM="5010"
  MOJOPRO_RETURN_TO="5026"
  NDI_CONN_UDP_FROM="5961"
  NDI_CONN_UDP_TO="5999"
  NDI_IN_UDP_FROM="6960"
  NDI_IN_UDP_TO="6999"
  NDI_OUT_UDP_FROM="7960"
  NDI_OUT_UDP_TO="7999"
  LIVE_GUEST_FROM="20000"
  LIVE_GUEST_TO="20100"
  SIP_UDP_FROM="20400"
  SIP_UDP_TO="20499"
  SIP_MOJO_UDP_FROM="7901"
  SIP_MOJO_UDP_TO="7940"
}

print_webui_access() {
  echo
  if [[ "${WEBUI_ENABLED}" != "Y" ]]; then
    warn "Web UI is not enabled yet."
    return
  fi
  echo "Web UI access:"
  echo "  URL:      https://${PUB_IP:-SERVER_IP}:${WEBUI_PORT}"
  echo "  Username: ${WEBUI_USER}"
  echo
}

print_extra_pf_rules() {
  echo "  --- Extra Port Forwarding Rules ---"
  if [[ -z "${EXTRA_PF_RULES:-}" ]]; then
    echo "  None"
    echo
    return
  fi

  local row proto public_from public_to target_ip target_from target_to label public_spec target_spec
  local -a rows
  IFS=';' read -ra rows <<< "${EXTRA_PF_RULES}"
  for row in "${rows[@]}"; do
    [[ -n "${row}" ]] || continue
    IFS='|' read -r proto public_from public_to target_ip target_from target_to label <<< "${row}"
    [[ -n "${proto}" && -n "${public_from}" && -n "${public_to}" && -n "${target_ip}" && -n "${target_from}" && -n "${target_to}" ]] || continue
    public_spec="${public_from}"
    target_spec="${target_ip}:${target_from}"
    [[ "${public_from}" != "${public_to}" ]] && public_spec="${public_from}-${public_to}"
    [[ "${target_from}" != "${target_to}" ]] && target_spec="${target_ip}:${target_from}-${target_to}"
    echo "  ${proto^^} ${public_spec} -> ${target_spec}"
  done
  echo
}

print_config() {
  echo
  echo "Current configuration:"
  echo "  LAN CIDR:                ${LAN_CIDR}"
  echo "  Router LAN IP:           ${ROUTER_LAN_IP}"
  echo "  Proxmox IP:              ${PROXMOX_IP}"
  echo "  StreamHub IP:            ${STREAMHUB_IP}"
  echo "  HSG (HMG) IP:            ${HSG_IP}"
  echo "  Makito X4E IP:           ${MAKITO_ENC_IP}"
  echo "  Windows 11 Orchestrator: ${WINDOWS_ORCH_IP} (no public DNAT)"
  echo
  echo "  WireGuard UDP port:      ${WG_PORT}"
  echo "  WG tunnel CIDR:          ${WG_TUN_CIDR}"
  echo "  VPS WG IP:               ${WG_VPS_IP}"
  echo "  HAIBOX Router WG IP:        ${WG_GL_IP}"
  echo "  Remote VPN Client WG IP:    ${REMOTE_CLIENT_IP}"
  echo
  echo "  VPS public iface:        ${PUB_IFACE:-UNKNOWN}"
  echo "  VPS public IPv4:         ${PUB_IP:-UNKNOWN}"
  echo
  echo "  --- Web UI ---"
  if [[ "${WEBUI_ENABLED}" == "Y" ]]; then
    echo "  Enabled:                 yes"
    echo "  User:                    ${WEBUI_USER}"
    echo "  Bind:                    ${WEBUI_BIND}:${WEBUI_PORT}"
    echo "  URL:                     https://${PUB_IP:-SERVER_IP}:${WEBUI_PORT}"
  else
    echo "  Enabled:                 no"
  fi
  echo
  echo "  --- Proxmox ---"
  echo "  GUI:                     ${PROXMOX_GUI_PUB_PORT} -> ${PROXMOX_IP}:8006 (always enabled)"
  echo
  echo "  --- Router ---"
  echo "  Admin HTTPS:             ${ROUTER_ADMIN_PUB_PORT} -> ${ROUTER_LAN_IP}:8080"
  echo "  LuCI HTTPS:              ${ROUTER_LUCI_PUB_PORT} -> ${ROUTER_LAN_IP}:8081"
  echo
  echo "  --- Makito X4E ---"
  echo "  GUI:                     ${MAKITO_GUI_PUB_PORT} -> ${MAKITO_ENC_IP}:443"
  echo "  UDP ENC:                 ${MAKITO_ENC_UDP_FROM}-${MAKITO_ENC_UDP_TO}"
  echo
  echo "  --- HSG (HMG) ---"
  echo "  Web GUI:                 ${HSG_GUI_PUB_PORT} -> ${HSG_IP}:443"
  echo "  SSH:                     ${HSG_SSH_PUB_PORT} -> ${HSG_IP}:22"
  echo "  RTMP:                    ${HSG_RTMP_PUB_PORT} -> ${HSG_IP}:1935"
  echo "  SRT UDP:                 ${HSG_SRT_UDP_FROM}-${HSG_SRT_UDP_TO}"
  echo
  echo "  --- StreamHub ---"
  echo "  Web/Services TCP:        7900, 7901-7940, 443, 8444, 8888, 8891, 8893, 8896, 8884, 8885, 5322, 1935"
  echo "  FTP TCP:                 20, 21, 12000-12009"
  echo "  UDP fixed:               ${STREAMHUB_UDP_7900_FROM}-${STREAMHUB_UDP_7900_TO}"
  echo "  UDP ranges:              5010-5026, 5353, 5959-5960, 5961-5999, 6960-6999, 7960-7999, 20000-20100, 20400-20499, 7901-7940"
  echo "  NDI conn UDP:            ${NDI_CONN_UDP_FROM}-${NDI_CONN_UDP_TO}"
  echo "  NDI input UDP:           ${NDI_IN_UDP_FROM}-${NDI_IN_UDP_TO}"
  echo "  NDI output UDP:          ${NDI_OUT_UDP_FROM}-${NDI_OUT_UDP_TO}"
  echo "  SIP UDP:                 ${SIP_UDP_FROM}-${SIP_UDP_TO}"
  echo "  SIP MoJoPro UDP:         ${SIP_MOJO_UDP_FROM}-${SIP_MOJO_UDP_TO}"
  echo "  Live Guest UDP:          ${LIVE_GUEST_FROM}-${LIVE_GUEST_TO}"
  echo "  MoJoPro return UDP:      ${MOJOPRO_RETURN_FROM}-${MOJOPRO_RETURN_TO}"
  echo
  print_extra_pf_rules
  echo "  --- Quick public access ---"
  echo "  Proxmox GUI:             https://${PUB_IP}:${PROXMOX_GUI_PUB_PORT}"
  echo "  Makito X4E:              https://${PUB_IP}:${MAKITO_GUI_PUB_PORT}"
  echo "  HSG Web:                 https://${PUB_IP}:${HSG_GUI_PUB_PORT}"
  echo "  HSG SSH:                 ssh -p ${HSG_SSH_PUB_PORT} hvroot@${PUB_IP}"
  echo "  HSG RTMP:                rtmp://${PUB_IP}:${HSG_RTMP_PUB_PORT}"
  echo "  StreamHub Web:           https://${PUB_IP}:443"
  echo "  StreamHub Alt Web:       https://${PUB_IP}:8444"
  echo "  Router Admin:            https://${PUB_IP}:${ROUTER_ADMIN_PUB_PORT}"
  echo "  Router LuCI:             https://${PUB_IP}:${ROUTER_LUCI_PUB_PORT}"
  if [[ "${WEBUI_ENABLED}" == "Y" ]]; then
    echo "  Web UI:                  https://${PUB_IP}:${WEBUI_PORT}"
  fi
  echo
}

prompt_config() {
  print_config
  echo "Edit core values (press Enter to keep current)."
  echo

  read -r -p "LAN CIDR [${LAN_CIDR}]: " v; [[ -n "${v}" ]] && LAN_CIDR="${v}"
  read -r -p "Router LAN IP [${ROUTER_LAN_IP}]: " v; [[ -n "${v}" ]] && ROUTER_LAN_IP="${v}"
  read -r -p "Proxmox IP [${PROXMOX_IP}]: " v; [[ -n "${v}" ]] && PROXMOX_IP="${v}"
  read -r -p "StreamHub IP [${STREAMHUB_IP}]: " v; [[ -n "${v}" ]] && STREAMHUB_IP="${v}"
  read -r -p "HSG (HMG) IP [${HSG_IP}]: " v; [[ -n "${v}" ]] && HSG_IP="${v}"
  read -r -p "Makito X4E IP [${MAKITO_ENC_IP}]: " v; [[ -n "${v}" ]] && MAKITO_ENC_IP="${v}"
  read -r -p "Windows 11 Orchestrator IP [${WINDOWS_ORCH_IP}]: " v; [[ -n "${v}" ]] && WINDOWS_ORCH_IP="${v}"

  read -r -p "WireGuard UDP port [${WG_PORT}]: " v; [[ -n "${v}" ]] && WG_PORT="${v}"
  read -r -p "WG tunnel CIDR [${WG_TUN_CIDR}]: " v; [[ -n "${v}" ]] && WG_TUN_CIDR="${v}"
  read -r -p "VPS WG IP [${WG_VPS_IP}]: " v; [[ -n "${v}" ]] && WG_VPS_IP="${v}"
  read -r -p "HAIBOX Router WG IP [${WG_GL_IP}]: " v; [[ -n "${v}" ]] && WG_GL_IP="${v}"
  read -r -p "Remote VPN Client WG IP [${REMOTE_CLIENT_IP}]: " v; [[ -n "${v}" ]] && REMOTE_CLIENT_IP="${v}"
  read -r -p "Makito UDP from [${MAKITO_ENC_UDP_FROM}]: " v; [[ -n "${v}" ]] && MAKITO_ENC_UDP_FROM="${v}"
  read -r -p "Makito UDP to [${MAKITO_ENC_UDP_TO}]: " v; [[ -n "${v}" ]] && MAKITO_ENC_UDP_TO="${v}"
  read -r -p "HSG SRT UDP from [${HSG_SRT_UDP_FROM}]: " v; [[ -n "${v}" ]] && HSG_SRT_UDP_FROM="${v}"
  read -r -p "HSG SRT UDP to [${HSG_SRT_UDP_TO}]: " v; [[ -n "${v}" ]] && HSG_SRT_UDP_TO="${v}"

  read -r -p "VPS public iface [${PUB_IFACE}]: " v; [[ -n "${v}" ]] && PUB_IFACE="${v}"
  read -r -p "VPS public IPv4 [${PUB_IP}]: " v; [[ -n "${v}" ]] && PUB_IP="${v}"

  save_state
  ok "Saved ${STATE_FILE}"
}

automatic_webui_setup() {
  WEBUI_USER="${WEBUI_USER:-admin}"
  WEBUI_PORT="${WEBUI_PORT:-65000}"
  WEBUI_BIND="0.0.0.0"
  WEBUI_ENABLED="Y"
  if [[ ! -s "${WEBUI_AUTH_FILE}" ]]; then
    WEBUI_USER="admin"
    WEBUI_PASSWORD="password"
    WEBUI_FORCE_PASSWORD_CHANGE="Y"
    ok "Initial Web UI credentials configured: admin / password"
    warn "A new password will be required at the first login."
  else
    ok "Existing Web UI credentials preserved."
  fi
}

install_deps() {
  have_cmd apt-get && have_cmd systemctl || { err "Debian/Ubuntu with systemd is required."; exit 1; }
  log "Installing packages..."
  if ! dpkg -s python3 >/dev/null 2>&1; then
    PYTHON3_INSTALLED_BY_SCRIPT="Y"
  fi
  apt-get update -y
  apt-get install -y wireguard wireguard-tools iptables iproute2 iputils-ping curl ca-certificates python3 openssl util-linux
  save_state
  ok "Packages installed."
}

install_self_copy() {
  local src
  src="$(script_real_path)"
  [[ -f "${src}" ]] || { err "Cannot locate the running script on disk."; exit 1; }
  if [[ "${src}" != "${SCRIPT_INSTALL_PATH}" ]]; then
    install -D -m 700 "${src}" "${SCRIPT_INSTALL_PATH}"
  fi
  ok "Installed script copy to ${SCRIPT_INSTALL_PATH}"
}

write_webui_auth() {
  [[ -n "${WEBUI_PASSWORD:-}" ]] || { err "Web UI password is empty."; exit 1; }
  python3 - "${WEBUI_USER}" "${WEBUI_AUTH_FILE}" "${WEBUI_FORCE_PASSWORD_CHANGE:-N}" 3<<< "${WEBUI_PASSWORD}" <<'PY'
import hashlib
import os
import secrets
import signal
import sys

user = sys.argv[1]
with os.fdopen(3, "r", encoding="utf-8") as password_input:
    password = password_input.read()[:-1]
out_path = sys.argv[2]
force_password_change = sys.argv[3]
salt = secrets.token_hex(16)
iterations = 200000
digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations).hex()

def esc(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')

content = "\n".join([
    f'WEBUI_USER="{esc(user)}"',
    f'WEBUI_PASS_SALT="{salt}"',
    f'WEBUI_PASS_ITERATIONS="{iterations}"',
    f'WEBUI_PASS_HASH="{digest}"',
    f'WEBUI_FORCE_PASSWORD_CHANGE="{force_password_change}"',
]) + "\n"

with open(out_path, "w", encoding="utf-8") as handle:
    handle.write(content)

os.chmod(out_path, 0o600)
PY
  unset WEBUI_PASSWORD
  ok "Wrote ${WEBUI_AUTH_FILE}"
}

write_webui_cert() {
  mkdir -p "${WEBUI_DIR}"

  if [[ -s "${WEBUI_CERT_FILE}" && -s "${WEBUI_KEY_FILE}" ]]; then
    ok "Using existing Web UI TLS certificate."
    return
  fi

  local cert_host san_ext
  cert_host="${PUB_IP:-haibox-webui.local}"
  if [[ "${cert_host}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    san_ext="subjectAltName=IP:${cert_host}"
  else
    san_ext="subjectAltName=DNS:${cert_host}"
  fi

  if openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
      -keyout "${WEBUI_KEY_FILE}" \
      -out "${WEBUI_CERT_FILE}" \
      -subj "/CN=${cert_host}" \
      -addext "${san_ext}" >/dev/null 2>&1; then
    :
  else
    warn "OpenSSL -addext failed; generating Web UI certificate without SAN."
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
      -keyout "${WEBUI_KEY_FILE}" \
      -out "${WEBUI_CERT_FILE}" \
      -subj "/CN=${cert_host}" >/dev/null 2>&1
  fi

  chmod 600 "${WEBUI_CERT_FILE}" "${WEBUI_KEY_FILE}"
  ok "Wrote Web UI TLS certificate: ${WEBUI_CERT_FILE}"
}

write_webui_app() {
  mkdir -p "${WEBUI_DIR}"
  cat > "${WEBUI_APP}" <<'PYEOF'
#!/usr/bin/env python3
import base64
import hashlib
import hmac
import html
import io
import ipaddress
import json
import os
import platform
import re
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import time
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote

STATE_FILE = "/root/haibox_wg_state.conf"
AUTH_FILE = "/root/haibox_webui_auth.conf"
ROUTER_CONF_OUT = "/root/haibox_router_wg.conf"
REMOTE_CLIENT_CONF_OUT = "/root/haibox_remote_client_wg.conf"
SCRIPT_PATH = "/usr/local/sbin/haibox-wireguard"
WEBUI_SERVICE_NAME = "haibox-webui.service"
CERT_FILE = "/opt/haibox-webui/haibox_webui.crt"
KEY_FILE = "/opt/haibox-webui/haibox_webui.key"
APPLIED_STATE_FILE = "/root/haibox_wg_applied.conf"
SCRIPT_VERSION = "6.5"
RELEASE_CHANNEL = "GOLDEN"
LOGO_URL = (
    "data:image/png;base64,"
    "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"
)

STATE_KEYS = [
    "PYTHON3_INSTALLED_BY_SCRIPT",
    "LAN_CIDR",
    "ROUTER_LAN_IP",
    "PROXMOX_IP",
    "STREAMHUB_IP",
    "HSG_IP",
    "MAKITO_ENC_IP",
    "WINDOWS_ORCH_IP",
    "UFW_WAS_ACTIVE",
    "WG_PORT",
    "WG_TUN_CIDR",
    "WG_VPS_IP",
    "WG_GL_IP",
    "REMOTE_CLIENT_IP",
    "MAKITO_ENC_UDP_FROM",
    "MAKITO_ENC_UDP_TO",
    "HSG_SRT_UDP_FROM",
    "HSG_SRT_UDP_TO",
    "PUB_IFACE",
    "PUB_IP",
    "WEBUI_ENABLED",
    "WEBUI_PORT",
    "WEBUI_USER",
    "WEBUI_BIND",
    "EXTRA_PF_RULES",
]

DEFAULTS = {
    "LAN_CIDR": "192.168.10.0/24",
    "ROUTER_LAN_IP": "192.168.10.1",
    "PROXMOX_IP": "192.168.10.250",
    "STREAMHUB_IP": "192.168.10.101",
    "HSG_IP": "192.168.10.102",
    "MAKITO_ENC_IP": "192.168.10.103",
    "WINDOWS_ORCH_IP": "192.168.10.104",
    "UFW_WAS_ACTIVE": "N",
    "WG_PORT": "443",
    "WG_TUN_CIDR": "10.66.66.0/24",
    "WG_VPS_IP": "10.66.66.1",
    "WG_GL_IP": "10.66.66.2",
    "REMOTE_CLIENT_IP": "10.66.66.3",
    "MAKITO_ENC_UDP_FROM": "30000",
    "MAKITO_ENC_UDP_TO": "30004",
    "HSG_SRT_UDP_FROM": "9000",
    "HSG_SRT_UDP_TO": "9100",
    "PUB_IFACE": "",
    "PUB_IP": "",
    "WEBUI_ENABLED": "Y",
    "WEBUI_PORT": "65000",
    "WEBUI_USER": "hairoot",
    "WEBUI_BIND": "0.0.0.0",
    "EXTRA_PF_RULES": "",
}

FIXED_PORTS = {
    "PROXMOX_GUI_PUB_PORT": "8006",
    "MAKITO_GUI_PUB_PORT": "10443",
    "HSG_GUI_PUB_PORT": "10444",
    "HSG_SSH_PUB_PORT": "2222",
    "HSG_RTMP_PUB_PORT": "1936",
    "ROUTER_ADMIN_PUB_PORT": "8080",
    "ROUTER_LUCI_PUB_PORT": "8081",
}

STREAMHUB_TCP_PORTS = [
    (7900, 7900, "StreamHub TCP 7900"),
    (7901, 7940, "StreamHub TCP 7901-7940"),
    (443, 443, "StreamHub HTTPS"),
    (8444, 8444, "StreamHub alternate HTTPS"),
    (8888, 8888, "StreamHub TCP 8888"),
    (8891, 8891, "StreamHub TCP 8891"),
    (8893, 8893, "StreamHub TCP 8893"),
    (8896, 8896, "StreamHub TCP 8896"),
    (8884, 8884, "StreamHub TCP 8884"),
    (8885, 8885, "StreamHub TCP 8885"),
    (5322, 5322, "StreamHub TCP 5322"),
    (1935, 1935, "StreamHub RTMP"),
    (20, 21, "StreamHub FTP"),
    (12000, 12009, "StreamHub passive FTP"),
]

STREAMHUB_UDP_PORTS = [
    (7900, 7940, "StreamHub UDP 7900-7940"),
    (5010, 5026, "StreamHub MoJoPro return"),
    (5353, 5353, "StreamHub mDNS"),
    (5959, 5960, "StreamHub UDP 5959-5960"),
    (5961, 5999, "StreamHub NDI connection"),
    (6960, 6999, "StreamHub NDI input"),
    (7960, 7999, "StreamHub NDI output"),
    (20000, 20100, "StreamHub Live Guest"),
    (20400, 20499, "StreamHub SIP"),
]

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
SESSION_COOKIE_NAME = "haibox_session"
SESSION_STORAGE_KEY = "haibox_ui_tab"
SESSION_TTL_SECONDS = 8 * 60 * 60
SESSIONS: Dict[str, Dict[str, object]] = {}


def load_shell_kv(path: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    file_path = Path(path)
    if not file_path.exists():
        return data
    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
            value = re.sub(r'\\([\\"$`])', lambda match: match.group(1), value)
        data[key.strip()] = value
    return data


def shell_escape(value: str) -> str:
    return re.sub(r'([\\"$`])', lambda match: "\\" + match.group(1), value)


def atomic_write(path: str, content: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".haibox-", dir=str(Path(path).parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            os.chmod(temporary, 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def merged_state() -> Dict[str, str]:
    state = dict(DEFAULTS)
    state.update(load_shell_kv(STATE_FILE))
    auth = load_shell_kv(AUTH_FILE)
    if auth.get("WEBUI_USER"):
        state["WEBUI_USER"] = auth["WEBUI_USER"]
    return state


def write_state(values: Dict[str, str]) -> None:
    state = merged_state()
    state.update(values)
    lines = [f'{key}="{shell_escape(str(state.get(key, "")))}"' for key in STATE_KEYS]
    atomic_write(STATE_FILE, "\n".join(lines) + "\n")


def applied_state() -> Optional[Dict[str, str]]:
    path = Path("/root/haibox_wg_applied.conf")
    if not path.exists():
        return None
    raw = load_shell_kv(str(path))
    if not raw:
        return None
    state = dict(DEFAULTS)
    state.update(raw)
    return state


def password_change_required() -> bool:
    return load_shell_kv(AUTH_FILE).get("WEBUI_FORCE_PASSWORD_CHANGE", "N").upper() == "Y"


def write_auth(user: str, password: Optional[str] = None, force_password_change: Optional[bool] = None) -> None:
    auth = load_shell_kv(AUTH_FILE)
    if password:
        salt = secrets.token_hex(16)
        iterations = 200000
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt),
            iterations,
        ).hex()
    else:
        salt = auth.get("WEBUI_PASS_SALT", "")
        iterations = int(auth.get("WEBUI_PASS_ITERATIONS", "200000"))
        digest = auth.get("WEBUI_PASS_HASH", "")
        if not salt or not digest:
            raise ValueError("Missing stored password hash. Set a new password.")

    if force_password_change is None:
        force_password_change = auth.get("WEBUI_FORCE_PASSWORD_CHANGE", "N").upper() == "Y"
    content = "\n".join([
        f'WEBUI_USER="{shell_escape(user)}"',
        f'WEBUI_PASS_SALT="{salt}"',
        f'WEBUI_PASS_ITERATIONS="{iterations}"',
        f'WEBUI_PASS_HASH="{digest}"',
        f'WEBUI_FORCE_PASSWORD_CHANGE="{"Y" if force_password_change else "N"}"',
    ]) + "\n"
    atomic_write(AUTH_FILE, content)


def verify_credentials(user: str, password: str) -> bool:
    auth = load_shell_kv(AUTH_FILE)
    if not auth:
        return False
    if not user or not password:
        return False
    try:
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(auth["WEBUI_PASS_SALT"]),
            int(auth["WEBUI_PASS_ITERATIONS"]),
        ).hex()
    except Exception:
        return False
    return hmac.compare_digest(user, auth.get("WEBUI_USER", "")) and hmac.compare_digest(
        digest,
        auth.get("WEBUI_PASS_HASH", ""),
    )


def prune_sessions() -> None:
    now = time.time()
    for session_id, payload in list(SESSIONS.items()):
        if float(payload.get("expires", 0)) <= now:
            SESSIONS.pop(session_id, None)


def create_session(user: str) -> str:
    prune_sessions()
    session_id = secrets.token_urlsafe(32)
    SESSIONS[session_id] = {
        "user": user,
        "expires": time.time() + SESSION_TTL_SECONDS,
    }
    return session_id


def set_session_flash(
    session_id: str,
    message: str,
    output: str = "",
    level: str = "info",
    state: Optional[Dict[str, str]] = None,
) -> None:
    payload = SESSIONS.get(session_id)
    if payload is not None:
        payload["flash"] = {
            "message": message,
            "output": output,
            "level": level,
            "state": state,
        }


def pop_session_flash(session_id: str) -> Dict[str, object]:
    payload = SESSIONS.get(session_id)
    if payload is None:
        return {}
    flash = payload.pop("flash", {})
    return flash if isinstance(flash, dict) else {}


def get_session_id_from_cookie(cookie_header: Optional[str]) -> Optional[str]:
    if not cookie_header:
        return None
    jar = SimpleCookie()
    try:
        jar.load(cookie_header)
    except Exception:
        return None
    morsel = jar.get(SESSION_COOKIE_NAME)
    return morsel.value if morsel else None


def get_active_session_id(cookie_header: Optional[str]) -> Optional[str]:
    prune_sessions()
    session_id = get_session_id_from_cookie(cookie_header)
    if not session_id:
        return None
    payload = SESSIONS.get(session_id)
    if not payload:
        return None
    payload["expires"] = time.time() + SESSION_TTL_SECONDS
    return session_id


def destroy_session(session_id: Optional[str]) -> None:
    if session_id:
        SESSIONS.pop(session_id, None)


def esc(value: object) -> str:
    return html.escape(str(value or ""))


def bool_checked(value: str) -> str:
    return "checked" if value == "Y" else ""


def input_row(label: str, name: str, value: str, input_type: str = "text", placeholder: str = "") -> str:
    placeholder_attr = f' placeholder="{esc(placeholder)}"' if placeholder else ""
    return (
        f'<label class="field">'
        f'<span>{esc(label)}</span>'
        f'<input type="{input_type}" name="{name}" value="{esc(value)}"{placeholder_attr}>'
        f"</label>"
    )


def option_selected(value: str, selected: str) -> str:
    return "selected" if value == selected else ""


def empty_extra_rule() -> Dict[str, str]:
    return {
        "proto": "udp",
        "public_from": "",
        "public_to": "",
        "target_ip": "",
        "target_from": "",
        "target_to": "",
        "label": "",
    }


def parse_extra_rules(raw_value: str) -> List[Dict[str, str]]:
    rules: List[Dict[str, str]] = []
    for row in (raw_value or "").split(";"):
        if not row:
            continue
        parts = row.split("|", 6)
        if len(parts) < 6:
            continue
        while len(parts) < 7:
            parts.append("")
        proto = parts[0].strip().lower()
        if proto not in ("tcp", "udp"):
            continue
        rules.append({
            "proto": proto,
            "public_from": parts[1].strip(),
            "public_to": parts[2].strip(),
            "target_ip": parts[3].strip(),
            "target_from": parts[4].strip(),
            "target_to": parts[5].strip(),
            "label": unquote(parts[6].strip()),
        })
    return rules


def encode_extra_rules(rules: List[Dict[str, str]]) -> str:
    rows: List[str] = []
    for rule in rules:
        rows.append("|".join([
            rule["proto"].lower(),
            rule["public_from"],
            rule["public_to"],
            rule["target_ip"],
            rule["target_from"],
            rule["target_to"],
            quote(rule.get("label", "")[:64], safe="-_.~"),
        ]))
    return ";".join(rows)


def range_text(first: str, last: str) -> str:
    return first if first == last else f"{first}-{last}"


def extra_rule_row(rule: Dict[str, str]) -> str:
    proto = rule.get("proto", "udp").lower()
    if proto not in ("tcp", "udp"):
        proto = "udp"
    port_value = range_text(rule.get("public_from", ""), rule.get("public_to", ""))
    return f"""
      <div class="extra-rule-row" data-extra-rule>
        <div class="extra-rule-head">
          <strong>{esc(rule.get("label") or "Extra rule")}</strong>
          <button class="danger small-button" type="button" data-remove-extra-rule>Remove</button>
        </div>
        <div class="extra-rule-grid">
          <label class="field">
            <span>Protocol</span>
            <select name="EXTRA_RULE_PROTO">
              <option value="udp" {option_selected(proto, "udp")}>UDP</option>
              <option value="tcp" {option_selected(proto, "tcp")}>TCP</option>
            </select>
          </label>
          {input_row("IP Address", "EXTRA_RULE_TARGET_IP", rule.get("target_ip", ""))}
          {input_row("Public port / range", "EXTRA_RULE_PORT", port_value)}
          {input_row("Local port / range", "EXTRA_RULE_TARGET_PORT", range_text(rule.get("target_from", ""), rule.get("target_to", "")))}
          {input_row("Label", "EXTRA_RULE_LABEL", rule.get("label", ""))}
        </div>
      </div>
"""


def extra_rule_form_rows(state: Dict[str, str]) -> str:
    rules = parse_extra_rules(state.get("EXTRA_PF_RULES", ""))
    if not rules:
        rules = [empty_extra_rule()]
    return "".join(extra_rule_row(rule) for rule in rules)


def extra_rules_summary_rows(state: Dict[str, str]) -> str:
    rules = parse_extra_rules(state.get("EXTRA_PF_RULES", ""))
    if not rules:
        return summary_row(
            "Extra rules",
            "None",
            "No custom forwarding rules configured",
            value_class="disabled",
        )

    rows: List[str] = []
    for index, rule in enumerate(rules, start=1):
        label = rule.get("label") or f"Extra rule {index}"
        public_range = range_text(rule["public_from"], rule["public_to"])
        target_range = range_text(rule["target_from"], rule["target_to"])
        rows.append(summary_row(
            label,
            f'{rule["proto"].upper()} {public_range}',
            f'To {rule["target_ip"]}:{target_range}',
        ))
    return "".join(rows)


def summary_row(label: str, value: str, note: str = "", href: str = "", value_class: str = "") -> str:
    note_html = f"<small>{esc(note)}</small>" if note else ""
    value_classes = "summary-value"
    if value_class:
        value_classes += f" {value_class}"
    if href:
        value_html = (
            f'<a class="{value_classes}" href="{esc(href)}" target="_blank" rel="noopener">{esc(value)}</a>'
        )
    else:
        value_html = f'<div class="{value_classes}">{esc(value)}</div>'
    return (
        '<div class="summary-row">'
        '<div class="summary-copy">'
        f'<strong>{esc(label)}</strong>'
        f'{note_html}'
        '</div>'
        f'{value_html}'
        '</div>'
    )


def management_rows(state: Dict[str, str]) -> str:
    host = state.get("PUB_IP") or "SERVER_IP"
    web_port = state.get("WEBUI_PORT", DEFAULTS["WEBUI_PORT"])
    web_url = f"https://{host}:{web_port}"
    wireguard_note = "%s <-> %s" % (
        state.get("WG_VPS_IP", DEFAULTS["WG_VPS_IP"]),
        state.get("WG_GL_IP", DEFAULTS["WG_GL_IP"]),
    )
    return "".join([
        summary_row("Control Panel", web_url, "Browser access to this panel", web_url),
        summary_row("WireGuard", "UDP %s" % state.get("WG_PORT", DEFAULTS["WG_PORT"]), wireguard_note),
        summary_row(
            "Public Network",
            state.get("PUB_IFACE", DEFAULTS["PUB_IFACE"]),
            "IPv4 %s" % state.get("PUB_IP", DEFAULTS["PUB_IP"]),
        ),
    ])


def public_service_rows(state: Dict[str, str]) -> str:
    host = state.get("PUB_IP") or "SERVER_IP"
    rows: List[str] = []
    proxmox_url = f"https://{host}:{FIXED_PORTS['PROXMOX_GUI_PUB_PORT']}"
    rows.append(summary_row("Proxmox GUI", proxmox_url, "Always published through the VPS", proxmox_url))

    rows.extend([
        summary_row(
            "Makito X4E GUI",
            f"https://{host}:{FIXED_PORTS['MAKITO_GUI_PUB_PORT']}",
            "HTTPS admin access",
            f"https://{host}:{FIXED_PORTS['MAKITO_GUI_PUB_PORT']}",
        ),
        summary_row(
            "HSG Web GUI",
            f"https://{host}:{FIXED_PORTS['HSG_GUI_PUB_PORT']}",
            "HTTPS admin access",
            f"https://{host}:{FIXED_PORTS['HSG_GUI_PUB_PORT']}",
        ),
        summary_row(
            "HSG SSH",
            f"ssh -p {FIXED_PORTS['HSG_SSH_PUB_PORT']} hvroot@{host}",
            "Shell access forwarded to the HSG",
        ),
        summary_row(
            "HSG RTMP",
            f"rtmp://{host}:{FIXED_PORTS['HSG_RTMP_PUB_PORT']}",
            "RTMP endpoint forwarded to the HSG",
        ),
        summary_row(
            "StreamHub",
            f"https://{host}:443",
            "Primary HTTPS entry point",
            f"https://{host}:443",
        ),
        summary_row(
            "StreamHub Alt",
            f"https://{host}:8444",
            "Alternate HTTPS entry point",
            f"https://{host}:8444",
        ),
        summary_row(
            "Router Admin",
            f"https://{host}:{FIXED_PORTS['ROUTER_ADMIN_PUB_PORT']}",
            "GL.iNet HTTPS interface",
            f"https://{host}:{FIXED_PORTS['ROUTER_ADMIN_PUB_PORT']}",
        ),
        summary_row(
            "Router LuCI",
            f"https://{host}:{FIXED_PORTS['ROUTER_LUCI_PUB_PORT']}",
            "OpenWrt LuCI HTTPS interface",
            f"https://{host}:{FIXED_PORTS['ROUTER_LUCI_PUB_PORT']}",
        ),
    ])
    return "".join(rows)


def public_service_links(state: Dict[str, str]) -> str:
    host = state.get("PUB_IP") or "SERVER_IP"
    services = [
        ("StreamHub", f"https://{host}:443"),
        ("Makito X4E", f"https://{host}:{FIXED_PORTS['MAKITO_GUI_PUB_PORT']}"),
        ("HSG / HMG", f"https://{host}:{FIXED_PORTS['HSG_GUI_PUB_PORT']}"),
        ("Proxmox", f"https://{host}:{FIXED_PORTS['PROXMOX_GUI_PUB_PORT']}"),
        ("Router", f"https://{host}:{FIXED_PORTS['ROUTER_ADMIN_PUB_PORT']}"),
        ("LuCI", f"https://{host}:{FIXED_PORTS['ROUTER_LUCI_PUB_PORT']}"),
    ]
    return "".join(
        f'<a class="service-link" href="{esc(url)}" target="_blank" rel="noopener">'
        f'<span>{esc(label)}</span><span class="external-icon" aria-hidden="true">↗</span></a>'
        for label, url in services
    )


def redirect_details(state: Dict[str, str]) -> str:
    rows = [
        ("StreamHub HTTPS", "TCP 443", state.get("STREAMHUB_IP", DEFAULTS["STREAMHUB_IP"]), "443"),
        ("StreamHub Alt HTTPS", "TCP 8444", state.get("STREAMHUB_IP", DEFAULTS["STREAMHUB_IP"]), "8444"),
        ("Makito HTTPS", f"TCP {FIXED_PORTS['MAKITO_GUI_PUB_PORT']}", state.get("MAKITO_ENC_IP", DEFAULTS["MAKITO_ENC_IP"]), "443"),
        ("HSG HTTPS", f"TCP {FIXED_PORTS['HSG_GUI_PUB_PORT']}", state.get("HSG_IP", DEFAULTS["HSG_IP"]), "443"),
        ("HSG SSH", f"TCP {FIXED_PORTS['HSG_SSH_PUB_PORT']}", state.get("HSG_IP", DEFAULTS["HSG_IP"]), "22"),
        ("HSG RTMP", f"TCP {FIXED_PORTS['HSG_RTMP_PUB_PORT']}", state.get("HSG_IP", DEFAULTS["HSG_IP"]), "1935"),
        ("Proxmox HTTPS", f"TCP {FIXED_PORTS['PROXMOX_GUI_PUB_PORT']}", state.get("PROXMOX_IP", DEFAULTS["PROXMOX_IP"]), "8006"),
        ("Router Admin", f"TCP {FIXED_PORTS['ROUTER_ADMIN_PUB_PORT']}", state.get("ROUTER_LAN_IP", DEFAULTS["ROUTER_LAN_IP"]), "8080"),
        ("Router LuCI", f"TCP {FIXED_PORTS['ROUTER_LUCI_PUB_PORT']}", state.get("ROUTER_LAN_IP", DEFAULTS["ROUTER_LAN_IP"]), "8081"),
    ]
    return "".join(
        '<div class="redirect-row">'
        f'<strong>{esc(label)}</strong><span>{esc(public_port)}</span>'
        f'<code>{esc(target_ip)}:{esc(target_port)}</code></div>'
        for label, public_port, target_ip, target_port in rows
    )


def udp_range_rows(state: Dict[str, str]) -> str:
    return "".join([
        summary_row(
            "Makito UDP Media",
            "%s-%s/udp" % (
                state.get("MAKITO_ENC_UDP_FROM", DEFAULTS["MAKITO_ENC_UDP_FROM"]),
                state.get("MAKITO_ENC_UDP_TO", DEFAULTS["MAKITO_ENC_UDP_TO"]),
            ),
            "Forwarded to %s" % state.get("MAKITO_ENC_IP", DEFAULTS["MAKITO_ENC_IP"]),
        ),
        summary_row(
            "HSG SRT UDP",
            "%s-%s/udp" % (
                state.get("HSG_SRT_UDP_FROM", DEFAULTS["HSG_SRT_UDP_FROM"]),
                state.get("HSG_SRT_UDP_TO", DEFAULTS["HSG_SRT_UDP_TO"]),
            ),
            "Forwarded to %s" % state.get("HSG_IP", DEFAULTS["HSG_IP"]),
        ),
    ])


def router_config_text() -> str:
    path = Path(ROUTER_CONF_OUT)
    if not path.exists():
        return "Router config has not been generated yet."
    return path.read_text(encoding="utf-8", errors="replace")


def remote_client_config_text() -> str:
    path = Path(REMOTE_CLIENT_CONF_OUT)
    if not path.exists():
        return "Remote VPN client has not been created yet."
    return path.read_text(encoding="utf-8", errors="replace")


def render_login_page(message: str = "", username: str = "") -> str:
    status_html = (
        f'<div class="login-status">{esc(message)}</div>'
        if message
        else ""
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HAIBOX Login</title>
  <style>
    :root {{
      --bg: #05090f;
      --panel: rgba(12, 18, 27, 0.94);
      --line: rgba(150, 176, 194, 0.14);
      --brand: #00a3e0;
      --ink: #f5fbff;
      --muted: #90a9ba;
      --shadow: 0 22px 48px rgba(0, 0, 0, 0.34);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
      font-family: "Aptos", "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at 12% 10%, rgba(0,163,224,0.16), transparent 22%),
        radial-gradient(circle at 88% 8%, rgba(0,163,224,0.12), transparent 18%),
        linear-gradient(180deg, #04070c 0%, #08111a 48%, #060b12 100%);
    }}
    .login-shell {{
      width: min(1100px, 100%);
      display: grid;
      grid-template-columns: minmax(0, 1.15fr) minmax(320px, 420px);
      gap: 20px;
      align-items: center;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 28px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(14px);
    }}
    .brand-panel {{
      padding: clamp(26px, 4vw, 42px);
      text-align: center;
    }}
    .brand-panel img {{
      display: block;
      width: min(760px, 100%);
      height: auto;
      margin: 0 auto 18px;
      filter: drop-shadow(0 18px 40px rgba(0, 0, 0, 0.38));
    }}
    .brand-panel h1 {{
      margin: 0;
      font-size: clamp(30px, 4vw, 44px);
      line-height: 1.05;
    }}
    .brand-panel p {{
      margin: 10px auto 0;
      max-width: 34ch;
      color: var(--muted);
      line-height: 1.5;
    }}
    .login-panel {{
      padding: 28px;
    }}
    .login-panel h2 {{
      margin: 0;
      font-size: 24px;
    }}
    .login-panel p {{
      margin: 8px 0 0 0;
      color: var(--muted);
      line-height: 1.45;
    }}
    .login-status {{
      margin: 18px 0 0 0;
      padding: 12px 14px;
      border-radius: 14px;
      background: rgba(0, 163, 224, 0.12);
      color: #a8e9ff;
      font-size: 14px;
    }}
    form {{
      display: grid;
      gap: 14px;
      margin-top: 18px;
    }}
    label {{
      display: grid;
      gap: 7px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.02em;
      text-transform: uppercase;
      color: var(--muted);
    }}
    input {{
      width: 100%;
      border: 1px solid rgba(146, 172, 190, 0.18);
      border-radius: 14px;
      padding: 13px 14px;
      background: #0b121a;
      color: var(--ink);
      outline: none;
    }}
    input:focus {{
      border-color: var(--brand);
      box-shadow: 0 0 0 4px rgba(0, 163, 224, 0.18);
    }}
    button {{
      margin-top: 4px;
      border: 0;
      border-radius: 999px;
      padding: 12px 18px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      color: white;
      background: linear-gradient(135deg, #00a3e0, #008bc5);
      box-shadow: 0 12px 26px rgba(0, 121, 170, 0.28);
    }}
    .login-note {{
      margin-top: 14px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.45;
    }}
    @media (max-width: 980px) {{
      .login-shell {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <div class="login-shell">
    <section class="panel brand-panel">
      <img src="{esc(LOGO_URL)}" alt="HAIBOX logo">
      <h1>WireGuard Control Panel</h1>
      <p>Sign in to manage WireGuard, DNAT and router export.</p>
    </section>
    <section class="panel login-panel">
      <h2>Login</h2>
      <p>Authentication is required every time you reopen the page.</p>
      {status_html}
      <form method="post" action="/login" autocomplete="off">
        <label>
          Username
          <input type="text" name="username" value="{esc(username)}" autocomplete="username" required>
        </label>
        <label>
          Password
          <input type="password" name="password" value="" autocomplete="current-password" required>
        </label>
        <button type="submit">Login</button>
      </form>
      <div class="login-note">Close the tab or use Logout to require a fresh login on the next access.</div>
    </section>
  </div>
  <script>
    try {{
      window.sessionStorage.removeItem("{SESSION_STORAGE_KEY}");
    }} catch (err) {{}}
  </script>
</body>
</html>
"""


def render_login_bootstrap() -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Signing In</title>
</head>
<body style="background:#060b12;color:#f5fbff;font-family:Aptos,Segoe UI,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;">
  <p>Signing in...</p>
  <script>
    try {{
      window.sessionStorage.setItem("{SESSION_STORAGE_KEY}", "1");
    }} catch (err) {{}}
    window.location.replace("/change-password");
  </script>
</body>
</html>
"""


def render_change_password_page(message: str = "", level: str = "info") -> str:
    status_html = f'<div class="login-status">{esc(message)}</div>' if message else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Set HAIBOX Password</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ margin:0; min-height:100vh; display:grid; place-items:center; padding:24px; font-family:Aptos,"Segoe UI",sans-serif; color:#f5fbff; background:linear-gradient(180deg,#04070c,#08111a 55%,#060b12); }}
    .panel {{ width:min(440px,100%); padding:28px; background:rgba(12,18,27,.96); border:1px solid rgba(150,176,194,.14); border-radius:24px; box-shadow:0 22px 48px rgba(0,0,0,.34); }}
    h1 {{ margin:0; font-size:25px; }} p {{ color:#90a9ba; line-height:1.5; }}
    form,label {{ display:grid; gap:10px; }} form {{ margin-top:20px; gap:15px; }} label {{ color:#90a9ba; font-size:12px; font-weight:700; text-transform:uppercase; }}
    input {{ width:100%; padding:13px 14px; border:1px solid rgba(146,172,190,.18); border-radius:14px; background:#0b121a; color:#f5fbff; outline:none; }}
    input:focus {{ border-color:#00a3e0; box-shadow:0 0 0 4px rgba(0,163,224,.18); }}
    button {{ border:0; border-radius:999px; padding:12px 18px; font:inherit; font-weight:700; cursor:pointer; color:white; background:linear-gradient(135deg,#00a3e0,#008bc5); }}
    .login-status {{ margin-top:16px; padding:12px 14px; border-radius:14px; background:rgba(0,163,224,.12); color:#a8e9ff; font-size:14px; }}
  </style>
</head>
<body><section class="panel">
  <h1>Choose a new password</h1>
  <p>The initial password must be replaced before the control panel can be used. Use at least 10 characters.</p>
  {status_html}
  <form method="post" action="/change-password" autocomplete="off">
    <label>New password<input type="password" name="password" autocomplete="new-password" minlength="10" required></label>
    <label>Confirm password<input type="password" name="confirm" autocomplete="new-password" minlength="10" required></label>
    <button type="submit">Save New Password</button>
  </form>
</section></body></html>"""


def render_logout_bootstrap() -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Signing Out</title>
</head>
<body style="background:#060b12;color:#f5fbff;font-family:Aptos,Segoe UI,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;">
  <p>Signing out...</p>
  <script>
    try {{
      window.sessionStorage.removeItem("{SESSION_STORAGE_KEY}");
    }} catch (err) {{}}
    window.location.replace("/login?logged_out=1");
  </script>
</body>
</html>
"""


def _script_sha256() -> str:
    try:
        digest = hashlib.sha256()
        with open(SCRIPT_PATH, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return "unavailable"


def _format_uptime(seconds: float) -> str:
    total_minutes = max(0, int(seconds // 60))
    days, remainder = divmod(total_minutes, 24 * 60)
    hours, minutes = divmod(remainder, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def build_information() -> Dict[str, str]:
    os_name = platform.platform()
    try:
        os_release = load_shell_kv("/etc/os-release")
        os_name = os_release.get("PRETTY_NAME", os_name)
    except OSError:
        pass
    try:
        uptime = _format_uptime(float(Path("/proc/uptime").read_text(encoding="ascii").split()[0]))
    except (OSError, ValueError, IndexError):
        uptime = "unavailable"
    try:
        applied_at = time.strftime(
            "%Y-%m-%d %H:%M:%S UTC",
            time.gmtime(Path(APPLIED_STATE_FILE).stat().st_mtime),
        )
    except OSError:
        applied_at = "never"
    try:
        started = subprocess.run(
            ["systemctl", "show", WEBUI_SERVICE_NAME, "--property=ActiveEnterTimestamp", "--value"],
            capture_output=True, text=True, timeout=2, check=False,
        ).stdout.strip() or "unavailable"
    except (OSError, subprocess.SubprocessError):
        started = "unavailable"
    return {
        "version": SCRIPT_VERSION,
        "channel": RELEASE_CHANNEL,
        "sha256": _script_sha256(),
        "os": os_name,
        "kernel": platform.release(),
        "uptime": uptime,
        "last_apply": applied_at,
        "webui_started": started,
    }


def _command_output(command: List[str], timeout: float = 8.0) -> str:
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False,
        )
        output = result.stdout
        if result.stderr:
            output += ("\n" if output else "") + result.stderr
        return f"$ {' '.join(command)}\nexit={result.returncode}\n{output}".rstrip() + "\n"
    except subprocess.TimeoutExpired:
        return f"$ {' '.join(command)}\nERROR: command timed out\n"
    except OSError as exc:
        return f"$ {' '.join(command)}\nERROR: {exc}\n"


def build_support_bundle() -> bytes:
    state = merged_state()
    info = build_information()
    safe_state = {key: state.get(key, "") for key in STATE_KEYS}
    files: Dict[str, str] = {
        "00-build-information.json": json.dumps(info, indent=2, sort_keys=True) + "\n",
        "01-sanitized-state.json": json.dumps(safe_state, indent=2, sort_keys=True) + "\n",
        "02-system-health.txt": _command_output([SCRIPT_PATH, "--health"], timeout=30),
        "03-wireguard-status.txt": _command_output(["wg", "show", "wg0"]),
        "04-ip-addresses.txt": _command_output(["ip", "-brief", "address"]),
        "05-ip-routes.txt": _command_output(["ip", "-4", "route", "show"]),
        "06-haibox-nat-chain.txt": _command_output(["iptables", "-t", "nat", "-S", "HAIBOX_NAT"]),
        "07-haibox-forward-chain.txt": _command_output(["iptables", "-S", "HAIBOX_FWD"]),
        "08-wireguard-service.txt": _command_output(["systemctl", "status", "wg-quick@wg0", "--no-pager", "--full"]),
        "09-webui-service.txt": _command_output(["systemctl", "status", WEBUI_SERVICE_NAME, "--no-pager", "--full"]),
        "10-rules-service.txt": _command_output(["systemctl", "status", "haibox-wg-rules.service", "--no-pager", "--full"]),
        "11-webui-journal.txt": _command_output(["journalctl", "-u", WEBUI_SERVICE_NAME, "-n", "200", "--no-pager", "--output=short-iso"]),
        "12-kernel-network.txt": "\n".join([
            _command_output(["sysctl", "net.ipv4.ip_forward"]),
            _command_output(["sysctl", "net.ipv4.conf.all.rp_filter"]),
            _command_output(["sysctl", "net.ipv4.conf.default.rp_filter"]),
        ]),
        "13-dashboard-status.json": json.dumps(dashboard_status(applied_state()), indent=2, sort_keys=True) + "\n",
        "README.txt": (
            "HAIBOX WireGuard sanitized support bundle\n"
            "Generated by v" + SCRIPT_VERSION + " (" + RELEASE_CHANNEL + ").\n"
            "Private WireGuard keys, Web UI credentials, authentication hashes, cookies,\n"
            "TLS private keys and downloadable client configurations are intentionally excluded.\n"
        ),
    }
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, content in files.items():
            payload = content.encode("utf-8", errors="replace")
            entry = tarfile.TarInfo(name=name)
            entry.size = len(payload)
            entry.mode = 0o600
            entry.mtime = int(time.time())
            archive.addfile(entry, io.BytesIO(payload))
    return output.getvalue()


def render_page(state: Dict[str, str], message: str = "", output: str = "", level: str = "info") -> str:
    status_class = {
        "info": "status info",
        "ok": "status ok",
        "error": "status error",
    }.get(level, "status info")
    host = state.get("PUB_IP") or "SERVER_IP"
    web_port = state.get("WEBUI_PORT", DEFAULTS["WEBUI_PORT"])
    management_summary = management_rows(state)
    services_summary = public_service_rows(state)
    services_links = public_service_links(state)
    redirects_html = redirect_details(state)
    udp_summary = udp_range_rows(state)
    extra_rules_html = extra_rule_form_rows(state)
    extra_rules_summary = extra_rules_summary_rows(state)
    build = build_information()
    status_html = f'<div class="{status_class} header-status">{esc(message)}</div>' if message else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HAIBOX WireGuard Control Panel</title>
  <style>
    :root {{
      --bg: #060b12;
      --panel: rgba(12, 18, 27, 0.92);
      --panel-strong: #0b121a;
      --panel-soft: #0f1721;
      --ink: #f5fbff;
      --muted: #90a9ba;
      --line: rgba(150, 176, 194, 0.14);
      --brand: #00a3e0;
      --brand-strong: #008bc5;
      --brand-soft: rgba(0, 163, 224, 0.16);
      --ok-soft: rgba(44, 158, 98, 0.16);
      --error-soft: rgba(194, 61, 76, 0.15);
      --shadow: 0 22px 48px rgba(0, 0, 0, 0.34);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      font-family: "Aptos", "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at -5% 12%, rgba(0,163,224,0.18), transparent 28%),
        radial-gradient(circle at 88% 8%, rgba(0,163,224,0.12), transparent 18%),
        linear-gradient(180deg, #04070c 0%, #08111a 48%, #060b12 100%);
      animation: page-in 260ms ease-out;
    }}
    @keyframes page-in {{
      from {{ opacity: 0; transform: translateY(8px); }}
      to {{ opacity: 1; transform: translateY(0); }}
    }}
    .page-shell {{ width: min(1560px, calc(100vw - 40px)); margin: 24px auto 36px; }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 24px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(14px);
    }}
    .hero {{
      padding: clamp(24px, 3.2vw, 34px) clamp(20px, 2.6vw, 28px) clamp(22px, 2.4vw, 26px);
      margin-bottom: 20px;
      background:
        linear-gradient(180deg, rgba(17, 24, 35, 0.96), rgba(11, 17, 25, 0.94)),
        linear-gradient(135deg, rgba(0,163,224,0.08), transparent);
    }}
    .hero-logo {{
      display: flex;
      justify-content: center;
      margin-bottom: 20px;
    }}
    .hero-logo img {{
      display: block;
      width: min(980px, calc(100vw - 120px));
      height: auto;
      filter: drop-shadow(0 18px 40px rgba(0, 0, 0, 0.38));
    }}
    .hero-copy {{
      text-align: center;
      margin-bottom: 20px;
    }}
    h1 {{
      margin: 0;
      font-size: 36px;
      line-height: 1.04;
      color: #ffffff;
    }}
    .hero-meta {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      max-width: 980px;
      margin: 0 auto;
    }}
    .hero-actions {{
      display: flex;
      justify-content: center;
      margin-top: 14px;
    }}
    .logout-form {{
      margin: 0;
    }}
    .meta-pill {{
      padding: 14px 16px;
      border-radius: 16px;
      background: linear-gradient(180deg, rgba(0,163,224,0.10), rgba(15,23,33,0.96));
      border: 1px solid rgba(0, 163, 224, 0.16);
    }}
    .meta-pill span {{
      display: block;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.16em;
      color: var(--muted);
      margin-bottom: 6px;
    }}
    .meta-pill strong {{
      display: block;
      font-size: 15px;
      color: #ffffff;
      word-break: break-word;
    }}
    .layout {{ display: grid; grid-template-columns: minmax(0, 1.38fr) minmax(320px, 0.92fr); gap: 20px; align-items: start; }}
    .aside {{ display: grid; gap: 20px; position: sticky; top: 22px; }}
    .panel-body {{ padding: clamp(20px, 2vw, 24px); }}
    .panel-head {{
      display: flex;
      justify-content: flex-start;
      gap: 16px;
      align-items: flex-start;
      margin-bottom: 16px;
    }}
    .panel-title {{
      margin: 0;
      font-size: 22px;
      line-height: 1.1;
      color: #ffffff;
    }}
    .panel-subtitle {{
      margin: 4px 0 0 0;
      color: var(--muted);
      line-height: 1.45;
    }}
    .config-block + .config-block {{
      margin-top: 18px;
    }}
    .config-block {{
      padding: 18px;
      border-radius: 18px;
      background: linear-gradient(180deg, rgba(16, 24, 35, 0.96), rgba(11, 18, 27, 0.96));
      border: 1px solid var(--line);
    }}
    .tab-bar {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 16px;
    }}
    .tab-button {{
      border-radius: 999px;
      background: rgba(255,255,255,0.04);
      color: #dfeef7;
      border: 1px solid var(--line);
      box-shadow: none;
    }}
    .tab-button.active {{
      background: rgba(0,163,224,0.16);
      border-color: rgba(0, 163, 224, 0.42);
      color: #ffffff;
    }}
    .primary-navigation {{
      padding: 6px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(5, 12, 18, 0.58);
    }}
    .primary-navigation .tab-button {{ flex: 1 1 150px; }}
    .subtab-bar {{
      display: inline-flex;
      flex-wrap: wrap;
      gap: 6px;
      padding: 5px;
      margin-bottom: 16px;
      border-radius: 14px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.025);
    }}
    .subtab-button {{
      min-height: 38px;
      padding: 8px 14px;
      border-radius: 10px;
      border: 0;
      box-shadow: none;
      background: transparent;
      color: var(--muted);
    }}
    .subtab-button.active {{ background: rgba(0,163,224,0.16); color: #fff; }}
    [data-config-page][hidden] {{ display: none; }}
    .tab-page[hidden] {{
      display: none;
    }}
    .block-head {{
      margin-bottom: 12px;
    }}
    .block-head h3 {{
      margin: 0;
      font-size: 15px;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: #dff6ff;
    }}
    .block-head p {{
      margin: 4px 0 0 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.4;
    }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; }}
    .field {{ display: grid; gap: 7px; }}
    .field span {{
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.02em;
      color: var(--muted);
      text-transform: uppercase;
    }}
    .field input,
    .field select {{
      width: 100%;
      min-width: 0;
      border: 1px solid rgba(146, 172, 190, 0.18);
      border-radius: 14px;
      padding: 13px 14px;
      background: var(--panel-strong);
      color: var(--ink);
      outline: none;
      transition: border-color 140ms ease, box-shadow 140ms ease, transform 140ms ease;
    }}
    .field input:focus,
    .field select:focus {{
      border-color: var(--brand);
      box-shadow: 0 0 0 4px rgba(0, 163, 224, 0.18);
      transform: translateY(-1px);
    }}
    .field input::placeholder {{ color: #70889a; }}
    .extra-rule-list {{
      display: grid;
      gap: 14px;
    }}
    .extra-rule-row {{
      padding: 16px;
      border-radius: 18px;
      background: rgba(5, 9, 15, 0.42);
      border: 1px solid var(--line);
    }}
    .extra-rule-head {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
    }}
    .extra-rule-head strong {{
      color: #ffffff;
      font-size: 14px;
    }}
    .extra-rule-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(min(100%, 180px), 1fr));
      gap: 12px;
      align-items: end;
    }}
    .extra-rule-grid .field {{
      min-width: 0;
    }}
    .extra-help {{
      margin: 0 0 14px 0;
      color: var(--muted);
      line-height: 1.5;
      font-size: 13px;
    }}
    .switch-card {{
      margin-top: 14px;
      display: flex;
      gap: 12px;
      align-items: flex-start;
      padding: 14px 16px;
      border-radius: 16px;
      background: rgba(0, 163, 224, 0.10);
      border: 1px solid rgba(0, 163, 224, 0.16);
      color: var(--ink);
      font-weight: 600;
    }}
    .switch-card small {{
      display: block;
      margin-top: 4px;
      color: var(--muted);
      font-weight: 400;
      line-height: 1.45;
    }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 12px; margin-top: 22px; }}
    button, .ghost-link {{
      border: 0;
      border-radius: 999px;
      padding: 12px 18px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      text-decoration: none;
      transition: transform 140ms ease, box-shadow 140ms ease, border-color 140ms ease;
    }}
    button:hover, .ghost-link:hover {{ transform: translateY(-1px); }}
    .primary {{
      background: linear-gradient(135deg, var(--brand), var(--brand-strong));
      color: white;
      box-shadow: 0 12px 26px rgba(0, 121, 170, 0.28);
    }}
    .secondary {{
      background: linear-gradient(135deg, #1b2d40, #101c29);
      color: white;
      box-shadow: 0 12px 26px rgba(0, 0, 0, 0.22);
    }}
    .ghost-link {{
      background: rgba(255,255,255,0.04);
      color: #dfeef7;
      border: 1px solid var(--line);
    }}
    .logout-button {{
      background: rgba(255,255,255,0.04);
      color: #e6f6ff;
      border: 1px solid var(--line);
      box-shadow: none;
    }}
    .logout-button:hover {{
      border-color: rgba(0, 163, 224, 0.32);
      background: rgba(0,163,224,0.10);
    }}
    .danger {{
      background: rgba(194, 61, 76, 0.14);
      color: #ffd7dc;
      border: 1px solid rgba(194, 61, 76, 0.28);
      box-shadow: none;
    }}
    .small-button {{
      padding: 8px 12px;
      font-size: 13px;
    }}
    .status {{ margin: 0 0 18px 0; padding: 13px 16px; border-radius: 16px; font-size: 14px; white-space: pre-line; line-height: 1.5; }}
    .status.info {{ background: rgba(0, 163, 224, 0.12); color: #a8e9ff; }}
    .status.ok {{ background: var(--ok-soft); color: #a4f0c9; }}
    .status.error {{ background: var(--error-soft); color: #ffb3bc; }}
    .summary-list {{ display: grid; gap: 0; }}
    .summary-row {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(150px, 220px);
      gap: 14px;
      align-items: start;
      padding: 12px 0;
      border-top: 1px solid var(--line);
    }}
    .summary-row:first-child {{
      padding-top: 0;
      border-top: 0;
    }}
    .summary-copy strong {{
      display: block;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      margin-bottom: 4px;
      color: #e8f7ff;
    }}
    .summary-copy small {{
      display: block;
      color: var(--muted);
      line-height: 1.45;
      font-size: 13px;
    }}
    .summary-value {{
      display: inline-flex;
      align-items: center;
      justify-content: flex-start;
      width: 100%;
      min-height: 40px;
      padding: 10px 12px;
      border-radius: 14px;
      border: 1px solid var(--line);
      background: var(--panel-soft);
      color: #f5fbff;
      text-decoration: none;
      word-break: break-word;
      font: 600 13px/1.45 "Consolas", "SFMono-Regular", monospace;
    }}
    a.summary-value:hover {{
      border-color: rgba(0, 163, 224, 0.32);
      background: rgba(0, 163, 224, 0.10);
    }}
    .summary-value.disabled {{
      color: var(--muted);
      background: rgba(92, 114, 134, 0.10);
    }}
    .panel-note {{
      margin-top: 16px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }}
    pre {{
      margin: 0;
      padding: 18px;
      max-height: 420px;
      overflow: auto;
      border-radius: 18px;
      background: linear-gradient(180deg, #05090f, #0a1118);
      color: #e8f5ff;
      line-height: 1.45;
      font-size: 13px;
      border: 1px solid rgba(120, 152, 176, 0.12);
    }}
    .footer-note {{ margin-top: 12px; font-size: 13px; color: var(--muted); line-height: 1.5; }}
    .config-actions-row {{
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
      margin: 12px 0;
    }}
    .copy-button {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      min-height: 40px;
      padding: 9px 13px;
      border-radius: 12px;
      border: 1px solid var(--line);
      background: var(--panel-soft);
      color: #e8f7ff;
      cursor: pointer;
      font-weight: 700;
    }}
    .copy-button:hover {{
      border-color: rgba(0, 163, 224, 0.45);
      background: rgba(0, 163, 224, 0.12);
    }}
    .copy-icon {{
      position: relative;
      width: 16px;
      height: 16px;
      flex: 0 0 16px;
    }}
    .copy-icon::before, .copy-icon::after {{
      content: "";
      position: absolute;
      width: 9px;
      height: 9px;
      border: 1.7px solid currentColor;
      border-radius: 2px;
    }}
    .copy-icon::before {{ left: 1px; top: 5px; }}
    .copy-icon::after {{ left: 5px; top: 1px; background: var(--panel-soft); }}
    .dashboard-grid {{
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 16px;
    }}
    .dashboard-card {{
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: linear-gradient(180deg, rgba(15, 25, 36, 0.98), rgba(9, 16, 24, 0.98));
    }}
    .dashboard-card-head {{
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 14px;
    }}
    .dashboard-card-head h4 {{ margin: 0; color: #fff; font-size: 15px; }}
    .dashboard-card-head small {{ display: block; margin-top: 4px; color: var(--muted); line-height: 1.4; }}
    .dashboard-list {{ display: grid; gap: 9px; }}
    .dashboard-row {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      align-items: center;
      gap: 12px;
      padding: 12px 13px;
      border-radius: 14px;
      background: rgba(255,255,255,0.025);
      border: 1px solid rgba(150,176,194,0.09);
    }}
    .dashboard-device {{ display: flex; align-items: center; gap: 11px; min-width: 0; }}
    .status-dot {{
      width: 11px; height: 11px; border-radius: 50%; flex: 0 0 11px;
      background: #607282; box-shadow: 0 0 0 4px rgba(96,114,130,0.10);
    }}
    .status-dot.online {{ background: #38d996; box-shadow: 0 0 0 4px rgba(56,217,150,0.12), 0 0 16px rgba(56,217,150,0.24); }}
    .status-dot.reachable {{ background: #f2b94b; box-shadow: 0 0 0 4px rgba(242,185,75,0.12), 0 0 14px rgba(242,185,75,0.18); }}
    .status-dot.offline {{ background: #ff5d6c; box-shadow: 0 0 0 4px rgba(255,93,108,0.11), 0 0 14px rgba(255,93,108,0.16); }}
    .status-dot.unknown {{ background: #8093a3; }}
    .device-copy {{ min-width: 0; }}
    .device-copy strong {{ display: block; color: #eef9ff; font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
    .device-copy small {{ display: block; margin-top: 3px; color: var(--muted); font: 12px/1.3 "Consolas", "SFMono-Regular", monospace; }}
    .device-state {{ text-align: right; }}
    .device-state strong {{ display: block; font-size: 12px; text-transform: uppercase; color: #dcecf5; }}
    .device-state small {{ display: block; margin-top: 3px; color: var(--muted); font-size: 11px; }}
    .dashboard-summary {{
      display: flex; align-items: center; gap: 9px; color: var(--muted); font-size: 12px;
      padding: 7px 10px; border-radius: 999px; background: rgba(255,255,255,0.035); border: 1px solid var(--line);
    }}
    .dashboard-summary b {{ color: #eef9ff; }}
    .dashboard-note {{ margin: 14px 0 0; color: var(--muted); font-size: 12px; line-height: 1.45; }}
    .network-stat-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }}
    .network-stat-card {{
      padding: 15px 16px;
      border: 1px solid var(--line);
      border-radius: 16px;
      background: var(--panel-soft);
    }}
    .network-stat-card span {{
      display: block;
      color: var(--muted);
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
      margin-bottom: 7px;
    }}
    .network-stat-card strong {{
      display: block;
      color: #f5fbff;
      font-size: 23px;
      line-height: 1.1;
      font-variant-numeric: tabular-nums;
    }}
    .network-chart-wrap {{
      position: relative;
      height: 320px;
      min-height: 240px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: linear-gradient(180deg, rgba(8, 18, 27, 0.95), rgba(5, 12, 18, 0.98));
      overflow: hidden;
    }}
    #network-chart {{ width: 100%; height: 100%; display: block; }}
    .network-chart-empty {{
      position: absolute;
      inset: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      text-align: center;
      color: var(--muted);
      pointer-events: none;
      background: rgba(5, 12, 18, 0.42);
      backdrop-filter: blur(2px);
    }}
    .network-chart-empty[hidden] {{ display: none !important; }}
    .network-legend {{
      display: flex;
      gap: 18px;
      flex-wrap: wrap;
      margin-top: 12px;
      color: var(--muted);
      font-size: 13px;
    }}
    .legend-item {{ display: inline-flex; align-items: center; gap: 7px; }}
    .legend-dot {{ width: 9px; height: 9px; border-radius: 50%; }}
    .legend-dot.rx {{ background: #12b8ff; }}
    .legend-dot.tx {{ background: #5ee6a8; }}
    .traffic-table {{ margin-top:16px; border:1px solid var(--line); border-radius:16px; overflow:hidden; }}
    .traffic-row {{ display:grid; grid-template-columns:minmax(150px,1fr) 130px 130px; align-items:center; gap:16px; padding:11px 16px; border-top:1px solid rgba(128,157,178,.11); }}
    .traffic-row:first-child {{ border-top:0; }}
    .traffic-row.header {{ color:var(--muted); background:rgba(128,157,178,.055); font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:.06em; }}
    .traffic-device {{ display:flex; align-items:center; gap:9px; color:#eef9ff; font-weight:750; }}
    .traffic-device-dot {{ width:8px; height:8px; border-radius:50%; background:#536676; }}
    .traffic-row.active .traffic-device-dot {{ background:#12b8ff; box-shadow:0 0 12px rgba(18,184,255,.5); }}
    .traffic-value {{ text-align:right; color:#c8d9e5; font-variant-numeric:tabular-nums; }}
    .traffic-value.rx {{ color:#55ceff; }}
    .traffic-value.tx {{ color:#7aefb9; }}
    .profiles-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 310px), 1fr)); gap: 16px; }}
    .profile-card {{
      padding: 20px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: linear-gradient(180deg, rgba(15,25,36,.98), rgba(8,15,23,.98));
    }}
    .profile-card-head {{ display:flex; justify-content:space-between; align-items:flex-start; gap:14px; }}
    .profile-card-head h3 {{ margin:0; color:#fff; font-size:17px; }}
    .profile-card-head p {{ margin:5px 0 0; color:var(--muted); font-size:13px; line-height:1.4; }}
    .profile-badge {{ padding:5px 9px; border-radius:999px; border:1px solid rgba(0,163,224,.3); background:rgba(0,163,224,.1); color:#bcecff; font-size:11px; font-weight:800; text-transform:uppercase; }}
    .profile-actions {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:18px; }}
    .icon-action {{
      display:inline-flex; align-items:center; justify-content:center; gap:8px; min-height:40px;
      padding:9px 12px; border-radius:12px; border:1px solid var(--line); background:var(--panel-soft);
      color:#e8f7ff; text-decoration:none; font-weight:750; cursor:pointer; box-shadow:none;
    }}
    .icon-action:hover {{ border-color:rgba(0,163,224,.45); background:rgba(0,163,224,.12); }}
    .icon-action.primary-action {{ background:rgba(0,163,224,.2); border-color:rgba(0,163,224,.45); }}
    .download-icon {{ position:relative; width:16px; height:16px; flex:0 0 16px; border-bottom:1.8px solid currentColor; }}
    .download-icon::before {{ content:""; position:absolute; left:7px; top:1px; height:9px; border-left:1.8px solid currentColor; }}
    .download-icon::after {{ content:""; position:absolute; left:4px; top:6px; width:6px; height:6px; border-right:1.8px solid currentColor; border-bottom:1.8px solid currentColor; transform:rotate(45deg); }}
    .refresh-icon {{ font-size:19px; line-height:14px; }}
    .profile-details {{ margin-top:16px; border-top:1px solid var(--line); padding-top:14px; }}
    .profile-details summary {{ color:var(--muted); cursor:pointer; font-weight:700; font-size:13px; }}
    .profile-details[open] summary {{ color:#dff6ff; margin-bottom:12px; }}
    .profile-details pre {{ max-height:300px; font-size:12px; }}
    .compact-header {{
      display: grid;
      grid-template-columns: auto minmax(220px, 1fr) auto auto;
      align-items: center;
      gap: 22px;
      min-height: 96px;
      padding: 12px 18px 12px 24px;
      margin-bottom: 16px;
      border-radius: 16px;
    }}
    .compact-brand {{ display:flex; align-items:center; min-width:360px; grid-column:1; grid-row:1; }}
    .compact-brand img {{ display:block; width:360px; max-height:68px; object-fit:contain; object-position:left center; }}
    .compact-header .primary-navigation {{ grid-column:3; grid-row:1; margin:0; min-width:min(540px, 44vw); }}
    .compact-header .logout-form {{ grid-column:4; grid-row:1; margin:0; }}
    .compact-header .logout-button {{ min-height:42px; padding:9px 15px; border-radius:9px; box-shadow:none; background:var(--panel-soft); border:1px solid var(--line); }}
    .header-status {{ grid-column:2; grid-row:1; margin:0; padding:8px 11px; font-size:12px; opacity:1; transition:opacity 220ms ease, transform 220ms ease; }}
    .header-status.dismissed {{ opacity:0; transform:translateY(-3px); pointer-events:none; }}
    .primary-navigation {{ border-radius:12px; }}
    .primary-navigation .tab-button {{ border-radius:8px; min-height:42px; }}
    .layout.focus-mode {{ grid-template-columns: minmax(0, 1fr); }}
    .layout.focus-mode .aside {{ display:none; }}
    .control-panel {{ border-radius:16px; box-shadow:0 14px 34px rgba(0,0,0,.24); }}
    .control-panel > .panel-body {{ padding:16px; }}
    .control-heading {{ display:none; }}
    .status {{ margin-bottom:14px; padding:10px 13px; border-radius:9px; }}
    .overview-summary {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:9px; margin-bottom:12px; }}
    .overview-metric {{ min-height:66px; padding:11px 13px; border-radius:10px; border:1px solid var(--line); background:var(--panel-soft); }}
    .overview-metric span {{ display:block; margin-bottom:5px; color:var(--muted); font-size:10px; font-weight:800; text-transform:uppercase; }}
    .overview-metric strong {{ display:block; color:#fff; font-size:14px; overflow-wrap:anywhere; }}
    .overview-services {{ display:flex; align-items:center; gap:7px; flex-wrap:wrap; margin-bottom:12px; }}
    .overview-services-label {{ margin-right:3px; color:var(--muted); font-size:11px; font-weight:800; text-transform:uppercase; }}
    .service-link {{ display:inline-flex; align-items:center; gap:7px; min-height:34px; padding:7px 10px; border:1px solid var(--line); border-radius:8px; background:var(--panel-soft); color:#e8f7ff; text-decoration:none; font-size:12px; font-weight:700; }}
    .service-link:hover {{ border-color:rgba(0,163,224,.45); background:rgba(0,163,224,.10); }}
    .external-icon {{ color:var(--brand); font-size:14px; }}
    .redirect-details {{ position:relative; }}
    .redirect-details summary {{ display:inline-flex; align-items:center; min-height:34px; padding:7px 10px; border:1px solid var(--line); border-radius:8px; background:var(--panel-soft); color:#cde8f5; cursor:pointer; font-size:12px; font-weight:700; list-style:none; }}
    .redirect-details summary::-webkit-details-marker {{ display:none; }}
    .redirect-details summary::after {{ content:"⌄"; margin-left:8px; color:var(--brand); }}
    .redirect-details[open] summary::after {{ content:"⌃"; }}
    .redirect-list {{ position:absolute; left:0; z-index:8; width:min(560px,86vw); margin-top:7px; padding:8px 12px; border:1px solid var(--line); border-radius:10px; background:#0b141e; box-shadow:var(--shadow); }}
    .redirect-row {{ display:grid; grid-template-columns:minmax(140px,1fr) 90px minmax(150px,1fr); gap:12px; align-items:center; padding:8px 4px; border-top:1px solid var(--line); font-size:12px; }}
    .redirect-row:first-child {{ border-top:0; }}
    .redirect-row span {{ color:var(--muted); }}
    .redirect-row code {{ color:#bfeaff; text-align:right; }}
    .overview-workspace {{ display:grid; grid-template-columns:minmax(330px,.78fr) minmax(520px,1.42fr); gap:12px; align-items:start; }}
    .overview-workspace .config-block {{ padding:14px; margin:0; border-radius:12px; }}
    .overview-workspace .dashboard-card {{ padding:12px; border-radius:10px; }}
    .overview-workspace .dashboard-card-head {{ margin-bottom:9px; }}
    .overview-workspace .dashboard-row {{ padding:8px 10px; border-radius:8px; }}
    .overview-workspace .dashboard-list {{ gap:6px; }}
    .overview-workspace .network-chart-wrap {{ height:255px; min-height:220px; border-radius:10px; }}
    .overview-workspace .network-stat-grid {{ margin-bottom:10px; }}
    .overview-workspace .network-stat-card {{ padding:10px 12px; border-radius:9px; }}
    .overview-workspace .network-stat-card strong {{ font-size:20px; }}
    .overview-workspace .traffic-table {{ margin-top:10px; border-radius:10px; }}
    .overview-workspace .traffic-row {{ grid-template-columns:minmax(130px,1fr) 100px 100px; padding:7px 11px; }}
    .overview-workspace .dashboard-note {{ display:none; }}
    .overview-footer {{ display:flex; justify-content:space-between; align-items:center; gap:12px; margin-top:12px; color:var(--muted); font-size:11px; }}
    .system-details {{ position:relative; }}
    .system-details summary {{ cursor:pointer; color:#cde8f5; font-weight:700; }}
    .system-details-content {{ position:absolute; right:0; z-index:5; width:min(460px,80vw); margin-top:8px; padding:14px; border:1px solid var(--line); border-radius:12px; background:#0b141e; box-shadow:var(--shadow); }}
    .system-details-content .summary-row {{ grid-template-columns:1fr; }}
    @media (max-width: 1180px) {{
      .hero {{
        padding: 26px 20px 22px;
      }}
      .hero-meta {{
        grid-template-columns: 1fr;
        width: 100%;
      }}
      .layout {{
        grid-template-columns: 1fr;
      }}
      .aside {{
        position: static;
      }}
      .summary-row {{
        grid-template-columns: 1fr;
      }}
      .extra-rule-grid {{
        grid-template-columns: repeat(auto-fit, minmax(min(100%, 180px), 1fr));
      }}
      .dashboard-grid {{ grid-template-columns: 1fr; }}
      .network-stat-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .compact-header {{ grid-template-columns:1fr auto; }}
      .compact-brand {{ grid-column:1; grid-row:1; }}
      .compact-header .logout-form {{ grid-column:2; grid-row:1; }}
      .compact-header .primary-navigation {{ grid-column:1 / -1; grid-row:2; width:100%; min-width:0; }}
      .header-status {{ grid-column:1 / -1; grid-row:3; }}
      .overview-summary {{ grid-template-columns:repeat(3,minmax(0,1fr)); }}
      .overview-workspace {{ grid-template-columns:1fr; }}
    }}
    * {{ min-width: 0; letter-spacing: 0 !important; }}
    .grid {{ grid-template-columns: repeat(auto-fit, minmax(min(100%, 240px), 1fr)); }}
    .extra-rule-head {{ flex-wrap: wrap; }}
    .extra-rule-head strong, .status, .panel-note, .footer-note {{ overflow-wrap: anywhere; }}
    button, .ghost-link {{ max-width: 100%; white-space: normal; overflow-wrap: anywhere; }}
    .summary-row {{ grid-template-columns: repeat(auto-fit, minmax(min(100%, 170px), 1fr)); }}
    img {{ max-width: 100%; }}
    @media (max-width: 600px) {{
      .page-shell {{ width: calc(100% - 20px); margin: 10px auto 20px; }}
      .panel-body, .config-block, .extra-rule-row {{ padding: 12px; }}
      .tab-bar {{ display: grid; grid-template-columns: 1fr; }}
      .actions > * {{ flex: 1 1 160px; text-align: center; }}
      h1 {{ font-size: 28px; }}
      .network-stat-grid {{ grid-template-columns: 1fr; }}
      .network-chart-wrap {{ height: 260px; }}
      .compact-brand {{ min-width:0; width:calc(100% - 90px); }}
      .compact-brand img {{ width:100%; }}
      .compact-header .primary-navigation {{ display:grid; grid-template-columns:1fr; }}
      .overview-summary {{ grid-template-columns:1fr 1fr; }}
      .overview-workspace .traffic-row {{ grid-template-columns:minmax(110px,1fr) 78px 78px; gap:7px; }}
      .overview-footer {{ align-items:flex-start; flex-direction:column; }}
      .system-details-content {{ left:0; right:auto; width:min(440px,calc(100vw - 52px)); }}
    }}
    @media (prefers-reduced-motion: reduce) {{
      *, *::before, *::after {{ animation: none !important; transition: none !important; }}
    }}
  </style>
</head>
<body>
  <div class="page-shell">
    <header class="panel compact-header">
      <div class="compact-brand"><img src="{esc(LOGO_URL)}" alt="HAIVISION HAIBOX"></div>
      <div class="tab-bar primary-navigation" role="tablist" aria-label="Control panel sections">
        <button class="tab-button active" type="button" data-tab-target="overview">Overview</button>
        <button class="tab-button" type="button" data-tab-target="configuration">Configuration</button>
        <button class="tab-button" type="button" data-tab-target="profiles">VPN Profiles</button>
      </div>
      <form class="logout-form" method="post" action="/logout">
        <button class="logout-button" type="submit">Logout</button>
      </form>
      {status_html}
    </header>

    <div class="layout focus-mode" id="main-layout">
      <section class="panel control-panel">
        <div class="panel-body">
          <div class="panel-head control-heading">
            <div>
              <h2 class="panel-title">HAIBOX Control Center</h2>
              <p class="panel-subtitle">Live status, traffic, configuration and VPN profiles.</p>
            </div>
          </div>
          <form method="post" action="/apply">
            <div class="tab-page" data-tab-page="overview">
              <div class="overview-summary">
                <div class="overview-metric"><span>Public IP</span><strong>{esc(host)}</strong></div>
                <div class="overview-metric"><span>WireGuard Port</span><strong>UDP {esc(state.get("WG_PORT", ""))}</strong></div>
                <div class="overview-metric"><span>Build</span><strong>v{esc(build["version"])} · {esc(build["channel"])}</strong></div>
                <div class="overview-metric"><span>VPS Uptime</span><strong>{esc(build["uptime"])}</strong></div>
              </div>
              <div class="overview-services"><span class="overview-services-label">Public Services</span>{services_links}<details class="redirect-details"><summary>Port Redirects</summary><div class="redirect-list">{redirects_html}</div></details></div>
              <div class="overview-workspace">
              <section class="config-block">
                <div class="block-head">
                  <h3>HAIBOX Live Status</h3>
                  <p>Live WireGuard peers and reachability of the configured HAIBOX LAN devices.</p>
                </div>
                <div class="dashboard-grid">
                  <div class="dashboard-card">
                    <div class="dashboard-card-head">
                      <div><h4>Connected Peers</h4><small>WireGuard peer activity on wg0.</small></div>
                      <div class="dashboard-summary"><b id="peer-online-count">0</b> online</div>
                    </div>
                    <div class="dashboard-list" id="peer-status-list">
                      <div class="dashboard-row"><div class="dashboard-device"><span class="status-dot unknown"></span><div class="device-copy"><strong>Loading peers…</strong><small>wg0</small></div></div><div class="device-state"><strong>Checking</strong></div></div>
                    </div>
                  </div>
                  <div class="dashboard-card">
                    <div class="dashboard-card-head">
                      <div><h4>LAN Devices</h4><small>ICMP and application-service reachability through the HAIBOX VPN.</small></div>
                      <div class="dashboard-summary"><b id="lan-online-count">0</b>/<span id="lan-total-count">0</span> online</div>
                    </div>
                    <div class="dashboard-list" id="lan-status-list">
                      <div class="dashboard-row"><div class="dashboard-device"><span class="status-dot unknown"></span><div class="device-copy"><strong>Loading devices…</strong><small>LAN</small></div></div><div class="device-state"><strong>Checking</strong></div></div>
                    </div>
                  </div>
                </div>
                <p class="dashboard-note">Status is sampled only while Overview is open and the page is visible. A device can be reported as Service Online when ICMP is blocked but a configured TCP service is reachable.</p>
              </section>
              <section class="config-block">
                <div class="block-head">
                  <h3>Network Statistics</h3>
                  <p>Live WireGuard RX and TX from the HAIBOX point of view, with per-device traffic.</p>
                </div>
                <div class="network-stat-grid">
                  <div class="network-stat-card"><span>RX Now</span><strong id="network-rx-now">0.00 Mbps</strong></div>
                  <div class="network-stat-card"><span>TX Now</span><strong id="network-tx-now">0.00 Mbps</strong></div>
                </div>
                <div class="network-chart-wrap">
                  <canvas id="network-chart" aria-label="Live WireGuard RX and TX traffic chart"></canvas>
                  <div class="network-chart-empty" id="network-chart-empty" hidden></div>
                </div>
                <div class="network-legend">
                  <span class="legend-item"><span class="legend-dot rx"></span>Total RX</span>
                  <span class="legend-item"><span class="legend-dot tx"></span>Total TX</span>
                  <span>60 second rolling window · Mbps</span>
                </div>
                <div class="traffic-table" id="network-consumers">
                  <div class="traffic-row header"><span>Device</span><span class="traffic-value">RX</span><span class="traffic-value">TX</span></div>
                </div>
              </section>
              </div>
              <div class="overview-footer">
                <span>Live data is sampled only while Overview is visible.</span>
                <details class="system-details">
                  <summary>System information</summary>
                  <div class="system-details-content">
                    <div class="summary-list">
                      {summary_row("Script SHA-256", build["sha256"], "Installed source identity")}
                      {summary_row("Operating System", build["os"], "Kernel " + build["kernel"])}
                      {summary_row("Last Apply", build["last_apply"], "Applied-state timestamp")}
                      {summary_row("Web UI Started", build["webui_started"], "Current service activation")}
                    </div>
                    <div class="config-actions-row"><a class="ghost-link" href="/download-support-bundle">Download Support Bundle</a></div>
                  </div>
                </details>
              </div>
            </div>

            <div class="tab-page" data-tab-page="configuration" hidden>
              <div class="subtab-bar" role="tablist" aria-label="Configuration sections">
                <button class="subtab-button active" type="button" data-config-target="core">Core</button>
                <button class="subtab-button" type="button" data-config-target="extra">Extra Port Forwarding</button>
              </div>
              <div data-config-page="core">
              <section class="config-block">
              <div class="block-head">
                <h3>Network</h3>
                <p>Remote LAN and public VPS settings.</p>
              </div>
              <div class="grid">
                {input_row("LAN CIDR", "LAN_CIDR", state.get("LAN_CIDR", ""))}
                {input_row("Router LAN IP", "ROUTER_LAN_IP", state.get("ROUTER_LAN_IP", ""))}
                {input_row("Public iface", "PUB_IFACE", state.get("PUB_IFACE", ""))}
                {input_row("Public IPv4", "PUB_IP", state.get("PUB_IP", ""))}
              </div>
            </section>

            <section class="config-block">
              <div class="block-head">
                <h3>Site Devices</h3>
                <p>Destination IPs for the published services.</p>
              </div>
              <div class="grid">
                {input_row("Proxmox IP", "PROXMOX_IP", state.get("PROXMOX_IP", ""))}
                {input_row("StreamHub IP", "STREAMHUB_IP", state.get("STREAMHUB_IP", ""))}
                {input_row("HSG / HMG IP", "HSG_IP", state.get("HSG_IP", ""))}
                {input_row("Makito X4E IP", "MAKITO_ENC_IP", state.get("MAKITO_ENC_IP", ""))}
                {input_row("Windows Orchestrator IP", "WINDOWS_ORCH_IP", state.get("WINDOWS_ORCH_IP", ""))}
              </div>
            </section>

            <section class="config-block">
              <div class="block-head">
                <h3>WireGuard</h3>
                <p>Port and peer addresses.</p>
              </div>
              <div class="grid">
                {input_row("WireGuard UDP port", "WG_PORT", state.get("WG_PORT", ""))}
                {input_row("WG tunnel CIDR", "WG_TUN_CIDR", state.get("WG_TUN_CIDR", ""))}
                {input_row("VPS WG IP", "WG_VPS_IP", state.get("WG_VPS_IP", ""))}
                {input_row("HAIBOX Router WG IP", "WG_GL_IP", state.get("WG_GL_IP", ""))}
                {input_row("Remote VPN Client WG IP", "REMOTE_CLIENT_IP", state.get("REMOTE_CLIENT_IP", ""))}
              </div>
            </section>

            <section class="config-block">
              <div class="block-head">
                <h3>UDP Ranges</h3>
                <p>Editable Makito and HSG ranges.</p>
              </div>
              <div class="grid">
                {input_row("HSG SRT UDP from", "HSG_SRT_UDP_FROM", state.get("HSG_SRT_UDP_FROM", ""))}
                {input_row("HSG SRT UDP to", "HSG_SRT_UDP_TO", state.get("HSG_SRT_UDP_TO", ""))}
                {input_row("Makito UDP from", "MAKITO_ENC_UDP_FROM", state.get("MAKITO_ENC_UDP_FROM", ""))}
                {input_row("Makito UDP to", "MAKITO_ENC_UDP_TO", state.get("MAKITO_ENC_UDP_TO", ""))}
              </div>
            </section>

            <section class="config-block">
              <div class="block-head">
                <h3>Web Access</h3>
                <p>Username, password and port.</p>
              </div>
              <div class="grid">
                {input_row("Web UI username", "WEBUI_USER", state.get("WEBUI_USER", ""))}
                {input_row("Web UI TCP port", "WEBUI_PORT", state.get("WEBUI_PORT", ""))}
                {input_row("Current Web UI password", "WEBUI_CURRENT_PASSWORD", "", "password")}
                {input_row("New Web UI password", "WEBUI_PASSWORD", "", "password")}
                {input_row("Confirm new password", "WEBUI_PASSWORD_CONFIRM", "", "password")}
              </div>
            </section>
              </div>

              <div data-config-page="extra" hidden>
              <section class="config-block">
                <div class="block-head">
                  <h3>Extra Port Forwarding Rules</h3>
                </div>
                <div class="extra-rule-list" id="extra-rule-list">
                  {extra_rules_html}
                </div>
                <div class="actions">
                  <button class="secondary" type="button" id="add-extra-rule">Add Extra Rule</button>
                </div>
                <template id="extra-rule-template">
                  {extra_rule_row(empty_extra_rule())}
                </template>
              </section>
              </div>
            <div class="actions">
              <button class="primary" type="submit">Apply + Make Persistent</button>
              <button class="secondary" type="submit" formaction="/test" formmethod="post">Run Test</button>
              <button class="secondary" type="submit" formaction="/health" formmethod="post">System Health</button>
            </div>
            <div class="footer-note">To change username or password, enter the current password. Leave all password fields empty to keep it unchanged.</div>
            </div>

            <div class="tab-page" data-tab-page="profiles" hidden>
              <div class="profiles-grid">
                <section class="profile-card">
                  <div class="profile-card-head">
                    <div><h3>HAIBOX Router</h3><p>Current GL-AXT1800 WireGuard peer profile.</p></div>
                    <span class="profile-badge">Router</span>
                  </div>
                  <div class="profile-actions">
                    <button class="icon-action" type="button" data-copy-target="router-config" title="Copy router configuration"><span class="copy-icon" aria-hidden="true"></span><span>Copy</span></button>
                    <a class="icon-action" href="/download-router-config" title="Download router configuration"><span class="download-icon" aria-hidden="true"></span><span>Download</span></a>
                  </div>
                  <details class="profile-details"><summary>View configuration</summary><pre id="router-config">{esc(router_config_text())}</pre></details>
                </section>
                <section class="profile-card">
                  <div class="profile-card-head">
                    <div><h3>Remote VPN Client</h3><p>Optional Windows, laptop or mobile peer.</p></div>
                    <span class="profile-badge">Client</span>
                  </div>
                  <div class="profile-actions">
                    <button class="icon-action primary-action" type="submit" formaction="/create-remote-client" formmethod="post"><span class="refresh-icon" aria-hidden="true">↻</span><span>Create / Refresh</span></button>
                    <button class="icon-action" type="button" data-copy-target="remote-client-config" title="Copy remote client configuration"><span class="copy-icon" aria-hidden="true"></span><span>Copy</span></button>
                    <a class="icon-action" href="/download-remote-client" title="Download remote client configuration"><span class="download-icon" aria-hidden="true"></span><span>Download</span></a>
                  </div>
                  <details class="profile-details"><summary>View configuration</summary><pre id="remote-client-config">{esc(remote_client_config_text())}</pre></details>
                </section>
              </div>
            </div>
          </form>
        </div>
      </section>

      <aside class="aside">
        <section class="panel summary-panel">
          <div class="panel-body">
            <div class="panel-head">
              <div>
                <h2 class="panel-title">Build Information</h2>
                <p class="panel-subtitle">Exact software and VPS identity.</p>
              </div>
            </div>
            <div class="summary-list">
              {summary_row("Version", "v" + build["version"], build["channel"])}
              {summary_row("Script SHA-256", build["sha256"], "Installed source identity")}
              {summary_row("Operating System", build["os"], "Kernel " + build["kernel"])}
              {summary_row("Last Apply", build["last_apply"], "Applied-state timestamp")}
              {summary_row("Web UI Started", build["webui_started"], "Current service activation")}
            </div>
            <div class="config-actions-row">
              <a class="ghost-link" href="/download-support-bundle">Download Support Bundle</a>
            </div>
          </div>
        </section>

        <section class="panel summary-panel">
          <div class="panel-body">
            <div class="panel-head">
              <div>
                <h2 class="panel-title">UDP Ranges</h2>
                <p class="panel-subtitle">Editable forwarding ranges.</p>
              </div>
            </div>
            <div class="summary-list">{udp_summary}</div>
            <div class="panel-note">StreamHub keeps the fixed port set from the script.</div>
          </div>
        </section>

        <section class="panel summary-panel">
          <div class="panel-body">
            <div class="panel-head">
              <div>
                <h2 class="panel-title">Extra Rules</h2>
                <p class="panel-subtitle">Custom user forwarding.</p>
              </div>
            </div>
            <div class="summary-list">{extra_rules_summary}</div>
          </div>
        </section>

        <section class="panel">
          <div class="panel-body">
            <div class="panel-head">
              <div>
                <h2 class="panel-title">Last Output</h2>
                <p class="panel-subtitle">Latest script output.</p>
              </div>
            </div>
            <pre>{esc(output or "No action executed yet.")}</pre>
          </div>
        </section>
      </aside>
    </div>

  </div>
  <script>
    (function() {{
      const activeTabKey = "haibox_active_config_tab";
      const activeConfigKey = "haibox_active_config_section";
      const tabButtons = document.querySelectorAll("[data-tab-target]");
      const tabPages = document.querySelectorAll("[data-tab-page]");
      const configButtons = document.querySelectorAll("[data-config-target]");
      const configPages = document.querySelectorAll("[data-config-page]");
      const headerStatus = document.querySelector(".header-status");
      if (headerStatus) {{
        window.setTimeout(function() {{
          headerStatus.classList.add("dismissed");
          window.setTimeout(function() {{ headerStatus.remove(); }}, 250);
        }}, 10000);
      }}

      function activateTab(tabName) {{
        tabButtons.forEach(function(button) {{
          const active = button.dataset.tabTarget === tabName;
          button.classList.toggle("active", active);
          button.setAttribute("aria-selected", active ? "true" : "false");
        }});
        tabPages.forEach(function(page) {{
          page.hidden = page.dataset.tabPage !== tabName;
        }});
        const mainLayout = document.getElementById("main-layout");
        if (mainLayout) mainLayout.classList.toggle("focus-mode", tabName !== "configuration");
        try {{
          window.sessionStorage.setItem(activeTabKey, tabName);
        }} catch (err) {{}}
        updateNetworkPolling();
        updateDashboardPolling();
      }}

      function activateConfigTab(tabName) {{
        configButtons.forEach(function(button) {{
          const active = button.dataset.configTarget === tabName;
          button.classList.toggle("active", active);
          button.setAttribute("aria-selected", active ? "true" : "false");
        }});
        configPages.forEach(function(page) {{
          page.hidden = page.dataset.configPage !== tabName;
        }});
        try {{ window.sessionStorage.setItem(activeConfigKey, tabName); }} catch (err) {{}}
      }}

      const peerStatusList = document.getElementById("peer-status-list");
      const lanStatusList = document.getElementById("lan-status-list");
      const peerOnlineCount = document.getElementById("peer-online-count");
      const lanOnlineCount = document.getElementById("lan-online-count");
      const lanTotalCount = document.getElementById("lan-total-count");
      let dashboardTimer = null;
      let dashboardRequestActive = false;

      function dashboardTabIsActive() {{
        const page = document.querySelector('[data-tab-page="overview"]');
        return !!page && !page.hidden && document.visibilityState === "visible";
      }}

      function formatBytes(value) {{
        const n = Number(value) || 0;
        if (n >= 1000000000) return (n / 1000000000).toFixed(2) + " GB";
        if (n >= 1000000) return (n / 1000000).toFixed(1) + " MB";
        if (n >= 1000) return (n / 1000).toFixed(1) + " KB";
        return n.toFixed(0) + " B";
      }}

      function handshakeText(age) {{
        if (age === null || age === undefined) return "No handshake";
        const seconds = Math.max(0, Number(age) || 0);
        if (seconds < 60) return Math.round(seconds) + "s ago";
        if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
        return Math.floor(seconds / 3600) + "h ago";
      }}

      function renderDashboard(payload) {{
        const peers = Array.isArray(payload.peers) ? payload.peers : [];
        const devices = Array.isArray(payload.devices) ? payload.devices : [];
        if (peerOnlineCount) peerOnlineCount.textContent = String(peers.filter(function(p) {{ return p.online; }}).length);
        if (lanOnlineCount) lanOnlineCount.textContent = String(devices.filter(function(d) {{ return d.online; }}).length);
        if (lanTotalCount) lanTotalCount.textContent = String(devices.length);
        if (peerStatusList) {{
          peerStatusList.innerHTML = peers.map(function(peer) {{
            const stateClass = peer.online ? "online" : "offline";
            const stateText = peer.online ? "Online" : (peer.configured ? "Offline" : "Not configured");
            const detail = peer.configured ? "Handshake " + handshakeText(peer.handshake_age) : "Peer not present on wg0";
            return '<div class="dashboard-row"><div class="dashboard-device"><span class="status-dot ' + stateClass + '"></span><div class="device-copy"><strong>' + escapeHtml(peer.name) + '</strong>' + (peer.ip ? '<small>' + escapeHtml(peer.ip) + '</small>' : '') + '</div></div><div class="device-state"><strong>' + stateText + '</strong><small>' + escapeHtml(detail) + '</small></div></div>';
          }}).join("");
        }}
        if (lanStatusList) {{
          lanStatusList.innerHTML = devices.map(function(device) {{
            const configured = device.configured !== false;
            const status = configured ? (device.status || (device.online ? "online" : "offline")) : "not_configured";
            const stateClass = status === "reachable" ? "reachable" : ((status === "online" || status === "service_online") ? "online" : "offline");
            const stateLabels = {{online:"Online", service_online:"Service Online", reachable:"Reachable", offline:"Offline", not_configured:"Not configured"}};
            const detail = configured ? (device.ping_online && device.latency_ms !== null ? "RTT " + Number(device.latency_ms).toFixed(1) + " ms" : "No ICMP reply") : "";
            return '<div class="dashboard-row"><div class="dashboard-device"><span class="status-dot ' + stateClass + '"></span><div class="device-copy"><strong>' + escapeHtml(device.name) + '</strong>' + (device.ip ? '<small>' + escapeHtml(device.ip) + '</small>' : '') + '</div></div><div class="device-state"><strong>' + escapeHtml(stateLabels[status] || "Unknown") + '</strong><small>' + escapeHtml(detail) + '</small></div></div>';
          }}).join("");
        }}
      }}

      function escapeHtml(value) {{
        return String(value == null ? "" : value).replace(/[&<>"']/g, function(ch) {{
          return {{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}}[ch];
        }});
      }}

      async function pollDashboard() {{
        if (!dashboardTabIsActive() || dashboardRequestActive) return;
        dashboardRequestActive = true;
        try {{
          const response = await fetch("/api/dashboard-status", {{ cache: "no-store", credentials: "same-origin" }});
          if (!response.ok) throw new Error("dashboard unavailable");
          renderDashboard(await response.json());
        }} catch (err) {{
          if (peerStatusList) peerStatusList.innerHTML = '<div class="dashboard-row"><div class="dashboard-device"><span class="status-dot offline"></span><div class="device-copy"><strong>Status unavailable</strong><small>Dashboard endpoint</small></div></div><div class="device-state"><strong>Offline</strong></div></div>';
        }} finally {{
          dashboardRequestActive = false;
        }}
      }}

      function updateDashboardPolling() {{
        if (dashboardTimer !== null) {{ window.clearInterval(dashboardTimer); dashboardTimer = null; }}
        if (dashboardTabIsActive()) {{
          pollDashboard();
          dashboardTimer = window.setInterval(pollDashboard, 5000);
        }}
      }}

      const networkCanvas = document.getElementById("network-chart");
      const networkEmpty = document.getElementById("network-chart-empty");
      const rxNow = document.getElementById("network-rx-now");
      const txNow = document.getElementById("network-tx-now");
      const consumerList = document.getElementById("network-consumers");
      const deviceMeta = {{
        router: "Router", streamhub: "StreamHub", hsg: "HSG / HMG",
        makito: "Makito X4E", windows: "Windows", proxmox: "Proxmox",
        other: "Other / VPN"
      }};
      let networkTimer = null;
      let previousNetworkSample = null;
      let networkSamples = [];
      let displayedYMax = 10;
      let scaleHoldUntil = 0;
      let lastScaleUpdate = performance.now();

      function formatMbps(value) {{
        if (!Number.isFinite(value) || value < 0) return "0.00 Mbps";
        if (value >= 100) return value.toFixed(1) + " Mbps";
        return value.toFixed(2) + " Mbps";
      }}

      function renderConsumers(rates) {{
        const entries = Object.keys(deviceMeta).map(function(key) {{
          const rate = rates[key] || {{}};
          return {{ key:key, label:deviceMeta[key], rx:Number(rate.rx || 0), tx:Number(rate.tx || 0) }};
        }});
        if (consumerList) consumerList.innerHTML = '<div class="traffic-row header"><span>Device</span><span class="traffic-value">RX</span><span class="traffic-value">TX</span></div>' + entries.map(function(item) {{
          const active = item.rx >= 0.01 || item.tx >= 0.01;
          return '<div class="traffic-row' + (active ? ' active' : '') + '"><span class="traffic-device"><i class="traffic-device-dot"></i>' + escapeHtml(item.label) + '</span><span class="traffic-value rx">' + formatMbps(item.rx) + '</span><span class="traffic-value tx">' + formatMbps(item.tx) + '</span></div>';
        }}).join("");
      }}

      function networkTabIsActive() {{
        const page = document.querySelector('[data-tab-page="overview"]');
        return !!page && !page.hidden && document.visibilityState === "visible";
      }}

      function stopNetworkPolling() {{
        if (networkTimer !== null) {{
          window.clearInterval(networkTimer);
          networkTimer = null;
        }}
        previousNetworkSample = null;
      }}

      function updateNetworkPolling() {{
        if (!networkCanvas) return;
        if (networkTabIsActive()) {{
          if (networkTimer === null) {{
            previousNetworkSample = null;
            fetchNetworkSample();
            networkTimer = window.setInterval(fetchNetworkSample, 1000);
          }}
        }} else {{
          stopNetworkPolling();
        }}
      }}

      async function fetchNetworkSample() {{
        if (!networkTabIsActive()) return;
        try {{
          const response = await fetch("/api/network-stats", {{ cache: "no-store", credentials: "same-origin" }});
          if (!response.ok) throw new Error("stats unavailable");
          const sample = await response.json();
          if (!sample.available) {{
            previousNetworkSample = null;
            if (networkEmpty) networkEmpty.textContent = "wg0 is not available. Apply the configuration to start monitoring.";
            if (networkEmpty) networkEmpty.hidden = false;
            drawNetworkChart();
            return;
          }}
          if (networkEmpty) networkEmpty.hidden = true;
          if (previousNetworkSample) {{
            const elapsed = (sample.timestamp - previousNetworkSample.timestamp) / 1000;
            if (elapsed > 0) {{
              // Present traffic from the HAIBOX/device point of view. Bytes sent
              // by the VPS into wg0 are received by HAIBOX; bytes received by
              // the VPS from wg0 were transmitted by HAIBOX.
              const rx = Math.max(0, (sample.tx_bytes - previousNetworkSample.tx_bytes) * 8 / elapsed / 1000000);
              const tx = Math.max(0, (sample.rx_bytes - previousNetworkSample.rx_bytes) * 8 / elapsed / 1000000);
              const deviceRates = {{}};
              Object.keys(deviceMeta).filter(function(key) {{ return key !== "other"; }}).forEach(function(key) {{
                const current = (sample.devices || {{}})[key] || {{}};
                const previous = (previousNetworkSample.devices || {{}})[key] || {{}};
                deviceRates[key] = {{
                  rx: Math.max(0, Number(current.tx_bytes || 0) - Number(previous.tx_bytes || 0)) * 8 / elapsed / 1000000,
                  tx: Math.max(0, Number(current.rx_bytes || 0) - Number(previous.rx_bytes || 0)) * 8 / elapsed / 1000000
                }};
              }});
              const classifiedRx = Object.values(deviceRates).reduce(function(sum, value) {{ return sum + value.rx; }}, 0);
              const classifiedTx = Object.values(deviceRates).reduce(function(sum, value) {{ return sum + value.tx; }}, 0);
              deviceRates.other = {{ rx:Math.max(0, rx-classifiedRx), tx:Math.max(0, tx-classifiedTx) }};
              networkSamples.push({{ rx: rx, tx: tx }});
              if (networkSamples.length > 60) networkSamples.shift();
              if (rxNow) rxNow.textContent = formatMbps(rx);
              if (txNow) txNow.textContent = formatMbps(tx);
              renderConsumers(deviceRates);
              drawNetworkChart();
            }}
          }}
          previousNetworkSample = sample;
        }} catch (err) {{
          previousNetworkSample = null;
          if (networkEmpty) {{
            networkEmpty.textContent = "Live network statistics are temporarily unavailable.";
            networkEmpty.hidden = false;
          }}
        }}
      }}

      function drawNetworkChart() {{
        if (!networkCanvas) return;
        const rect = networkCanvas.getBoundingClientRect();
        if (rect.width < 10 || rect.height < 10) return;
        const dpr = Math.max(1, window.devicePixelRatio || 1);
        const width = Math.round(rect.width * dpr);
        const height = Math.round(rect.height * dpr);
        if (networkCanvas.width !== width || networkCanvas.height !== height) {{
          networkCanvas.width = width;
          networkCanvas.height = height;
        }}
        const ctx = networkCanvas.getContext("2d");
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, rect.width, rect.height);

        const pad = {{ left: 58, right: 20, top: 22, bottom: 34 }};
        const plotW = Math.max(1, rect.width - pad.left - pad.right);
        const plotH = Math.max(1, rect.height - pad.top - pad.bottom);
        const maxData = networkSamples.reduce(function(maximum, point) {{ return Math.max(maximum, point.rx, point.tx); }}, 0);

        function scaleTarget(value) {{
          if (!Number.isFinite(value) || value <= 0) return 10;
          const wanted = Math.max(10, value * 1.22);
          if (wanted <= 12) return 12;
          if (wanted <= 15) return 15;
          if (wanted <= 20) return 20;
          if (wanted <= 30) return 30;
          if (wanted <= 40) return 40;
          if (wanted <= 50) return 50;
          if (wanted <= 60) return 60;
          if (wanted <= 75) return 75;
          if (wanted <= 100) return 100;
          const magnitude = Math.pow(10, Math.floor(Math.log10(wanted)));
          const normalized = wanted / magnitude;
          let step = 1;
          if (normalized <= 1.25) step = 1.25;
          else if (normalized <= 1.5) step = 1.5;
          else if (normalized <= 2) step = 2;
          else if (normalized <= 2.5) step = 2.5;
          else if (normalized <= 5) step = 5;
          else step = 10;
          return step * magnitude;
        }}

        const nowMs = performance.now();
        const targetYMax = scaleTarget(maxData);
        const elapsedScaleSeconds = Math.max(0, (nowMs - lastScaleUpdate) / 1000);
        lastScaleUpdate = nowMs;

        // Fast attack, slow release: bursts expand the scale immediately, while
        // the graph returns gradually to its normal range after the burst leaves
        // the 60-second rolling window. This avoids abrupt visual compression.
        if (maxData > displayedYMax * 0.92 || targetYMax > displayedYMax) {{
          displayedYMax = Math.max(displayedYMax, targetYMax);
          scaleHoldUntil = nowMs + 8000;
        }} else if (nowMs > scaleHoldUntil && targetYMax < displayedYMax) {{
          const decay = Math.pow(0.94, elapsedScaleSeconds);
          displayedYMax = Math.max(targetYMax, displayedYMax * decay);
          if (displayedYMax - targetYMax < 0.25) displayedYMax = targetYMax;
        }}

        const yMax = Math.max(10, displayedYMax);
        ctx.font = '12px system-ui, -apple-system, sans-serif';
        ctx.lineWidth = 1;
        ctx.fillStyle = 'rgba(164, 190, 208, 0.72)';
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        for (let i = 0; i <= 4; i++) {{
          const y = pad.top + plotH * i / 4;
          ctx.strokeStyle = i === 4 ? 'rgba(128, 157, 178, 0.24)' : 'rgba(128, 157, 178, 0.13)';
          ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left + plotW, y); ctx.stroke();
          const value = yMax * (1 - i / 4);
          const label = value >= 100 ? value.toFixed(0) : (value >= 10 ? value.toFixed(1) : value.toFixed(2));
          ctx.fillText(label, pad.left - 10, y);
        }}
        ctx.save();
        ctx.translate(15, pad.top + plotH / 2);
        ctx.rotate(-Math.PI / 2);
        ctx.textAlign = 'center';
        ctx.fillStyle = 'rgba(164, 190, 208, 0.58)';
        ctx.fillText('Mbps', 0, 0);
        ctx.restore();
        ctx.textAlign = 'left';
        ctx.textBaseline = 'top';
        ctx.fillStyle = 'rgba(164, 190, 208, 0.72)';
        ctx.fillText('-60s', pad.left, pad.top + plotH + 10);
        ctx.textAlign = 'center';
        ctx.fillText('-30s', pad.left + plotW / 2, pad.top + plotH + 10);
        ctx.textAlign = 'right';
        ctx.fillText('Now', pad.left + plotW, pad.top + plotH + 10);

        function pointFor(index, key) {{
          const slot = Math.max(0, 60 - networkSamples.length + index);
          const x = pad.left + plotW * slot / 59;
          const y = pad.top + plotH * (1 - Math.min(yMax, networkSamples[index][key]) / yMax);
          return {{ x: x, y: y }};
        }}

        function traceSeries(key, stroke, fillTop, fillBottom) {{
          if (!networkSamples.length) return;
          const points = networkSamples.map(function(_, index) {{ return pointFor(index, key); }});
          const gradient = ctx.createLinearGradient(0, pad.top, 0, pad.top + plotH);
          gradient.addColorStop(0, fillTop);
          gradient.addColorStop(1, fillBottom);
          ctx.beginPath();
          ctx.moveTo(points[0].x, pad.top + plotH);
          ctx.lineTo(points[0].x, points[0].y);
          for (let i = 1; i < points.length; i++) {{
            const previous = points[i - 1];
            const current = points[i];
            const midX = (previous.x + current.x) / 2;
            ctx.bezierCurveTo(midX, previous.y, midX, current.y, current.x, current.y);
          }}
          ctx.lineTo(points[points.length - 1].x, pad.top + plotH);
          ctx.closePath();
          ctx.fillStyle = gradient;
          ctx.fill();

          ctx.beginPath();
          ctx.moveTo(points[0].x, points[0].y);
          for (let i = 1; i < points.length; i++) {{
            const previous = points[i - 1];
            const current = points[i];
            const midX = (previous.x + current.x) / 2;
            ctx.bezierCurveTo(midX, previous.y, midX, current.y, current.x, current.y);
          }}
          ctx.strokeStyle = stroke;
          ctx.lineWidth = 2.35;
          ctx.lineJoin = 'round';
          ctx.lineCap = 'round';
          ctx.stroke();

          const last = points[points.length - 1];
          ctx.beginPath();
          ctx.arc(last.x, last.y, 3.2, 0, Math.PI * 2);
          ctx.fillStyle = stroke;
          ctx.fill();
        }}

        traceSeries('rx', '#12b8ff', 'rgba(18, 184, 255, 0.18)', 'rgba(18, 184, 255, 0.015)');
        traceSeries('tx', '#5ee6a8', 'rgba(94, 230, 168, 0.16)', 'rgba(94, 230, 168, 0.012)');
      }}

      document.addEventListener("visibilitychange", function() {{ updateNetworkPolling(); updateDashboardPolling(); }});
      window.addEventListener("resize", function() {{ if (networkTabIsActive()) drawNetworkChart(); }});

      document.querySelectorAll("[data-copy-target]").forEach(function(button) {{
        button.addEventListener("click", async function() {{
          const target = document.getElementById(button.dataset.copyTarget || "");
          if (!target) return;
          const text = target.textContent || "";
          const label = button.querySelector("span:last-child");
          try {{
            await navigator.clipboard.writeText(text);
            if (label) label.textContent = "Copied";
          }} catch (err) {{
            const area = document.createElement("textarea");
            area.value = text;
            area.style.position = "fixed";
            area.style.opacity = "0";
            document.body.appendChild(area);
            area.focus();
            area.select();
            document.execCommand("copy");
            area.remove();
            if (label) label.textContent = "Copied";
          }}
          window.setTimeout(function() {{ if (label) label.textContent = "Copy to Clipboard"; }}, 1400);
        }});
      }});

      tabButtons.forEach(function(button) {{
        button.addEventListener("click", function() {{
          activateTab(button.dataset.tabTarget || "overview");
        }});
      }});

      configButtons.forEach(function(button) {{
        button.addEventListener("click", function() {{ activateConfigTab(button.dataset.configTarget || "core"); }});
      }});

      let initialTab = "overview";
      try {{
        initialTab = window.sessionStorage.getItem(activeTabKey) || "overview";
      }} catch (err) {{}}
      if (!["overview", "configuration", "profiles"].includes(initialTab)) initialTab = "overview";
      activateTab(initialTab);
      let initialConfigTab = "core";
      try {{ initialConfigTab = window.sessionStorage.getItem(activeConfigKey) || "core"; }} catch (err) {{}}
      if (!["core", "extra"].includes(initialConfigTab)) initialConfigTab = "core";
      activateConfigTab(initialConfigTab);

      const extraRuleList = document.getElementById("extra-rule-list");
      const extraRuleTemplate = document.getElementById("extra-rule-template");
      const addExtraRuleButton = document.getElementById("add-extra-rule");

      function refreshExtraRuleTitles() {{
        if (!extraRuleList) {{
          return;
        }}
        extraRuleList.querySelectorAll("[data-extra-rule]").forEach(function(row, index) {{
          const labelInput = row.querySelector('input[name="EXTRA_RULE_LABEL"]');
          const title = row.querySelector(".extra-rule-head strong");
          const label = labelInput ? labelInput.value.trim() : "";
          if (title) {{
            title.textContent = label || "Extra rule " + (index + 1);
          }}
        }});
      }}

      if (addExtraRuleButton && extraRuleList && extraRuleTemplate) {{
        addExtraRuleButton.addEventListener("click", function() {{
          extraRuleList.insertAdjacentHTML("beforeend", extraRuleTemplate.innerHTML.trim());
          refreshExtraRuleTitles();
        }});
      }}

      if (extraRuleList) {{
        extraRuleList.addEventListener("input", refreshExtraRuleTitles);
        extraRuleList.addEventListener("click", function(event) {{
          const clicked = event.target;
          if (!clicked || !clicked.closest) {{
            return;
          }}
          const button = clicked.closest("[data-remove-extra-rule]");
          if (!button) {{
            return;
          }}
          const rows = extraRuleList.querySelectorAll("[data-extra-rule]");
          const row = button.closest("[data-extra-rule]");
          if (!row) {{
            return;
          }}
          if (rows.length <= 1) {{
            row.querySelectorAll("input").forEach(function(input) {{
              input.value = "";
            }});
            const proto = row.querySelector('select[name="EXTRA_RULE_PROTO"]');
            if (proto) {{
              proto.value = "udp";
            }}
          }} else {{
            row.remove();
          }}
          refreshExtraRuleTitles();
        }});
        refreshExtraRuleTitles();
      }}

    }})();
  </script>
</body>
</html>
"""

def run_script(flag: str) -> Tuple[int, str]:
    try:
        proc = subprocess.Popen(
            [SCRIPT_PATH, flag], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, start_new_session=True,
        )
        try:
            output, _ = proc.communicate(timeout=600)
            return proc.returncode, output
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                output, _ = proc.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                output, _ = proc.communicate()
            return 124, output + "\nOperation timed out. Inspect service status before applying again."
    except OSError as exc:
        return 127, str(exc)


def schedule_restart() -> None:
    subprocess.Popen(
        ["/bin/sh", "-c", "sleep 2; systemctl restart %s >/dev/null 2>&1" % WEBUI_SERVICE_NAME],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def safe_int(value: str) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_port(value: str, label: str, errors: List[str]) -> Optional[int]:
    if not value:
        errors.append(f"{label} is required.")
        return None
    port = safe_int(value)
    if port is None:
        errors.append(f"{label} must be numeric.")
        return None
    if port < 1 or port > 65535:
        errors.append(f"{label} must be between 1 and 65535.")
        return None
    return port


def parse_port_spec(value: str, rule_name: str, errors: List[str]) -> Tuple[Optional[int], Optional[int]]:
    raw = value.strip()
    if not raw:
        errors.append(f"{rule_name}: port is required.")
        return None, None

    normalized = raw.replace(" ", "")
    if "-" in normalized and ":" in normalized:
        errors.append(f"{rule_name}: use either '-' or ':' for a range, not both.")
        return None, None

    separator = "-" if "-" in normalized else ":" if ":" in normalized else ""
    if separator:
        parts = normalized.split(separator)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            errors.append(f"{rule_name}: use a range like 12000-12010.")
            return None, None
        first_text, last_text = parts
    else:
        first_text = normalized
        last_text = normalized

    first = parse_port(first_text, f"{rule_name} port", errors)
    last = parse_port(last_text, f"{rule_name} port", errors)
    if first is not None and last is not None and first > last:
        errors.append(f"{rule_name}: port range start must be less than or equal to the end.")
    return first, last


def add_reservation(
    reservations: Dict[str, List[Tuple[int, int, str]]],
    proto: str,
    first: Optional[int],
    last: Optional[int],
    label: str,
) -> None:
    if first is None or last is None:
        return
    reservations[proto].append((min(first, last), max(first, last), label))


def standard_port_reservations(values: Dict[str, str]) -> Dict[str, List[Tuple[int, int, str]]]:
    reservations: Dict[str, List[Tuple[int, int, str]]] = {"tcp": [], "udp": []}
    add_reservation(reservations, "tcp", 22, 22, "VPS SSH")
    # Include custom SSH ports from the effective sshd configuration.
    try:
        result = subprocess.run(["/usr/sbin/sshd", "-T"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith("port "):
                    port = safe_int(line.split()[1])
                    if port != 22:
                        add_reservation(reservations, "tcp", port, port, "VPS SSH")
    except (OSError, subprocess.TimeoutExpired):
        pass

    add_reservation(reservations, "udp", safe_int(values.get("WG_PORT", "")), safe_int(values.get("WG_PORT", "")), "WireGuard")
    add_reservation(reservations, "tcp", safe_int(values.get("WEBUI_PORT", "")), safe_int(values.get("WEBUI_PORT", "")), "Web UI")

    add_reservation(reservations, "tcp", 8006, 8006, "Proxmox GUI")

    add_reservation(reservations, "tcp", 8080, 8080, "Router admin")
    add_reservation(reservations, "tcp", 8081, 8081, "Router LuCI")
    add_reservation(reservations, "tcp", 10443, 10443, "Makito X4E GUI")
    add_reservation(reservations, "tcp", 10444, 10444, "HSG Web GUI")
    add_reservation(reservations, "tcp", 2222, 2222, "HSG SSH")
    add_reservation(reservations, "tcp", 1936, 1936, "HSG RTMP")
    add_reservation(
        reservations,
        "udp",
        safe_int(values.get("MAKITO_ENC_UDP_FROM", "")),
        safe_int(values.get("MAKITO_ENC_UDP_TO", "")),
        "Makito UDP media",
    )
    add_reservation(
        reservations,
        "udp",
        safe_int(values.get("HSG_SRT_UDP_FROM", "")),
        safe_int(values.get("HSG_SRT_UDP_TO", "")),
        "HSG SRT UDP",
    )

    for first, last, label in STREAMHUB_TCP_PORTS:
        add_reservation(reservations, "tcp", first, last, label)
    for first, last, label in STREAMHUB_UDP_PORTS:
        add_reservation(reservations, "udp", first, last, label)

    return reservations


def ranges_overlap(first: int, last: int, other_first: int, other_last: int) -> bool:
    return max(first, other_first) <= min(last, other_last)


def collect_extra_rules(
    form: Dict[str, List[str]],
    values: Dict[str, str],
) -> Tuple[List[Dict[str, str]], List[str]]:
    field_names = [
        "EXTRA_RULE_PROTO",
        "EXTRA_RULE_TARGET_IP",
        "EXTRA_RULE_PORT",
        "EXTRA_RULE_TARGET_PORT",
        "EXTRA_RULE_LABEL",
        "EXTRA_RULE_PUBLIC_FROM",
        "EXTRA_RULE_PUBLIC_TO",
    ]
    lists = {name: form.get(name, []) for name in field_names}
    row_count = max((len(items) for items in lists.values()), default=0)
    if row_count > 128:
        return [], ["At most 128 extra forwarding rules are supported."]
    errors: List[str] = []
    rules: List[Dict[str, str]] = []

    lan_network = None
    lan_error = ""
    if row_count:
        try:
            lan_network = ipaddress.ip_network(values.get("LAN_CIDR", ""), strict=False)
            if lan_network.version != 4:
                lan_error = "LAN_CIDR must be an IPv4 CIDR before using extra rules."
        except ValueError:
            lan_error = "LAN_CIDR must be a valid IPv4 CIDR before using extra rules."

    def at(name: str, index: int) -> str:
        items = lists[name]
        return items[index].strip() if index < len(items) else ""

    for index in range(row_count):
        proto = at("EXTRA_RULE_PROTO", index).lower() or "udp"
        target_ip_text = at("EXTRA_RULE_TARGET_IP", index)
        port_spec_text = at("EXTRA_RULE_PORT", index)
        label = " ".join(at("EXTRA_RULE_LABEL", index).split())

        if not port_spec_text:
            old_public_from = at("EXTRA_RULE_PUBLIC_FROM", index)
            old_public_to = at("EXTRA_RULE_PUBLIC_TO", index)
            if old_public_from and old_public_to and old_public_from != old_public_to:
                port_spec_text = f"{old_public_from}-{old_public_to}"
            else:
                port_spec_text = old_public_from or old_public_to

        if not any([port_spec_text, target_ip_text, label, at("EXTRA_RULE_TARGET_PORT", index)]):
            continue

        rule_name = label or f"Extra rule {index + 1}"
        row_errors: List[str] = []

        if proto not in ("tcp", "udp"):
            row_errors.append(f"{rule_name}: protocol must be TCP or UDP.")

        public_from, public_to = parse_port_spec(port_spec_text, rule_name, row_errors)
        target_spec = at("EXTRA_RULE_TARGET_PORT", index) or port_spec_text
        target_from, target_to = parse_port_spec(target_spec, rule_name + " local", row_errors)
        if all(port is not None for port in (public_from, public_to, target_from, target_to)):
            if public_to - public_from != target_to - target_from:
                row_errors.append(f"{rule_name}: public and local ranges must contain the same number of ports.")

        target_ip = None
        if not target_ip_text:
            row_errors.append(f"{rule_name}: IP address is required.")
        else:
            try:
                target_ip = ipaddress.ip_address(target_ip_text)
                if target_ip.version != 4:
                    row_errors.append(f"{rule_name}: IP address must be IPv4.")
                elif lan_error:
                    row_errors.append(lan_error)
                elif lan_network is not None and (target_ip not in lan_network or target_ip in (lan_network.network_address, lan_network.broadcast_address)):
                    row_errors.append(f"{rule_name}: IP address must be inside LAN CIDR {values.get('LAN_CIDR', '')}.")
            except ValueError:
                row_errors.append(f"{rule_name}: IP address must be a valid IPv4 address.")

        if len(label) > 64:
            row_errors.append(f"{rule_name} label must be 64 characters or less.")
        if any(char in label for char in "|;\r\n"):
            row_errors.append(f"{rule_name}: label cannot contain semicolons or pipes.")

        if row_errors:
            errors.extend(row_errors)
            continue

        rules.append({
            "proto": proto,
            "public_from": str(public_from),
            "public_to": str(public_to),
            "target_ip": str(target_ip),
            "target_from": str(target_from),
            "target_to": str(target_to),
            "label": label,
        })

    reservations = standard_port_reservations(values)
    for index, rule in enumerate(rules):
        proto = rule["proto"]
        public_from = int(rule["public_from"])
        public_to = int(rule["public_to"])
        rule_name = rule.get("label") or f"Extra rule {index + 1}"
        for reserved_from, reserved_to, reserved_label in reservations[proto]:
            if ranges_overlap(public_from, public_to, reserved_from, reserved_to):
                errors.append(
                    f'{rule_name} overlaps {reserved_label}: {proto.upper()} '
                    f'{range_text(str(public_from), str(public_to))} conflicts with '
                    f'{range_text(str(reserved_from), str(reserved_to))}.'
                )
        for other_index, other in enumerate(rules[:index]):
            if proto != other["proto"]:
                continue
            other_from = int(other["public_from"])
            other_to = int(other["public_to"])
            if ranges_overlap(public_from, public_to, other_from, other_to):
                other_name = other.get("label") or f"Extra rule {other_index + 1}"
                errors.append(
                    f'{rule_name} overlaps {other_name}: {proto.upper()} '
                    f'{range_text(str(public_from), str(public_to))} conflicts with '
                    f'{range_text(str(other_from), str(other_to))}.'
                )

    return rules, errors


def apply_form_values(form: Dict[str, List[str]], current: Dict[str, str]) -> Tuple[Dict[str, str], List[str], str]:
    values = {
        "LAN_CIDR": form.get("LAN_CIDR", [current["LAN_CIDR"]])[0].strip(),
        "ROUTER_LAN_IP": form.get("ROUTER_LAN_IP", [current["ROUTER_LAN_IP"]])[0].strip(),
        "PROXMOX_IP": form.get("PROXMOX_IP", [current["PROXMOX_IP"]])[0].strip(),
        "STREAMHUB_IP": form.get("STREAMHUB_IP", [current["STREAMHUB_IP"]])[0].strip(),
        "HSG_IP": form.get("HSG_IP", [current["HSG_IP"]])[0].strip(),
        "MAKITO_ENC_IP": form.get("MAKITO_ENC_IP", [current["MAKITO_ENC_IP"]])[0].strip(),
        "WINDOWS_ORCH_IP": form.get("WINDOWS_ORCH_IP", [current["WINDOWS_ORCH_IP"]])[0].strip(),
        "WG_PORT": form.get("WG_PORT", [current["WG_PORT"]])[0].strip(),
        "WG_TUN_CIDR": form.get("WG_TUN_CIDR", [current["WG_TUN_CIDR"]])[0].strip(),
        "WG_VPS_IP": form.get("WG_VPS_IP", [current["WG_VPS_IP"]])[0].strip(),
        "WG_GL_IP": form.get("WG_GL_IP", [current["WG_GL_IP"]])[0].strip(),
        "REMOTE_CLIENT_IP": form.get("REMOTE_CLIENT_IP", [current["REMOTE_CLIENT_IP"]])[0].strip(),
        "MAKITO_ENC_UDP_FROM": form.get("MAKITO_ENC_UDP_FROM", [current["MAKITO_ENC_UDP_FROM"]])[0].strip(),
        "MAKITO_ENC_UDP_TO": form.get("MAKITO_ENC_UDP_TO", [current["MAKITO_ENC_UDP_TO"]])[0].strip(),
        "HSG_SRT_UDP_FROM": form.get("HSG_SRT_UDP_FROM", [current["HSG_SRT_UDP_FROM"]])[0].strip(),
        "HSG_SRT_UDP_TO": form.get("HSG_SRT_UDP_TO", [current["HSG_SRT_UDP_TO"]])[0].strip(),
        "PUB_IFACE": form.get("PUB_IFACE", [current["PUB_IFACE"]])[0].strip(),
        "PUB_IP": form.get("PUB_IP", [current["PUB_IP"]])[0].strip(),
        "WEBUI_PORT": form.get("WEBUI_PORT", [current["WEBUI_PORT"]])[0].strip(),
        "WEBUI_USER": form.get("WEBUI_USER", [current["WEBUI_USER"]])[0].strip(),
        "WEBUI_ENABLED": "Y",
        "WEBUI_BIND": current.get("WEBUI_BIND", "0.0.0.0"),
        "EXTRA_PF_RULES": current.get("EXTRA_PF_RULES", ""),
        "UFW_WAS_ACTIVE": current.get("UFW_WAS_ACTIVE", "N"),
    }
    password = form.get("WEBUI_PASSWORD", [""])[0]
    confirm = form.get("WEBUI_PASSWORD_CONFIRM", [""])[0]
    current_password = form.get("WEBUI_CURRENT_PASSWORD", [""])[0]
    errors: List[str] = []
    networks = {}
    for key in ("LAN_CIDR", "WG_TUN_CIDR"):
        try:
            networks[key] = ipaddress.IPv4Network(values[key], strict=True)
        except ValueError:
            errors.append(f"{key} must be a canonical IPv4 network, for example 192.168.10.0/24.")
    if len(networks) == 2 and networks["LAN_CIDR"].overlaps(networks["WG_TUN_CIDR"]):
        errors.append("LAN and WireGuard networks must not overlap.")
    for key in ("ROUTER_LAN_IP", "PROXMOX_IP", "STREAMHUB_IP", "HSG_IP", "MAKITO_ENC_IP",
                "WINDOWS_ORCH_IP", "WG_VPS_IP", "WG_GL_IP", "REMOTE_CLIENT_IP", "PUB_IP"):
        try:
            address = ipaddress.IPv4Address(values[key])
            network = networks.get("WG_TUN_CIDR" if key in {"WG_VPS_IP", "WG_GL_IP", "REMOTE_CLIENT_IP"} else "LAN_CIDR")
            if key != "PUB_IP" and network is not None:
                if address not in network or address in (network.network_address, network.broadcast_address):
                    errors.append(f"{key} must be a usable host inside {network}.")
            if address.is_multicast or address.is_unspecified or address.is_loopback:
                errors.append(f"{key} is not a usable endpoint.")
        except ValueError:
            errors.append(f"{key} must be an IPv4 address.")
    wg_hosts = [values["WG_VPS_IP"], values["WG_GL_IP"], values["REMOTE_CLIENT_IP"]]
    if len(set(wg_hosts)) != len(wg_hosts):
        errors.append("VPS, HAIBOX Router and Remote VPN Client WireGuard addresses must all be different.")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", values["PUB_IFACE"]):
        errors.append("Public interface name is invalid.")
    parse_port(values["WG_PORT"], "WireGuard UDP port", errors)
    for key, value in values.items():
        if any(char in value for char in "\r\n\x00"):
            errors.append(f"{key} contains invalid control characters.")
    reservations = standard_port_reservations(values)
    adjustable = {"WireGuard", "Web UI", "Makito UDP media", "HSG SRT UDP"}
    for proto, entries in reservations.items():
        for index, (first, last, label) in enumerate(entries):
            for other_first, other_last, other_label in entries[:index]:
                if (label in adjustable or other_label in adjustable) and ranges_overlap(first, last, other_first, other_last):
                    errors.append(f"{proto.upper()} port conflict: {label} and {other_label}.")

    for key in [
        "LAN_CIDR",
        "ROUTER_LAN_IP",
        "PROXMOX_IP",
        "STREAMHUB_IP",
        "HSG_IP",
        "MAKITO_ENC_IP",
        "WINDOWS_ORCH_IP",
        "WG_PORT",
        "WG_TUN_CIDR",
        "WG_VPS_IP",
        "WG_GL_IP",
        "REMOTE_CLIENT_IP",
        "MAKITO_ENC_UDP_FROM",
        "MAKITO_ENC_UDP_TO",
        "HSG_SRT_UDP_FROM",
        "HSG_SRT_UDP_TO",
        "PUB_IFACE",
        "PUB_IP",
        "WEBUI_USER",
        "WEBUI_PORT",
    ]:
        if not values[key]:
            errors.append(f"{key} cannot be empty.")

    if values["WEBUI_USER"] and not USERNAME_RE.fullmatch(values["WEBUI_USER"]):
        errors.append("Web UI username can only contain letters, numbers, dot, underscore or dash.")

    if values["WEBUI_PORT"]:
        try:
            port = int(values["WEBUI_PORT"])
            if port < 1024 or port > 65535:
                errors.append("Web UI port must be between 1024 and 65535.")
        except ValueError:
            errors.append("Web UI port must be numeric.")

    for key, label in [
        ("MAKITO_ENC_UDP_FROM", "Makito UDP from"),
        ("MAKITO_ENC_UDP_TO", "Makito UDP to"),
        ("HSG_SRT_UDP_FROM", "HSG SRT UDP from"),
        ("HSG_SRT_UDP_TO", "HSG SRT UDP to"),
    ]:
        try:
            port = int(values[key])
            if port < 1 or port > 65535:
                errors.append("%s must be between 1 and 65535." % label)
        except ValueError:
            errors.append("%s must be numeric." % label)

    if not errors:
        if int(values["MAKITO_ENC_UDP_FROM"]) > int(values["MAKITO_ENC_UDP_TO"]):
            errors.append("Makito UDP from must be less than or equal to Makito UDP to.")
        if int(values["HSG_SRT_UDP_FROM"]) > int(values["HSG_SRT_UDP_TO"]):
            errors.append("HSG SRT UDP from must be less than or equal to HSG SRT UDP to.")

    if password or confirm:
        if password != confirm:
            errors.append("Web UI passwords do not match.")
        elif len(password) < 10:
            errors.append("New Web UI passwords must be at least 10 characters.")

    if password or values["WEBUI_USER"] != current.get("WEBUI_USER", ""):
        if not verify_credentials(current.get("WEBUI_USER", ""), current_password):
            errors.append("The current Web UI password is required to change login credentials.")

    extra_rules, extra_errors = collect_extra_rules(form, values)
    errors.extend(extra_errors)
    values["EXTRA_PF_RULES"] = encode_extra_rules(extra_rules)

    return values, errors, password


def _ping_target(ip: str) -> Tuple[bool, Optional[float]]:
    start = time.monotonic()
    try:
        result = subprocess.run(
            ["ping", "-n", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1.5,
            check=False,
        )
        if result.returncode == 0:
            return True, round((time.monotonic() - start) * 1000, 1)
    except (OSError, subprocess.SubprocessError):
        pass
    return False, None


def _tcp_target(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=0.8):
            return True
    except (OSError, TimeoutError):
        return False


def _probe_device(name: str, ip: str, ports: List[Tuple[int, str]]) -> Dict[str, object]:
    ping_online, latency = _ping_target(ip)
    services = [
        {"port": port, "label": label, "online": _tcp_target(ip, port)}
        for port, label in ports
    ]
    service_online = any(bool(service["online"]) for service in services)
    if ping_online:
        status = "online"
    elif service_online:
        status = "service_online"
    elif ping_online:
        status = "reachable"
    else:
        status = "offline"
    return {
        "name": name,
        "ip": ip,
        "configured": True,
        "online": ping_online or service_online,
        "ping_online": ping_online,
        "service_online": service_online,
        "status": status,
        "latency_ms": latency,
        "services": services,
    }


def dashboard_status(state: Optional[Dict[str, str]]) -> Dict[str, object]:
    if state is None:
        return {
            "timestamp": int(time.time() * 1000), "applied": False,
            "peers": [
                {"name":"HAIBOX Router","kind":"router","ip":"","configured":False,"online":False,"handshake_age":None,"endpoint":"","rx_bytes":0,"tx_bytes":0},
                {"name":"Remote VPN Client","kind":"remote","ip":"","configured":False,"online":False,"handshake_age":None,"endpoint":"","rx_bytes":0,"tx_bytes":0},
            ],
            "devices": [
                {"name":name,"ip":"","configured":False,"online":False,"ping_online":False,"service_online":False,"status":"not_configured","latency_ms":None,"services":[]}
                for name in ("Router","StreamHub","HSG / HMG","Makito X4E","Windows Orchestrator","Proxmox")
            ],
        }
    now = int(time.time())
    peers: List[Dict[str, object]] = []
    peer_specs = [
        ("HAIBOX Router", state.get("WG_GL_IP", DEFAULTS["WG_GL_IP"]), "router"),
        ("Remote VPN Client", state.get("REMOTE_CLIENT_IP", DEFAULTS["REMOTE_CLIENT_IP"]), "remote"),
    ]
    wg_rows: List[List[str]] = []
    try:
        dump = subprocess.run(
            ["wg", "show", "wg0", "dump"],
            capture_output=True,
            text=True,
            timeout=1.5,
            check=False,
        )
        if dump.returncode == 0:
            wg_rows = [line.split("\t") for line in dump.stdout.splitlines()[1:] if line.strip()]
    except (OSError, subprocess.SubprocessError):
        wg_rows = []

    for label, peer_ip, kind in peer_specs:
        cidr = peer_ip + "/32"
        match = None
        for row in wg_rows:
            if len(row) >= 8 and cidr in [item.strip() for item in row[3].split(",")]:
                match = row
                break
        configured = match is not None
        handshake = 0
        rx_bytes = 0
        tx_bytes = 0
        endpoint = ""
        if match is not None:
            endpoint = "" if match[2] == "(none)" else match[2]
            try: handshake = int(match[4])
            except ValueError: handshake = 0
            try: rx_bytes = int(match[5])
            except ValueError: rx_bytes = 0
            try: tx_bytes = int(match[6])
            except ValueError: tx_bytes = 0
        age = (now - handshake) if handshake > 0 else None
        if configured:
            online, _ = _ping_target(peer_ip)
        else:
            online = False
        peers.append({
            "name": label,
            "kind": kind,
            "ip": peer_ip,
            "configured": configured,
            "online": online,
            "handshake_age": age,
            "endpoint": endpoint,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
        })

    device_specs: List[Tuple[str, str, List[Tuple[int, str]]]] = [
        ("Router", state.get("ROUTER_LAN_IP", ""), [(8080, "Admin"), (8081, "LuCI")]),
        ("StreamHub", state.get("STREAMHUB_IP", ""), [(443, "HTTPS"), (8444, "Alt HTTPS")]),
        ("HSG / HMG", state.get("HSG_IP", ""), [(443, "HTTPS"), (22, "SSH")]),
        ("Makito X4E", state.get("MAKITO_ENC_IP", ""), [(443, "HTTPS")]),
        ("Windows Orchestrator", state.get("WINDOWS_ORCH_IP", ""), [(3389, "RDP")]),
        ("Proxmox", state.get("PROXMOX_IP", ""), [(8006, "HTTPS")]),
    ]
    devices: List[Dict[str, object]] = []
    valid_specs = [(name, ip, ports) for name, ip, ports in device_specs if ip]
    if valid_specs:
        with ThreadPoolExecutor(max_workers=min(6, len(valid_specs))) as pool:
            futures = [pool.submit(_probe_device, name, ip, ports) for name, ip, ports in valid_specs]
            for index, future in enumerate(futures):
                name, ip, ports = valid_specs[index]
                try:
                    devices.append(future.result(timeout=5.0))
                except Exception:
                    devices.append({
                        "name": name, "ip": ip, "configured": True, "online": False,
                        "ping_online": False, "service_online": False, "status": "offline",
                        "latency_ms": None,
                        "services": [{"port": port, "label": label, "online": False} for port, label in ports],
                    })

    return {"timestamp": int(time.time() * 1000), "applied": True, "peers": peers, "devices": devices}


def device_traffic_counters() -> Dict[str, Dict[str, int]]:
    counters: Dict[str, Dict[str, int]] = {}
    try:
        result = subprocess.run(
            ["iptables-save", "-c", "-t", "filter"],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
        if result.returncode != 0:
            return counters
        pattern = re.compile(
            r'^\[(\d+):(\d+)\] -A HAIBOX_STATS .*--comment "?(rx|tx):([a-z0-9_-]+)"?'
        )
        for line in result.stdout.splitlines():
            match = pattern.search(line)
            if not match:
                continue
            direction, device = match.group(3), match.group(4)
            counters.setdefault(device, {"rx_bytes": 0, "tx_bytes": 0})
            counters[device][direction + "_bytes"] += int(match.group(2))
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}
    return counters


REQUEST_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server_version = "HAIBOX-WebUI/6.5"

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def send_html(
        self,
        content: str,
        status: int = 200,
        extra_headers: Optional[List[Tuple[str, str]]] = None,
    ) -> None:
        encoded = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        if extra_headers:
            for header, value in extra_headers:
                self.send_header(header, value)
        self.end_headers()
        self.wfile.write(encoded)

    def send_json(self, payload: Dict[str, object], status: int = 200) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(encoded)

    def send_download(self, data: bytes, filename: str, content_type: str = "application/octet-stream") -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def send_redirect(
        self,
        location: str,
        extra_headers: Optional[List[Tuple[str, str]]] = None,
    ) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        if extra_headers:
            for header, value in extra_headers:
                self.send_header(header, value)
        self.end_headers()

    def session_cookie(self, session_id: str) -> str:
        return f"{SESSION_COOKIE_NAME}={session_id}; Path=/; HttpOnly; Secure; SameSite=Strict"

    def clear_session_cookie(self) -> str:
        return f"{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"

    def current_session_id(self) -> Optional[str]:
        return get_active_session_id(self.headers.get("Cookie"))

    def split_path(self) -> Tuple[str, Dict[str, List[str]]]:
        if "?" not in self.path:
            return self.path, {}
        path, query_string = self.path.split("?", 1)
        return path, parse_qs(query_string, keep_blank_values=True)

    def do_GET(self) -> None:
        path, query = self.split_path()
        session_id = self.current_session_id()

        if path == "/login":
            if "logged_out" in query:
                message = "Logged out."
            elif "reauth" in query:
                message = "Session closed. Login required."
            elif "password_changed" in query:
                message = "Password changed. Sign in with the new password."
            elif "credentials_changed" in query:
                message = "Login credentials updated. Sign in again."
            else:
                message = ""
            self.send_html(render_login_page(message))
            return
        if path == "/change-password":
            if not session_id:
                self.send_redirect("/login")
            elif password_change_required():
                self.send_html(render_change_password_page())
            else:
                self.send_redirect("/")
            return
        if path == "/":
            if not session_id:
                self.send_redirect("/login")
                return
            if password_change_required():
                self.send_redirect("/change-password")
                return
            flash = pop_session_flash(session_id)
            flash_state = flash.get("state")
            page_state = flash_state if isinstance(flash_state, dict) else merged_state()
            self.send_html(render_page(
                page_state,
                str(flash.get("message", "")),
                str(flash.get("output", "")),
                str(flash.get("level", "info")),
            ))
            return
        if not session_id:
            self.send_redirect("/login")
            return
        if password_change_required():
            self.send_redirect("/change-password")
            return
        if path == "/api/dashboard-status":
            self.send_json(dashboard_status(applied_state()))
            return
        if path == "/api/network-stats":
            stats_dir = Path("/sys/class/net/wg0/statistics")
            try:
                rx_bytes = int((stats_dir / "rx_bytes").read_text(encoding="ascii").strip())
                tx_bytes = int((stats_dir / "tx_bytes").read_text(encoding="ascii").strip())
                self.send_json({
                    "available": True,
                    "timestamp": int(time.time() * 1000),
                    "rx_bytes": rx_bytes,
                    "tx_bytes": tx_bytes,
                    "devices": device_traffic_counters(),
                })
            except (OSError, ValueError):
                self.send_json({"available": False, "timestamp": int(time.time() * 1000), "rx_bytes": 0, "tx_bytes": 0, "devices": {}})
            return
        if path == "/download-support-bundle":
            bundle = build_support_bundle()
            stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
            self.send_download(
                bundle,
                f"haibox-support-v{SCRIPT_VERSION}-{stamp}.tar.gz",
                "application/gzip",
            )
            return
        if path == "/download-router-config":
            conf_path = Path(ROUTER_CONF_OUT)
            if not conf_path.exists():
                self.send_html(render_page(merged_state(), "Router config has not been generated yet.", "", "error"), 404)
                return
            data = conf_path.read_bytes()
            self.send_download(data, "haibox_axt1800_wg.conf")
            return
        if path == "/download-remote-client":
            conf_path = Path(REMOTE_CLIENT_CONF_OUT)
            if not conf_path.exists():
                self.send_html(render_page(merged_state(), "Remote VPN client has not been created yet.", "", "error"), 404)
                return
            data = conf_path.read_bytes()
            self.send_download(data, "haibox_remote_client_wg.conf")
            return
        if path != "/":
            self.send_html(render_page(merged_state(), "Page not found.", "", "error"), 404)
            return

    def do_POST(self) -> None:
        if not REQUEST_LOCK.acquire(blocking=False):
            self.send_error(503, "Another operation is running. Retry shortly.")
            return
        try:
            self.handle_post()
        except (OSError, ValueError, subprocess.SubprocessError):
            self.send_error(500, "Operation failed. Check the service journal.")
        finally:
            REQUEST_LOCK.release()

    def handle_post(self) -> None:
        path, _ = self.split_path()
        origin = self.headers.get("Origin")
        if self.headers.get("Sec-Fetch-Site") == "cross-site" or (origin and origin != "https://" + self.headers.get("Host", "")):
            self.send_error(403, "Cross-origin request rejected.")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if self.headers.get("Transfer-Encoding") or not 0 <= length <= 65536:
                self.send_error(413, "Invalid or oversized request.")
                return
            payload = self.rfile.read(length).decode("utf-8")
            form = parse_qs(payload, keep_blank_values=True, max_num_fields=2048)
        except (ValueError, UnicodeError):
            self.send_error(400, "Invalid form data.")
            return

        if path == "/login":
            username = form.get("username", [""])[0].strip()
            password = form.get("password", [""])[0]
            if verify_credentials(username, password):
                session_id = create_session(username)
                self.send_html(
                    render_login_bootstrap(),
                    extra_headers=[("Set-Cookie", self.session_cookie(session_id))],
                )
                return
            self.send_html(render_login_page("Invalid username or password.", username), 401)
            return

        if path == "/logout":
            destroy_session(get_session_id_from_cookie(self.headers.get("Cookie")))
            self.send_html(
                render_logout_bootstrap(),
                extra_headers=[("Set-Cookie", self.clear_session_cookie())],
            )
            return

        session_id = self.current_session_id()
        if not session_id:
            self.send_redirect(
                "/login?reauth=1",
                extra_headers=[("Set-Cookie", self.clear_session_cookie())],
            )
            return

        if path == "/change-password":
            if not password_change_required():
                self.send_redirect("/")
                return
            password = form.get("password", [""])[0]
            confirm = form.get("confirm", [""])[0]
            if password != confirm:
                self.send_html(render_change_password_page("Passwords do not match.", "error"), 400)
                return
            if len(password) < 10:
                self.send_html(render_change_password_page("Password must contain at least 10 characters.", "error"), 400)
                return
            write_auth(merged_state().get("WEBUI_USER", "admin"), password, False)
            SESSIONS.clear()
            self.send_redirect(
                "/login?password_changed=1",
                extra_headers=[("Set-Cookie", self.clear_session_cookie())],
            )
            return

        if password_change_required():
            self.send_redirect("/change-password")
            return

        if path == "/apply":
            current = merged_state()
            values, errors, password = apply_form_values(form, current)
            if errors:
                message = "Configuration not applied. Fix the following fields:\n" + "\n".join(
                    "%d. %s" % (index, error) for index, error in enumerate(errors, 1)
                )
                set_session_flash(session_id, message, "", "error", values)
                self.send_redirect("/")
                return

            try:
                write_state(values)
            except Exception as exc:
                set_session_flash(session_id, "Failed to write configuration: %s" % exc, "", "error", values)
                self.send_redirect("/")
                return

            rc, output = run_script("--web-apply")
            credentials_changed = bool(password or values["WEBUI_USER"] != current.get("WEBUI_USER", ""))
            if rc == 0 and credentials_changed:
                write_auth(values["WEBUI_USER"], password or None)
                SESSIONS.clear()
            if rc != 0:
                write_state(current)
            message = "Apply + Make Persistent completed."
            level = "ok" if rc == 0 else "error"

            if rc == 0 and values["WEBUI_PORT"] != current.get("WEBUI_PORT", DEFAULTS["WEBUI_PORT"]):
                schedule_restart()
                message += " Web UI restart scheduled on https://%s:%s." % (
                    values["PUB_IP"] or "SERVER_IP",
                    values["WEBUI_PORT"],
                )

            if rc != 0:
                detail = next((line.strip() for line in reversed(output.splitlines()) if line.strip()), "No diagnostic detail was returned.")
                message = "Apply failed and the previous configuration was restored.\nReason: " + detail
            if rc == 0 and credentials_changed:
                self.send_redirect(
                    "/login?credentials_changed=1",
                    extra_headers=[("Set-Cookie", self.clear_session_cookie())],
                )
                return
            set_session_flash(session_id, message, output, level)
            self.send_redirect("/")
            return

        if path == "/test":
            rc, output = run_script("--web-test")
            message = "Test completed." if rc == 0 else "Test returned errors."
            level = "ok" if rc == 0 else "error"
            set_session_flash(session_id, message, output, level)
            self.send_redirect("/")
            return

        if path == "/health":
            rc, output = run_script("--health")
            if rc == 0:
                message = "System Health: HEALTHY."
                level = "ok"
            elif rc == 1:
                message = "System Health: WARNING."
                level = "info"
            else:
                message = "System Health: ERROR."
                level = "error"
            set_session_flash(session_id, message, output, level)
            self.send_redirect("/")
            return

        if path == "/create-remote-client":
            rc, output = run_script("--create-remote-client")
            message = "Remote VPN client created. Download the .conf and import it in WireGuard." if rc == 0 else "Remote VPN client creation failed."
            level = "ok" if rc == 0 else "error"
            set_session_flash(session_id, message, output, level)
            self.send_redirect("/")
            return

        set_session_flash(session_id, "Unsupported action.", "", "error")
        self.send_redirect("/")


class ThreadingTLSServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, server_address: Tuple[str, int], handler_class, context: ssl.SSLContext) -> None:
        self.ssl_context = context
        super().__init__(server_address, handler_class)

    def get_request(self):
        raw_socket, address = self.socket.accept()
        raw_socket.settimeout(15)
        tls_socket = self.ssl_context.wrap_socket(
            raw_socket,
            server_side=True,
            do_handshake_on_connect=False,
        )
        tls_socket.settimeout(30)
        return tls_socket, address

    def handle_error(self, request, client_address) -> None:
        exc_type, _, _ = sys.exc_info()
        if exc_type in (BrokenPipeError, ConnectionResetError, TimeoutError, ssl.SSLError):
            return
        super().handle_error(request, client_address)


def main() -> None:
    state = merged_state()
    host = state.get("WEBUI_BIND", "0.0.0.0")
    port = int(state.get("WEBUI_PORT", "65000"))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    server = ThreadingTLSServer((host, port), Handler, context)
    server.serve_forever()


if __name__ == "__main__":
    main()
PYEOF
  chmod 700 "${WEBUI_APP}"
  ok "Wrote ${WEBUI_APP}"
}

write_webui_service() {
  local python_bin
  python_bin="$(command -v python3)"
  cat > "${WEBUI_SERVICE_FILE}" <<EOF
[Unit]
Description=Haibox VPN Web UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=${SCRIPT_INSTALL_PATH} --ensure-webui-input
ExecStart=${python_bin} ${WEBUI_APP}
WorkingDirectory=${WEBUI_DIR}
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  ok "Wrote ${WEBUI_SERVICE_FILE}"
}

start_webui_service() {
  systemctl daemon-reload
  systemctl enable "${WEBUI_SERVICE_NAME}" >/dev/null 2>&1 || true
  systemctl restart "${WEBUI_SERVICE_NAME}" >/dev/null 2>&1 || systemctl start "${WEBUI_SERVICE_NAME}"
  ok "Web UI service is running: ${WEBUI_SERVICE_NAME}"
}

install_webui_stack() {
  install_self_copy
  if [[ -n "${WEBUI_PASSWORD:-}" ]]; then
    write_webui_auth
  fi
  write_webui_cert
  write_webui_app
  write_webui_service
  start_webui_service
}

gen_keys() {
  mkdir -p "${WG_DIR}"
  chmod 700 "${WG_DIR}"

  if [[ ! -f "${WG_DIR}/vps_private.key" ]]; then
    umask 077
    wg genkey | tee "${WG_DIR}/vps_private.key" | wg pubkey > "${WG_DIR}/vps_public.key"
  fi

  if [[ ! -f "${WG_DIR}/gl_private.key" ]]; then
    umask 077
    wg genkey | tee "${WG_DIR}/gl_private.key" | wg pubkey > "${WG_DIR}/gl_public.key"
  fi

  VPS_PRIV="$(cat "${WG_DIR}/vps_private.key")"
  VPS_PUB="$(cat "${WG_DIR}/vps_public.key")"
  GL_PRIV="$(cat "${WG_DIR}/gl_private.key")"
  GL_PUB="$(cat "${WG_DIR}/gl_public.key")"
  if [[ -f "${WG_DIR}/remote_client_private.key" && -f "${WG_DIR}/remote_client_public.key" ]]; then
    REMOTE_CLIENT_PRIV="$(cat "${WG_DIR}/remote_client_private.key")"
    REMOTE_CLIENT_PUB="$(cat "${WG_DIR}/remote_client_public.key")"
  fi
}

write_wg_configs() {
  gen_keys
  local prefix
  prefix="$(cidr_prefix "${WG_TUN_CIDR}")"
  [[ -n "${prefix}" ]] || { err "Invalid WG tunnel CIDR: ${WG_TUN_CIDR}"; exit 1; }

  cat > "${WG_CONF}" <<EOF
[Interface]
Address = ${WG_VPS_IP}/${prefix}
ListenPort = ${WG_PORT}
PrivateKey = ${VPS_PRIV}

[Peer]
PublicKey = ${GL_PUB}
AllowedIPs = ${WG_GL_IP}/32, ${LAN_CIDR}
EOF
  if [[ -n "${REMOTE_CLIENT_PUB:-}" ]]; then
    cat >> "${WG_CONF}" <<EOF

[Peer]
PublicKey = ${REMOTE_CLIENT_PUB}
AllowedIPs = ${REMOTE_CLIENT_IP}/32
EOF
  fi
  chmod 600 "${WG_CONF}"
  ok "Wrote ${WG_CONF}"

  cat > "${ROUTER_CONF_OUT}" <<EOF
[Interface]
PrivateKey = ${GL_PRIV}
Address = ${WG_GL_IP}/${prefix}
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = ${VPS_PUB}
Endpoint = ${PUB_IP}:${WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
  chmod 600 "${ROUTER_CONF_OUT}"
  ok "Wrote ${ROUTER_CONF_OUT}"

  if [[ -n "${REMOTE_CLIENT_PRIV:-}" ]]; then
    cat > "${REMOTE_CLIENT_CONF_OUT}" <<EOF
[Interface]
PrivateKey = ${REMOTE_CLIENT_PRIV}
Address = ${REMOTE_CLIENT_IP}/${prefix}
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = ${VPS_PUB}
Endpoint = ${PUB_IP}:${WG_PORT}
AllowedIPs = ${LAN_CIDR}, ${WG_VPS_IP}/32
PersistentKeepalive = 25
EOF
    chmod 600 "${REMOTE_CLIENT_CONF_OUT}"
    ok "Wrote ${REMOTE_CLIENT_CONF_OUT}"
  fi
}

create_remote_client() {
  load_state
  init_defaults
  mkdir -p "${WG_DIR}"
  chmod 700 "${WG_DIR}"
  if [[ ! -f "${WG_DIR}/remote_client_private.key" ]]; then
    umask 077
    wg genkey | tee "${WG_DIR}/remote_client_private.key" | wg pubkey > "${WG_DIR}/remote_client_public.key"
  fi
  write_wg_configs
  if systemctl is-active --quiet "wg-quick@${WG_NAME}"; then
    systemctl restart "wg-quick@${WG_NAME}"
  fi
  ok "Remote VPN client ready: ${REMOTE_CLIENT_IP}"
  ok "Config: ${REMOTE_CLIENT_CONF_OUT}"
}

apply_sysctl() {
  cat > "${SYSCTL_FILE}" <<EOF
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
  sysctl -p "${SYSCTL_FILE}" >/dev/null
  ok "Applied sysctl settings."
}

wg_up() {
  systemctl stop "wg-quick@${WG_NAME}" >/dev/null 2>&1 || true
  systemctl start "wg-quick@${WG_NAME}"
  ok "WireGuard is up: wg-quick@${WG_NAME}"
}

wireguard_input_rule_exists() {
  iptables -C INPUT -p udp --dport "${WG_PORT}" -j ACCEPT >/dev/null 2>&1
}

ensure_wireguard_input_rule() {
  if ! wireguard_input_rule_exists; then
    iptables -I INPUT 1 -p udp --dport "${WG_PORT}" -j ACCEPT
  fi
  ok "Allowed WireGuard on INPUT: UDP ${WG_PORT}"
}

remove_wireguard_input_rule() {
  while wireguard_input_rule_exists; do
    iptables -D INPUT -p udp --dport "${WG_PORT}" -j ACCEPT >/dev/null 2>&1 || true
  done
}

remove_webui_input_rules() {
  local rule
  while IFS= read -r rule; do
    [[ -n "${rule}" ]] || continue
    eval "iptables ${rule/-A /-D }" >/dev/null 2>&1 || true
  done < <(iptables -S INPUT 2>/dev/null | grep -F -- "${WEBUI_RULE_COMMENT}" || true)
}

ensure_webui_input_rule() {
  remove_webui_input_rules
  if [[ "${WEBUI_ENABLED}" == "Y" ]]; then
    iptables -I INPUT 1 -p tcp --dport "${WEBUI_PORT}" -m comment --comment "${WEBUI_RULE_COMMENT}" -j ACCEPT
    ok "Allowed Web UI on INPUT: TCP ${WEBUI_PORT}"
  fi
}

prepare_host_firewall() {
  if have_cmd ufw; then
    local ufw_status
    ufw_status="$(ufw status 2>/dev/null | head -n 1 || true)"
    if [[ "${ufw_status}" == "Status: active" ]]; then
      warn "UFW is active. Disabling it to avoid blocking WireGuard and custom iptables rules."
      ufw --force disable >/dev/null
      UFW_WAS_ACTIVE="Y"
      ok "UFW disabled."
    fi
  fi

  ensure_wireguard_input_rule
  ensure_webui_input_rule
  save_state
}

iptables_cleanup_chains() {
  iptables -t nat -D PREROUTING -j "${TAG_CHAIN_NAT}" >/dev/null 2>&1 || true
  iptables -t nat -F "${TAG_CHAIN_NAT}" >/dev/null 2>&1 || true
  iptables -t nat -X "${TAG_CHAIN_NAT}" >/dev/null 2>&1 || true

  iptables -D FORWARD -j "${TAG_CHAIN_FWD}" >/dev/null 2>&1 || true
  iptables -F "${TAG_CHAIN_FWD}" >/dev/null 2>&1 || true
  iptables -X "${TAG_CHAIN_FWD}" >/dev/null 2>&1 || true

  iptables -D FORWARD -j "${TAG_CHAIN_STATS}" >/dev/null 2>&1 || true
  iptables -F "${TAG_CHAIN_STATS}" >/dev/null 2>&1 || true
  iptables -X "${TAG_CHAIN_STATS}" >/dev/null 2>&1 || true
}

# helper: add DNAT rule for BOTH public iface and wg0 (hairpin)
dnat_both() {
  local proto="$1"
  local dport="$2"
  local to="$3"
  # From Internet
  iptables -t nat -A "${TAG_CHAIN_NAT}" -i "${PUB_IFACE}" -p "${proto}" --dport "${dport}" -j DNAT --to-destination "${to}"
  # From inside tunnel, only when dst is VPS public IP
  iptables -t nat -A "${TAG_CHAIN_NAT}" -i "${WG_NAME}" -d "${PUB_IP}" -p "${proto}" --dport "${dport}" -j DNAT --to-destination "${to}"
}

dnat_range_both() {
  local proto="$1"
  local dport_range="$2"
  local to="$3"
  iptables -t nat -A "${TAG_CHAIN_NAT}" -i "${PUB_IFACE}" -p "${proto}" --dport "${dport_range}" -j DNAT --to-destination "${to}"
  iptables -t nat -A "${TAG_CHAIN_NAT}" -i "${WG_NAME}" -d "${PUB_IP}" -p "${proto}" --dport "${dport_range}" -j DNAT --to-destination "${to}"
}

apply_extra_pf_rules() {
  [[ -n "${EXTRA_PF_RULES:-}" ]] || return 0

  local row proto public_from public_to target_ip target_from target_to label dport target
  local -a rows
  IFS=';' read -ra rows <<< "${EXTRA_PF_RULES}"
  for row in "${rows[@]}"; do
    [[ -n "${row}" ]] || continue
    IFS='|' read -r proto public_from public_to target_ip target_from target_to label <<< "${row}"
    [[ -n "${proto}" && -n "${public_from}" && -n "${public_to}" && -n "${target_ip}" && -n "${target_from}" && -n "${target_to}" ]] || continue

    if [[ "${public_from}" == "${public_to}" ]]; then
      target="${target_ip}:${target_from}"
      dnat_both "${proto}" "${public_from}" "${target}"
    else
      dport="${public_from}:${public_to}"
      if [[ "${public_from}" == "${target_from}" && "${public_to}" == "${target_to}" ]]; then
        target="${target_ip}"
      else
        target="${target_ip}:${target_from}-${target_to}/${public_from}"
      fi
      dnat_range_both "${proto}" "${dport}" "${target}"
    fi
  done
}

iptables_apply_rules() {
  [[ -n "${PUB_IFACE}" ]] || { err "Public iface is empty."; exit 1; }
  [[ -n "${PUB_IP}" ]] || { err "Public IPv4 is empty."; exit 1; }

  iptables_cleanup_chains

  iptables -t nat -N "${TAG_CHAIN_NAT}"
  iptables -t nat -A PREROUTING -j "${TAG_CHAIN_NAT}"

  iptables -N "${TAG_CHAIN_FWD}"
  iptables -A FORWARD -j "${TAG_CHAIN_FWD}"

  # Dedicated non-terminating counters provide per-device traffic telemetry.
  # They do not alter packet handling and are read by the Web UI.
  iptables -N "${TAG_CHAIN_STATS}"
  iptables -I FORWARD 1 -j "${TAG_CHAIN_STATS}"
  local stats_name stats_ip
  while IFS='|' read -r stats_name stats_ip; do
    [[ -n "${stats_name}" && -n "${stats_ip}" ]] || continue
    iptables -A "${TAG_CHAIN_STATS}" -i "${WG_NAME}" -s "${stats_ip}" -m comment --comment "rx:${stats_name}"
    iptables -A "${TAG_CHAIN_STATS}" -o "${WG_NAME}" -d "${stats_ip}" -m comment --comment "tx:${stats_name}"
  done <<EOF
router|${ROUTER_LAN_IP}
streamhub|${STREAMHUB_IP}
hsg|${HSG_IP}
makito|${MAKITO_ENC_IP}
windows|${WINDOWS_ORCH_IP}
proxmox|${PROXMOX_IP}
EOF
  iptables -A "${TAG_CHAIN_STATS}" -j RETURN

  # Internet egress NAT (support both GL masquerade modes)
  iptables -t nat -C POSTROUTING -s "${LAN_CIDR}" -o "${PUB_IFACE}" -j MASQUERADE >/dev/null 2>&1 || \
    iptables -t nat -A POSTROUTING -s "${LAN_CIDR}" -o "${PUB_IFACE}" -j MASQUERADE
  iptables -t nat -C POSTROUTING -s "${WG_TUN_CIDR}" -o "${PUB_IFACE}" -j MASQUERADE >/dev/null 2>&1 || \
    iptables -t nat -A POSTROUTING -s "${WG_TUN_CIDR}" -o "${PUB_IFACE}" -j MASQUERADE

  # DNAT-to-LAN replies source rewritten to VPS WG IP (stable return path)
  iptables -t nat -C POSTROUTING -d "${LAN_CIDR}" -o "${WG_NAME}" -j SNAT --to-source "${WG_VPS_IP}" >/dev/null 2>&1 || \
    iptables -t nat -A POSTROUTING -d "${LAN_CIDR}" -o "${WG_NAME}" -j SNAT --to-source "${WG_VPS_IP}"

  # Forwarding allow rules
  iptables -A "${TAG_CHAIN_FWD}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A "${TAG_CHAIN_FWD}" -i "${WG_NAME}" -o "${PUB_IFACE}" -j ACCEPT
  iptables -A "${TAG_CHAIN_FWD}" -i "${PUB_IFACE}" -o "${WG_NAME}" -j ACCEPT
  iptables -A "${TAG_CHAIN_FWD}" -i "${WG_NAME}" -o "${WG_NAME}" -j ACCEPT

  # Proxmox GUI is part of the standard HAIBOX public service map.
  dnat_both tcp "${PROXMOX_GUI_PUB_PORT}" "${PROXMOX_IP}:8006"

  # Router
  dnat_both tcp "${ROUTER_ADMIN_PUB_PORT}" "${ROUTER_LAN_IP}:8080"
  dnat_both tcp "${ROUTER_LUCI_PUB_PORT}" "${ROUTER_LAN_IP}:8081"

  # Makito X4E
  dnat_both tcp "${MAKITO_GUI_PUB_PORT}" "${MAKITO_ENC_IP}:443"
  dnat_range_both udp "${MAKITO_ENC_UDP_FROM}:${MAKITO_ENC_UDP_TO}" "${MAKITO_ENC_IP}"

  # HSG (HMG)
  dnat_both tcp "${HSG_GUI_PUB_PORT}" "${HSG_IP}:443"
  dnat_both tcp "${HSG_SSH_PUB_PORT}" "${HSG_IP}:22"
  dnat_both tcp "${HSG_RTMP_PUB_PORT}" "${HSG_IP}:1935"
  dnat_range_both udp "${HSG_SRT_UDP_FROM}:${HSG_SRT_UDP_TO}" "${HSG_IP}"

  # StreamHub (PDF + fixed TCP/UDP 7900-7940)
  dnat_both tcp 7900 "${STREAMHUB_IP}:7900"
  dnat_range_both tcp "7901:7940" "${STREAMHUB_IP}"
  dnat_range_both udp "${STREAMHUB_UDP_7900_FROM}:${STREAMHUB_UDP_7900_TO}" "${STREAMHUB_IP}"

  # StreamHub TCP per PDF
  dnat_both tcp 443  "${STREAMHUB_IP}:443"
  dnat_both tcp 8888 "${STREAMHUB_IP}:8888"
  dnat_both tcp 8891 "${STREAMHUB_IP}:8891"
  dnat_both tcp 8893 "${STREAMHUB_IP}:8893"
  dnat_both tcp 8896 "${STREAMHUB_IP}:8896"
  dnat_both tcp 8444 "${STREAMHUB_IP}:8444"
  dnat_both tcp 8884 "${STREAMHUB_IP}:8884"
  dnat_both tcp 8885 "${STREAMHUB_IP}:8885"
  dnat_both tcp 5322 "${STREAMHUB_IP}:5322"
  dnat_both tcp 1935 "${STREAMHUB_IP}:1935"

  # StreamHub FTP per PDF
  dnat_both tcp 20 "${STREAMHUB_IP}:20"
  dnat_both tcp 21 "${STREAMHUB_IP}:21"
  dnat_range_both tcp "12000:12009" "${STREAMHUB_IP}"

  # StreamHub UDP per PDF
  dnat_range_both udp "5010:5026" "${STREAMHUB_IP}"
  dnat_both udp 5353 "${STREAMHUB_IP}"
  dnat_range_both udp "5959:5960" "${STREAMHUB_IP}"
  dnat_range_both udp "5961:5999" "${STREAMHUB_IP}"
  dnat_range_both udp "6960:6999" "${STREAMHUB_IP}"
  dnat_range_both udp "7960:7999" "${STREAMHUB_IP}"
  dnat_range_both udp "20000:20100" "${STREAMHUB_IP}"
  dnat_range_both udp "20400:20499" "${STREAMHUB_IP}"
  dnat_range_both udp "7901:7940" "${STREAMHUB_IP}"

  # User-defined extra rules from the Web UI.
  apply_extra_pf_rules

  ok "iptables rules applied."
}

make_persistent() {
  log "Creating persistence..."
  prepare_host_firewall
  local temporary
  temporary="$(mktemp "${RULES_FILE}.XXXXXX")"
  iptables-save > "${temporary}"
  chmod 600 "${temporary}"
  iptables-restore --test < "${temporary}"
  mv -f "${temporary}" "${RULES_FILE}"

  cat > "${UNIT_FILE}" <<EOF
[Unit]
Description=Haibox WireGuard iptables rules
After=network-online.target wg-quick@${WG_NAME}.service
Wants=network-online.target wg-quick@${WG_NAME}.service

[Service]
Type=oneshot
ExecStart=/bin/sh -c '/usr/sbin/iptables-restore < ${RULES_FILE}'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "${UNIT_NAME}" >/dev/null 2>&1 || true
  systemctl restart "${UNIT_NAME}" >/dev/null 2>&1 || systemctl start "${UNIT_NAME}"
  if [[ -f "${WG_CONF}" ]]; then
    systemctl enable "wg-quick@${WG_NAME}" >/dev/null 2>&1 || true
    systemctl restart "wg-quick@${WG_NAME}" >/dev/null 2>&1 || systemctl start "wg-quick@${WG_NAME}"
  else
    warn "WireGuard config not found yet. Skipping wg-quick enable/restart."
  fi
  ok "Persistence enabled: ${UNIT_NAME}"
}

do_test() {
  echo
  log "WireGuard status:"
  systemctl --no-pager --full status "wg-quick@${WG_NAME}" || true
  echo
  if have_cmd wg; then
    wg show "${WG_NAME}" || true
  fi

  echo
  log "iptables quick checks:"
  echo "  WG INPUT rule present:            $(iptables -S INPUT 2>/dev/null | grep -c -- "-p udp -m udp --dport ${WG_PORT} -j ACCEPT" || true)"
  if [[ "${WEBUI_ENABLED}" == "Y" ]]; then
    echo "  Web UI INPUT rule present:        $(iptables -S INPUT 2>/dev/null | grep -c -- "${WEBUI_RULE_COMMENT}" || true)"
  fi
  echo "  DNAT rules for public iface exist: $(iptables -t nat -S "${TAG_CHAIN_NAT}" 2>/dev/null | grep -c -- "-i ${PUB_IFACE}" || true)"
  echo "  DNAT hairpin rules on wg0 exist:   $(iptables -t nat -S "${TAG_CHAIN_NAT}" 2>/dev/null | grep -c -- "-i ${WG_NAME} -d ${PUB_IP}" || true)"
  echo
  if systemctl list-unit-files "${WEBUI_SERVICE_NAME}" >/dev/null 2>&1; then
    log "Web UI status:"
    systemctl --no-pager --full status "${WEBUI_SERVICE_NAME}" || true
    echo
  fi
  echo "Client-side tests:"
  echo "  Proxmox GUI:   https://${PUB_IP}:${PROXMOX_GUI_PUB_PORT}"
  if [[ "${WEBUI_ENABLED}" == "Y" ]]; then
    echo "  Web UI:        https://${PUB_IP}:${WEBUI_PORT}"
  fi
  echo "  Makito GUI:    https://${PUB_IP}:${MAKITO_GUI_PUB_PORT}"
  echo "  HSG Web:       https://${PUB_IP}:${HSG_GUI_PUB_PORT}"
  echo "  HSG SSH:       ssh -p ${HSG_SSH_PUB_PORT} hvroot@${PUB_IP}"
  echo "  HSG RTMP:      rtmp://${PUB_IP}:${HSG_RTMP_PUB_PORT}"
  echo "  HSG SRT:       Use UDP ports ${HSG_SRT_UDP_FROM}-${HSG_SRT_UDP_TO} on ${PUB_IP}"
  echo "  StreamHub:     https://${PUB_IP} and https://${PUB_IP}:8444"
  echo "  Router:        https://${PUB_IP}:${ROUTER_ADMIN_PUB_PORT} and https://${PUB_IP}:${ROUTER_LUCI_PUB_PORT}"
  echo
}

system_health() {
  local health_warn=0 health_error=0
  local latest_handshake now age route_line

  health_ok() { printf '[OK]      %s\n' "$*"; }
  health_warn_msg() { printf '[WARNING] %s\n' "$*"; health_warn=$((health_warn + 1)); }
  health_err_msg() { printf '[ERROR]   %s\n' "$*"; health_error=$((health_error + 1)); }

  echo
  echo "============================================================"
  echo " HAIBOX WireGuard v6.5 - System Health"
  echo "============================================================"
  echo

  # WireGuard interface and service
  if ip link show "${WG_NAME}" >/dev/null 2>&1; then
    health_ok "WireGuard interface ${WG_NAME} exists."
  else
    health_err_msg "WireGuard interface ${WG_NAME} is missing."
  fi

  if systemctl is-active --quiet "wg-quick@${WG_NAME}"; then
    health_ok "WireGuard service wg-quick@${WG_NAME} is active."
  else
    health_err_msg "WireGuard service wg-quick@${WG_NAME} is not active."
  fi

  if ip -4 addr show dev "${WG_NAME}" 2>/dev/null | grep -Fq "${WG_VPS_IP}/"; then
    health_ok "VPS WireGuard address ${WG_VPS_IP} is configured on ${WG_NAME}."
  else
    health_err_msg "VPS WireGuard address ${WG_VPS_IP} is not configured on ${WG_NAME}."
  fi

  # HAIBOX router peer and handshake
  if have_cmd wg && wg show "${WG_NAME}" allowed-ips 2>/dev/null | awk '{print $2}' | tr ',' '\n' | grep -Fxq "${WG_GL_IP}/32"; then
    health_ok "HAIBOX router peer ${WG_GL_IP} is configured."
  else
    health_err_msg "HAIBOX router peer ${WG_GL_IP} is not present in ${WG_NAME}."
  fi

  # Active router reachability check. The latest WireGuard handshake is diagnostic
  # history only; it must not be used by itself to declare the router online.
  local router_pubkey
  router_pubkey="$(wg show "${WG_NAME}" allowed-ips 2>/dev/null | awk -v ip="${WG_GL_IP}/32" '$2 ~ ip {print $1; exit}')"
  if [[ -n "${router_pubkey}" ]]; then
    latest_handshake="$(wg show "${WG_NAME}" latest-handshakes 2>/dev/null | awk -v key="${router_pubkey}" '$1 == key {print $2; exit}')"
  else
    latest_handshake="0"
  fi

  if have_cmd ping && ping -n -c 1 -W 1 "${WG_GL_IP}" >/dev/null 2>&1; then
    if [[ "${latest_handshake:-0}" =~ ^[0-9]+$ ]] && (( latest_handshake > 0 )); then
      now="$(date +%s)"
      age=$((now - latest_handshake))
      health_ok "HAIBOX router is online (active check passed; last handshake ${age}s ago)."
    else
      health_ok "HAIBOX router is online (active check passed)."
    fi
  else
    if [[ "${latest_handshake:-0}" =~ ^[0-9]+$ ]] && (( latest_handshake > 0 )); then
      now="$(date +%s)"
      age=$((now - latest_handshake))
      health_err_msg "HAIBOX router is offline (active check failed; last handshake ${age}s ago)."
    else
      health_err_msg "HAIBOX router is offline (active check failed; no WireGuard handshake detected)."
    fi
  fi

  # Kernel forwarding
  if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" == "1" ]]; then
    health_ok "IPv4 forwarding is enabled."
  else
    health_err_msg "IPv4 forwarding is disabled."
  fi

  # Route to HAIBOX LAN
  route_line="$(ip -4 route show "${LAN_CIDR}" 2>/dev/null | head -n1 || true)"
  if [[ -n "${route_line}" && " ${route_line} " == *" dev ${WG_NAME} "* ]]; then
    health_ok "Route to HAIBOX LAN ${LAN_CIDR} uses ${WG_NAME}."
  else
    health_err_msg "Route to HAIBOX LAN ${LAN_CIDR} through ${WG_NAME} is missing."
  fi

  # Firewall/NAT runtime chains and jumps
  if iptables -t nat -S "${TAG_CHAIN_NAT}" >/dev/null 2>&1; then
    health_ok "NAT chain ${TAG_CHAIN_NAT} exists."
  else
    health_err_msg "NAT chain ${TAG_CHAIN_NAT} is missing."
  fi
  if iptables -S "${TAG_CHAIN_FWD}" >/dev/null 2>&1; then
    health_ok "Forwarding chain ${TAG_CHAIN_FWD} exists."
  else
    health_err_msg "Forwarding chain ${TAG_CHAIN_FWD} is missing."
  fi
  if iptables -t nat -C PREROUTING -j "${TAG_CHAIN_NAT}" >/dev/null 2>&1; then
    health_ok "PREROUTING is connected to ${TAG_CHAIN_NAT}."
  else
    health_err_msg "PREROUTING jump to ${TAG_CHAIN_NAT} is missing."
  fi
  if iptables -C FORWARD -j "${TAG_CHAIN_FWD}" >/dev/null 2>&1; then
    health_ok "FORWARD is connected to ${TAG_CHAIN_FWD}."
  else
    health_err_msg "FORWARD jump to ${TAG_CHAIN_FWD} is missing."
  fi
  if iptables -t nat -S POSTROUTING 2>/dev/null | grep -Fq -- "-s ${LAN_CIDR}"; then
    health_ok "HAIBOX LAN has a POSTROUTING NAT rule."
  else
    health_err_msg "POSTROUTING NAT rule for HAIBOX LAN ${LAN_CIDR} is missing."
  fi

  # Persistent configuration
  if [[ -s "${WG_CONF}" ]]; then
    health_ok "WireGuard configuration ${WG_CONF} exists."
  else
    health_err_msg "WireGuard configuration ${WG_CONF} is missing or empty."
  fi
  if [[ -s "${RULES_FILE}" ]]; then
    health_ok "Persistent firewall rules ${RULES_FILE} exist."
  else
    health_err_msg "Persistent firewall rules ${RULES_FILE} are missing or empty."
  fi
  if systemctl is-enabled --quiet "${UNIT_NAME}" 2>/dev/null; then
    health_ok "Persistence service ${UNIT_NAME} is enabled."
  else
    health_err_msg "Persistence service ${UNIT_NAME} is not enabled."
  fi
  if systemctl is-active --quiet "${UNIT_NAME}"; then
    health_ok "Persistence service ${UNIT_NAME} is active."
  else
    health_warn_msg "Persistence service ${UNIT_NAME} is not active."
  fi

  # Web UI
  if [[ "${WEBUI_ENABLED}" == "Y" ]]; then
    if systemctl is-active --quiet "${WEBUI_SERVICE_NAME}"; then
      health_ok "Web UI service ${WEBUI_SERVICE_NAME} is active."
    else
      health_err_msg "Web UI is enabled but ${WEBUI_SERVICE_NAME} is not active."
    fi
    if ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${WEBUI_PORT}$"; then
      health_ok "Web UI TCP port ${WEBUI_PORT} is listening."
    else
      health_err_msg "Web UI TCP port ${WEBUI_PORT} is not listening."
    fi
  else
    health_warn_msg "Web UI is disabled in the current configuration."
  fi

  echo
  echo "------------------------------------------------------------"
  if (( health_error > 0 )); then
    echo "SYSTEM HEALTH: ERROR (${health_error} error(s), ${health_warn} warning(s))"
    echo "------------------------------------------------------------"
    echo
    return 2
  elif (( health_warn > 0 )); then
    echo "SYSTEM HEALTH: WARNING (${health_warn} warning(s))"
    echo "------------------------------------------------------------"
    echo
    return 1
  else
    echo "SYSTEM HEALTH: HEALTHY"
    echo "------------------------------------------------------------"
    echo
    return 0
  fi
}

remove_all() {
  warn "REMOVE ALL will delete WireGuard configs, keys, systemd units, sysctl, rules, and generated files."
  read -r -p "Type YES to continue: " a
  [[ "${a}" == "YES" ]] || { warn "Cancelled."; return; }

  load_state
  load_webui_auth
  init_defaults

  log "Stopping services..."
  systemctl disable --now "${WEBUI_SERVICE_NAME}" >/dev/null 2>&1 || true
  systemctl disable --now "${UNIT_NAME}" >/dev/null 2>&1 || true
  systemctl disable --now "wg-quick@${WG_NAME}" >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true

  log "Removing iptables rules..."
  remove_wireguard_input_rule
  remove_webui_input_rules
  iptables_cleanup_chains
  iptables -t nat -D POSTROUTING -s "${LAN_CIDR}" -o "${PUB_IFACE}" -j MASQUERADE >/dev/null 2>&1 || true
  iptables -t nat -D POSTROUTING -s "${WG_TUN_CIDR}" -o "${PUB_IFACE}" -j MASQUERADE >/dev/null 2>&1 || true
  iptables -t nat -D POSTROUTING -d "${LAN_CIDR}" -o "${WG_NAME}" -j SNAT --to-source "${WG_VPS_IP}" >/dev/null 2>&1 || true

  if [[ "${UFW_WAS_ACTIVE}" == "Y" ]] && have_cmd ufw; then
    log "Re-enabling UFW because it was active before APPLY..."
    ufw --force enable >/dev/null 2>&1 || true
  fi

  log "Deleting files..."
  rm -f "${UNIT_FILE}" "${RULES_FILE}" "${SYSCTL_FILE}" "${STATE_FILE}" "${APPLIED_STATE_FILE}" "${WEBUI_SERVICE_FILE}" "${WEBUI_AUTH_FILE}"
  rm -f "${ROUTER_CONF_OUT}" "${REMOTE_CLIENT_CONF_OUT}" "${WG_CONF}" "${SCRIPT_INSTALL_PATH}"
  rm -f "${WG_DIR}/vps_private.key" "${WG_DIR}/vps_public.key" "${WG_DIR}/gl_private.key" "${WG_DIR}/gl_public.key" "${WG_DIR}/remote_client_private.key" "${WG_DIR}/remote_client_public.key"
  rm -f "${EULA_FLAG}" >/dev/null 2>&1 || true
  rm -rf "${WEBUI_DIR}"
  systemctl daemon-reload >/dev/null 2>&1 || true

  log "Reload sysctl defaults..."
  sysctl --system >/dev/null 2>&1 || true

  log "Purging packages (wireguard)..."
  apt-get purge -y wireguard wireguard-tools >/dev/null 2>&1 || true
  if [[ "${PYTHON3_INSTALLED_BY_SCRIPT}" == "Y" ]]; then
    log "Purging python3 because it was installed by this script..."
    apt-get purge -y python3 >/dev/null 2>&1 || true
  fi
  apt-get autoremove -y >/dev/null 2>&1 || true

  ok "REMOVE ALL completed."
}

print_apply_summary() {
  echo
  echo "GL-AXT1800 WireGuard config saved to: ${ROUTER_CONF_OUT}"
  echo "Proxmox GUI exposed on: https://${PUB_IP}:${PROXMOX_GUI_PUB_PORT}"
  echo
  echo "GL-AXT1800 VPN options recommendation:"
  echo "  Kill Switch: ON"
  echo "  Services from GL.iNet Use VPN: OFF"
  echo "  Allow Remote Access the LAN Subnet: ON"
  echo "  IP Masquerading: ON recommended (OFF also works)"
  if [[ "${WEBUI_ENABLED}" == "Y" ]]; then
    echo
    echo "Web UI:"
    echo "  https://${PUB_IP}:${WEBUI_PORT}"
    echo "  Username: ${WEBUI_USER}"
  fi
  echo
}

validate_config() {
  python3 - "$(script_real_path)" <<'PYVALIDATE'
import sys
from pathlib import Path
source = Path(sys.argv[1]).read_text(encoding="utf-8")
app = source.split("<<'PYEOF'\n", 1)[1].split("\nPYEOF", 1)[0]
namespace = {"__name__": "haibox_validation"}
exec(compile(app, "haibox_webui.py", "exec"), namespace)
state = namespace["merged_state"]()
form = {key: [value] for key, value in state.items()}
for rule in namespace["parse_extra_rules"](state.get("EXTRA_PF_RULES", "")):
    for field, value in {
        "PROTO": rule["proto"], "TARGET_IP": rule["target_ip"], "LABEL": rule["label"],
        "PORT": rule["public_from"] + "-" + rule["public_to"],
        "TARGET_PORT": rule["target_from"] + "-" + rule["target_to"],
    }.items():
        form.setdefault("EXTRA_RULE_" + field, []).append(value)
_, errors, _ = namespace["apply_form_values"](form, state)
if errors:
    print("Configuration rejected:\n" + "\n".join(errors), file=sys.stderr)
    sys.exit(1)
if not Path("/sys/class/net", state["PUB_IFACE"]).exists():
    sys.exit("Public network interface does not exist.")
PYVALIDATE
}

cleanup_previous_network_rules() (
  [[ -f "${APPLIED_STATE_FILE}" ]] || exit 0
  source "${APPLIED_STATE_FILE}"
  remove_wireguard_input_rule
  iptables -t nat -D POSTROUTING -s "${LAN_CIDR}" -o "${PUB_IFACE}" -j MASQUERADE 2>/dev/null || true
  iptables -t nat -D POSTROUTING -s "${WG_TUN_CIDR}" -o "${PUB_IFACE}" -j MASQUERADE 2>/dev/null || true
  iptables -t nat -D POSTROUTING -d "${LAN_CIDR}" -o "${WG_NAME}" -j SNAT --to-source "${WG_VPS_IP}" 2>/dev/null || true
)

apply_runtime() (
  exec 9>/run/haibox-apply.lock
  flock -n 9 || { err "Another Haibox operation is running."; exit 1; }
  validate_config
  local backup item ufw_active=N wg_active=N wg_enabled=N rules_enabled=N
  backup="$(mktemp -d /root/haibox-rollback.XXXXXX)"
  iptables-save > "${backup}/iptables.v4"
  systemctl is-active --quiet "wg-quick@${WG_NAME}" && wg_active=Y
  systemctl is-enabled --quiet "wg-quick@${WG_NAME}" && wg_enabled=Y
  systemctl is-enabled --quiet "${UNIT_NAME}" && rules_enabled=Y
  if have_cmd ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then ufw_active=Y; fi
  for item in "${WG_CONF}" "${SYSCTL_FILE}" "${RULES_FILE}" "${UNIT_FILE}"; do
    [[ ! -f "${item}" ]] || cp -p "${item}" "${backup}/$(basename "${item}")"
  done
  sysctl -n net.ipv4.ip_forward > "${backup}/ip_forward"
  sysctl -n net.ipv4.conf.all.rp_filter > "${backup}/rp_all"
  sysctl -n net.ipv4.conf.default.rp_filter > "${backup}/rp_default"
  rollback_runtime() {
    local rc=$?
    trap - EXIT
    if (( rc != 0 )); then
      set +e
      err "Apply failed; restoring previous firewall and WireGuard configuration. Backup: ${backup}"
      for item in "${WG_CONF}" "${SYSCTL_FILE}" "${RULES_FILE}" "${UNIT_FILE}"; do
        if [[ -f "${backup}/$(basename "${item}")" ]]; then
          cp -p "${backup}/$(basename "${item}")" "${item}"
        else
          rm -f "${item}"
        fi
      done
      systemctl daemon-reload
      [[ "${wg_enabled}" == Y ]] || systemctl disable "wg-quick@${WG_NAME}"
      [[ "${rules_enabled}" == Y ]] || systemctl disable "${UNIT_NAME}"
      if [[ "${wg_active}" == Y ]]; then systemctl restart "wg-quick@${WG_NAME}"; else systemctl stop "wg-quick@${WG_NAME}"; fi
      [[ "${ufw_active}" != Y ]] || ufw --force enable
      iptables-restore < "${backup}/iptables.v4"
      sysctl -w "net.ipv4.ip_forward=$(cat "${backup}/ip_forward")" "net.ipv4.conf.all.rp_filter=$(cat "${backup}/rp_all")" "net.ipv4.conf.default.rp_filter=$(cat "${backup}/rp_default")" >/dev/null
    else
      rm -rf -- "${backup}"
    fi
    exit "${rc}"
  }
  trap rollback_runtime EXIT
  trap 'exit 143' TERM
  trap 'exit 130' INT
  cleanup_previous_network_rules
  write_wg_configs
  apply_sysctl
  wg_up
  prepare_host_firewall
  iptables_apply_rules
  if [[ "${1:-N}" == Y ]]; then make_persistent; fi
  cp -p "${STATE_FILE}" "${APPLIED_STATE_FILE}"
)

apply_all() {
  prompt_config
  apply_runtime
  ok "APPLY completed."
  print_apply_summary
}

web_apply_all() {
  apply_runtime Y
  ok "APPLY + MAKE PERSISTENT completed."
  print_apply_summary
}

install_workflow() {
  load_state
  load_webui_auth
  init_defaults
  show_eula_if_needed
  automatic_webui_setup
  install_deps
  save_state
  prepare_host_firewall
  install_webui_stack
  print_webui_access
  echo "Use the Web UI to fill the configuration and press Apply."
  echo
}

reset_webui_credentials() {
  load_state
  load_webui_auth
  init_defaults
  WEBUI_USER="admin"
  WEBUI_PASSWORD="password"
  WEBUI_FORCE_PASSWORD_CHANGE="Y"
  WEBUI_PORT="${WEBUI_PORT:-65000}"
  WEBUI_BIND="0.0.0.0"
  WEBUI_ENABLED="Y"
  write_webui_auth
  save_state
  systemctl restart "${WEBUI_SERVICE_NAME}" >/dev/null 2>&1 || true
  ok "Web UI credentials reset to admin / password."
  warn "A new password will be required at the next login."
}

run_noninteractive_command() {
  case "${1:-}" in
    --web-apply)
      load_state
      load_webui_auth
      init_defaults
      web_apply_all
      ;;
    --web-test)
      load_state
      load_webui_auth
      init_defaults
      do_test
      ;;
    --health)
      load_state
      load_webui_auth
      init_defaults
      system_health
      ;;
    --create-remote-client)
      create_remote_client
      ;;
    --ensure-webui-input)
      load_state
      load_webui_auth
      init_defaults
      ensure_webui_input_rule
      ensure_wireguard_input_rule
      ;;
    --print-webui-access)
      load_state
      load_webui_auth
      init_defaults
      print_webui_access
      ;;
    --reset-webui-credentials)
      reset_webui_credentials
      ;;
    *)
      return 1
      ;;
  esac
}

menu() {
  while true; do
    load_state
    load_webui_auth
    init_defaults

    echo
    echo "HAIBOX WireGuard v6.5 (GOLDEN)"
    echo "1) INSTALL + WEB UI"
    echo "2) APPLY (terminal fallback)"
    echo "3) TEST"
    echo "4) SYSTEM HEALTH"
    echo "5) MAKE PERSISTENT"
    echo "6) REMOVE ALL"
    echo "7) Show current config"
    echo "8) Show Web UI access"
    echo "9) Reset Web UI credentials"
    echo "0) Exit"
    echo
    read -r -p "Select: " c
    case "${c}" in
      1) install_workflow; pause ;;
      2) apply_all; pause ;;
      3) do_test; pause ;;
      4) system_health || true; pause ;;
      5) make_persistent; pause ;;
      6) remove_all; pause ;;
      7) print_config; pause ;;
      8) print_webui_access; pause ;;
      9) reset_webui_credentials; pause ;;
      0) exit 0 ;;
      *) warn "Invalid choice."; pause ;;
    esac
  done
}

need_root
if [[ $# -gt 0 ]]; then
  case "$1" in
    --web-apply|--web-test|--health|--ensure-webui-input|--print-webui-access|--create-remote-client) ;;
    *) err "Unknown option: $1"; exit 1 ;;
  esac
  run_noninteractive_command "$1"
  exit 0
fi
menu
