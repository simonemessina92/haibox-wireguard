# HAIBOX WireGuard

HAIBOX WireGuard is a deployment and management script for building a WireGuard-based HAIBOX remote access and Internet breakout environment on a clean Debian/Ubuntu VPS.

The project is designed around a simple goal:

> Start from a fresh VPS, run one command, follow the guided setup, and obtain a fully configured HAIBOX VPN environment.

## Quick Install

Run this command as root on a fresh Debian/Ubuntu VPS:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/simonemessina92/haibox-wireguard/main/install.sh)
