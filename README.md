# HAIBOX WireGuard

HAIBOX WireGuard deploys and manages a WireGuard-based remote-access environment for HAIBOX systems through a public Debian/Ubuntu VPS.

## Stable installation

Run as `root` on a clean VPS:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/simonemessina92/haibox-wireguard/main/install.sh)
```

The stable installer always downloads the asset attached to the latest published GitHub Release. Work in progress on `develop` is never selected by this command.

## Development installation

Development builds are only for the HAIBOX test environment:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/simonemessina92/haibox-wireguard/develop/install-dev.sh)
```

The development installer downloads the current `haibox-wireguard.sh` from the `develop` branch, validates its Bash syntax, stores it as `/root/haibox-wireguard-dev.sh`, and runs it. It can change the active HAIBOX/VPS configuration and must not be treated as a production release.

## Branch policy

| Branch | Purpose |
|---|---|
| `main` | Latest physically tested Golden release |
| `develop` | Next version under development and field testing |

`main` must never contain an untested networking build. Development changes remain on `develop` until they pass the required regression tests and Simone explicitly approves promotion to Golden.

The tracked source filename is always `haibox-wireguard.sh`. Versioned filenames such as `haibox-wireguard_v6.4.sh` are generated only as GitHub Release assets. Previous versions remain available through tags and Releases rather than as duplicate source files on `main`.

## Development lifecycle

1. Start from the current Golden source.
2. Implement and statically validate changes on `develop`.
3. Test with `install-dev.sh` on the real VPS + HAIBOX environment.
4. Repeat until the mandatory regression checks pass.
5. Obtain explicit Golden approval from Simone.
6. Merge the approved source into `main`.
7. Commit a validated `.github/release-request.json` on `main` to create the tag, GitHub Release, versioned script asset, and SHA-256 checksum automatically.

See [`DEVELOPMENT_BASELINE.md`](DEVELOPMENT_BASELINE.md) for architecture, invariants, and the mandatory regression checklist. See [`CHANGELOG.md`](CHANGELOG.md) for release history.

## Main features

- WireGuard server deployment on a VPS
- HAIBOX router full-tunnel configuration
- HAIBOX LAN Internet breakout through the VPS public IPv4
- Public and hairpin DNAT for HAIBOX services
- Optional Remote VPN Client
- Persistent routing and firewall configuration
- Authenticated HTTPS management Web UI
- System Health diagnostics
- Live WireGuard and HAIBOX LAN dashboard
- Downloadable router and remote-client configurations

## Default addressing

| Component | Default address |
|---|---:|
| HAIBOX Router | `192.168.10.1` |
| StreamHub | `192.168.10.101` |
| HSG/HMG | `192.168.10.102` |
| Makito X4E | `192.168.10.103` |
| Windows Orchestrator | `192.168.10.104` |
| Proxmox | `192.168.10.250` |
| VPS WireGuard | `10.66.66.1` |
| HAIBOX Router WireGuard | `10.66.66.2` |
| Remote VPN Client | `10.66.66.3` |

## Project

Designed and developed by **Simone Messina**.

The software is provided as-is, without warranty. Review the configuration before using it on production systems.
