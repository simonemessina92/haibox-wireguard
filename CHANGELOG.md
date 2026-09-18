# Changelog

All notable HAIBOX WireGuard releases are recorded here. Development builds are not Golden releases until they pass physical regression testing and receive explicit approval.

## [Unreleased]

Development target: v6.4.

Current test build: v6.4-dev.1.

### Added in v6.4-dev.1

- Exact build identity in the Web UI: version, channel, installed-script SHA-256, VPS uptime, OS/kernel, last Apply time, and Web UI activation time.
- Authenticated download of a sanitized support bundle containing diagnostics, HAIBOX-owned firewall chains, service states, logs, and dashboard status.
- Service-aware LAN monitoring using ICMP plus selected TCP probes for Router, StreamHub, HSG/HMG, Makito X4E, Windows Orchestrator, and Proxmox.
- Dashboard states: Online, Service Online, Reachable, Offline, and Not configured.

### Safety

- The support bundle excludes private WireGuard keys, Web UI credentials and password hashes, TLS private keys, cookies, sessions, and downloadable client configurations.
- WireGuard, routing, NAT, DNAT, hairpin DNAT, persistence, and Remote VPN Client logic remain unchanged from v6.3.

## [6.3] — 2026-09-18

Golden baseline for subsequent development.

### Added

- Live HAIBOX Web UI dashboard.
- WireGuard peer connectivity, handshake, RX, and TX status.
- HAIBOX LAN device reachability and latency monitoring.
- Parallel LAN reachability checks.
- Dashboard polling limited to the active and visible dashboard page.

### Preserved

- Tested WireGuard, routing, NAT, DNAT, hairpin DNAT, Remote VPN Client, System Health, and Network Statistics behavior from v6.2.

### Artifact

- Release asset: `haibox-wireguard_v6.3.sh`
- SHA-256: `aa01be1c788310fd10675a437cf6efe442387e1a3dad21b8147b92bd783e35d2`

## Earlier releases

The complete v6.0, v6.1, and v6.2 artifacts and notes remain available in GitHub Releases.

[Unreleased]: https://github.com/simonemessina92/haibox-wireguard/compare/v6.3...develop
[6.3]: https://github.com/simonemessina92/haibox-wireguard/releases/tag/v6.3
