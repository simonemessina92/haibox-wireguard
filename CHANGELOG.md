# Changelog

All notable HAIBOX WireGuard releases are recorded here. Development builds are not Golden releases until they pass physical regression testing and receive explicit approval.

## [Unreleased]

### Added in v6.6-dev.4

- Optional hostname in Configuration → Public Links. Add uses it in Public Services links and service URLs; Remove restores the VPS public IP. Saved independently of Apply, without changing DNS, VPN endpoints or forwarding rules.

### Improved in v6.6-dev.3

- Apply keeps a healthy WireGuard interface running when its generated configuration has not changed; changed or unhealthy runtime state still uses the existing restart path.
- Make Persistent enables the firewall and WireGuard services without restarting already active services and replaying the firewall a second time.
- Apply reports elapsed validation, WireGuard, firewall and total times in Last Output; the button displays an in-progress indicator while the request runs.

### Added in v6.6-dev.2

- Router-first profile switch in the initial wizard, with an optional Remote VPN Client profile for Android, iOS and computers; both profiles have authenticated QR codes in the wizard and VPN Profiles.
- Connection check animates a pulsing circle and shows a green check only after active router tunnel verification.
- Optional DMZ destination in Configuration: fixed and Extra mappings take precedence; VPS listener ports are excluded; public and WireGuard hairpin paths use the same fallback.
- Existing Remote VPN Client keys and live router tunnel are kept when creating or refreshing a client that already exists. A new peer is added live without restarting WireGuard.

### Added in v6.6-dev.1

- First-run browser wizard for router LAN, automatic Apply + Make Persistent, router WireGuard profile with copy/download/QR, and active tunnel verification before Overview.
- Password replacement continues in the authenticated setup session. A refresh restarts the wizard display with saved values and reuses existing WireGuard keys and generated profile.
- Existing installations with an applied configuration retain their dashboard without seeing the wizard.

## [6.5] — 2026-09-18

Promoted to Golden after live VPN, streaming, browser-refresh, Remote VPN Client and Web UI regression testing on the Amsterdam HAIBOX test bench.

### Fixed in v6.5-dev.7

- Action messages now use the otherwise empty header space between the HAIBOX logo and navigation without creating a second row or changing header height on desktop.
- Action messages automatically fade out and are removed after 10 seconds.

### Changed in v6.5-dev.6

- Enlarged the HAIBOX logo while retaining the compact left-aligned header.
- Action results now appear in the header only when an action has actually produced a message; the permanent Ready banner was removed.
- Removed the redundant Web UI metric and renamed WireGuard to WireGuard Port.
- Removed StreamHub Alt from the direct Public Services shortcuts.
- Added an expandable Port Redirects summary for occasional inspection of HTTPS, SSH, RTMP, router, and Proxmox mappings.
- Simplified peer rows to handshake age and LAN device rows to ICMP RTT only, removing verbose service-probe details from Overview.

### Changed in v6.5-dev.5

- Replaced the oversized hero area with a compact header using the HAIBOX logo, rectangular navigation, and a single Logout action.
- Redesigned Overview as a full-width operational dashboard with compact connection/build summary, direct Public Services links, live device status, and Network Statistics visible together.
- Removed duplicated Summary and Public Services panels from the sidebar.
- Moved the support bundle into the expandable System Information area and reduced vertical scrolling on Full HD displays.
- The Configuration sidebar remains available only where its build, UDP, rule, and output details are relevant.

### Changed in v6.5-dev.4

- Reorganized the Web UI into three clear areas: Overview, Configuration, and VPN Profiles.
- Combined live HAIBOX status and Network Statistics in the default Overview page.
- Grouped Core and Extra Port Forwarding settings inside Configuration; Apply, Test, and System Health actions now appear only there.
- Replaced the large always-visible WireGuard configuration blocks with compact profile cards, copy/download actions, and expandable configuration text.

### Fixed in v6.5-dev.3

- Converted Web UI actions to POST/Redirect/GET so refreshing the result page cannot repeat Apply, restart WireGuard, or repeat other state-changing actions.
- Apply, Test, System Health, and Remote Client results are carried through a one-time session message after the redirect.
- Corrected Network Statistics RX/TX labels to use the HAIBOX device perspective rather than the VPS `wg0` interface perspective.

### Changed in v6.5-dev.2

- Simplified Network Statistics after real-world UI testing.
- Reduced the summary to current RX and TX only.
- The chart now contains only the two total RX/TX lines.
- Replaced dynamic rankings, relative bars, peak cards, RTT ranking, and per-device chart lines with a fixed device table showing exact RX and TX rates.

### Added in v6.5-dev.1

- Per-device live traffic accounting for Router, StreamHub, HSG/HMG, Makito X4E, Windows Orchestrator, and Proxmox, plus an `Other / VPN` category.
- Redesigned Network Statistics view with device lines, live consumer ranking, total RX/TX peaks, and RTT visibility.

### Changed in v6.5-dev.1

- Proxmox TCP 8006 is now always published; the optional exposure switch has been removed.
- Configuration validation and Apply failures now present clearer, actionable error messages.

### Fixed in v6.5-dev.1

- Browser refresh no longer destroys the authenticated Web UI session. Logout remains explicit and sessions still expire server-side.

## [6.4] — 2026-09-18

Promoted to Golden after physical regression testing on the Amsterdam HAIBOX test bench.

### Added in v6.4-dev.3

- Non-interactive Web UI setup on HTTPS TCP 65000 with initial credentials `admin` / `password` on fresh installations.
- Mandatory password replacement before the dashboard can be accessed for the first time.
- Web UI credential changes require the current password and accept new passwords of at least 10 characters.
- CLI recovery action to reset credentials to `admin` / `password` and require another password replacement.
- Existing credentials are preserved during upgrades.

### Changed in v6.4-dev.3

- Removed the temporary login-attempt lockout as requested; failed logins no longer block subsequent attempts.

### Fixed in v6.4-dev.2

- Stacked Connected Peers and LAN Devices cards vertically to prevent compressed and overlapping service details.
- A device that answers ICMP is now reported as Online even when an optional monitored service is closed; the closed service remains visible in the detail line.

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

[Unreleased]: https://github.com/simonemessina92/haibox-wireguard/compare/v6.5...develop
[6.5]: https://github.com/simonemessina92/haibox-wireguard/releases/tag/v6.5
[6.4]: https://github.com/simonemessina92/haibox-wireguard/releases/tag/v6.4
[6.3]: https://github.com/simonemessina92/haibox-wireguard/releases/tag/v6.3
